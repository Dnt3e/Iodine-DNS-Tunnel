#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

CONF_DIR="/etc/iodine-manager"
CONF_FILE="$CONF_DIR/tunnel.conf"
PASSWORD_FILE="$CONF_DIR/password"
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="iodine-mgr"
LOG_FILE="/var/log/iodine-manager.log"
LOCK_FILE="/var/run/iodine-manager.lock"
TUN_SERVER_IP="10.50.50.1"
TUN_SUBNET="10.50.50.0/24"
DNS_RESOLVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")
LOG_MAX_SIZE=$((5 * 1024 * 1024))

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "Another instance is running."
    exit 1
fi

cleanup_on_exit() {
    rm -f /tmp/iodine-mgr-* 2>/dev/null
    flock -u 200 2>/dev/null
    unset PASSWORD PASSWORD2
}

trap cleanup_on_exit EXIT
trap 'echo -e "\n${YELLOW}Interrupted${NC}"; cleanup_on_exit; exit 130' INT TERM

log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    if [ -f "$LOG_FILE" ]; then
        local log_size
        log_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$log_size" -gt "$LOG_MAX_SIZE" ]; then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            gzip "${LOG_FILE}.old" 2>/dev/null &
        fi
    fi
    echo "$message" >> "$LOG_FILE"
    case $level in
        ERROR) echo -e "${RED}[ERROR] $*${NC}" >&2 ;;
        WARN)  echo -e "${YELLOW}[WARN] $*${NC}" >&2 ;;
        INFO)  echo -e "${GREEN}[INFO] $*${NC}" ;;
        *)     echo "$message" ;;
    esac
}

validate_domain() {
    local domain=$1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_port_list() {
    local port_list=$1
    IFS=',' read -ra PORTS <<< "$port_list"
    for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs)
        validate_port "$port" || return 1
    done
    return 0
}

load_config() {
    local conf_file="$1"
    if [ ! -f "$conf_file" ]; then
        log ERROR "Config file not found: $conf_file"
        return 1
    fi
    local allowed_keys=(ROLE DOMAIN PORT_LIST MTU_SIZE DNS_TYPE DOWN_CODEC LAZY_INTERVAL FORCE_DNS MAX_HOSTNAME_LEN)
    ROLE=""
    DOMAIN=""
    PORT_LIST=""
    MTU_SIZE=""
    DNS_TYPE=""
    DOWN_CODEC=""
    LAZY_INTERVAL=""
    FORCE_DNS=""
    MAX_HOSTNAME_LEN=""
    while IFS='=' read -r key value; do
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        local valid=false
        for allowed in "${allowed_keys[@]}"; do
            if [ "$key" == "$allowed" ]; then
                valid=true
                break
            fi
        done
        $valid || continue
        declare -g "$key=$value"
    done < "$conf_file"
    if [[ -n "$ROLE" && "$ROLE" != "server" && "$ROLE" != "client" ]]; then
        log ERROR "Invalid ROLE: $ROLE"
        return 1
    fi
    return 0
}

draw_header() {
    clear
    local service_stat=""
    local role="NONE"
    if systemctl is-active --quiet iodine-server 2>/dev/null; then
        service_stat="${GREEN}RUNNING${NC}"
        role="SERVER"
    elif systemctl is-active --quiet iodine-client 2>/dev/null; then
        service_stat="${GREEN}RUNNING${NC}"
        role="CLIENT"
    else
        service_stat="${RED}STOPPED${NC}"
    fi
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}I O D I N E   D N S   T U N N E L   M A N A G E R${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                 ${YELLOW}Created by: Dnt3e${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Status: ${service_stat}     Role: ${YELLOW}${role}${NC}"
    if [[ "$role" != "NONE" ]]; then
        local tun_ip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        [ -n "$tun_ip" ] && echo -e "${CYAN}║${NC}  Tunnel IP: ${BLUE}${tun_ip}${NC}"
    fi
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
}

preflight_checks() {
    if [ ! -e /dev/net/tun ]; then
        log ERROR "/dev/net/tun not found"
        echo -e "${RED}TUN device not available${NC}" >&2
        echo -e "${YELLOW}Run: mkdir -p /dev/net && mknod /dev/net/tun c 10 200${NC}" >&2
        exit 1
    fi
    lsmod | grep -q tun 2>/dev/null || modprobe tun 2>/dev/null || true
}

preflight_checks

enable_ip_forward_permanent() {
    sysctl -w net.ipv4.ip_forward=1 >> "$LOG_FILE" 2>&1
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-iodine.conf
    sysctl --system >/dev/null 2>&1
}

mtu_detect() {
    local target=$1
    echo -e "${YELLOW}Detecting optimal MTU...${NC}" >&2
    local low=1280
    local high=1500
    local optimal=$low
    if ! ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Target unreachable, default MTU 1280${NC}" >&2
        echo "1280"
        return
    fi
    while [ $low -le $high ]; do
        local mid=$(( (low + high) / 2 ))
        echo -ne "  MTU ${CYAN}${mid}${NC}... " >&2
        if ping -M do -s $((mid - 28)) -c 2 -W 2 "$target" >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}" >&2
            optimal=$mid
            low=$((mid + 1))
        else
            echo -e "${RED}✗${NC}" >&2
            high=$((mid - 1))
        fi
    done
    echo -e "${GREEN}✓ Optimal MTU: ${BOLD}$optimal${NC}" >&2
    echo "$optimal"
}

test_dns_multi() {
    local domain=$1
    echo -e "${YELLOW}Testing DNS delegation...${NC}"
    local resolvers_ok=0
    for resolver in "${DNS_RESOLVERS[@]}"; do
        echo -ne "  Resolver ${CYAN}${resolver}${NC}... "
        local ns_result=$(dig +short NS "$domain" "@$resolver" +time=2 +tries=1 2>/dev/null | head -n1)
        if [ -n "$ns_result" ]; then
            echo -e "${GREEN}✓${NC}"
            ((resolvers_ok++))
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    if [ $resolvers_ok -eq 0 ]; then
        echo -e "\n${RED}⚠ No NS records found!${NC}"
        echo -e "${YELLOW}Required DNS setup:${NC}"
        echo -e "  1. A record:  ${CYAN}tun.yourdomain.com${NC} → Your Server IP"
        echo -e "  2. NS record: ${CYAN}$domain${NC} → ${CYAN}tun.yourdomain.com${NC}"
        echo ""
        read -p "Continue anyway? (y/n): " cont
        [[ "$cont" =~ ^[Yy]$ ]] || return 1
    else
        echo -e "${GREEN}✓ DNS working on $resolvers_ok/${#DNS_RESOLVERS[@]} resolvers${NC}"
    fi
    return 0
}

fw_apply() {
    if [ ! -f "$CONF_FILE" ]; then
        log ERROR "Config file not found"
        return 1
    fi
    load_config "$CONF_FILE" || return 1
    local DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -z "$DEFAULT_IF" ]; then
        log ERROR "Cannot determine default interface"
        return 1
    fi
    enable_ip_forward_permanent
    iptables -t nat -N IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST 2>/dev/null
    iptables -t nat -A IODINE_POST -s "$TUN_SUBNET" -o "$DEFAULT_IF" -j MASQUERADE
    iptables -t nat -C POSTROUTING -j IODINE_POST 2>/dev/null || \
        iptables -t nat -A POSTROUTING -j IODINE_POST
    iptables -D FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT
    iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    if [ "$ROLE" == "client" ] && [ -n "$PORT_LIST" ]; then
        iptables -t nat -N IODINE_PRE 2>/dev/null
        iptables -t nat -F IODINE_PRE 2>/dev/null
        IFS=',' read -ra PORTS <<< "$PORT_LIST"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | xargs)
            validate_port "$port" || continue
            iptables -t nat -A IODINE_PRE -i "$DEFAULT_IF" -p tcp --dport "$port" -j DNAT --to-destination "$TUN_SERVER_IP:$port"
            iptables -t nat -A IODINE_PRE -i "$DEFAULT_IF" -p udp --dport "$port" -j DNAT --to-destination "$TUN_SERVER_IP:$port"
            iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            iptables -A FORWARD -i "$DEFAULT_IF" -o dns0 -p udp --dport "$port" -j ACCEPT 2>/dev/null
        done
        iptables -t nat -C PREROUTING -j IODINE_PRE 2>/dev/null || \
            iptables -t nat -A PREROUTING -j IODINE_PRE
    fi
    log INFO "Firewall rules applied"
}

fw_clean() {
    iptables -t nat -D POSTROUTING -j IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST 2>/dev/null
    iptables -t nat -X IODINE_POST 2>/dev/null
    iptables -t nat -D PREROUTING -j IODINE_PRE 2>/dev/null
    iptables -t nat -F IODINE_PRE 2>/dev/null
    iptables -t nat -X IODINE_PRE 2>/dev/null
    local DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -n "$DEFAULT_IF" ]; then
        iptables -D FORWARD -i dns0 -o "$DEFAULT_IF" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i "$DEFAULT_IF" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi
    log INFO "Firewall cleaned"
}

build_exec_cmd() {
    local password
    password=$(cat "$PASSWORD_FILE" 2>/dev/null)
    if [ -z "$password" ]; then
        log ERROR "Password file empty or missing"
        return 1
    fi
    if [ "$ROLE" == "server" ]; then
        EXEC_CMD="/usr/sbin/iodined -f -c -P \"${password}\" -4"
        [ -n "$MTU_SIZE" ] && EXEC_CMD="$EXEC_CMD -M $MTU_SIZE"
        [ -n "$DNS_TYPE" ] && EXEC_CMD="$EXEC_CMD -T $DNS_TYPE"
        [ -n "$LAZY_INTERVAL" ] && EXEC_CMD="$EXEC_CMD -I $LAZY_INTERVAL"
        EXEC_CMD="$EXEC_CMD $TUN_SERVER_IP $DOMAIN"
    else
        EXEC_CMD="/usr/sbin/iodine -f -P \"${password}\""
        [ -n "$MTU_SIZE" ] && EXEC_CMD="$EXEC_CMD -M $MTU_SIZE"
        [ -n "$MAX_HOSTNAME_LEN" ] && EXEC_CMD="$EXEC_CMD -m $MAX_HOSTNAME_LEN"
        [ -n "$DNS_TYPE" ] && EXEC_CMD="$EXEC_CMD -T $DNS_TYPE"
        [ -n "$DOWN_CODEC" ] && EXEC_CMD="$EXEC_CMD -O $DOWN_CODEC"
        [ -n "$LAZY_INTERVAL" ] && EXEC_CMD="$EXEC_CMD -I $LAZY_INTERVAL"
        [ "$FORCE_DNS" == "yes" ] && EXEC_CMD="$EXEC_CMD -r"
        EXEC_CMD="$EXEC_CMD $DOMAIN"
    fi
    return 0
}

service_create() {
    local service_name="iodine-${ROLE}"
    log INFO "Creating systemd service: $service_name"

    build_exec_cmd || return 1

    cat <<EOF > /etc/systemd/system/${service_name}.service
[Unit]
Description=Iodine DNS Tunnel ($ROLE)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash -c '${EXEC_CMD}'
ExecStartPost=/bin/sleep 3
ExecStartPost=$INSTALL_DIR/$SCRIPT_NAME --apply-fw
ExecStopPost=$INSTALL_DIR/$SCRIPT_NAME --clean-fw
Restart=always
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=iodine-${ROLE}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${service_name}" >/dev/null 2>&1

    systemctl stop iodine-server iodine-client 2>/dev/null

    systemctl start "${service_name}"
    sleep 5

    if ! systemctl is-active --quiet "${service_name}"; then
        log ERROR "Service failed to start"
        echo -e "${RED}✗ Tunnel failed to start${NC}"
        echo -e "${YELLOW}Debug info:${NC}"
        journalctl -u "${service_name}" --no-pager -n 15
        echo ""
        echo -e "${YELLOW}Manual test:${NC}"
        echo -e "${CYAN}${EXEC_CMD}${NC}"
        return 1
    fi
    log INFO "Service $service_name started"
    return 0
}

install_deps() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    local missing=false
    for tool in iodined iodine iptables lsof dig; do
        command -v "$tool" &>/dev/null || missing=true
    done
    if $missing; then
        log INFO "Installing packages"
        if [ -f /etc/debian_version ]; then
            apt-get update -qq 2>>"$LOG_FILE" || true
            apt-get install -y -qq iodine iproute2 iptables lsof dnsutils bc >>"$LOG_FILE" 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y -q epel-release >>"$LOG_FILE" 2>&1 || true
            yum install -y -q iodine iproute iptables lsof bind-utils bc >>"$LOG_FILE" 2>&1
        else
            echo -e "${RED}Unsupported distribution. Install manually: iodine iptables lsof dnsutils${NC}"
            exit 1
        fi
        for tool in iodined iodine; do
            if ! command -v "$tool" &>/dev/null; then
                echo -e "${RED}Failed to install $tool${NC}"
                exit 1
            fi
        done
    fi
    local current_path
    current_path="$(realpath "$0" 2>/dev/null || readlink -f "$0")"
    if [[ "$current_path" != "$INSTALL_DIR/$SCRIPT_NAME" ]]; then
        cp "$current_path" "$INSTALL_DIR/$SCRIPT_NAME"
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    fi
    echo -e "${GREEN}✓ Dependencies ready${NC}"
}

check_port_53() {
    echo -e "${YELLOW}Checking UDP port 53...${NC}"
    local occupier=$(lsof -i UDP:53 -t 2>/dev/null | head -n1)
    if [ -n "$occupier" ]; then
        local pname=$(ps -p "$occupier" -o comm= 2>/dev/null || echo "unknown")
        echo -e "${RED}Port 53 occupied by: ${BOLD}$pname${NC}"
        if [[ "$pname" == *"systemd-resolve"* ]] || [[ "$pname" == "systemd-resolved" ]]; then
            read -p "Stop systemd-resolved? (y/n): " fix_dns
            if [[ "$fix_dns" =~ ^[Yy]$ ]]; then
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                rm -f /etc/resolv.conf
                cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF
                chmod 644 /etc/resolv.conf
                echo -e "${GREEN}✓ Port 53 freed${NC}"
            else
                exit 1
            fi
        else
            echo -e "${YELLOW}Kill it manually: sudo kill $occupier${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ Port 53 available${NC}"
    fi
}

read_password() {
    local password=""
    local password2=""
    while true; do
        read -rs -p "Tunnel Password (min 8 chars): " password
        echo
        if [ ${#password} -lt 8 ]; then
            echo -e "${RED}Too short${NC}"
            continue
        fi
        read -rs -p "Confirm: " password2
        echo
        [ "$password" == "$password2" ] && break
        echo -e "${RED}Passwords don't match${NC}"
    done
    (
        umask 077
        printf '%s' "$password" > "$PASSWORD_FILE"
    )
    chown root:root "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
    password=""
    password2=""
}

run_setup() {
    install_deps
    echo -e "${BOLD}Select Role:${NC}"
    echo "1) Server (Exit Node)"
    echo "2) Client (Entry Point)"
    read -p "Select [1/2]: " opt

    if [ "$opt" == "1" ]; then
        ROLE="server"
        check_port_53
        echo -e "\n${YELLOW}DNS Requirements:${NC}"
        echo "  1. A record:  tun.example.com → Your Server IP"
        echo "  2. NS record: t1.example.com  → tun.example.com"
        echo ""
        while true; do
            read -p "NS Subdomain (e.g. t1.example.com): " DOMAIN
            validate_domain "$DOMAIN" && break
            echo -e "${RED}Invalid domain${NC}"
        done
        test_dns_multi "$DOMAIN" || return 1
        read_password
        echo -e "\n${BOLD}Advanced Options:${NC}"
        read -p "Auto-detect MTU? (y/n): " auto_mtu
        if [[ "$auto_mtu" =~ ^[Yy]$ ]]; then
            MTU_SIZE=$(mtu_detect "8.8.8.8")
        else
            read -p "MTU (default 1280): " MTU_SIZE
            MTU_SIZE=${MTU_SIZE:-1280}
        fi
        read -p "DNS type (null/txt/srv/mx, default auto): " DNS_TYPE
        read -p "Lazy interval (default 4): " LAZY_INTERVAL
        LAZY_INTERVAL=${LAZY_INTERVAL:-4}
        PORT_LIST=""
        FORCE_DNS="no"
        MAX_HOSTNAME_LEN=""
        DOWN_CODEC=""

    elif [ "$opt" == "2" ]; then
        ROLE="client"
        while true; do
            read -p "Server NS Subdomain: " DOMAIN
            validate_domain "$DOMAIN" && break
            echo -e "${RED}Invalid domain${NC}"
        done
        read_password
        echo -e "\n${YELLOW}Ports to forward (comma-separated, e.g. 443,2053):${NC}"
        while true; do
            read -p "Ports: " PORT_LIST
            [ -z "$PORT_LIST" ] && break
            validate_port_list "$PORT_LIST" && break
            echo -e "${RED}Invalid port format${NC}"
        done
        echo -e "\n${BOLD}Advanced Options:${NC}"
        read -p "Auto-detect MTU? (y/n): " auto_mtu
        if [[ "$auto_mtu" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Will detect after tunnel is up${NC}"
            MTU_SIZE=""
        else
            read -p "MTU (default 1280): " MTU_SIZE
            MTU_SIZE=${MTU_SIZE:-1280}
        fi
        read -p "Max hostname length (default 255): " MAX_HOSTNAME_LEN
        read -p "DNS type (null/txt/srv/mx, default auto): " DNS_TYPE
        read -p "Downstream codec (raw/base128/base64, default auto): " DOWN_CODEC
        read -p "Lazy interval (default 4): " LAZY_INTERVAL
        LAZY_INTERVAL=${LAZY_INTERVAL:-4}
        read -p "Force DNS mode? (y/n, default n): " force_answer
        [[ "$force_answer" =~ ^[Yy]$ ]] && FORCE_DNS="yes" || FORCE_DNS="no"
    else
        echo "Invalid option"
        return
    fi

    cat <<EOF > "$CONF_FILE"
ROLE=$ROLE
DOMAIN=$DOMAIN
PORT_LIST=$PORT_LIST
MTU_SIZE=$MTU_SIZE
DNS_TYPE=$DNS_TYPE
DOWN_CODEC=$DOWN_CODEC
LAZY_INTERVAL=$LAZY_INTERVAL
FORCE_DNS=$FORCE_DNS
MAX_HOSTNAME_LEN=$MAX_HOSTNAME_LEN
EOF
    chmod 600 "$CONF_FILE"

    systemctl stop iodine-server iodine-client 2>/dev/null
    systemctl disable iodine-server iodine-client 2>/dev/null
    rm -f /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service
    systemctl daemon-reload

    echo ""
    if ! service_create; then
        echo -e "${RED}Setup failed${NC}"
        return 1
    fi

    echo -e "${GREEN}✓ Iodine $ROLE configured and running${NC}"

    if [ "$ROLE" == "client" ] && [ -z "$MTU_SIZE" ]; then
        echo ""
        sleep 3
        local detected_mtu
        detected_mtu=$(mtu_detect "$TUN_SERVER_IP")
        if [[ "$detected_mtu" =~ ^[0-9]+$ ]]; then
            MTU_SIZE="$detected_mtu"
            sed -i "s/^MTU_SIZE=.*/MTU_SIZE=$MTU_SIZE/" "$CONF_FILE"
            service_create
            echo -e "${GREEN}✓ MTU set to $MTU_SIZE${NC}"
        fi
    fi

    echo -e "\n${CYAN}Summary:${NC}"
    echo -e "  Role:   ${YELLOW}$ROLE${NC}"
    echo -e "  Domain: ${YELLOW}$DOMAIN${NC}"
    echo -e "  MTU:    ${YELLOW}${MTU_SIZE:-auto}${NC}"
    [ -n "$PORT_LIST" ] && echo -e "  Ports:  ${YELLOW}$PORT_LIST${NC}"
    echo ""
    read -p "Press Enter..."
}

show_status() {
    draw_header

    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured. Run Install first.${NC}"
        read -p "Press Enter..."
        return
    fi

    load_config "$CONF_FILE" || return
    local svc="iodine-${ROLE}"

    echo -e "${BOLD}[Interface]${NC}"
    if ip addr show dns0 2>/dev/null | grep -q inet; then
        local tun_ip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e "  dns0: ${GREEN}UP${NC} (${tun_ip})"
    else
        echo -e "  dns0: ${RED}DOWN${NC}"
    fi

    echo -e "\n${BOLD}[Service]${NC}"
    if systemctl is-active --quiet "$svc"; then
        echo -e "  $svc: ${GREEN}● Running${NC}"
    else
        echo -e "  $svc: ${RED}● Stopped${NC}"
    fi

    echo -e "\n${BOLD}[Connection]${NC}"
    if [ "$ROLE" == "server" ]; then
        echo -e "  Listening on $TUN_SERVER_IP"
    else
        echo -ne "  Ping $TUN_SERVER_IP: "
        if ping -c 3 -W 3 "$TUN_SERVER_IP" >/dev/null 2>&1; then
            local rtt=$(ping -c 5 -q "$TUN_SERVER_IP" 2>/dev/null | grep 'rtt min' | awk -F'/' '{print $5}')
            echo -e "${GREEN}✓${NC} (${rtt}ms)"
        else
            echo -e "${RED}✗ Failed${NC}"
        fi
    fi

    echo -e "\n${BOLD}[Config]${NC}"
    echo -e "  Role:   ${YELLOW}$ROLE${NC}"
    echo -e "  Domain: ${YELLOW}$DOMAIN${NC}"
    echo -e "  MTU:    ${YELLOW}${MTU_SIZE:-auto}${NC}"
    [ -n "$PORT_LIST" ] && echo -e "  Ports:  ${YELLOW}$PORT_LIST${NC}"

    echo -e "\n${BOLD}[Interface Stats]${NC}"
    ip -s link show dns0 2>/dev/null | grep -E "RX|TX|bytes" || echo "  N/A"

    echo -e "\n${BOLD}[Recent Logs]${NC}"
    journalctl -u "$svc" --no-pager -n 5 2>/dev/null || echo "  No logs"

    echo ""
    read -p "Press Enter..."
}

edit_config() {
    draw_header
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        read -p "Press Enter..."
        return
    fi
    load_config "$CONF_FILE" || return
    echo -e "${BOLD}Configuration Editor${NC}\n"
    echo "1) DNS Type:       ${YELLOW}${DNS_TYPE:-auto}${NC}"
    echo "2) MTU Size:       ${YELLOW}${MTU_SIZE:-auto}${NC}"
    echo "3) Lazy Interval:  ${YELLOW}${LAZY_INTERVAL:-4}s${NC}"
    [ "$ROLE" == "client" ] && echo "4) Codec:          ${YELLOW}${DOWN_CODEC:-auto}${NC}"
    echo "5) Change Password"
    echo "0) Back"
    echo ""
    read -p "Edit: " edit_opt
    case $edit_opt in
        1)
            read -p "DNS Type (null/txt/srv/mx): " DNS_TYPE
            sed -i "s/^DNS_TYPE=.*/DNS_TYPE=$DNS_TYPE/" "$CONF_FILE"
            ;;
        2)
            read -p "Auto-detect? (y/n): " amtu
            if [[ "$amtu" =~ ^[Yy]$ ]]; then
                MTU_SIZE=$(mtu_detect "$TUN_SERVER_IP")
                [[ "$MTU_SIZE" =~ ^[0-9]+$ ]] || { echo -e "${RED}Failed${NC}"; read -p "Press Enter..."; return; }
            else
                read -p "MTU: " MTU_SIZE
            fi
            sed -i "s/^MTU_SIZE=.*/MTU_SIZE=$MTU_SIZE/" "$CONF_FILE"
            ;;
        3)
            read -p "Lazy Interval (s): " LAZY_INTERVAL
            sed -i "s/^LAZY_INTERVAL=.*/LAZY_INTERVAL=$LAZY_INTERVAL/" "$CONF_FILE"
            ;;
        4)
            [ "$ROLE" != "client" ] && return
            read -p "Codec (raw/base128/base64): " DOWN_CODEC
            sed -i "s/^DOWN_CODEC=.*/DOWN_CODEC=$DOWN_CODEC/" "$CONF_FILE"
            ;;
        5)
            read_password
            ;;
        0) return ;;
        *) return ;;
    esac
    echo -e "${GREEN}Updated${NC}"
    read -p "Restart service? (y/n): " dorst
    if [[ "$dorst" =~ ^[Yy]$ ]]; then
        load_config "$CONF_FILE" || return
        service_create
    fi
    read -p "Press Enter..."
}

service_menu() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}Not configured${NC}"
        sleep 2
        return
    fi
    load_config "$CONF_FILE" || return
    local svc="iodine-${ROLE}"

    while true; do
        draw_header
        echo -e "${BOLD}Service Management${NC}"
        echo "1) Live Logs"
        echo "2) Recent Logs (50 lines)"
        echo "3) Restart"
        echo "4) Stop"
        echo "5) Start"
        echo "6) Full Status"
        echo "7) Performance Test"
        echo "0) Back"
        echo ""
        read -p "Select: " s_opt
        case $s_opt in
            1)
                echo -e "\n${CYAN}Ctrl+C to exit${NC}\n"
                sleep 1
                journalctl -u "$svc" -f
                ;;
            2)
                journalctl -u "$svc" --no-pager -n 50
                read -p "Press Enter..."
                ;;
            3)
                load_config "$CONF_FILE" || continue
                service_create
                ;;
            4)
                systemctl stop "$svc"
                echo -e "${YELLOW}Stopped${NC}"
                sleep 1
                ;;
            5)
                systemctl start "$svc"
                echo -e "${GREEN}✓ Started${NC}"
                sleep 1
                ;;
            6)
                systemctl status "$svc" --no-pager
                read -p "Press Enter..."
                ;;
            7)
                if [ "$ROLE" != "client" ]; then
                    echo -e "${YELLOW}Performance test only for client${NC}"
                    read -p "Press Enter..."
                    continue
                fi
                echo -e "${BOLD}Performance Test${NC}\n"
                echo -e "${CYAN}[1/3] Latency${NC}"
                if ping -c 10 -q "$TUN_SERVER_IP" >/dev/null 2>&1; then
                    ping -c 10 -q "$TUN_SERVER_IP" | grep 'rtt min'
                else
                    echo -e "${RED}Ping failed${NC}"
                fi
                echo -e "\n${CYAN}[2/3] Interface Stats${NC}"
                ip -s link show dns0 2>/dev/null || echo "N/A"
                echo -e "\n${CYAN}[3/3] Recent Activity${NC}"
                journalctl -u "$svc" --since "10 minutes ago" --no-pager | tail -10
                echo ""
                read -p "Press Enter..."
                ;;
            0) break ;;
        esac
    done
}

clean_all() {
    draw_header
    echo -e "${RED}${BOLD}Complete Removal${NC}"
    echo ""
    read -p "Type 'YES' to confirm: " confirm
    [[ "$confirm" != "YES" ]] && return
    for svc in iodine-server iodine-client; do
        systemctl stop "$svc" 2>/dev/null
        systemctl disable "$svc" 2>/dev/null
        rm -f "/etc/systemd/system/${svc}.service"
    done
    fw_clean
    rm -f /etc/sysctl.d/99-iodine.conf
    sysctl --system >/dev/null 2>&1
    rm -rf "$CONF_DIR"
    rm -f "$LOG_FILE" "${LOG_FILE}.old" "${LOG_FILE}.old.gz"
    rm -f "$LOCK_FILE"
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/$SCRIPT_NAME"
    echo -e "${GREEN}✓ Removed${NC}"
    sleep 2
    exit 0
}

show_usage() {
    echo "Usage: $SCRIPT_NAME [OPTION]"
    echo ""
    echo "  --setup       Interactive setup"
    echo "  --status      Quick status"
    echo "  --start       Start service"
    echo "  --stop        Stop service"
    echo "  --restart     Restart service"
    echo "  --apply-fw    Apply firewall"
    echo "  --clean-fw    Clean firewall"
    echo "  --uninstall   Remove all"
    echo "  --help        This help"
    echo ""
    echo "No args = interactive menu"
}

case "${1:-}" in
    --apply-fw)  fw_apply; exit $? ;;
    --clean-fw)  fw_clean; exit $? ;;
    --setup)     run_setup; exit $? ;;
    --status)    show_status; exit $? ;;
    --start)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; systemctl start "iodine-${ROLE}"; } || echo "Not configured"
        exit $? ;;
    --stop)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; systemctl stop "iodine-${ROLE}"; } || echo "Not configured"
        exit $? ;;
    --restart)
        [ -f "$CONF_FILE" ] && { load_config "$CONF_FILE"; service_create; } || echo "Not configured"
        exit $? ;;
    --uninstall) clean_all; exit $? ;;
    --help|-h)   show_usage; exit 0 ;;
    "")          ;;
    *)           echo "Unknown: $1"; show_usage; exit 1 ;;
esac

while true; do
    draw_header
    echo "1) Install & Configure"
    echo "2) Status"
    echo "3) Edit Configuration"
    echo "4) Service Manager"
    echo "5) Uninstall"
    echo "0) Exit"
    echo ""
    read -p "Select: " opt
    case $opt in
        1) run_setup ;;
        2) show_status ;;
        3) edit_config ;;
        4) service_menu ;;
        5) clean_all ;;
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
    esac
done
