#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

CONF_DIR="/etc/iodine-manager"
CONF_FILE="$CONF_DIR/tunnel.conf"
PASSWORD_FILE="$CONF_DIR/password"
ENV_FILE="$CONF_DIR/iodine.env"
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
    flock -u 200 2>/dev/null
}
trap cleanup_on_exit EXIT
trap 'echo -e "\n${YELLOW}Interrupted${NC}"; exit 130' INT TERM

log() {
    local level=$1; shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    if [ -f "$LOG_FILE" ]; then
        local sz
        sz=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$LOG_MAX_SIZE" ]; then
            mv "$LOG_FILE" "${LOG_FILE}.1"
        fi
    fi
    echo "$msg" >> "$LOG_FILE"
    case $level in
        ERROR) echo -e "${RED}$msg${NC}" >&2 ;;
        WARN)  echo -e "${YELLOW}$msg${NC}" >&2 ;;
        INFO)  echo -e "${GREEN}$msg${NC}" ;;
    esac
}

validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && [[ "$1" == *.* ]]
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

validate_port_list() {
    local pl="$1"
    [ -z "$pl" ] && return 0
    IFS=',' read -ra arr <<< "$pl"
    for p in "${arr[@]}"; do
        p=$(echo "$p" | tr -d ' ')
        validate_port "$p" || return 1
    done
    return 0
}

load_config() {
    ROLE="" DOMAIN="" PORT_LIST="" MTU_SIZE="" DNS_TYPE=""
    DOWN_CODEC="" LAZY_INTERVAL="" FORCE_DNS="" MAX_HOSTNAME_LEN=""
    [ ! -f "$CONF_FILE" ] && return 1
    local allowed="ROLE DOMAIN PORT_LIST MTU_SIZE DNS_TYPE DOWN_CODEC LAZY_INTERVAL FORCE_DNS MAX_HOSTNAME_LEN"
    while IFS='=' read -r k v; do
        k=$(echo "$k" | tr -d '[:space:]')
        v=$(echo "$v" | tr -d '[:space:]')
        [[ -z "$k" || "$k" == \#* ]] && continue
        local ok=false
        for a in $allowed; do [ "$k" = "$a" ] && ok=true && break; done
        $ok && declare -g "$k=$v"
    done < "$CONF_FILE"
    [[ "$ROLE" == "server" || "$ROLE" == "client" ]] || return 1
    return 0
}

save_config() {
    cat > "$CONF_FILE" <<EOF
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
}

get_svc_name() {
    load_config 2>/dev/null && echo "iodine-${ROLE}" || echo ""
}

get_default_if() {
    ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

draw_header() {
    clear
    local sstat role="NONE"
    if systemctl is-active --quiet iodine-server 2>/dev/null; then
        sstat="${GREEN}RUNNING${NC}"; role="SERVER"
    elif systemctl is-active --quiet iodine-client 2>/dev/null; then
        sstat="${GREEN}RUNNING${NC}"; role="CLIENT"
    else
        sstat="${RED}STOPPED${NC}"
    fi
    echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}I O D I N E   D N S   T U N N E L   M G R${NC}        ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Status: ${sstat}    Role: ${YELLOW}${role}${NC}"
    if [[ "$role" != "NONE" ]]; then
        local tip
        tip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        [ -n "$tip" ] && echo -e "${CYAN}║${NC}  Tunnel: ${BLUE}${tip}${NC}"
    fi
    echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
    echo
}

preflight_checks() {
    if [ ! -e /dev/net/tun ]; then
        echo -e "${RED}TUN device missing. Create with:${NC}" >&2
        echo "  mkdir -p /dev/net && mknod /dev/net/tun c 10 200" >&2
        exit 1
    fi
    lsmod | grep -q '^tun ' 2>/dev/null || modprobe tun 2>/dev/null || true
}
preflight_checks

enable_ip_forward() {
    sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null
    local f="/etc/sysctl.d/99-iodine.conf"
    if [ ! -f "$f" ] || ! grep -q 'net.ipv4.ip_forward=1' "$f" 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" > "$f"
        sysctl --system >/dev/null 2>&1
    fi
}

mtu_detect() {
    local target=$1
    echo -e "${YELLOW}Detecting MTU to $target ...${NC}" >&2
    local lo=1280 hi=1500 best=1280
    if ! ping -c1 -W2 "$target" >/dev/null 2>&1; then
        echo -e "${YELLOW}Unreachable, using 1280${NC}" >&2
        echo 1280; return
    fi
    while [ $lo -le $hi ]; do
        local mid=$(( (lo+hi)/2 ))
        if ping -M do -s $((mid-28)) -c2 -W2 "$target" >/dev/null 2>&1; then
            best=$mid; lo=$((mid+1))
        else
            hi=$((mid-1))
        fi
    done
    echo -e "${GREEN}MTU: $best${NC}" >&2
    echo "$best"
}

detect_dns_type() {
    local domain=$1
    echo -e "${YELLOW}Detecting DNS type...${NC}" >&2
    for t in NULL TXT SRV MX CNAME; do
        if dig +short -t "$t" "test123.$domain" "@${DNS_RESOLVERS[0]}" +time=3 +tries=1 2>/dev/null | grep -q .; then
            echo -e "${GREEN}Best: $t${NC}" >&2
            echo "$t"; return
        fi
    done
    echo -e "${YELLOW}None responded, using NULL${NC}" >&2
    echo "NULL"
}

test_dns_delegation() {
    local domain=$1 ok=0
    echo -e "${YELLOW}Testing DNS delegation...${NC}"
    for r in "${DNS_RESOLVERS[@]}"; do
        printf "  %-16s" "$r"
        if dig +short NS "$domain" "@$r" +time=2 +tries=1 2>/dev/null | grep -q .; then
            echo -e "${GREEN}✓${NC}"; ((ok++))
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    if [ $ok -eq 0 ]; then
        echo -e "\n${RED}No NS records found.${NC}"
        echo -e "${YELLOW}Setup required:${NC}"
        echo "  A  record: tun.yourdomain.com  → server IP"
        echo "  NS record: $domain → tun.yourdomain.com"
        echo
        read -rp "Continue anyway? (y/n): " c
        [[ "$c" =~ ^[Yy]$ ]] || return 1
    else
        echo -e "${GREEN}OK ($ok/${#DNS_RESOLVERS[@]})${NC}"
    fi
}

check_port_53() {
    echo -e "${YELLOW}Checking port 53...${NC}"
    local pid
    pid=$(lsof -i UDP:53 -t 2>/dev/null | head -1)
    if [ -z "$pid" ]; then
        echo -e "${GREEN}✓ Available${NC}"; return 0
    fi
    local pn
    pn=$(ps -p "$pid" -o comm= 2>/dev/null)
    echo -e "${RED}Port 53 used by: $pn (PID $pid)${NC}"
    if [[ "$pn" == *"systemd-resolve"* ]]; then
        read -rp "Disable systemd-resolved? (y/n): " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            systemctl stop systemd-resolved 2>/dev/null
            systemctl disable systemd-resolved 2>/dev/null
            rm -f /etc/resolv.conf
            printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > /etc/resolv.conf
            echo -e "${GREEN}✓ Fixed${NC}"; return 0
        fi
    fi
    echo -e "${RED}Free port 53 manually.${NC}"; return 1
}

read_password() {
    local pw pw2
    while true; do
        read -rs -p "Password (min 8 chars): " pw; echo
        [ ${#pw} -lt 8 ] && { echo -e "${RED}Too short${NC}"; continue; }
        read -rs -p "Confirm: " pw2; echo
        [ "$pw" = "$pw2" ] && break
        echo -e "${RED}Mismatch${NC}"
    done
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    printf '%s' "$pw" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
}

write_env_file() {
    [ ! -f "$PASSWORD_FILE" ] && { log ERROR "No password file"; return 1; }
    local pw
    pw=$(cat "$PASSWORD_FILE")
    [ -z "$pw" ] && { log ERROR "Empty password"; return 1; }
    printf 'IODINE_PASS=%s\n' "$pw" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
}

fw_apply() {
    load_config || return 1
    local iface
    iface=$(get_default_if)
    [ -z "$iface" ] && { log ERROR "No default interface"; return 1; }
    enable_ip_forward

    iptables -t nat -N IODINE_POST 2>/dev/null; iptables -t nat -F IODINE_POST
    iptables -t nat -A IODINE_POST -s "$TUN_SUBNET" -o "$iface" -j MASQUERADE
    iptables -t nat -C POSTROUTING -j IODINE_POST 2>/dev/null || \
        iptables -t nat -A POSTROUTING -j IODINE_POST

    iptables -D FORWARD -i dns0 -o "$iface" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$iface" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i dns0 -o "$iface" -j ACCEPT
    iptables -A FORWARD -i "$iface" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT

    if [ "$ROLE" = "client" ] && [ -n "$PORT_LIST" ]; then
        iptables -t nat -N IODINE_PRE 2>/dev/null; iptables -t nat -F IODINE_PRE
        IFS=',' read -ra ports <<< "$PORT_LIST"
        for p in "${ports[@]}"; do
            p=$(echo "$p" | tr -d ' ')
            validate_port "$p" || continue
            iptables -t nat -A IODINE_PRE -i "$iface" -p tcp --dport "$p" -j DNAT --to "$TUN_SERVER_IP:$p"
            iptables -t nat -A IODINE_PRE -i "$iface" -p udp --dport "$p" -j DNAT --to "$TUN_SERVER_IP:$p"
        done
        iptables -t nat -C PREROUTING -j IODINE_PRE 2>/dev/null || \
            iptables -t nat -A PREROUTING -j IODINE_PRE
    fi
    log INFO "Firewall applied on $iface"
}

fw_clean() {
    iptables -t nat -D POSTROUTING -j IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST 2>/dev/null
    iptables -t nat -X IODINE_POST 2>/dev/null
    iptables -t nat -D PREROUTING -j IODINE_PRE 2>/dev/null
    iptables -t nat -F IODINE_PRE 2>/dev/null
    iptables -t nat -X IODINE_PRE 2>/dev/null
    local iface
    iface=$(get_default_if)
    if [ -n "$iface" ]; then
        iptables -D FORWARD -i dns0 -o "$iface" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i "$iface" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi
    log INFO "Firewall cleaned"
}

build_service_file() {
    load_config || return 1
    write_env_file || return 1
    local svc="iodine-${ROLE}"
    local bin args

    if [ "$ROLE" = "server" ]; then
        bin="/usr/sbin/iodined"
        args="-f -c -4"
        [ -n "$MTU_SIZE" ] && args="$args -M $MTU_SIZE"
        [ -n "$DNS_TYPE" ] && args="$args -T $DNS_TYPE"
        [ -n "$LAZY_INTERVAL" ] && args="$args -I $LAZY_INTERVAL"
        args="$args $TUN_SERVER_IP $DOMAIN"
    else
        bin="/usr/sbin/iodine"
        args="-f"
        [ -n "$MTU_SIZE" ] && args="$args -M $MTU_SIZE"
        [ -n "$MAX_HOSTNAME_LEN" ] && args="$args -m $MAX_HOSTNAME_LEN"
        [ -n "$DNS_TYPE" ] && args="$args -T $DNS_TYPE"
        [ -n "$DOWN_CODEC" ] && args="$args -O $DOWN_CODEC"
        [ -n "$LAZY_INTERVAL" ] && args="$args -I $LAZY_INTERVAL"
        [ "$FORCE_DNS" = "yes" ] && args="$args -r"
        args="$args $DOMAIN"
    fi

    cat > "/etc/systemd/system/${svc}.service" <<UNIT
[Unit]
Description=Iodine DNS Tunnel (${ROLE})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${bin} ${args} -P \${IODINE_PASS}
ExecStartPost=${INSTALL_DIR}/${SCRIPT_NAME} --apply-fw
ExecStopPost=${INSTALL_DIR}/${SCRIPT_NAME} --clean-fw
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=120

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    log INFO "Service file written: $svc"
}

start_tunnel() {
    load_config || return 1
    local svc="iodine-${ROLE}"
    systemctl stop iodine-server iodine-client 2>/dev/null
    build_service_file || return 1
    systemctl enable "$svc" >/dev/null 2>&1
    systemctl start "$svc"
    local i=0
    echo -ne "${YELLOW}Starting tunnel " >&2
    while [ $i -lt 10 ]; do
        if systemctl is-active --quiet "$svc" && ip link show dns0 >/dev/null 2>&1; then
            echo -e " ${GREEN}✓${NC}" >&2
            log INFO "$svc running"
            return 0
        fi
        echo -ne "." >&2; sleep 1; ((i++))
    done
    echo -e " ${RED}✗${NC}" >&2
    echo -e "${RED}Failed to start. Last logs:${NC}" >&2
    journalctl -u "$svc" --no-pager -n 10 >&2
    return 1
}

install_deps() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    local need=false
    for t in iodined iodine iptables lsof dig; do
        command -v "$t" &>/dev/null || need=true
    done
    if $need; then
        if [ -f /etc/debian_version ]; then
            apt-get update -qq 2>>"$LOG_FILE"
            apt-get install -y -qq iodine iproute2 iptables lsof dnsutils >>"$LOG_FILE" 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y -q epel-release >>"$LOG_FILE" 2>&1 || true
            yum install -y -q iodine iproute iptables lsof bind-utils >>"$LOG_FILE" 2>&1
        else
            echo -e "${RED}Unsupported distro${NC}"; exit 1
        fi
        for t in iodined iodine; do
            command -v "$t" &>/dev/null || { echo -e "${RED}Cannot install $t${NC}"; exit 1; }
        done
    fi
    local me
    me=$(realpath "$0" 2>/dev/null || readlink -f "$0")
    if [ "$me" != "$INSTALL_DIR/$SCRIPT_NAME" ]; then
        cp "$me" "$INSTALL_DIR/$SCRIPT_NAME"
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    fi
    echo -e "${GREEN}✓ Ready${NC}"
}

run_setup() {
    install_deps
    echo -e "\n${BOLD}Role:${NC}"
    echo "  1) Server (exit node)"
    echo "  2) Client (entry point)"
    read -rp "Select [1/2]: " role_opt

    case "$role_opt" in
        1)
            ROLE="server"
            check_port_53 || return 1
            echo -e "\n${YELLOW}DNS setup needed:${NC}"
            echo "  A  → tun.example.com  → your server IP"
            echo "  NS → t1.example.com   → tun.example.com"
            echo
            while true; do
                read -rp "NS subdomain (e.g. t1.example.com): " DOMAIN
                validate_domain "$DOMAIN" && break
                echo -e "${RED}Invalid domain${NC}"
            done
            test_dns_delegation "$DOMAIN" || return 1
            read_password
            echo -e "\n${BOLD}Options (Enter = auto/default):${NC}"
            read -rp "Auto-detect MTU? [Y/n]: " m; m=${m:-y}
            if [[ "$m" =~ ^[Yy]$ ]]; then
                MTU_SIZE=$(mtu_detect "8.8.8.8")
            else
                read -rp "MTU [1280]: " MTU_SIZE; MTU_SIZE=${MTU_SIZE:-1280}
            fi
            read -rp "DNS type (Enter=auto): " DNS_TYPE
            [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            read -rp "Lazy interval [4]: " LAZY_INTERVAL; LAZY_INTERVAL=${LAZY_INTERVAL:-4}
            PORT_LIST=""; FORCE_DNS="no"; MAX_HOSTNAME_LEN=""; DOWN_CODEC=""
            ;;
        2)
            ROLE="client"
            while true; do
                read -rp "Server NS subdomain: " DOMAIN
                validate_domain "$DOMAIN" && break
                echo -e "${RED}Invalid domain${NC}"
            done
            read_password
            echo -e "\n${YELLOW}Port forwarding (e.g. 443,2053, Enter=none):${NC}"
            while true; do
                read -rp "Ports: " PORT_LIST
                validate_port_list "$PORT_LIST" && break
                echo -e "${RED}Invalid${NC}"
            done
            echo -e "\n${BOLD}Options (Enter = auto/default):${NC}"
            read -rp "Auto-detect MTU after connect? [Y/n]: " m; m=${m:-y}
            if [[ "$m" =~ ^[Yy]$ ]]; then
                MTU_SIZE=""
            else
                read -rp "MTU [1280]: " MTU_SIZE; MTU_SIZE=${MTU_SIZE:-1280}
            fi
            read -rp "Max hostname len [255]: " MAX_HOSTNAME_LEN; MAX_HOSTNAME_LEN=${MAX_HOSTNAME_LEN:-255}
            read -rp "DNS type (Enter=auto): " DNS_TYPE
            [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            read -rp "Downstream codec (Enter=auto): " DOWN_CODEC
            read -rp "Lazy interval [4]: " LAZY_INTERVAL; LAZY_INTERVAL=${LAZY_INTERVAL:-4}
            read -rp "Force DNS mode? [y/N]: " fd
            [[ "$fd" =~ ^[Yy]$ ]] && FORCE_DNS="yes" || FORCE_DNS="no"
            ;;
        *) echo "Invalid"; return ;;
    esac

    systemctl stop iodine-server iodine-client 2>/dev/null
    systemctl disable iodine-server iodine-client 2>/dev/null
    rm -f /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service
    systemctl daemon-reload

    save_config

    if ! start_tunnel; then
        echo -e "${RED}Setup failed.${NC}"
        return 1
    fi

    if [ "$ROLE" = "client" ] && [ -z "$MTU_SIZE" ]; then
        echo -e "\n${YELLOW}Post-connect MTU detection...${NC}"
        local tries=0 dmtu=""
        while [ $tries -lt 3 ]; do
            sleep 3
            dmtu=$(mtu_detect "$TUN_SERVER_IP")
            [[ "$dmtu" =~ ^[0-9]+$ ]] && [ "$dmtu" -gt 0 ] && break
            ((tries++))
        done
        if [[ "$dmtu" =~ ^[0-9]+$ ]] && [ "$dmtu" -gt 0 ]; then
            MTU_SIZE="$dmtu"
            save_config
            start_tunnel
            echo -e "${GREEN}✓ MTU=$MTU_SIZE${NC}"
        else
            echo -e "${YELLOW}MTU detection failed, using iodine default${NC}"
        fi
    fi

    echo -e "\n${CYAN}═══ Summary ═══${NC}"
    echo -e "  Role:   ${YELLOW}$ROLE${NC}"
    echo -e "  Domain: ${YELLOW}$DOMAIN${NC}"
    echo -e "  MTU:    ${YELLOW}${MTU_SIZE:-auto}${NC}"
    echo -e "  DNS:    ${YELLOW}${DNS_TYPE:-auto}${NC}"
    [ -n "$PORT_LIST" ] && echo -e "  Ports:  ${YELLOW}$PORT_LIST${NC}"
    echo
    read -rp "Press Enter..."
}

status_menu() {
    load_config 2>/dev/null
    local svc
    svc=$(get_svc_name)

    while true; do
        draw_header
        echo -e "${BOLD}Status & Logs${NC}\n"
        echo "  1) Service status"
        echo "  2) Tunnel interface"
        echo "  3) Connection test"
        echo "  4) Recent logs (20)"
        echo "  5) Live logs"
        echo "  6) Start service"
        echo "  7) Stop service"
        echo "  8) Restart service"
        echo "  0) Back"
        echo
        read -rp "Select: " ch

        if [ -z "$svc" ] && [[ "$ch" =~ ^[1-8]$ ]]; then
            echo -e "${RED}Not configured.${NC}"
            read -rp "Press Enter..."; continue
        fi

        case "$ch" in
            1)
                echo
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    echo -e "  ${GREEN}● $svc is running${NC}"
                    local pid
                    pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
                    [ "$pid" != "0" ] && echo "  PID: $pid"
                    local up
                    up=$(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null)
                    [ -n "$up" ] && echo "  Since: $up"
                else
                    echo -e "  ${RED}● $svc is stopped${NC}"
                fi
                read -rp "Press Enter..."
                ;;
            2)
                echo
                if ip link show dns0 >/dev/null 2>&1; then
                    local tip
                    tip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
                    echo -e "  dns0: ${GREEN}UP${NC}  IP: ${BLUE}${tip:-n/a}${NC}"
                    echo
                    ip -s link show dns0 2>/dev/null | grep -E 'RX|TX|bytes' | sed 's/^/  /'
                else
                    echo -e "  dns0: ${RED}DOWN${NC}"
                fi
                read -rp "Press Enter..."
                ;;
            3)
                echo
                if [ "$ROLE" = "server" ]; then
                    echo -e "  Server mode — listening on $TUN_SERVER_IP"
                else
                    echo -ne "  Ping $TUN_SERVER_IP: "
                    if ping -c3 -W3 "$TUN_SERVER_IP" >/dev/null 2>&1; then
                        local rtt
                        rtt=$(ping -c5 -q "$TUN_SERVER_IP" 2>/dev/null | awk -F'/' '/rtt/{print $5}')
                        echo -e "${GREEN}✓${NC} avg=${rtt}ms"
                    else
                        echo -e "${RED}✗ unreachable${NC}"
                    fi
                fi
                read -rp "Press Enter..."
                ;;
            4)
                echo
                journalctl -u "$svc" --no-pager -n 20 2>/dev/null || echo "  No logs"
                read -rp "Press Enter..."
                ;;
            5)
                echo -e "\n${CYAN}Ctrl+C to stop${NC}\n"
                journalctl -u "$svc" -f 2>/dev/null
                ;;
            6)
                systemctl start "$svc" 2>/dev/null
                echo -e "${GREEN}Started${NC}"; sleep 1
                ;;
            7)
                systemctl stop "$svc" 2>/dev/null
                echo -e "${YELLOW}Stopped${NC}"; sleep 1
                ;;
            8)
                load_config && start_tunnel
                sleep 1
                ;;
            0) break ;;
        esac
    done
}

edit_config() {
    draw_header
    if ! load_config; then
        echo -e "${RED}Not configured${NC}"; read -rp "Press Enter..."; return
    fi
    echo -e "${BOLD}Edit Configuration${NC}\n"
    echo "  1) DNS Type:      ${YELLOW}${DNS_TYPE:-auto}${NC}"
    echo "  2) MTU:           ${YELLOW}${MTU_SIZE:-auto}${NC}"
    echo "  3) Lazy Interval: ${YELLOW}${LAZY_INTERVAL:-4}${NC}"
    [ "$ROLE" = "client" ] && \
    echo "  4) Codec:         ${YELLOW}${DOWN_CODEC:-auto}${NC}"
    echo "  5) Password"
    echo "  0) Back"
    echo
    read -rp "Select: " e
    case "$e" in
        1)
            read -rp "DNS type (Enter=auto): " DNS_TYPE
            [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            ;;
        2)
            read -rp "Auto-detect? [Y/n]: " a; a=${a:-y}
            if [[ "$a" =~ ^[Yy]$ ]]; then
                MTU_SIZE=$(mtu_detect "$TUN_SERVER_IP")
                [[ "$MTU_SIZE" =~ ^[0-9]+$ ]] || { echo -e "${RED}Failed${NC}"; read -rp "Enter..."; return; }
            else
                read -rp "MTU: " MTU_SIZE
            fi
            ;;
        3) read -rp "Interval [4]: " LAZY_INTERVAL; LAZY_INTERVAL=${LAZY_INTERVAL:-4} ;;
        4) [ "$ROLE" = "client" ] && { read -rp "Codec (Enter=auto): " DOWN_CODEC; } ;;
        5) read_password ;;
        0) return ;;
        *) return ;;
    esac
    save_config
    echo -e "${GREEN}Saved${NC}"
    read -rp "Restart now? [Y/n]: " r; r=${r:-y}
    if [[ "$r" =~ ^[Yy]$ ]]; then
        load_config && start_tunnel
    fi
    read -rp "Press Enter..."
}

service_menu() {
    load_config 2>/dev/null
    local svc
    svc=$(get_svc_name)

    while true; do
        draw_header
        echo -e "${BOLD}Service Manager${NC}\n"
        echo "  1) Start"
        echo "  2) Stop"
        echo "  3) Restart (rebuild)"
        echo "  4) Enable on boot"
        echo "  5) Disable on boot"
        echo "  6) systemctl status"
        echo "  7) Performance test"
        echo "  0) Back"
        echo
        read -rp "Select: " ch

        if [ -z "$svc" ] && [[ "$ch" =~ ^[1-7]$ ]]; then
            echo -e "${RED}Not configured.${NC}"; read -rp "Enter..."; continue
        fi

        case "$ch" in
            1) systemctl start "$svc"; echo -e "${GREEN}Started${NC}"; sleep 1 ;;
            2) systemctl stop "$svc"; echo -e "${YELLOW}Stopped${NC}"; sleep 1 ;;
            3) load_config && start_tunnel; sleep 1 ;;
            4) systemctl enable "$svc" >/dev/null 2>&1; echo -e "${GREEN}Enabled${NC}"; sleep 1 ;;
            5) systemctl disable "$svc" >/dev/null 2>&1; echo -e "${YELLOW}Disabled${NC}"; sleep 1 ;;
            6) systemctl status "$svc" --no-pager 2>/dev/null; read -rp "Enter..." ;;
            7)
                if [ "$ROLE" != "client" ]; then
                    echo -e "${YELLOW}Client only${NC}"; read -rp "Enter..."; continue
                fi
                echo -e "\n${BOLD}Performance${NC}"
                echo -e "\n${CYAN}Latency:${NC}"
                if ping -c10 -q "$TUN_SERVER_IP" >/dev/null 2>&1; then
                    ping -c10 -q "$TUN_SERVER_IP" 2>/dev/null | grep rtt
                else
                    echo -e "${RED}Unreachable${NC}"
                fi
                echo -e "\n${CYAN}Interface:${NC}"
                ip -s link show dns0 2>/dev/null || echo "N/A"
                echo -e "\n${CYAN}Activity:${NC}"
                journalctl -u "$svc" --since "10 min ago" --no-pager 2>/dev/null | tail -5
                echo; read -rp "Enter..."
                ;;
            0) break ;;
        esac
    done
}

do_uninstall() {
    draw_header
    echo -e "${RED}${BOLD}Uninstall${NC}"
    echo "This removes all iodine-manager config, services, and firewall rules."
    echo
    read -rp "Type YES to confirm: " c
    [ "$c" != "YES" ] && return
    systemctl stop iodine-server iodine-client 2>/dev/null
    systemctl disable iodine-server iodine-client 2>/dev/null
    rm -f /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service
    fw_clean
    rm -f /etc/sysctl.d/99-iodine.conf; sysctl --system >/dev/null 2>&1
    rm -rf "$CONF_DIR"
    rm -f "$LOG_FILE" "${LOG_FILE}.1" "$LOCK_FILE"
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/$SCRIPT_NAME"
    echo -e "${GREEN}✓ Removed${NC}"
    sleep 2
    exit 0
}

case "${1:-}" in
    --apply-fw)  fw_apply;  exit $? ;;
    --clean-fw)  fw_clean;  exit $? ;;
    --start)     load_config && { systemctl start "iodine-${ROLE}"; }; exit $? ;;
    --stop)      load_config && { systemctl stop  "iodine-${ROLE}"; }; exit $? ;;
    --restart)   load_config && start_tunnel; exit $? ;;
    --status)    load_config && systemctl status "iodine-${ROLE}" --no-pager; exit $? ;;
    --help|-h)
        echo "Usage: $SCRIPT_NAME [--apply-fw|--clean-fw|--start|--stop|--restart|--status|--help]"
        exit 0 ;;
    "") ;;
    *)  echo "Unknown: $1"; exit 1 ;;
esac

while true; do
    draw_header
    echo "  1) Install & Configure"
    echo "  2) Status & Logs"
    echo "  3) Edit Configuration"
    echo "  4) Service Manager"
    echo "  5) Uninstall"
    echo "  0) Exit"
    echo
    read -rp "Select: " opt
    case "$opt" in
        1) run_setup ;;
        2) status_menu ;;
        3) edit_config ;;
        4) service_menu ;;
        5) do_uninstall ;;
        0) echo -e "${GREEN}Bye${NC}"; exit 0 ;;
    esac
done
