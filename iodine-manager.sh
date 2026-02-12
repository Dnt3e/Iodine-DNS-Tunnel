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

IODINED_BIN="/usr/sbin/iodined"
IODINE_BIN="/usr/sbin/iodine"

acquire_lock() {
    local caller="${1:-menu}"
    [[ "$caller" == "service" ]] && return 0
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "Another instance is running."
        exit 1
    fi
}

case "${1:-}" in
    --apply-fw|--clean-fw) ;;
    *) acquire_lock "menu" ;;
esac

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
    echo "$msg" >> "$LOG_FILE" 2>/dev/null
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
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
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

detect_iodine_flags() {
    local bin="$1"
    local help_text
    help_text=$("$bin" -h 2>&1)

    HAS_FLAG_f=false; HAS_FLAG_c=false; HAS_FLAG_4=false
    HAS_FLAG_M=false; HAS_FLAG_m=false; HAS_FLAG_T=false
    HAS_FLAG_I=false; HAS_FLAG_i=false; HAS_FLAG_O=false
    HAS_FLAG_r=false; HAS_FLAG_P=false; HAS_FLAG_D=false

    echo "$help_text" | grep -q '\-f ' && HAS_FLAG_f=true
    echo "$help_text" | grep -q '\-c ' && HAS_FLAG_c=true
    echo "$help_text" | grep -q '\-P ' && HAS_FLAG_P=true
    echo "$help_text" | grep -q '\-D ' && HAS_FLAG_D=true

    if echo "$help_text" | grep -q '\-4'; then
        HAS_FLAG_4=true
    fi

    if echo "$help_text" | grep -q -- '-M '; then
        HAS_FLAG_M=true
    fi
    if echo "$help_text" | grep -q -- '-m '; then
        HAS_FLAG_m=true
    fi

    if echo "$help_text" | grep -q -- '-T '; then
        HAS_FLAG_T=true
    fi

    if echo "$help_text" | grep -q -- '-I '; then
        HAS_FLAG_I=true
    fi
    if echo "$help_text" | grep -q -- '-i '; then
        HAS_FLAG_i=true
    fi

    if echo "$help_text" | grep -q -- '-O '; then
        HAS_FLAG_O=true
    fi

    if echo "$help_text" | grep -q -- '-r'; then
        HAS_FLAG_r=true
    fi

    if $HAS_FLAG_M; then
        MTU_FLAG="-M"
    elif $HAS_FLAG_m; then
        MTU_FLAG="-m"
    else
        MTU_FLAG=""
    fi

    if $HAS_FLAG_I; then
        LAZY_FLAG="-I"
    elif $HAS_FLAG_i; then
        LAZY_FLAG="-i"
    else
        LAZY_FLAG=""
    fi

    log INFO "Detected flags for $bin: MTU=$MTU_FLAG LAZY=$LAZY_FLAG T=$HAS_FLAG_T O=$HAS_FLAG_O r=$HAS_FLAG_r 4=$HAS_FLAG_4"
}

show_detected_flags() {
    local bin="$1"
    echo -e "${CYAN}Binary: $bin${NC}" >&2
    echo -ne "  MTU: " >&2
    [ -n "$MTU_FLAG" ] && echo -e "${GREEN}$MTU_FLAG${NC}" >&2 || echo -e "${RED}none${NC}" >&2
    echo -ne "  Lazy: " >&2
    [ -n "$LAZY_FLAG" ] && echo -e "${GREEN}$LAZY_FLAG${NC}" >&2 || echo -e "${RED}none${NC}" >&2
    echo -ne "  DNS type (-T): " >&2
    $HAS_FLAG_T && echo -e "${GREEN}yes${NC}" >&2 || echo -e "${RED}no${NC}" >&2
    echo -ne "  Codec (-O): " >&2
    $HAS_FLAG_O && echo -e "${GREEN}yes${NC}" >&2 || echo -e "${RED}no${NC}" >&2
    echo -ne "  Force DNS (-r): " >&2
    $HAS_FLAG_r && echo -e "${GREEN}yes${NC}" >&2 || echo -e "${RED}no${NC}" >&2
    echo -ne "  IPv4 only (-4): " >&2
    $HAS_FLAG_4 && echo -e "${GREEN}yes${NC}" >&2 || echo -e "${RED}no${NC}" >&2
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
        echo -e "${RED}TUN device missing.${NC}" >&2
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
    echo -e "${YELLOW}Detecting MTU to $target...${NC}" >&2
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
        echo -e "${YELLOW}Required DNS setup:${NC}"
        echo "  A  record: tun.yourdomain.com → server IP"
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
    mkdir -p "$CONF_DIR"
    printf 'IODINE_PASS=%s\n' "$pw" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
}

fw_apply() {
    load_config || return 1
    local iface
    iface=$(get_default_if)
    [ -z "$iface" ] && { log ERROR "No default interface"; return 1; }
    enable_ip_forward

    iptables -t nat -N IODINE_POST 2>/dev/null
    iptables -t nat -F IODINE_POST
    iptables -t nat -A IODINE_POST -s "$TUN_SUBNET" -o "$iface" -j MASQUERADE
    iptables -t nat -C POSTROUTING -j IODINE_POST 2>/dev/null || \
        iptables -t nat -A POSTROUTING -j IODINE_POST

    iptables -D FORWARD -i dns0 -o "$iface" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$iface" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -A FORWARD -i dns0 -o "$iface" -j ACCEPT
    iptables -A FORWARD -i "$iface" -o dns0 -m state --state RELATED,ESTABLISHED -j ACCEPT

    if [ "$ROLE" = "client" ] && [ -n "$PORT_LIST" ]; then
        iptables -t nat -N IODINE_PRE 2>/dev/null
        iptables -t nat -F IODINE_PRE
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
        bin="$IODINED_BIN"
        detect_iodine_flags "$bin"
        args="-f"
        $HAS_FLAG_c && args="$args -c"
        $HAS_FLAG_4 && args="$args -4"
        if [ -n "$MTU_SIZE" ] && [ -n "$MTU_FLAG" ]; then
            args="$args $MTU_FLAG $MTU_SIZE"
        fi
        if [ -n "$DNS_TYPE" ] && $HAS_FLAG_T; then
            args="$args -T $DNS_TYPE"
        fi
        if [ -n "$LAZY_INTERVAL" ] && [ -n "$LAZY_FLAG" ]; then
            args="$args $LAZY_FLAG $LAZY_INTERVAL"
        fi
        args="$args $TUN_SERVER_IP $DOMAIN"
    else
        bin="$IODINE_BIN"
        detect_iodine_flags "$bin"
        args="-f"
        if [ -n "$MTU_SIZE" ] && [ -n "$MTU_FLAG" ]; then
            args="$args $MTU_FLAG $MTU_SIZE"
        fi
        if [ -n "$MAX_HOSTNAME_LEN" ] && $HAS_FLAG_m; then
            args="$args -m $MAX_HOSTNAME_LEN"
        fi
        if [ -n "$DNS_TYPE" ] && $HAS_FLAG_T; then
            args="$args -T $DNS_TYPE"
        fi
        if [ -n "$DOWN_CODEC" ] && $HAS_FLAG_O; then
            args="$args -O $DOWN_CODEC"
        fi
        if [ -n "$LAZY_INTERVAL" ] && [ -n "$LAZY_FLAG" ]; then
            args="$args $LAZY_FLAG $LAZY_INTERVAL"
        fi
        if [ "$FORCE_DNS" = "yes" ] && $HAS_FLAG_r; then
            args="$args -r"
        fi
        args="$args $DOMAIN"
    fi

    log INFO "ExecStart will be: $bin $args -P \${IODINE_PASS}"

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
    log INFO "Service file created: $svc"

    echo -e "${CYAN}Generated service command:${NC}" >&2
    echo -e "  ${YELLOW}$bin $args -P ****${NC}" >&2
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
    while [ $i -lt 12 ]; do
        if systemctl is-active --quiet "$svc" && ip link show dns0 >/dev/null 2>&1; then
            echo -e " ${GREEN}✓${NC}" >&2
            log INFO "$svc running"
            return 0
        fi
        echo -ne "." >&2
        sleep 1
        ((i++))
    done
    echo -e " ${RED}✗${NC}" >&2
    echo -e "${RED}Failed. Recent logs:${NC}" >&2
    journalctl -u "$svc" --no-pager -n 12 >&2
    return 1
}

reset_tunnel_interface() {
    echo -e "${YELLOW}Resetting tunnel interface...${NC}"
    if ip link show dns0 >/dev/null 2>&1; then
        ip link set dns0 down 2>/dev/null
        ip link delete dns0 2>/dev/null
        echo -e "${GREEN}✓ dns0 removed${NC}"
    else
        echo -e "${YELLOW}dns0 not present${NC}"
    fi
    local svc
    svc=$(get_svc_name)
    if [ -n "$svc" ]; then
        read -rp "Restart service to recreate tunnel? (y/n): " r
        if [[ "$r" =~ ^[Yy]$ ]]; then
            load_config && start_tunnel
        fi
    fi
}

install_deps() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
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
            echo -e "${RED}Unsupported distro. Install manually: iodine iptables lsof dnsutils${NC}"
            exit 1
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
            detect_iodine_flags "$IODINED_BIN"
            echo -e "\n${BOLD}Detected iodined capabilities:${NC}"
            show_detected_flags "$IODINED_BIN"
            echo

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

            if [ -n "$MTU_FLAG" ]; then
                read -rp "Auto-detect MTU? [Y/n]: " m
                m=${m:-y}
                if [[ "$m" =~ ^[Yy]$ ]]; then
                    MTU_SIZE=$(mtu_detect "8.8.8.8")
                else
                    read -rp "MTU [1280]: " MTU_SIZE
                    MTU_SIZE=${MTU_SIZE:-1280}
                fi
            else
                MTU_SIZE=""
                echo -e "${YELLOW}MTU flag not supported by this iodined version${NC}"
            fi

            if $HAS_FLAG_T; then
                read -rp "DNS type (Enter=auto): " DNS_TYPE
                [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            else
                DNS_TYPE=""
            fi

            if [ -n "$LAZY_FLAG" ]; then
                read -rp "Idle timeout seconds [0=disable]: " LAZY_INTERVAL
                LAZY_INTERVAL=${LAZY_INTERVAL:-0}
                [ "$LAZY_INTERVAL" = "0" ] && LAZY_INTERVAL=""
            else
                LAZY_INTERVAL=""
            fi

            PORT_LIST=""
            FORCE_DNS="no"
            MAX_HOSTNAME_LEN=""
            DOWN_CODEC=""
            ;;
        2)
            ROLE="client"
            detect_iodine_flags "$IODINE_BIN"
            echo -e "\n${BOLD}Detected iodine capabilities:${NC}"
            show_detected_flags "$IODINE_BIN"
            echo

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

            if [ -n "$MTU_FLAG" ]; then
                read -rp "Auto-detect MTU after connect? [Y/n]: " m
                m=${m:-y}
                if [[ "$m" =~ ^[Yy]$ ]]; then
                    MTU_SIZE=""
                else
                    read -rp "MTU [1280]: " MTU_SIZE
                    MTU_SIZE=${MTU_SIZE:-1280}
                fi
            else
                MTU_SIZE=""
            fi

            MAX_HOSTNAME_LEN=""
            if $HAS_FLAG_T; then
                read -rp "DNS type (Enter=auto): " DNS_TYPE
                [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            else
                DNS_TYPE=""
            fi

            if $HAS_FLAG_O; then
                read -rp "Downstream codec (Enter=auto): " DOWN_CODEC
            else
                DOWN_CODEC=""
            fi

            if [ -n "$LAZY_FLAG" ]; then
                read -rp "Idle timeout seconds [0=disable]: " LAZY_INTERVAL
                LAZY_INTERVAL=${LAZY_INTERVAL:-0}
                [ "$LAZY_INTERVAL" = "0" ] && LAZY_INTERVAL=""
            else
                LAZY_INTERVAL=""
            fi

            if $HAS_FLAG_r; then
                read -rp "Force DNS mode? [y/N]: " fd
                [[ "$fd" =~ ^[Yy]$ ]] && FORCE_DNS="yes" || FORCE_DNS="no"
            else
                FORCE_DNS="no"
            fi
            ;;
        *)
            echo "Invalid"
            return
            ;;
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

    if [ "$ROLE" = "client" ] && [ -z "$MTU_SIZE" ] && [ -n "$MTU_FLAG" ]; then
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
    echo -e "  MTU:    ${YELLOW}${MTU_SIZE:-default}${NC}"
    [ -n "$DNS_TYPE" ] && echo -e "  DNS:    ${YELLOW}$DNS_TYPE${NC}"
    [ -n "$PORT_LIST" ] && echo -e "  Ports:  ${YELLOW}$PORT_LIST${NC}"
    echo
    read -rp "Press Enter..."
}

status_menu() {
    local svc
    while true; do
        draw_header
        svc=$(get_svc_name)
        echo -e "${BOLD}Status & Logs${NC}\n"
        echo "  1) Service status"
        echo "  2) Tunnel interface"
        echo "  3) Connection test"
        echo "  4) Recent logs (20 lines)"
        echo "  5) Live logs"
        echo "  6) Start service"
        echo "  7) Stop service"
        echo "  8) Restart service"
        echo "  9) Reset tunnel interface"
        echo "  0) Back"
        echo
        read -rp "Select: " ch

        if [ -z "$svc" ] && [[ "$ch" =~ ^[1-9]$ ]]; then
            echo -e "${RED}Not configured. Run Install first.${NC}"
            read -rp "Press Enter..."
            continue
        fi

        case "$ch" in
            1)
                echo
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    echo -e "  ${GREEN}● $svc is running${NC}"
                    local pid uptime
                    pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
                    [ "$pid" != "0" ] && [ -n "$pid" ] && echo "  PID: $pid"
                    uptime=$(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null)
                    [ -n "$uptime" ] && echo "  Since: $uptime"
                else
                    echo -e "  ${RED}● $svc is stopped${NC}"
                fi
                echo
                read -rp "Press Enter..."
                ;;
            2)
                echo
                if ip link show dns0 >/dev/null 2>&1; then
                    local tip
                    tip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
                    echo -e "  dns0: ${GREEN}UP${NC}  IP: ${BLUE}${tip:-n/a}${NC}"
                    echo
                    echo -e "  ${BOLD}Stats:${NC}"
                    ip -s link show dns0 2>/dev/null | sed 's/^/    /'
                else
                    echo -e "  dns0: ${RED}DOWN${NC}"
                fi
                echo
                read -rp "Press Enter..."
                ;;
            3)
                echo
                load_config 2>/dev/null
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
                echo
                read -rp "Press Enter..."
                ;;
            4)
                echo
                journalctl -u "$svc" --no-pager -n 20 2>/dev/null || echo "  No logs"
                echo
                read -rp "Press Enter..."
                ;;
            5)
                echo -e "\n${CYAN}Ctrl+C to stop${NC}\n"
                journalctl -u "$svc" -f 2>/dev/null
                ;;
            6)
                systemctl start "$svc" 2>/dev/null
                sleep 1
                if systemctl is-active --quiet "$svc"; then
                    echo -e "${GREEN}✓ Started${NC}"
                else
                    echo -e "${RED}Failed to start${NC}"
                fi
                sleep 1
                ;;
            7)
                systemctl stop "$svc" 2>/dev/null
                echo -e "${YELLOW}Stopped${NC}"
                sleep 1
                ;;
            8)
                load_config && start_tunnel
                sleep 1
                ;;
            9)
                reset_tunnel_interface
                read -rp "Press Enter..."
                ;;
            0)
                break
                ;;
        esac
    done
}

edit_config() {
    draw_header
    if ! load_config; then
        echo -e "${RED}Not configured${NC}"
        read -rp "Press Enter..."
        return
    fi

    local bin
    [ "$ROLE" = "server" ] && bin="$IODINED_BIN" || bin="$IODINE_BIN"
    detect_iodine_flags "$bin"

    echo -e "${BOLD}Edit Configuration${NC}\n"
    local opts=()
    local labels=()

    if [ -n "$MTU_FLAG" ]; then
        opts+=("mtu")
        labels+=("MTU:            ${YELLOW}${MTU_SIZE:-default}${NC}")
    fi
    if $HAS_FLAG_T; then
        opts+=("dns_type")
        labels+=("DNS Type:       ${YELLOW}${DNS_TYPE:-auto}${NC}")
    fi
    if [ -n "$LAZY_FLAG" ]; then
        opts+=("lazy")
        labels+=("Idle Timeout:   ${YELLOW}${LAZY_INTERVAL:-none}${NC}")
    fi
    if [ "$ROLE" = "client" ] && $HAS_FLAG_O; then
        opts+=("codec")
        labels+=("Codec:          ${YELLOW}${DOWN_CODEC:-auto}${NC}")
    fi
    if [ "$ROLE" = "client" ] && $HAS_FLAG_r; then
        opts+=("force_dns")
        labels+=("Force DNS:      ${YELLOW}${FORCE_DNS:-no}${NC}")
    fi
    opts+=("password")
    labels+=("Password")

    local i=1
    for label in "${labels[@]}"; do
        echo "  $i) $label"
        ((i++))
    done
    echo "  0) Back"
    echo
    read -rp "Select: " e

    [ "$e" = "0" ] && return
    if ! [[ "$e" =~ ^[0-9]+$ ]] || [ "$e" -lt 1 ] || [ "$e" -gt ${#opts[@]} ]; then
        return
    fi

    local selected="${opts[$((e-1))]}"

    case "$selected" in
        mtu)
            read -rp "Auto-detect? [Y/n]: " a
            a=${a:-y}
            if [[ "$a" =~ ^[Yy]$ ]]; then
                MTU_SIZE=$(mtu_detect "$TUN_SERVER_IP")
                [[ "$MTU_SIZE" =~ ^[0-9]+$ ]] || {
                    echo -e "${RED}Detection failed${NC}"
                    read -rp "Press Enter..."; return
                }
            else
                read -rp "MTU: " MTU_SIZE
            fi
            ;;
        dns_type)
            read -rp "DNS type (Enter=auto-detect): " DNS_TYPE
            [ -z "$DNS_TYPE" ] && DNS_TYPE=$(detect_dns_type "$DOMAIN")
            ;;
        lazy)
            read -rp "Idle timeout seconds [0=disable]: " LAZY_INTERVAL
            [ "$LAZY_INTERVAL" = "0" ] && LAZY_INTERVAL=""
            ;;
        codec)
            read -rp "Codec (raw/base128/base64, Enter=auto): " DOWN_CODEC
            ;;
        force_dns)
            read -rp "Force DNS? [y/N]: " fd
            [[ "$fd" =~ ^[Yy]$ ]] && FORCE_DNS="yes" || FORCE_DNS="no"
            ;;
        password)
            read_password
            ;;
    esac

    save_config
    echo -e "${GREEN}Saved${NC}"
    read -rp "Restart service now? [Y/n]: " r
    r=${r:-y}
    if [[ "$r" =~ ^[Yy]$ ]]; then
        load_config && start_tunnel
    fi
    read -rp "Press Enter..."
}

service_menu() {
    local svc
    while true; do
        draw_header
        svc=$(get_svc_name)
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
            echo -e "${RED}Not configured.${NC}"
            read -rp "Press Enter..."
            continue
        fi

        case "$ch" in
            1)
                systemctl start "$svc" 2>/dev/null
                sleep 1
                if systemctl is-active --quiet "$svc"; then
                    echo -e "${GREEN}✓ Started${NC}"
                else
                    echo -e "${RED}Failed${NC}"
                fi
                sleep 1
                ;;
            2)
                systemctl stop "$svc" 2>/dev/null
                echo -e "${YELLOW}Stopped${NC}"
                sleep 1
                ;;
            3)
                load_config && start_tunnel
                sleep 1
                ;;
            4)
                systemctl enable "$svc" >/dev/null 2>&1
                echo -e "${GREEN}Enabled on boot${NC}"
                sleep 1
                ;;
            5)
                systemctl disable "$svc" >/dev/null 2>&1
                echo -e "${YELLOW}Disabled on boot${NC}"
                sleep 1
                ;;
            6)
                echo
                systemctl status "$svc" --no-pager 2>/dev/null
                echo
                read -rp "Press Enter..."
                ;;
            7)
                echo
                load_config 2>/dev/null
                if [ "$ROLE" != "client" ]; then
                    echo -e "${YELLOW}Performance test is for client mode only${NC}"
                    read -rp "Press Enter..."
                    continue
                fi
                echo -e "${BOLD}Performance Test${NC}\n"
                echo -e "${CYAN}[1/3] Latency:${NC}"
                if ping -c10 -q "$TUN_SERVER_IP" >/dev/null 2>&1; then
                    ping -c10 -q "$TUN_SERVER_IP" 2>/dev/null | grep rtt
                else
                    echo -e "  ${RED}Unreachable${NC}"
                fi
                echo -e "\n${CYAN}[2/3] Interface stats:${NC}"
                if ip link show dns0 >/dev/null 2>&1; then
                    ip -s link show dns0 2>/dev/null | sed 's/^/  /'
                else
                    echo "  N/A"
                fi
                echo -e "\n${CYAN}[3/3] Recent activity:${NC}"
                journalctl -u "$svc" --since "10 min ago" --no-pager 2>/dev/null | tail -5
                echo
                read -rp "Press Enter..."
                ;;
            0)
                break
                ;;
        esac
    done
}

do_uninstall() {
    draw_header
    echo -e "${RED}${BOLD}Uninstall iodine-manager${NC}"
    echo
    echo "This will remove:"
    echo "  - Systemd services"
    echo "  - Firewall rules"
    echo "  - Configuration files"
    echo "  - IP forwarding settings"
    echo "  - Log files"
    echo "  - Manager script"
    echo
    read -rp "Type YES to confirm: " c
    [ "$c" != "YES" ] && return

    systemctl stop iodine-server iodine-client 2>/dev/null
    systemctl disable iodine-server iodine-client 2>/dev/null
    rm -f /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service

    fw_clean

    rm -f /etc/sysctl.d/99-iodine.conf
    sysctl --system >/dev/null 2>&1

    rm -rf "$CONF_DIR"
    rm -f "$LOG_FILE" "${LOG_FILE}.1" "$LOCK_FILE"

    systemctl daemon-reload

    rm -f "$INSTALL_DIR/$SCRIPT_NAME"

    echo -e "${GREEN}✓ Completely removed${NC}"
    sleep 2
    exit 0
}

case "${1:-}" in
    --apply-fw)
        fw_apply
        exit $?
        ;;
    --clean-fw)
        fw_clean
        exit $?
        ;;
    --start)
        if load_config; then
            systemctl start "iodine-${ROLE}"
        else
            echo "Not configured"
        fi
        exit $?
        ;;
    --stop)
        if load_config; then
            systemctl stop "iodine-${ROLE}"
        else
            echo "Not configured"
        fi
        exit $?
        ;;
    --restart)
        if load_config; then
            start_tunnel
        else
            echo "Not configured"
        fi
        exit $?
        ;;
    --status)
        if load_config; then
            systemctl status "iodine-${ROLE}" --no-pager
        else
            echo "Not configured"
        fi
        exit $?
        ;;
    --help|-h)
        echo "Usage: $SCRIPT_NAME [option]"
        echo
        echo "Options:"
        echo "  --apply-fw   Apply firewall rules"
        echo "  --clean-fw   Remove firewall rules"
        echo "  --start      Start tunnel service"
        echo "  --stop       Stop tunnel service"
        echo "  --restart    Restart tunnel service"
        echo "  --status     Show service status"
        echo "  --help       Show this help"
        echo
        echo "Run without options for interactive menu."
        exit 0
        ;;
    "")
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage info."
        exit 1
        ;;
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
        0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
    esac
done
