#!/bin/bash

# ==============================================================================
#   IODINE DNS TUNNEL MANAGER 
# ==============================================================================

# --- Safety Check: Ensure Root Access ---
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

# --- Global Configuration ---
CONF_FILE="/etc/iodine-manager.conf"
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="iodine-mgr"
LOG_FILE="/tmp/iodine_install.log"

# Tunnel Configuration
TUN_SERVER_IP="10.50.50.1"
MTU_SIZE="1200" 

# --- Colors & Styling ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Helper: Progress Bar ---
show_progress() {
    local duration=${1}
    local prefix=${2}
    local block="█"
    local empty="░"
    local width=30
    echo -ne "${prefix} "
    for (( i=0; i<=$width; i++ )); do
        local percent=$(( i * 100 / width ))
        local num_block=$i
        local num_empty=$(( width - i ))
        local bar_str=""
        for (( j=0; j<num_block; j++ )); do bar_str="${bar_str}${block}"; done
        for (( j=0; j<num_empty; j++ )); do bar_str="${bar_str}${empty}"; done
        echo -ne "[${BLUE}${bar_str}${NC}] ${percent}%\r"
        sleep $duration
    done
    echo -ne "\n"
}

# --- Helper: Dynamic Header ---
draw_header() {
    clear
    local service_stat="inactive"
    local role="NONE"
    
    if systemctl is-active --quiet iodine-server; then
        service_stat="${GREEN}RUNNING${NC}"
        role="SERVER"
    elif systemctl is-active --quiet iodine-client; then
        service_stat="${GREEN}RUNNING${NC}"
        role="CLIENT"
    else
        service_stat="${RED}STOPPED${NC}"
    fi

    echo -e "${CYAN}======================================================${NC}"
    echo -e "${BOLD}      I O D I N E   D N S   T U N N E L   M G R       ${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo -e " Service Status: ${service_stat}"
    echo -e " Current Role:   ${YELLOW}${role}${NC}"
    
    if [[ "$service_stat" == *"RUNNING"* ]]; then
        local tun_ip=$(ip -4 addr show dns0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e " Tunnel IP:      ${BLUE}${tun_ip:-Unknown}${NC}"
    fi
    echo -e "${CYAN}======================================================${NC}"
    echo ""
}

# --- Core: Dependency Installation ---
install_deps() {
    echo -e "${YELLOW}>>> Starting Dependency Check & Installation...${NC}"
    
    show_progress 0.05 "Checking System "
    
    # Check for lsof (needed for port check) along with others
    if ! command -v iodined &> /dev/null || ! command -v iptables &> /dev/null || ! command -v lsof &> /dev/null; then
        echo -e "Installing tools..." >> $LOG_FILE
        if [ -f /etc/debian_version ]; then
            apt-get update -q && apt-get install -y -q iodine iproute2 iptables curl lsof >> $LOG_FILE 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y -q epel-release >> $LOG_FILE 2>&1
            yum install -y -q iodine iproute iptables curl lsof >> $LOG_FILE 2>&1
        fi
    fi

    if [[ "$(realpath $0)" != "$INSTALL_DIR/$SCRIPT_NAME" ]]; then
        cp "$(realpath $0)" "$INSTALL_DIR/$SCRIPT_NAME"
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    fi

    echo -e "${GREEN}>>> Dependencies Ready.${NC}"
    sleep 1
}

# --- CRITICAL: Check Port 53 ---
check_port_53() {
    echo -e "${YELLOW}Checking Port 53 availability...${NC}"
    # Check if anything is listening on UDP 53
    local occupier=$(lsof -i :53 -t)
    
    if [ -n "$occupier" ]; then
        local process_name=$(ps -p $occupier -o comm=)
        echo -e "${RED}[WARNING] Port 53 is occupied by process: ${BOLD}$process_name${NC}"
        
        if [[ "$process_name" == "systemd-resolve" || "$process_name" == "systemd-resolved" ]]; then
            echo -e "This prevents Iodine from starting."
            read -p "Do you want to STOP systemd-resolved and fix DNS? (recommended) [y/n]: " fix_dns
            if [[ "$fix_dns" == "y" || "$fix_dns" == "Y" ]]; then
                echo -e "${BLUE}Fixing DNS conflict...${NC}"
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                rm -f /etc/resolv.conf
                echo "nameserver 8.8.8.8" > /etc/resolv.conf
                echo "nameserver 1.1.1.1" >> /etc/resolv.conf
                echo -e "${GREEN}Port 53 freed. DNS set to Google.${NC}"
            else
                echo -e "${RED}Aborting. Iodine cannot run while Port 53 is busy.${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Unknown process on Port 53. Please free it manually.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}Port 53 is free.${NC}"
    fi
}

# --- Core: Firewall Logic (NAT/Masquerade) ---
apply_firewall() {
    source $CONF_FILE 2>/dev/null
    DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1)
    
    echo -e "${YELLOW}Applying Firewall Rules...${NC}" >> $LOG_FILE

    sysctl -w net.ipv4.ip_forward=1 >> $LOG_FILE 2>&1

    iptables -t nat -C POSTROUTING -o $DEFAULT_IF -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o $DEFAULT_IF -j MASQUERADE
    
    iptables -t nat -C POSTROUTING -o dns0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o dns0 -j MASQUERADE

    if [ "$ROLE" == "client" ] && [ -n "$PORT_LIST" ]; then
        IFS=',' read -ra ADDR <<< "$PORT_LIST"
        for port in "${ADDR[@]}"; do
            port=$(echo $port | xargs)
            
            iptables -t nat -D PREROUTING -p tcp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port 2>/dev/null
            iptables -t nat -D PREROUTING -p udp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port 2>/dev/null
            
            iptables -t nat -A PREROUTING -p tcp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port
            iptables -t nat -A PREROUTING -p udp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port
        done
    fi
}

# --- Logic: Create Systemd Service ---
create_service() {
    local service_name="iodine-${ROLE}"
    local exec_cmd=""

    if [ "$ROLE" == "server" ]; then
        exec_cmd="/usr/sbin/iodined -f -c -P $PASSWORD -M $MTU_SIZE $TUN_SERVER_IP $DOMAIN"
    else
        exec_cmd="/usr/sbin/iodine -f -P $PASSWORD -M $MTU_SIZE $DOMAIN"
    fi

    cat <<EOF > /etc/systemd/system/${service_name}.service
[Unit]
Description=Iodine DNS Tunnel ($ROLE)
After=network.target

[Service]
ExecStart=$exec_cmd
Restart=always
RestartSec=5
User=root
ExecStartPost=/bin/bash -c '$INSTALL_DIR/$SCRIPT_NAME --apply-fw'

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${service_name} >> $LOG_FILE 2>&1
    systemctl restart ${service_name}
}

# --- Logic: Setup ---
run_setup() {
    install_deps
    
    echo -e "${BOLD}Select Installation Role:${NC}"
    echo "1) Server (The Exit Node / Internet Source)"
    echo "2) Client (The Bridge / Entry Point)"
    read -p "Select [1/2]: " opt

    if [ "$opt" == "1" ]; then
        ROLE="server"
        
        # Check Port 53 BEFORE asking for details
        check_port_53
        
        echo -e "\n${RED}${BOLD}IMPORTANT REQUIREMENT:${NC}"
        echo -e "You must have a real domain."
        echo -e "1. Create an 'A' record (e.g. ${CYAN}tun.domain.com${NC}) pointing to this server IP."
        echo -e "2. Create an 'NS' record (e.g. ${CYAN}t1.domain.com${NC}) pointing to ${CYAN}tun.domain.com${NC}."
        echo -e "------------------------------------------------------"
        
        read -p "Enter your NS Subdomain (e.g. t1.domain.com): " DOMAIN
        read -p "Enter Tunnel Password: " PASSWORD
        PORT_LIST=""
        
    elif [ "$opt" == "2" ]; then
        ROLE="client"
        read -p "Enter Server NS Subdomain (e.g. t1.domain.com): " DOMAIN
        read -p "Enter Tunnel Password: " PASSWORD
        echo -e "${YELLOW}Enter ports to forward traffic to Server (Comma separated)${NC}"
        read -p "Ports (e.g. 443, 2053): " PORT_LIST
    else
        echo "Invalid option."
        return
    fi

    cat <<EOF > $CONF_FILE
ROLE=$ROLE
DOMAIN=$DOMAIN
PASSWORD=$PASSWORD
PORT_LIST=$PORT_LIST
EOF

    systemctl stop iodine-server 2>/dev/null
    systemctl stop iodine-client 2>/dev/null
    systemctl disable iodine-server 2>/dev/null
    systemctl disable iodine-client 2>/dev/null

    show_progress 0.05 "Configuring Service"
    create_service
    
    echo -e "\n${GREEN}[SUCCESS] Iodine $ROLE installed and started!${NC}"
    
    sleep 3
    apply_firewall
    
    read -p "Do you want to check connection status now? (y/n): " do_check
    if [[ "$do_check" == "y" || "$do_check" == "Y" ]]; then
        check_status
    fi
}

# --- Feature: Status & Ping ---
check_status() {
    draw_header
    echo -e "${BOLD}--- Interface Info (dns0) ---${NC}"
    ip addr show dns0 2>/dev/null | grep inet || echo -e "${RED}Tunnel interface not found! Service might be down.${NC}"
    
    echo -e "\n${BOLD}--- Connection Test ---${NC}"
    
    if [ -f $CONF_FILE ]; then
        source $CONF_FILE
        local target_ip=""
        if [ "$ROLE" == "server" ]; then
            target_ip="$TUN_SERVER_IP"
            echo -e "Server Mode: Listening on $TUN_SERVER_IP"
        else
            target_ip="$TUN_SERVER_IP"
            echo -e "Pinging Server IP: ${YELLOW}$target_ip${NC} ..."
            ping -c 3 -W 3 $target_ip
            if [ $? -eq 0 ]; then
                 echo -e "\n${GREEN}[SUCCESS] Tunnel Connection is Alive!${NC}"
            else
                 echo -e "\n${RED}[FAIL] Could not reach server. Check DNS settings or Firewall.${NC}"
            fi
        fi
    fi
    
    echo -e "\n------------------------------------------------------"
    read -p "Press Enter..."
}

# --- Feature: Uninstall ---
clean_all() {
    echo -e "${RED}>>> WARNING: This will remove Iodine and Firewall rules.${NC}"
    read -p "Are you sure? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    systemctl stop iodine-server 2>/dev/null
    systemctl stop iodine-client 2>/dev/null
    systemctl disable iodine-server 2>/dev/null
    systemctl disable iodine-client 2>/dev/null
    
    source $CONF_FILE 2>/dev/null
    iptables -t nat -D POSTROUTING -o dns0 -j MASQUERADE 2>/dev/null
    
    if [ -n "$PORT_LIST" ]; then
        IFS=',' read -ra ADDR <<< "$PORT_LIST"
        for port in "${ADDR[@]}"; do
            port=$(echo $port | xargs)
            iptables -t nat -D PREROUTING -p tcp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port 2>/dev/null
            iptables -t nat -D PREROUTING -p udp --dport $port -j DNAT --to-destination $TUN_SERVER_IP:$port 2>/dev/null
        done
    fi

    rm -f $CONF_FILE /etc/systemd/system/iodine-server.service /etc/systemd/system/iodine-client.service "$INSTALL_DIR/$SCRIPT_NAME"
    systemctl daemon-reload
    
    echo -e "${GREEN}[SUCCESS] Removed Successfully.${NC}"
    read -p "Press Enter..."
}

# --- Service Menu ---
service_menu() {
    local svc="iodine-${ROLE}"
    if [ ! -f $CONF_FILE ]; then
        if systemctl is-active --quiet iodine-server; then svc="iodine-server"; fi
        if systemctl is-active --quiet iodine-client; then svc="iodine-client"; fi
    fi

    while true; do
        draw_header
        echo -e "${BOLD}--- Service Management ($svc) ---${NC}"
        echo "1) View Logs (journalctl)"
        echo "2) Restart Service"
        echo "3) Stop Service"
        echo "4) Back to Main Menu"
        read -p "Select: " s_opt
        case $s_opt in
            1) journalctl -u $svc -f -n 50 ;;
            2) systemctl restart $svc; echo -e "${GREEN}Restarted.${NC}"; sleep 1 ;;
            3) systemctl stop $svc; echo -e "${RED}Stopped.${NC}"; sleep 1 ;;
            4) break ;;
        esac
    done
}

# --- Hidden Flag for Post-Start Firewall ---
if [ "$1" == "--apply-fw" ]; then
    apply_firewall
    exit 0
fi

# --- Main Menu ---
case "$1" in
    *)
        while true; do
            draw_header
            echo "1) Install & Configure"
            echo "2) Service Manager"
            echo "3) Show Status / Ping Test"
            echo "4) Uninstall & Remove"
            echo "5) Exit"
            echo "------------------------------------------------------"
            read -p "Select option: " opt
            case $opt in
                1) run_setup ;;
                2) service_menu ;;
                3) check_status ;;
                4) clean_all ;;
                5) exit 0 ;;
                *) echo "Invalid Option"; sleep 1 ;;
            esac
        done
        ;;
esac
