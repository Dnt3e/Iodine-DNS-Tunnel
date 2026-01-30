#!/bin/bash
clear
# =========================
# Color Definitions
# =========================
GREEN="\e[1;92m"
YELLOW="\e[1;93m"
ORANGE="\e[38;5;208m"
RED="\e[1;91m"
WHITE="\e[1;97m"
RESET="\e[0m"
CYAN="\e[1;96m"

# =========================
# Logo
# =========================
echo -e "
${CYAN}
  ___   ____    ____                              ____                  _____                                  _ 
 |_ _| |  _ \  / ___|   _   _   _ __    _ __     |  _ \   _ __    ___  |_   _|  _   _   _ __    _ __     ___  | |
  | |  | |_) | \___ \  | | | | | '_ \  | '_ \    | | | | | '_ \  / __|   | |   | | | | | '_ \  | '_ \   / _ \ | |
  | |  |  _ <   ___) | | |_| | | |_) | | |_) |   | |_| | | | | | \__ \   | |   | |_| | | | | | | | | | |  __/ | |
 |___| |_| \_\ |____/   \__,_| | .__/  | .__/    |____/  |_| |_| |___/   |_|    \__,_| |_| |_| |_| |_|  \___| |_|  
                               |_|     |_|                                                                         
${RESET}"

LINE="${YELLOW}═══════════════════════════════════════════${RESET}"

# =========================
# Get public IP info
# =========================
IP_ADDRv4=$(curl -s --max-time 5 https://api.ipify.org)
[ -z "$IP_ADDRv4" ] && IP_ADDRv4="Can't Find"

IP_ADDRv6=$(curl -s --max-time 5 https://icanhazip.com -6)
[ -z "$IP_ADDRv6" ] && IP_ADDRv6="Can't Find"

GEO_INFO=$(curl -s --max-time 5 https://ipwho.is/)
LOCATION=$(echo "$GEO_INFO" | grep -oP '"country"\s*:\s*"\K[^"]+')
[ -z "$LOCATION" ] && LOCATION="Unknown"
DATACENTER=$(echo "$GEO_INFO" | grep -oP '"org"\s*:\s*"\K[^"]+')
[ -z "$DATACENTER" ] && DATACENTER="Unknown"

# =========================
# Display info
# =========================
echo -e "$LINE"
echo -e "${CYAN}Script Version${RESET}: ${YELLOW}v2${RESET}"
echo -e "${CYAN}Telegram Channel${RESET}: ${YELLOW}@irsuppchannel${RESET}"
echo -e "$LINE"
echo -e "${CYAN}IPv4 Address${RESET}: ${YELLOW}$IP_ADDRv4${RESET}"
echo -e "${CYAN}IPv6 Address${RESET}: ${YELLOW}$IP_ADDRv6${RESET}"
echo -e "${CYAN}Location${RESET}: ${YELLOW}$LOCATION${RESET}"
echo -e "${CYAN}Datacenter${RESET}: ${YELLOW}$DATACENTER${RESET}"
echo -e "$LINE"

# =========================
# Menu
# =========================
echo -e "${GREEN}1. Install${RESET}"
echo -e "${YELLOW}2. Restart${RESET}"
echo -e "${ORANGE}3. Update${RESET}"
echo -e "${WHITE}4. Edit${RESET}"
echo -e "${RED}5. Uninstall${RESET}"
echo -e "${CYAN}6. Add Port Forwarding${RESET}"
echo -e "${CYAN}7. Remove Port Forwarding${RESET}"
echo -e "${ORANGE}8. Change NAT Interface${RESET}"
echo    "9. Close"
echo -e "$LINE"
read -p "Select option : " OPTION

# =========================
# Function: Add Port Forwarding
# =========================
add_port_forwarding() {
    read -p "Select Side (server/client): " ROLE
    read -p "Enter NAT interface name (e.g., dns0): " TUN_IF
    read -p "Enter ports to forward (comma separated, e.g., 2001,2002,1010): " PORTS
    PORT_ARRAY=($(echo $PORTS | tr ',' ' '))
    TABLE_NAME="iodine"
    MARK_ID=1

    echo -e "${GREEN}Enabling IP forwarding...${RESET}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    echo -e "${GREEN}Disabling rp_filter on tunnel interface...${RESET}"
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf.$TUN_IF.rp_filter=0 >/dev/null

    echo -e "${GREEN}Creating routing table...${RESET}"
    grep -q "$TABLE_NAME" /etc/iproute2/rt_tables || echo "100 $TABLE_NAME" >> /etc/iproute2/rt_tables

    echo -e "${GREEN}Adding default route for forwarded traffic...${RESET}"
    ip route add default dev $TUN_IF table $TABLE_NAME 2>/dev/null

    echo -e "${GREEN}Marking ports...${RESET}"
    for PORT in "${PORT_ARRAY[@]}"; do
        iptables -t mangle -A OUTPUT -p tcp --dport $PORT -j MARK --set-mark $MARK_ID
    done

    echo -e "${GREEN}Adding policy routing rule...${RESET}"
    ip rule add fwmark $MARK_ID table $TABLE_NAME 2>/dev/null

    echo -e "${GREEN}Enabling NAT on tunnel...${RESET}"
    iptables -t nat -A POSTROUTING -o $TUN_IF -j MASQUERADE

    echo -e "${GREEN}Port Forwarding applied successfully.${RESET}"
}

# =========================
# Function: Remove Port Forwarding
# =========================
remove_port_forwarding() {
    read -p "Enter NAT interface used (e.g., dns0): " TUN_IF
    TABLE_NAME="iodine"
    MARK_ID=1

    echo -e "${RED}Removing iptables mangle rules...${RESET}"
    iptables -t mangle -F

    echo -e "${RED}Removing NAT rules for tunnel...${RESET}"
    iptables -t nat -D POSTROUTING -o $TUN_IF -j MASQUERADE 2>/dev/null

    echo -e "${RED}Deleting policy routing rules and flushing table...${RESET}"
    ip rule del fwmark $MARK_ID table $TABLE_NAME 2>/dev/null
    ip route flush table $TABLE_NAME 2>/dev/null

    echo -e "${GREEN}Restoring rp_filter...${RESET}"
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
    sysctl -w net.ipv4.conf.$TUN_IF.rp_filter=1 >/dev/null

    echo -e "${GREEN}Port Forwarding removed successfully.${RESET}"
}

# =========================
# Function: Change NAT Interface
# =========================
change_nat_interface() {
    read -p "Enter new NAT interface name: " NEW_IF
    echo -e "${GREEN}NAT interface updated. Remember to reapply Port Forwarding if needed.${RESET}"
}

# =========================
# Main Menu Actions
# =========================
case "$OPTION" in

1)
    read -p "Select Side (server/client): " ROLE
    SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
    read -p "NS Address: " DOMAIN
    read -p "Tunnel Password: " PASSWORD

    if [ "$ROLE" == "server" ]; then
        read -p "Server Tunnel IP: " TUNNEL_IP
    else
        echo -e "${GREEN}Client side detected. IP not required.${RESET}"
    fi

    echo -e "${GREEN}Installing iodine...${RESET}"
    apt update && apt install iodine -y

    echo -e "${GREEN}Building service...${RESET}"
    if [ "$ROLE" == "server" ]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Iodine DNS Tunnel Server
After=network.target

[Service]
ExecStart=/usr/sbin/iodined -f -c -P $PASSWORD $TUNNEL_IP $DOMAIN
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Iodine DNS Tunnel Client
After=network.target
Wants=network-online.target

[Service]
ExecStart=/usr/sbin/iodine -f -P $PASSWORD $DOMAIN
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    fi

    echo -e "${GREEN}Enabling and starting service...${RESET}"
    systemctl daemon-reload
    systemctl enable $(basename "$SERVICE_FILE")
    systemctl restart $(basename "$SERVICE_FILE")

    echo -e "${GREEN}Installation complete.${RESET}"
    systemctl status $(basename "$SERVICE_FILE") --no-pager
;;

2)
    read -p "Select Side (server/client): " ROLE
    SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
    echo -e "${YELLOW}Restarting service...${RESET}"
    systemctl restart $(basename "$SERVICE_FILE")
    echo -e "${GREEN}Service restarted.${RESET}"
    systemctl status $(basename "$SERVICE_FILE") --no-pager
;;

3)
    read -p "Select Side (server/client): " ROLE
    SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
    echo -e "${ORANGE}Opening service file for update...${RESET}"
    nano "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl restart $(basename "$SERVICE_FILE")
    echo -e "${GREEN}Service updated and restarted.${RESET}"
;;

4)
    read -p "Select Side (server/client): " ROLE
    SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
    echo -e "${WHITE}Opening service file for edit...${RESET}"
    nano "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl restart $(basename "$SERVICE_FILE")
    echo -e "${GREEN}Service edited and restarted.${RESET}"
;;

5)
    read -p "Select Side to uninstall (server/client): " ROLE
    SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${RED}Uninstalling service...${RESET}"
        systemctl stop $(basename "$SERVICE_FILE")
        systemctl disable $(basename "$SERVICE_FILE")
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        echo -e "${GREEN}Service uninstalled successfully.${RESET}"
    else
        echo -e "${RED}Service not found. Nothing to uninstall.${RESET}"
    fi
;;

6)
    add_port_forwarding
;;

7)
    remove_port_forwarding
;;

8)
    change_nat_interface
;;

9)
    echo "Closing script."
    exit 0
;;

*)
    echo -e "${RED}Invalid option selected.${RESET}"
;;

esac
