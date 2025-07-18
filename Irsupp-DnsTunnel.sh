#!/bin/bash
clear

GREEN="\e[1;92m"
YELLOW="\e[1;93m"
ORANGE="\e[38;5;208m"
RED="\e[1;91m"
WHITE="\e[1;97m"
RESET="\e[0m"
CYAN="\e[1;96m"

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

IP_ADDRv4=$(curl -s --max-time 5 https://api.ipify.org)
[ -z "$IP_ADDRv4" ] && IP_ADDRv4="Can't Find"

IP_ADDRv6=$(curl -s --max-time 5 https://icanhazip.com -6)
[ -z "$IP_ADDRv6" ] && IP_ADDRv6="Can't Find"

GEO_INFO=$(curl -s --max-time 5 https://ipwho.is/)
LOCATION=$(echo "$GEO_INFO" | grep -oP '"country"\s*:\s*"\K[^"]+')
[ -z "$LOCATION" ] && LOCATION="Unknown"

DATACENTER=$(echo "$GEO_INFO" | grep -oP '"org"\s*:\s*"\K[^"]+')
[ -z "$DATACENTER" ] && DATACENTER="Unknown"

echo -e "$LINE"
echo -e "${CYAN}Script Version${RESET}: ${YELLOW}v1${RESET}"
echo -e "${CYAN}Telegram Channel${RESET}: ${YELLOW}@irsuppchannel${RESET}"
echo -e "$LINE"
echo -e "${CYAN}IPv4 Address${RESET}: ${YELLOW}$IP_ADDRv4${RESET}"
echo -e "${CYAN}IPv6 Address${RESET}: ${YELLOW}$IP_ADDRv6${RESET}"
echo -e "${CYAN}Location${RESET}: ${YELLOW}$LOCATION${RESET}"
echo -e "${CYAN}Datacenter${RESET}: ${YELLOW}$DATACENTER${RESET}"
echo -e "$LINE"

configure_port_forwarding() {
    ROLE=$1
    echo -e "$LINE"
    echo -e "${GREEN}Port Forwarding Configuration${RESET}"
    echo -e "$LINE"
    
    if [ "$ROLE" == "server" ]; then
        read -p "Enter ports to forward to Iran (e.g. 80,443 or 1000-2000): " PORTS
        for port in $(echo $PORTS | tr ',' ' '); do
            iptables -t nat -A PREROUTING -p tcp --dport $port -j DNAT --to-destination 10.0.0.2
            iptables -t nat -A PREROUTING -p udp --dport $port -j DNAT --to-destination 10.0.0.2
        done
    else
        read -p "Enter ports to forward to Foreign (e.g. 22,3389 or 1000-2000): " PORTS
        for port in $(echo $PORTS | tr ',' ' '); do
            iptables -t nat -A PREROUTING -p tcp --dport $port -j DNAT --to-destination 10.0.0.1
            iptables -t nat -A PREROUTING -p udp --dport $port -j DNAT --to-destination 10.0.0.1
        done
    fi
    
    sysctl -w net.ipv4.ip_forward=1
    echo -e "${GREEN}Port forwarding configured for: $PORTS${RESET}"
}

echo -e "${GREEN}1. Install${RESET}"
echo -e "${YELLOW}2. Restart${RESET}"
echo -e "${ORANGE}3. Update${RESET}"
echo -e "${WHITE}4. Edit${RESET}"
echo -e "${RED}5. Uninstall${RESET}"
echo -e "${CYAN}6. Port Forwarding${RESET}"
echo    "7. Close"
echo -e "$LINE"
read -p "Select option : " OPTION

case "$OPTION" in
    1)
        read -p "Select Side (server/client): " ROLE
        SERVICE_FILE="/etc/systemd/system/iodine-${ROLE}.service"
        read -p "NS Address: " DOMAIN
        read -p "Tunnel Password: " PASSWORD

        if [ "$ROLE" == "server" ]; then
            read -p "Server Tunnel IP: " TUNNEL_IP
        fi

        apt update && apt install iodine -y

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

        configure_port_forwarding "$ROLE"
        
        systemctl daemon-reload
        systemctl enable $(basename "$SERVICE_FILE")
        systemctl restart $(basename "$SERVICE_FILE")

        echo -e "${GREEN}Installation complete with port forwarding!${RESET}"
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
        read -p "Select Side (server/client): " ROLE
        configure_port_forwarding "$ROLE"
        ;;
    7)
        echo "Closing script."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option selected.${RESET}"
        ;;
esac
