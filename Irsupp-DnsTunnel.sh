#!/bin/bash
clear

# COLORS
GREEN="\e[1;92m"
YELLOW="\e[1;93m"
ORANGE="\e[38;5;208m"
RED="\e[1;91m"
CYAN="\e[1;96m"
RESET="\e[0m"

SERVICE_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

echo -e "${CYAN}
IODINE DNS TUNNEL MANAGER v4.0 (DEBUGGED)
MultiClient | IPv6 | DNS-LB | Monitor | Failover
${RESET}"

echo "========================================="
echo "1) Install (Server / Client)"
echo "2) Restart Service"
echo "3) Edit Service"
echo "4) Enable Tunnel Monitoring"
echo "5) Disable Tunnel Monitoring"
echo "6) Enable Failover (Client)"
echo "7) Disable Failover"
echo "8) Uninstall"
echo "9) Exit"
echo "========================================="
read -p "Select option: " OPT

case $OPT in

# --------------------------------------------------
1)
read -p "Role (server/client): " ROLE
read -p "Primary Domain (NS1): " DOMAIN1
read -p "Backup Domain (NS2 optional): " DOMAIN2
read -p "Tunnel Password: " PASS
read -p "Enable IPv6? (y/n): " IPV6

apt update && apt install iodine iproute2 -y

# ---------------- SYSCTL ----------------
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q net.ipv4.ip_forward /etc/sysctl.conf || \
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

[ "$IPV6" = "y" ] && {
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  grep -q net.ipv6.conf.all.forwarding /etc/sysctl.conf || \
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
}

# ---------------- SERVER ----------------
if [ "$ROLE" = "server" ]; then
  R=$((RANDOM%200+10))
  TUNNET="10.60.$R.0/24"
  TUNIP="10.60.$R.1"

  # NAT only for tunnel subnet
  iptables -t nat -C POSTROUTING -s $TUNNET -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s $TUNNET -j MASQUERADE
fi

SERVICE="$SERVICE_DIR/iodine-$ROLE.service"

# ---------------- SERVICE FILE ----------------
if [ "$ROLE" = "server" ]; then
cat > $SERVICE <<EOF
[Unit]
Description=Iodine DNS Tunnel Server
After=network.target

[Service]
ExecStart=/usr/sbin/iodined -f -c -P $PASS $TUNIP $DOMAIN1
Restart=always
CPUQuota=35%
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF
else
cat > $SERVICE <<EOF
[Unit]
Description=Iodine DNS Tunnel Client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/sbin/iodine -f -P $PASS $DOMAIN1
Restart=always
CPUQuota=35%
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF
fi

# ---------------- DNS LOAD BALANCE ----------------
cat > /etc/resolv.conf <<EOF
options rotate timeout:1 attempts:2
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF

systemctl daemon-reload
systemctl enable iodine-$ROLE
systemctl restart iodine-$ROLE

echo -e "${GREEN}Installed successfully.${RESET}"
echo -e "${YELLOW}NOTE:${RESET} After connection, check tun interface:"
echo "ip addr show tun0"
;;

# --------------------------------------------------
2)
read -p "Role (server/client): " ROLE
systemctl restart iodine-$ROLE
;;

# --------------------------------------------------
3)
read -p "Role (server/client): " ROLE
nano $SERVICE_DIR/iodine-$ROLE.service
systemctl daemon-reload
systemctl restart iodine-$ROLE
;;

# --------------------------------------------------
4)
cat > $BIN_DIR/iodine-monitor.sh <<'EOF'
#!/bin/bash
IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep '^tun' | head -n1)
[ -z "$IFACE" ] && exit 0

RX=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
TX=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)

echo "$(date) IF=$IFACE RX=$((RX/1024))KB TX=$((TX/1024))KB" >> /var/log/iodine-monitor.log
EOF

chmod +x $BIN_DIR/iodine-monitor.sh

cat > $SERVICE_DIR/iodine-monitor.service <<EOF
[Unit]
Description=Iodine Tunnel Monitor

[Service]
Type=oneshot
ExecStart=$BIN_DIR/iodine-monitor.sh
EOF

cat > $SERVICE_DIR/iodine-monitor.timer <<EOF
[Timer]
OnBootSec=30
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now iodine-monitor.timer
echo -e "${GREEN}Monitoring enabled${RESET}"
;;

# --------------------------------------------------
5)
systemctl disable --now iodine-monitor.timer
rm -f $SERVICE_DIR/iodine-monitor.*
rm -f $BIN_DIR/iodine-monitor.sh
echo -e "${YELLOW}Monitoring disabled${RESET}"
;;

# --------------------------------------------------
6)
read -p "Primary Domain: " P
read -p "Backup Domain: " S

cat > $BIN_DIR/iodine-failover.sh <<EOF
#!/bin/bash
FAIL=0
while true; do
  ping -c1 8.8.8.8 >/dev/null || FAIL=\$((FAIL+1))
  if [ \$FAIL -ge 3 ]; then
    sed -i "s/$P/$S/" /etc/systemd/system/iodine-client.service
    systemctl daemon-reload
    systemctl restart iodine-client
    FAIL=0
  fi
  sleep 10
done
EOF

chmod +x $BIN_DIR/iodine-failover.sh

cat > $SERVICE_DIR/iodine-failover.service <<EOF
[Unit]
Description=Iodine Client Failover

[Service]
ExecStart=$BIN_DIR/iodine-failover.sh
Restart=always
EOF

systemctl daemon-reload
systemctl enable --now iodine-failover
echo -e "${GREEN}Failover enabled${RESET}"
;;

# --------------------------------------------------
7)
systemctl disable --now iodine-failover
rm -f $BIN_DIR/iodine-failover.sh
rm -f $SERVICE_DIR/iodine-failover.service
echo -e "${YELLOW}Failover disabled${RESET}"
;;

# --------------------------------------------------
8)
read -p "Role (server/client): " ROLE
systemctl stop iodine-$ROLE
systemctl disable iodine-$ROLE
rm -f $SERVICE_DIR/iodine-$ROLE.service
systemctl daemon-reload
echo -e "${RED}Uninstalled${RESET}"
;;

# --------------------------------------------------
9)
exit 0
;;

*)
echo -e "${RED}Invalid option${RESET}"
;;
esac
