# Iodine DNS Tunnel Manager

A lightweight Bash tool to **deploy and manage Iodine DNS tunnels** with automatic networking, firewall, and service configuration.

---

## ✨ Features

* Automatic dependency installation
* Server and Client deployment modes
* Automatic **Kernel IP Forwarding** configuration
* Smart **iptables NAT & Masquerade** setup
* Multi-Port forwarding support (TCP & UDP)
* Automatic systemd service creation & management
* Port 53 conflict detection and DNS fix
* Real-time tunnel status monitoring
* Interactive CLI interface
* Safe uninstall and cleanup

---

## 📦 Installation

```bash
curl -O https://raw.githubusercontent.com/Dnt3e/Iodine-DNS-Tunnel/main/iodine-manager.sh
chmod +x iodine-manager.sh
sudo ./iodine-manager.sh
```
---

## ⚙️ Usage & Networking Capabilities

This script automatically prepares your system for DNS tunneling by:

### 🔹 Kernel Networking

* Enables **IPv4 Forwarding**
* Allows traffic routing between tunnel and external interface
* Configures NAT to provide internet access through the tunnel

### 🔹 Firewall & Routing

* Applies MASQUERADE rules for outgoing traffic
* Supports **Multi-Port Forwarding**
* Allows forwarding multiple TCP/UDP ports from client to server

---

## 🌐 DNS Record Setup (Server Mode)

Before running server mode you must configure your domain DNS:

### Step 1 — Create A Record

Point a subdomain to your server IP:

```
tun.yourdomain.com → YOUR_SERVER_IP
```

---

### Step 2 — Create NS Record

Create a nameserver record pointing to the A record:

```
t1.yourdomain.com → tun.yourdomain.com
```

---

### Step 3 — Use NS Subdomain in Script

When installing server mode, enter:

```
t1.yourdomain.com
```

---

## ⚠️ Requirements

* Root access
* Linux server (Debian / Ubuntu / CentOS / RHEL)
* Available UDP Port 53
* Valid domain name for server mode

---
👨‍💻 Developer

Developed by: Dnt3e
