<div align="center">

🌐 **Language:** [🇷🇺 Русский](README.md) | [🇬🇧 English](README_EN.md)

</div>

<div align="center">

```
███╗   ██╗ █████╗ ██╗██╗   ██╗███████╗    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
████╗  ██║██╔══██╗██║██║   ██║██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██╔██╗ ██║███████║██║██║   ██║█████╗      ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
██║╚██╗██║██╔══██║██║╚██╗ ██╔╝██╔══╝      ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
██║ ╚████║██║  ██║██║ ╚████╔╝ ███████╗    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
                                                                         MANAGER
```

**Professional private proxy server manager**
Caddy 2 · NaiveProxy · Let's Encrypt · Telegram · SSH Hardening · QR Connection

---

[![Version](https://img.shields.io/badge/version-3.8.0-D4A017?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ivanstudiya-cpu/naiveproxy/releases)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-3FB950?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.shellcheck.net)
[![Bash](https://img.shields.io/badge/Bash-5.0+-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![Caddy](https://img.shields.io/badge/Caddy-auto-00ADD8?style=for-the-badge&logo=caddy&logoColor=white)](https://caddyserver.com)
[![License](https://img.shields.io/badge/License-MIT-58A6FF?style=for-the-badge)](LICENSE)

---

[**Quick Start**](#-quick-start) • [**Features**](#-features) • [**SSH Hardening**](#-ssh-hardening) • [**Firewall**](#-firewall) • [**Clients**](#-client-apps) • [**FAQ**](#-faq)

</div>

---

## 🤔 What is this

**NaiveProxy** disguises traffic as Chrome browser using the real Chromium network stack. DPI systems and censors see legitimate HTTPS/2 — and let it through.

**NaiveProxy Manager** — a single bash script that turns a bare VPS into a fully protected proxy server. No Docker, no GUI panels, no extra dependencies.

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
│  Your       │     │  Censor/DPI  │     │   Your VPS        │     │              │
│  phone      │────▶│              │────▶│   Caddy +         │────▶│  Internet    │
│  laptop     │     │  Sees Chrome │     │   forwardproxy    │     │              │
└─────────────┘     │  HTTPS/2 ✓   │     │   probe_resist.   │     └──────────────┘
 naive-client        └──────────────┘     └───────────────────┘
 Chromium stack       Passes through       TLS from Let's Encrypt
```

---

## ⚡ Quick Start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanstudiya-cpu/naiveproxy/main/naiveproxy.sh)
```

### What happens during installation:

```
[1/5] 🔄  System Update
         apt upgrade + unattended-upgrades
         → skip if already updated: press n

[2/5] 🔒  SSH Hardening                              [OPTIONAL]
         ED25519 key · auto-save · new user · Fail2Ban
         → skip if SSH already configured: press n

[3/5] 📦  Building Caddy
         git clone klzgrad/forwardproxy@naive
         xcaddy build with auto version detection  ~5-15 min

[4/5] ⚙️   Configuration
         Caddyfile (:443, domain) · systemd · UFW · BBR · Telegram

[5/5] ✅  Done
         URI + JSON configs + QR code for phone
```

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔐 Security
- **SSH Hardening** — ED25519 key, port change, root block
- **SSH key auto-save** — to `/etc/naiveproxy/ssh_private_key`
- **Fail2Ban 3 levels** — bruteforce/DDoS/recidive
- **UFW** — deny all incoming + scanner port blocking
- **probe_resistance** — looks like a normal website
- **Camouflage page** — DevStack IT blog

### 📡 Proxy
- **Automatic TLS** — Let's Encrypt via Caddy
- **HTTP/2 + HTTP/3** — explicitly enabled
- **QR code** — one-scan phone connection
- **Multi-user** — add users without restart
- **Multiple domains** — on one server
- **TCP BBR** — optional speed boost

</td>
<td width="50%" valign="top">

### 🤖 Automation
- **Telegram bot** — alerts + stats on demand
- **Watchdog** — cron every 5 min, auto-restart
- **Auto Caddy update** — every Sunday at 3:00
- **Self-update** — script update from GitHub
- **Certificate check** — alert when < 7 days left

### 🛡️ Code Quality
- `set -euo pipefail` — strict mode
- **SHA256 verification** of Go binary
- `grep -vF` instead of `sed` — no regex injection
- `--data-urlencode` for Telegram
- `trap` cleanup of temp files
- **ShellCheck passing** — 0 warnings

</td>
</tr>
</table>

---

## 📋 Requirements

| | |
|--|--|
| **OS** | Ubuntu 20.04 / 22.04 / 24.04 |
| **Rights** | root |
| **Domain** | A-record → server IP |
| **Ports** | 80/tcp · 443/tcp · 443/udp |
| **RAM** | 512 MB+ |
| **Disk** | 1 GB+ |

---

## 🎮 Menu

```
──────────────────────────────────────────────────────
   NaiveProxy Manager v3.8.0
   Status: ● running  │  Domain: proxy.example.com
   Telegram: connected  │  Users: 3  │  SSH: 52847
──────────────────────────────────────────────────────
   1)  Install NaiveProxy          9)  Update Caddy
   2)  Status + certificate        10) Logs
   3)  Client config + QR          11) Remove NaiveProxy
   4)  Users                       ──────────────────
   5)  Domains                     12) 🔒 SSH Hardening
   6)  Monitoring + stats          13) 🔄 Update system
   7)  Telegram setup              14) ⬆️  Update script
   8)  Restart Caddy               15) 🎭 Update camouflage
──────────────────────────────────────────────────────
```

### CLI commands:

```bash
sudo bash naiveproxy.sh install        # Full installation
sudo bash naiveproxy.sh status         # Status + TLS certificate
sudo bash naiveproxy.sh config         # Config + QR code
sudo bash naiveproxy.sh qr             # QR code only
sudo bash naiveproxy.sh cert           # Certificate only
sudo bash naiveproxy.sh users          # User management
sudo bash naiveproxy.sh domains        # Domain management
sudo bash naiveproxy.sh monitor        # Monitoring + stats
sudo bash naiveproxy.sh restart        # Restart Caddy
sudo bash naiveproxy.sh update         # Update Caddy
sudo bash naiveproxy.sh logs           # Live logs
sudo bash naiveproxy.sh tg-stats       # Stats to Telegram
sudo bash naiveproxy.sh ssh-hardening  # SSH Hardening
sudo bash naiveproxy.sh ssh-key        # Show SSH private key
sudo bash naiveproxy.sh sysupdate      # System update
sudo bash naiveproxy.sh self-update    # Update script from GitHub
sudo bash naiveproxy.sh camouflage     # Reinstall camouflage page
sudo bash naiveproxy.sh version        # Show version
sudo bash naiveproxy.sh remove         # Remove everything
```

---

## 🔒 SSH Hardening

```bash
sudo bash naiveproxy.sh ssh-hardening
```

> 💡 **Can be skipped** if SSH is already configured. Press `n` during installation.

### 5 steps:

**① New sudo user** — created with password (or random)

**② ED25519 SSH key + auto-save**

Key is automatically saved to `/etc/naiveproxy/ssh_private_key`.
Script outputs ready-to-use download command:

```bash
# Linux/macOS:
scp root@YOUR_IP:/etc/naiveproxy/ssh_private_key ~/.ssh/id_naiveproxy
chmod 600 ~/.ssh/id_naiveproxy

# Windows PowerShell:
scp root@YOUR_IP:/etc/naiveproxy/ssh_private_key $HOME\.ssh\id_naiveproxy

# Connect:
ssh -i ~/.ssh/id_naiveproxy -p NEW_PORT user@YOUR_IP
```

Show key anytime:
```bash
sudo bash naiveproxy.sh ssh-key
```

**③ SSH port change** — manual or random (49000-65000)

**④ sshd_config**
```ini
PermitRootLogin        no
PasswordAuthentication no
MaxAuthTries           3
LoginGraceTime         30
X11Forwarding          no
```

**⑤ UFW + Fail2Ban** — new port opened BEFORE closing the old one

---

## 🛡️ Firewall

### UFW
```
Default: DENY ALL INCOMING
Open: 80/tcp (ACME), 443/tcp, 443/udp, SSH port
Blocked: MySQL(3306), Redis(6379), MongoDB(27017),
         Elasticsearch(9200), 8080, 8888...
Rate limit: 80/tcp — DDoS protection on ACME
```

### Fail2Ban — 3 protection levels

| Level | Trigger | Ban |
|-------|---------|-----|
| SSH bruteforce | 3 wrong passwords | **7 days** |
| SSH DDoS | 10 attempts in 1 minute | **7 days** |
| Recidivist | Repeated violations | **30 days** |

---

## 📱 QR Code

After installation the script generates a QR code right in the terminal:

```
█████████████████████████████████
█ ▄▄▄▄▄ █▀▄▀█▀▄▀ ▀█▄▀ █ ▄▄▄▄▄ █
...
```

Scan with **NekoBox** or **Shadowrocket** — one-tap connection!

Show QR anytime:
```bash
sudo bash naiveproxy.sh qr
```

---

## ⚠️ Critical — Caddyfile

**This is what prevents connection in most cases:**

```bash
# ❌ WRONG — clients won't connect:
your-domain.com:443 {
  ...
}

# ✅ CORRECT — :443 must be FIRST:
:443, your-domain.com {
  tls your@email.com
  forward_proxy {
    basic_auth user password
    hide_ip
    hide_via
    probe_resistance
  }
  file_server {
    root /var/www/html
  }
}
```

The script generates the correct config automatically since v3.7.0.

---

## 🤖 Telegram Bot

1. [@BotFather](https://t.me/BotFather) → `/newbot` → token
2. [@userinfobot](https://t.me/userinfobot) → chat_id
3. Menu → **7) Telegram setup**

| Event | Message |
|-------|---------|
| Installation done | ✅ NaiveProxy started |
| Caddy crashed | 🔴 Down → auto-restart |
| SSH Hardening | 🔒 Port: 52847 |
| Certificate < 7 days | ⚠️ 5 days left! |
| Stats | 📊 Traffic · RAM · Disk · Cert |

---

## 📱 Client Apps

### URI (paste into any client):
```
naive+https://USERNAME:PASSWORD@YOUR_DOMAIN:443
```

### JSON (naive-client Windows/Linux):
```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://USERNAME:PASSWORD@YOUR_DOMAIN:443",
  "log": "naive.log"
}
```

### Recommended clients:

| Client | Platform | How to add |
|--------|----------|------------|
| [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) | Android | Scan QR / URI |
| [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | iPhone | URI |
| [Hiddify](https://github.com/hiddify/hiddify-next/releases) | Windows / macOS | URI |
| [naive](https://github.com/klzgrad/naiveproxy/releases) | Windows / Linux | config.json |
| [sing-box](https://github.com/SagerNet/sing-box) | All platforms | JSON config |

> ⚠️ **v2rayNG does NOT support NaiveProxy.** Use NekoBox or Hiddify.

---

## 🎭 Camouflage Page

Default — **DevStack** IT blog. Looks like a real website to scanners.

**Path:** `/var/www/html/index.html`

```bash
# Replace with your own page:
scp my_site.html user@YOUR_IP:/var/www/html/index.html

# Restore DevStack:
sudo bash naiveproxy.sh camouflage
```

---

## 📁 File Structure

```
/usr/local/bin/caddy
/etc/caddy/Caddyfile                       (chmod 600)
/etc/naiveproxy/
├── naive.conf                             (chmod 600)
├── users.conf                             (chmod 600)
├── ssh_private_key                        ← SSH key (auto-saved)
├── ssh_public_key
├── monitor.sh
├── .ssh_hardened
├── .sysupdate_done
└── backups/
/etc/fail2ban/jail.local
/var/www/html/index.html                   ← camouflage page
/var/log/caddy/access.log
/var/log/caddy/naive.log
```

---

## ❓ FAQ

<details>
<summary><b>Client won't connect</b></summary>

Check Caddyfile:
```bash
cat /etc/caddy/Caddyfile | grep ":443"
# Should be: :443, your-domain.com {
# NOT: your-domain.com:443 {
```

Check ALPN:
```bash
openssl s_client -connect YOUR_DOMAIN:443 -alpn h2 2>/dev/null | grep "ALPN protocol"
# Should be: ALPN protocol: h2
```

</details>

<details>
<summary><b>How to download SSH key to my computer</b></summary>

```bash
# Linux/macOS:
scp root@YOUR_IP:/etc/naiveproxy/ssh_private_key ~/.ssh/id_naiveproxy
chmod 600 ~/.ssh/id_naiveproxy

# Windows PowerShell:
scp root@YOUR_IP:/etc/naiveproxy/ssh_private_key $HOME\.ssh\id_naiveproxy

# Connect:
ssh -i ~/.ssh/id_naiveproxy -p SSH_PORT user@YOUR_IP
```

</details>

<details>
<summary><b>Locked myself out after SSH hardening</b></summary>

Access via hosting console (VNC/KVM):
```bash
ufw allow 22/tcp && systemctl restart sshd
```

</details>

<details>
<summary><b>Caddy can't get TLS certificate</b></summary>

```bash
dig +short YOUR_DOMAIN        # must return server IP
ss -tlnp | grep :80           # port 80 must be listening
journalctl -u caddy -n 50 | grep -i "acme\|error\|cert"
```

</details>

<details>
<summary><b>How to verify IP changed</b></summary>

```bash
# On server:
curl https://ifconfig.me

# Windows with naive.exe running:
curl.exe --proxy socks5://127.0.0.1:1080 https://ifconfig.me
```

</details>

---

## 📊 Comparison

| Feature | **NaiveProxy Manager** | x-ui / 3x-ui | Marzban |
|---------|:---:|:---:|:---:|
| No Docker | ✅ | ❌ | ❌ |
| SSH Hardening | ✅ | ❌ | ❌ |
| SSH key auto-save | ✅ | ❌ | ❌ |
| QR code on install | ✅ | ❌ | ❌ |
| Fail2Ban 3 levels | ✅ | ❌ | ❌ |
| UFW deny all + scanners | ✅ | ❌ | ❌ |
| System update | ✅ | ❌ | ❌ |
| Script self-update | ✅ | ❌ | ❌ |
| Camouflage page | ✅ | ❌ | ❌ |
| Certificate check | ✅ | ❌ | ❌ |
| Correct Caddyfile | ✅ v3.7+ | — | — |
| Telegram alerts | ✅ | ✅ | ✅ |
| ShellCheck passing | ✅ | — | — |

---

## 📜 Changelog

<details>
<summary><b>v3.8.0</b> — Security & UX ← CURRENT</summary>

- ✨ SSH key auto-save to `/etc/naiveproxy/ssh_private_key`
- ✨ QR code generation in terminal
- ✨ scp command for key download
- 🛡️ UFW: `deny all incoming` + scanner port blocking
- 🛡️ Fail2Ban 3 levels: bruteforce(7d) / DDoS(7d) / recidive(30d)
- 🆕 CLI: `qr`, `ssh-key`

</details>

<details>
<summary><b>v3.7.0</b> — Critical Caddyfile Fix</summary>

- 🔴 Critical fix: `:443, domain` instead of `domain:443`
- ✅ Confirmed working: NekoBox Android + naive.exe Windows

</details>

<details>
<summary><b>v3.6.0</b> — Critical Build Fix</summary>

- 🔴 build_caddy: direct git clone of `klzgrad/forwardproxy@naive`
- 🔴 Auto-detect compatible Caddy version from go.mod

</details>

<details>
<summary><b>v3.5.0</b> — Security Audit</summary>

- 🔒 grep -vF instead of sed, --data-urlencode, trap cleanup

</details>

<details>
<summary><b>v3.0-3.4</b> — Core Features</summary>

- System update, SSH Hardening, Self-update, Domains, Camouflage

</details>

---

## 📄 License

MIT © [ivanstudiya-cpu](https://github.com/ivanstudiya-cpu)

---

<div align="center">

**If this helped you — leave a ⭐ star**

[![GitHub stars](https://img.shields.io/github/stars/ivanstudiya-cpu/naiveproxy?style=for-the-badge&color=D4A017)](https://github.com/ivanstudiya-cpu/naiveproxy/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ivanstudiya-cpu/naiveproxy?style=for-the-badge&color=58A6FF)](https://github.com/ivanstudiya-cpu/naiveproxy/network)

*NaiveProxy Manager · Caddy 2 · klzgrad/forwardproxy@naive · Ubuntu*

</div>
