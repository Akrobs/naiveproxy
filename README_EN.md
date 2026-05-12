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

### 🚀 Professional private proxy server manager

**One script. Bare VPS → secure proxy with ad blocking in 10 minutes.**

Caddy 2 · NaiveProxy · Telegram Bot · DNS Ad Blocking · Diagnostics · SSH Hardening

---

[![Version](https://img.shields.io/badge/version-4.2.3-D4A017?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ivanstudiya-cpu/naiveproxy/releases)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-3FB950?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.shellcheck.net)
[![Bash](https://img.shields.io/badge/Bash-5.0+-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-GPL--3.0-58A6FF?style=for-the-badge)](LICENSE)

---

### 💛 Support the project

[![Donate](https://img.shields.io/badge/💛_Donate-DonationAlerts-FF5E3A?style=for-the-badge)](https://www.donationalerts.com/r/ivan_yurievich)
[![Telegram](https://img.shields.io/badge/Telegram-Channel-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/+XVSkY6blCTY0ZDU6)
[![Website](https://img.shields.io/badge/Website-ivan--it.net-D4A017?style=for-the-badge&logo=googlechrome&logoColor=white)](https://ivan-it.net)

**🔔 Updates released once a month**

</div>

---

<div align="center">

[**⚡ Quick Start**](#-quick-start) • [**✨ Features**](#-features) • [**🤖 Bot**](#-telegram-bot) • [**🚫 DNS Block**](#-dns-ad-blocking) • [**🔍 Diagnostics**](#-diagnostics) • [**❓ FAQ**](#-faq) • [**💛 Donate**](#-support-the-project-1)

</div>

---

## 🎉 What's new in v4.2.3

<table>
<tr>
<td width="50%" valign="top">

### 🐛 Bug fixes

✅ `/qr` command — curl conflict fix
✅ `/adduser` — login and password validation
✅ Bot commands — `\r\n` cleanup
✅ `set +e` — error doesn't break the bot
✅ Diagnostics — `pass=$((pass+1))` counters
✅ ALPN — `-servername` + `-a` for binary output
✅ SSH port on Ubuntu 22.04+ via `sshd_config.d/`
✅ Protection against deleting last domain
✅ `apt update` before Fail2Ban
✅ Auto-restart Caddy and bot on failure

</td>
<td width="50%" valign="top">

### ⚡ New features

🤖 **16 bot commands** + multi-admin
🚫 **DNS blocking** ~1.5M domains + DoT
🔍 **Diagnostics** — 7 blocks, 18+ checks
🔒 **SSH Hardening** — ED25519, `ssh.socket` fix
🛡️ **Fail2Ban** 3 levels (iptables-multiport)
♻️ **Auto-recovery** — `Restart=on-failure`
🎨 **ASCII banner** + branding
💛 **Donate** via DonationAlerts

</td>
</tr>
</table>

[👉 Full Changelog](#-changelog)

---

## 🤔 What is this

**NaiveProxy** disguises traffic as Chrome browser using the real Chromium network stack. DPI systems and censors see legitimate HTTPS/2 — and let it through.

**NaiveProxy Manager** — a single bash script that turns a bare VPS into a fully protected proxy server with ad blocking and Telegram management.

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────────────┐     ┌──────────┐
│  Your       │     │  Censor/DPI  │     │   Your VPS                │     │          │
│  phone      │────▶│              │────▶│   Caddy + NaiveProxy      │────▶│ Internet │
│  laptop     │     │  Sees Chrome │     │   unbound DNS blocking    │     │          │
└─────────────┘     │  HTTPS/2 ✓   │     │   probe_resistance        │     └──────────┘
 naive-client        └──────────────┘     └───────────────────────────┘
 Chromium stack       Passes through       ads blocked 🚫
```

---

## ⚡ Quick Start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanstudiya-cpu/naiveproxy/main/naiveproxy.sh)
```

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔐 Security
- SSH Hardening ED25519 + `sshd_config.d/`
- SSH key auto-save
- Fail2Ban 3 levels (iptables-multiport)
- UFW deny all + scanner blocking
- probe_resistance — looks like a website
- DevStack camouflage page
- Last domain protection

### 📡 Proxy
- Auto TLS — Let's Encrypt
- HTTP/2 + HTTP/3
- QR code — one-scan phone connection
- Multi-user without restart
- Multiple domains
- TCP BBR
- `Restart=on-failure`

</td>
<td width="50%" valign="top">

### 🚫 DNS Blocking
- ~1.5M ad domains
- unbound + DNS-over-TLS
- 3 blocklist sources
- Whitelist
- Auto-update

### 🤖 Telegram Bot
- 16 commands
- Multi-admin
- QR code as image
- Auto-install dependencies
- 24/7 system service

### 🔍 Diagnostics
- 7 blocks, 18+ checks
- Color report
- Send to Telegram

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

---

## 🤖 Telegram Bot

```bash
sudo bash naiveproxy.sh bot-install    # Auto-start
```

| Command | Action |
|---------|--------|
| `/help` `/status` `/stats` | Information |
| `/diagnose` `/cert` `/logs` | Diagnostics |
| `/users` `/adduser` `/deluser` `/qr` | Users |
| `/restart` `/update` `/selfupdate` | Management |
| `/admins` `/addadmin` `/deladmin` | Administration |

---

## 🚫 DNS Ad Blocking

```bash
sudo bash naiveproxy.sh dns-install
```

| Source | Blocks |
|--------|--------|
| StevenBlack/hosts | Ads + malware |
| AdAway | Mobile ads |
| Hagezi Pro | Aggressive blocking |

---

## 🔍 Diagnostics

```bash
sudo bash naiveproxy.sh diagnose
```

```
[1/7] Caddy          ✅ running · ✅ naive padding · ✅ module
[2/7] Configuration  ✅ :443,domain · ✅ users
[3/7] TLS & Network  ✅ DNS · ✅ ports · ✅ ALPN h2 · ✅ cert
[4/7] Firewall       ✅ UFW · ✅ Fail2Ban active
[5/7] Resources      ✅ RAM 40% · ✅ Disk 37%
[6/7] Logs           ✅ no errors
[7/7] Version        ✅ up to date

📊 RESULT: ✅ 18  ⚠️ 0  ❌ 0
```

---

## ⚠️ Caddyfile — critical

```
{
    order forward_proxy before file_server
    servers :443 {
        protocols h1 h2 h3
    }
}

:443, your-domain.com {
  tls your@email.com
  forward_proxy {
    basic_auth USER PASS
    hide_ip
    hide_via
    probe_resistance
  }
  file_server { root /var/www/html }
}
```

---

## 📱 Clients

```
URI: naive+https://USERNAME:PASSWORD@YOUR_DOMAIN:443
```

| Client | Platform |
|--------|----------|
| [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) | Android |
| [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | iPhone ($2.99) |
| [Hiddify](https://github.com/hiddify/hiddify-next/releases) | Windows / macOS |

---

## ❓ FAQ

<details>
<summary><b>Client won't connect</b></summary>

```bash
sudo bash naiveproxy.sh diagnose
echo | openssl s_client -connect YOUR_DOMAIN:443 -alpn h2 -servername YOUR_DOMAIN 2>/dev/null | grep -a "ALPN protocol"
```

</details>

<details>
<summary><b>DNS blocking breaks a website</b></summary>

```bash
sudo bash naiveproxy.sh dns
# → 4) Allow domain
```

</details>

<details>
<summary><b>Telegram bot not responding</b></summary>

```bash
journalctl -u naiveproxy-bot -n 20 --no-pager
systemctl restart naiveproxy-bot
```

</details>

---

## 💛 Support the Project

<div align="center">

### If this script helped you — support development! 🙏

[![Donate](https://img.shields.io/badge/💛_DonationAlerts-Any_amount-FF5E3A?style=for-the-badge)](https://www.donationalerts.com/r/ivan_yurievich)

**👉 https://www.donationalerts.com/r/ivan_yurievich**

</div>

### What your donation will fund:
- 🚀 **More time** on development
- 🐛 **Quick bug fixes**
- ✨ **New features** every month
- 📚 **Documentation** and support
- 🆕 **Exclusive** content for donors in Telegram

### All ways to support:

| Way | Link |
|-----|------|
| 💛 **Donate** | [donationalerts.com/r/ivan_yurievich](https://www.donationalerts.com/r/ivan_yurievich) |
| ⭐ **GitHub Star** | [Give a star](https://github.com/ivanstudiya-cpu/naiveproxy) |
| 📱 **Telegram channel** | [t.me/+XVSkY6blCTY0ZDU6](https://t.me/+XVSkY6blCTY0ZDU6) |
| 🌐 **Website** | [ivan-it.net](https://ivan-it.net) |
| 📢 **Share** | Tell your friends |

**Thanks for your support! Every donation motivates me to make the project even better 💛**

---

## 📜 Changelog

<details>
<summary><b>v4.2.3</b> — ALPN Fix ← CURRENT</summary>

- 🐛 Fixed `grep: binary file matches` — added `-a` flag
- ✅ Diagnostics correctly shows `ALPN: h2` on all servers

</details>

<details>
<summary><b>v4.2.2</b> — Security Audit (10 fixes)</summary>

**Critical:**
- 🔒 SSH `sshd_config.d/` + `ssh.socket` disable
- 🛡️ Protection against deleting last domain
- 📦 `apt update` before Fail2Ban
- 🔧 `PasswordAuthentication`/`PermitRootLogin` add if missing

**Security:**
- ⚡ Fail2Ban `iptables-multiport`
- 🌐 UFW `allow 80/tcp` (ACME)
- 🔑 Passwords 20 chars `[a-zA-Z0-9_-]`
- ♻️ Caddy `Restart=on-failure`

**Bot:**
- ✅ `/qr` curl fix
- ✅ `/adduser` validation
- ✅ `\r\n` cleanup
- ✅ `set +e` in handler

**Diagnostics:**
- 🐛 `pass=$((pass+1))` counters
- 🐛 ALPN `-servername`
- 🐛 Naive padding multi-criteria

</details>

<details>
<summary><b>v4.2.1</b> — Banner & Branding</summary>

- ✨ ASCII banner + Telegram channel + website
- 🐛 `DIM`, `BLUE` variables

</details>

<details>
<summary><b>v4.2.0</b> — DNS Ad Blocker</summary>

- ✨ unbound + ~1.5M domains
- ✨ DNS-over-TLS
- 🆕 `dns`, `dns-install`, `dns-update`

</details>

<details>
<summary><b>v4.1.0</b> — Security Audit</summary>

- 🔒 Bot validation + args sanitization

</details>

<details>
<summary><b>v4.0.0</b> — Telegram Bot</summary>

- ✨ 16 commands + multi-admin + QR image

</details>

<details>
<summary><b>v3.9.0</b> — Diagnostics</summary>

- ✨ 7 blocks, 18+ checks

</details>

<details>
<summary><b>v3.8.0</b> — Security & UX</summary>

- ✨ SSH key + QR + Fail2Ban 3 levels

</details>

<details>
<summary><b>v3.7.0</b> — Critical Caddyfile Fix</summary>

- 🔴 `:443, domain` instead of `domain:443`

</details>

---

## 📄 License

GPL-3.0 © **Ivan Yurievich (Иван Юрьевич)**  
Commercial use without author permission is prohibited.  
📞 Contact: [Telegram](https://t.me/+XVSkY6blCTY0ZDU6) · [ivan-it.net](https://ivan-it.net)

---

<div align="center">

### 💛 Liked it? Support the project!

[![Donate](https://img.shields.io/badge/💛_Support-DonationAlerts-FF5E3A?style=for-the-badge)](https://www.donationalerts.com/r/ivan_yurievich)
[![Star](https://img.shields.io/github/stars/ivanstudiya-cpu/naiveproxy?style=for-the-badge&color=D4A017)](https://github.com/ivanstudiya-cpu/naiveproxy/stargazers)

📱 [Telegram](https://t.me/+XVSkY6blCTY0ZDU6) · 🌐 [ivan-it.net](https://ivan-it.net) · 💻 [GitHub](https://github.com/ivanstudiya-cpu/naiveproxy)

*NaiveProxy Manager · by Ivan Yurievich · Updates once a month*

</div>
