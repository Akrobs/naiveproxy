#!/usr/bin/env bash
set -Eeuo pipefail

LABEL="${1:-$(hostname)}"
PROFILE="${2:-standard}"
MASTER_IP="${3:-}"
HYSTERIA_TAG="app%2Fv2.10.0"
HYSTERIA_ASSET="hysteria-linux-amd64"
HYSTERIA_SHA256="04f7804159ef1d798de12a817d73aab4b9040ebe45fc62e223000c5c59e987fe"
HYSTERIA_STAGED="/tmp/yurich-hysteria-v2.10.0-amd64"

case "$PROFILE" in
    standard) XRAY_XHTTP_VALUE=0; LOCK_EDGE_SSH=1 ;;
    xhttp-only) XRAY_XHTTP_VALUE=1; LOCK_EDGE_SSH=1 ;;
    control) XRAY_XHTTP_VALUE=0; LOCK_EDGE_SSH=0 ;;
    *) echo "Unknown profile: $PROFILE" >&2; exit 2 ;;
esac

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
for command_name in apt-get curl sha256sum python3 systemctl timeout tar awk grep install \
    jq ss sshd ufw caddy haproxy xray unbound-checkconf augenrules sysctl flock; do
    command -v "$command_name" >/dev/null || { echo "Missing: $command_name" >&2; exit 1; }
done

if (( LOCK_EDGE_SSH )); then
    [[ -n "$MASTER_IP" ]] || {
        echo "Usage: $0 <label> <standard|xhttp-only> <master-ip>" >&2
        exit 2
    }
    python3 - "$MASTER_IP" <<'PY'
import ipaddress
import sys

try:
    ipaddress.ip_address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f"Invalid master IP: {exc}")
PY
fi

install -d -m 0755 /run/lock
exec 9>/run/lock/yurich-security-rollout.lock
flock -n 9 || { echo "Another security rollout is already running" >&2; exit 1; }

umask 077
timestamp=$(date +%Y%m%d_%H%M%S)
backup_dir="/etc/naiveproxy/backups/security-rollout-${timestamp}"
mkdir -p "$backup_dir"

backup_file() {
    local source_path="$1" target_name="$2"
    [[ ! -e "$source_path" ]] || cp -a "$source_path" "$backup_dir/$target_name"
}

restore_file_or_remove() {
    local target_path="$1" backup_path="$2"
    rm -f -- "$target_path"
    [[ ! -e "$backup_path" ]] || cp -a -- "$backup_path" "$target_path"
}

backup_file /etc/naiveproxy/naive.conf naive.conf.before
backup_file /etc/naiveproxy/xray-compat-users.conf xray-compat-users.before
backup_file /etc/caddy/Caddyfile Caddyfile.before
backup_file /etc/xray/config.json xray-config.before
backup_file /etc/haproxy/haproxy.cfg haproxy.cfg.before
backup_file /etc/systemd/system/caddy.service caddy.service.before
backup_file /etc/systemd/system/xray.service xray.service.before
backup_file /etc/systemd/system/haproxy.service haproxy.service.before
backup_file /usr/local/bin/hysteria hysteria.before
tar -C /etc/systemd/system -czf "$backup_dir/systemd-dropins.before.tar.gz" \
    caddy.service.d xray.service.d hysteria.service.d haproxy.service.d unbound.service.d 2>/dev/null || true
ufw status numbered > "$backup_dir/ufw.before.txt" 2>&1 || true

echo "[$LABEL 1/7] packages"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt-get update -qq
apt-get upgrade -y -qq

echo "[$LABEL 2/7] hysteria"
hysteria_url="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_TAG}"
temp_dir=$(mktemp -d)
trap 'rm -rf "${temp_dir:-}"' EXIT
if [[ -f "$HYSTERIA_STAGED" ]]; then
    cp "$HYSTERIA_STAGED" "$temp_dir/hysteria"
else
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 \
        "$hysteria_url/$HYSTERIA_ASSET" -o "$temp_dir/hysteria"
fi
actual_hash=$(sha256sum "$temp_dir/hysteria" | awk '{print $1}')
[[ "$HYSTERIA_SHA256" == "$actual_hash" ]]
chmod 755 "$temp_dir/hysteria"
"$temp_dir/hysteria" version 2>&1 | grep -q 'Version:.*v2.10.0'
install -m 755 "$temp_dir/hysteria" /usr/local/bin/hysteria.next
mv -f /usr/local/bin/hysteria.next /usr/local/bin/hysteria
if ! systemctl restart hysteria \
    || ! timeout 20s bash -c 'until systemctl is-active --quiet hysteria; do sleep 1; done'; then
    restore_file_or_remove /usr/local/bin/hysteria "$backup_dir/hysteria.before"
    if [[ -e "$backup_dir/hysteria.before" ]]; then
        systemctl restart hysteria || true
    else
        systemctl stop hysteria || true
    fi
    echo "HYSTERIA_ROLLBACK backup=$backup_dir" >&2
    exit 1
fi

echo "[$LABEL 3/7] auditd"
apt-get install -y -qq auditd audispd-plugins
install -d -m 0750 /etc/audit/rules.d
cat > /etc/audit/rules.d/50-yurich-config.rules <<'EOF'
-w /etc/naiveproxy/naive.conf -p wa -k yurich_config
-w /etc/naiveproxy/users.conf -p wa -k yurich_users
-w /etc/naiveproxy/hysteria.yaml -p wa -k yurich_hysteria
-w /etc/xray/config.json -p wa -k yurich_xray
-w /etc/caddy/Caddyfile -p wa -k yurich_caddy
-w /etc/haproxy/haproxy.cfg -p wa -k yurich_haproxy
-w /etc/unbound/unbound.conf.d/ -p wa -k yurich_dns
-w /etc/ssh/sshd_config -p wa -k yurich_ssh
-w /etc/ssh/sshd_config.d/ -p wa -k yurich_ssh
EOF
chmod 0640 /etc/audit/rules.d/50-yurich-config.rules
augenrules --load >/dev/null
systemctl enable auditd >/dev/null
systemctl start auditd
systemctl is-active --quiet auditd

echo "[$LABEL 4/7] sysctl"
cat > /etc/sysctl.d/99-yurich-network-hardening.conf <<'EOF'
# Keep forwarding enabled for VPN and WARP routing.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
chmod 0644 /etc/sysctl.d/99-yurich-network-hardening.conf
sysctl --system >/dev/null
[[ $(sysctl -n net.ipv4.conf.all.send_redirects) == 0 ]]
[[ $(sysctl -n net.ipv4.conf.default.accept_source_route) == 0 ]]
[[ $(sysctl -n net.ipv4.conf.all.log_martians) == 1 ]]

echo "[$LABEL 5/7] systemd"
common_hardening='[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true'
for service_name in caddy xray hysteria haproxy unbound; do
    dropin_dir="/etc/systemd/system/${service_name}.service.d"
    dropin_path="${dropin_dir}/90-yurich-hardening.conf"
    backup_file "$dropin_path" "${service_name}.hardening.before"
    install -d -m 0755 "$dropin_dir"
    case "$service_name" in
        caddy) protect_home=false ;;
        hysteria) protect_home=read-only ;;
        *) protect_home=true ;;
    esac
    printf '%s\nProtectHome=%s\n' "$common_hardening" "$protect_home" > "$dropin_path"
    chmod 0644 "$dropin_path"
    systemctl daemon-reload
    if ! systemctl restart "$service_name" \
        || ! timeout 20s bash -c "until systemctl is-active --quiet '$service_name'; do sleep 1; done"; then
        restore_file_or_remove "$dropin_path" "$backup_dir/${service_name}.hardening.before"
        systemctl daemon-reload
        systemctl restart "$service_name" || true
        echo "SYSTEMD_ROLLBACK service=$service_name backup=$backup_dir" >&2
        exit 1
    fi
done

echo "[$LABEL 6/7] protocol configs"
XRAY_XHTTP_VALUE="$XRAY_XHTTP_VALUE" python3 - <<'PY'
import os
from pathlib import Path

path = Path('/etc/naiveproxy/naive.conf')
updates = {
    'XRAY_XHTTP_ENABLED': os.environ['XRAY_XHTTP_VALUE'],
    'XRAY_MOBILE_ALT_ENABLED': '0',
}
lines = path.read_text().splitlines()
result = []
seen = set()
for line in lines:
    key = line.split('=', 1)[0] if '=' in line else ''
    if key in updates:
        result.append(f'{key}={updates[key]}')
        seen.add(key)
    else:
        result.append(line)
for key, value in updates.items():
    if key not in seen:
        result.append(f'{key}={value}')
path.write_text('\n'.join(result) + '\n')
PY
chmod 600 /etc/naiveproxy/naive.conf
: > /etc/naiveproxy/xray-compat-users.conf
chmod 600 /etc/naiveproxy/xray-compat-users.conf

validate_protocol_configs() {
    if [[ "$PROFILE" == xhttp-only ]]; then
        jq -e '[.inbounds[].tag] == ["vless-reality", "vless-xhttp"]' /etc/xray/config.json >/dev/null \
            && grep -qE '@xhttp|127\.0\.0\.1:8448' /etc/caddy/Caddyfile \
            || return 1
    else
        jq -e '[.inbounds[].tag] == ["vless-reality"]' /etc/xray/config.json >/dev/null \
            && ! grep -qE '@xhttp|127\.0\.0\.1:8448' /etc/caddy/Caddyfile \
            || return 1
    fi
    ! grep -qE 'xray_reality_mobile_alt|www\.cloudflare\.com|8445' /etc/haproxy/haproxy.cfg \
        && ss -ltnH | awk '$4 == "127.0.0.1:7443" { found=1 } END { exit found ? 0 : 1 }'
}

if ! bash /usr/local/bin/yurich-panel.sh safe-apply \
    || ! bash /usr/local/bin/yurich-panel.sh xray-rebuild \
    || ! validate_protocol_configs; then
    restore_file_or_remove /etc/naiveproxy/naive.conf "$backup_dir/naive.conf.before"
    restore_file_or_remove /etc/naiveproxy/xray-compat-users.conf "$backup_dir/xray-compat-users.before"
    restore_file_or_remove /etc/caddy/Caddyfile "$backup_dir/Caddyfile.before"
    restore_file_or_remove /etc/xray/config.json "$backup_dir/xray-config.before"
    restore_file_or_remove /etc/haproxy/haproxy.cfg "$backup_dir/haproxy.cfg.before"
    restore_file_or_remove /etc/systemd/system/caddy.service "$backup_dir/caddy.service.before"
    restore_file_or_remove /etc/systemd/system/xray.service "$backup_dir/xray.service.before"
    restore_file_or_remove /etc/systemd/system/haproxy.service "$backup_dir/haproxy.service.before"
    systemctl daemon-reload
    caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true
    xray run -test -config /etc/xray/config.json >/dev/null 2>&1 || true
    haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1 || true
    systemctl restart caddy xray haproxy >/dev/null 2>&1 || true
    echo "PROTOCOL_CONFIG_ROLLBACK backup=$backup_dir" >&2
    exit 1
fi

echo "[$LABEL 7/7] firewall and verification"
ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
if (( LOCK_EDGE_SSH )); then
    if ! ufw status | grep -Eq "^${ssh_port}/tcp[[:space:]]+ALLOW[[:space:]]+${MASTER_IP//./\\.}"; then
        ufw allow from "$MASTER_IP" to any port "$ssh_port" proto tcp comment 'Yurich master SSH' >/dev/null
    fi
    echo "SSH master allow rule verified; broad SSH rules are preserved for a two-session manual cutover."
fi
hysteria_port=$(awk -F= '$1 == "HYSTERIA_PORT" {gsub(/[^0-9]/, "", $2); print $2; exit}' \
    /etc/naiveproxy/naive.conf)
hysteria_port=${hysteria_port:-8443}
if [[ "$hysteria_port" != 443 ]]; then
    ufw --force delete allow 443/udp >/dev/null 2>&1 || true
fi

for service_name in caddy xray hysteria haproxy unbound fail2ban crowdsec auditd apparmor unattended-upgrades; do
    timeout 30s bash -c "until systemctl is-active --quiet '$service_name'; do sleep 1; done"
done
caddy validate --config /etc/caddy/Caddyfile >/dev/null
haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
xray run -test -config /etc/xray/config.json >/dev/null
unbound-checkconf >/dev/null
hysteria version 2>&1 | grep -q 'Version:.*v2.10.0'
[[ $(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l) -eq 0 ]]

test_user="${YURICH_ROLLOUT_TEST_USER:-}"
if [[ -z "$test_user" && -f /etc/naiveproxy/users.conf ]]; then
    test_user=$(awk -F: 'NF >= 2 && $1 != "" {print $1; exit}' /etc/naiveproxy/users.conf)
fi
[[ -n "$test_user" ]] || { echo "No subscription user available for data-plane verification" >&2; exit 1; }
bash /usr/local/bin/yurich-panel.sh health
bash /usr/local/bin/yurich-panel.sh protocol-validate
bash /usr/local/bin/yurich-panel.sh protocol-benchmark "$test_user" 3

echo "ROLLOUT_OK label=$LABEL profile=$PROFILE backup=$backup_dir hysteria=v2.10.0 ssh_port=$ssh_port test_user=$test_user"
