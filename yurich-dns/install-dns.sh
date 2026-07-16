#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/unbound/unbound.conf.d/yurich-dns.conf"
LEGACY_CONF="/etc/unbound/unbound.conf.d/aurum-vpn.conf"
LEGACY_NAIVE_CONF="/etc/unbound/unbound.conf.d/naiveproxy-dns.conf"
LEGACY_BLOCKLIST="/etc/unbound/blocklist.conf"
LEGACY_WHITELIST="/etc/unbound/whitelist.txt"
ENV_DIR="/etc/yurich-dns"
ENV_FILE="${ENV_DIR}/yurich-dns.env"
LEGACY_ENV_FILE="/etc/aurum-dns/aurum-dns.env"
NO_STUB="/etc/systemd/resolved.conf.d/no-stub.conf"
GATEWAY_SERVICE="/etc/systemd/system/yurich-dns-gateway.service"
LEGACY_GATEWAY_SERVICE="/etc/systemd/system/aurum-dns-gateway.service"
DEFAULT_GATEWAY="10.0.0.1"
DEFAULT_CIDRS="10.0.0.0/24"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_DIR=""
ROLLBACK_ARMED=0
ROLLBACK_CIDRS=""
ROLLBACK_PATHS=(
    "$CONF"
    "$LEGACY_CONF"
    "$LEGACY_NAIVE_CONF"
    "$LEGACY_BLOCKLIST"
    "$LEGACY_WHITELIST"
    "$ENV_FILE"
    "$LEGACY_ENV_FILE"
    "$NO_STUB"
    "$GATEWAY_SERVICE"
    "$LEGACY_GATEWAY_SERVICE"
    /usr/local/bin/yurich-dns-status
    /usr/local/bin/yurich-dns-test
    /usr/local/bin/yurich-dns-restart
    /usr/local/bin/aurum-dns-status
    /usr/local/bin/aurum-dns-test
    /usr/local/bin/aurum-dns-restart
)

log() { printf '[i] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERR] %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash install-dns.sh"
}

backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    cp -a "$file" "${file}.bak.$(date '+%Y%m%d-%H%M%S')"
}

snapshot_service_state() {
    local unit="$1" enabled="no" active="no"
    systemctl is-enabled --quiet "$unit" 2>/dev/null && enabled="yes"
    systemctl is-active --quiet "$unit" 2>/dev/null && active="yes"
    printf '%s|%s|%s\n' "$unit" "$enabled" "$active" >> "$ROLLBACK_DIR/services.state"
}

snapshot_install_state() {
    local path rel
    ROLLBACK_DIR=$(mktemp -d /tmp/yurich-dns-rollback.XXXXXX)
    chmod 700 "$ROLLBACK_DIR"
    mkdir -p "$ROLLBACK_DIR/files"
    : > "$ROLLBACK_DIR/present.list"
    : > "$ROLLBACK_DIR/services.state"
    for path in "${ROLLBACK_PATHS[@]}"; do
        if [[ -e "$path" || -L "$path" ]]; then
            rel="${path#/}"
            mkdir -p "$ROLLBACK_DIR/files/$(dirname "$rel")"
            cp -a -- "$path" "$ROLLBACK_DIR/files/$rel"
            printf '%s\n' "$path" >> "$ROLLBACK_DIR/present.list"
        fi
    done
    snapshot_service_state unbound.service
    snapshot_service_state systemd-resolved.service
    snapshot_service_state "$(basename "$GATEWAY_SERVICE")"
    snapshot_service_state "$(basename "$LEGACY_GATEWAY_SERVICE")"
    ROLLBACK_ARMED=1
}

restore_service_state() {
    local unit="$1" enabled="$2" active="$3"
    if [[ "$enabled" == "yes" ]]; then
        systemctl enable "$unit" >/dev/null 2>&1 || true
    else
        systemctl disable "$unit" >/dev/null 2>&1 || true
    fi
    if [[ "$active" == "yes" ]]; then
        systemctl restart "$unit" >/dev/null 2>&1 || systemctl start "$unit" >/dev/null 2>&1 || true
    else
        systemctl stop "$unit" >/dev/null 2>&1 || true
    fi
}

rollback_install() {
    local path rel unit enabled active cidr
    local -a cidr_list
    [[ "$ROLLBACK_ARMED" -eq 1 && -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" ]] || return 0
    warn "Installation failed; restoring previous DNS configuration"
    set +e
    if command -v ufw >/dev/null 2>&1 && [[ -n "$ROLLBACK_CIDRS" ]]; then
        IFS=',' read -r -a cidr_list <<< "$ROLLBACK_CIDRS"
        for cidr in "${cidr_list[@]}"; do
            [[ -z "$cidr" ]] && continue
            ufw delete allow from "$cidr" to any port 53 proto udp >/dev/null 2>&1 || true
            ufw delete allow from "$cidr" to any port 53 proto tcp >/dev/null 2>&1 || true
        done
    fi
    for path in "${ROLLBACK_PATHS[@]}"; do
        rm -rf -- "$path"
        if grep -Fxq -- "$path" "$ROLLBACK_DIR/present.list"; then
            rel="${path#/}"
            mkdir -p "$(dirname "$path")"
            cp -a -- "$ROLLBACK_DIR/files/$rel" "$path"
        fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    while IFS='|' read -r unit enabled active; do
        [[ -n "$unit" ]] && restore_service_state "$unit" "$enabled" "$active"
    done < "$ROLLBACK_DIR/services.state"
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
    ROLLBACK_ARMED=0
}

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    if [[ "$ROLLBACK_ARMED" -eq 1 ]]; then
        rollback_install
    fi
    [[ -n "$ROLLBACK_DIR" && "$ROLLBACK_DIR" == /tmp/yurich-dns-rollback.* ]] && rm -rf -- "$ROLLBACK_DIR"
    exit "$rc"
}

is_ipv4() {
    local ip="$1" part
    local -a parts
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a parts <<< "$ip"
    for part in "${parts[@]}"; do
        [[ "$part" =~ ^[0-9]{1,3}$ ]] || return 1
        [[ "$part" == "0" || "$part" != 0* ]] || return 1
        (( 10#$part <= 255 )) || return 1
    done
}

is_cidr4() {
    local cidr="$1" ip mask
    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || return 1
    ip="${cidr%/*}"
    mask="${cidr#*/}"
    is_ipv4 "$ip" && [[ "$mask" -ge 0 && "$mask" -le 32 ]]
}

is_private_vpn_ipv4() {
    local ip="$1" a b
    is_ipv4 "$ip" || return 1
    IFS='.' read -r a b _ _ <<< "$ip"
    case "$a" in
        10) return 0 ;;
        172) (( 10#$b >= 16 && 10#$b <= 31 )) ;;
        192) (( 10#$b == 168 )) ;;
        100) (( 10#$b >= 64 && 10#$b <= 127 )) ;;
        127) [[ "$ip" == "127.0.0.1" ]] ;;
        *) return 1 ;;
    esac
}

is_allowed_vpn_cidr4() {
    local cidr="$1" ip mask a b
    is_cidr4 "$cidr" || return 1
    ip="${cidr%/*}"
    mask="${cidr#*/}"
    IFS='.' read -r a b _ _ <<< "$ip"
    case "$a" in
        10) (( mask >= 8 )) ;;
        172) (( 10#$b >= 16 && 10#$b <= 31 && mask >= 12 )) ;;
        192) (( 10#$b == 168 && mask >= 16 )) ;;
        100) (( 10#$b >= 64 && 10#$b <= 127 && mask >= 10 )) ;;
        *) [[ "${YURICH_DNS_ALLOW_PUBLIC_CIDRS:-0}" == "1" && "$mask" -ge 24 ]] ;;
    esac
}

normalize_cidrs() {
    local raw="$1" item out="" count=0
    local -a items
    raw="${raw// /}"
    IFS=',' read -r -a items <<< "$raw"
    for item in "${items[@]}"; do
        [[ -z "$item" ]] && continue
        is_cidr4 "$item" || die "Invalid CIDR: $item"
        is_allowed_vpn_cidr4 "$item" || die "Unsafe VPN CIDR: $item (use private/CGNAT ranges; public access requires YURICH_DNS_ALLOW_PUBLIC_CIDRS=1 and /24 or narrower)"
        count=$((count + 1))
        (( count <= 32 )) || die "Too many VPN CIDRs (maximum: 32)"
        out="${out},${item}"
    done
    [[ -n "$out" ]] || die "At least one VPN CIDR is required"
    printf '%s\n' "${out#,}"
}

server_ipv4s() {
    ip -o -4 addr show scope global up 2>/dev/null \
        | awk '{split($4, a, "/"); if (a[1] != "" && a[1] !~ /^127\./ && a[1] !~ /^169\.254\./) print a[1]}' \
        | sort -u
}

detect_gateway() {
    server_ipv4s | awk '/^10\./ || /^192\.168\./ || /^172\.(1[6-9]|2[0-9]|3[0-1])\./ {print; exit}'
}

ip_on_server() {
    local gateway="$1"
    [[ "$gateway" == "127.0.0.1" ]] && return 0
    server_ipv4s | grep -Fxq "$gateway"
}

ensure_managed_gateway() {
    local gateway="$1" ip_bin
    is_ipv4 "$gateway" || die "Invalid gateway IP: $gateway"
    if ! is_private_vpn_ipv4 "$gateway" && [[ "${YURICH_DNS_ALLOW_PUBLIC_GATEWAY:-0}" != "1" ]]; then
        die "Public DNS gateway is forbidden without YURICH_DNS_ALLOW_PUBLIC_GATEWAY=1: $gateway"
    fi
    ip_bin=$(command -v ip || echo "/usr/sbin/ip")
    cat > "$GATEWAY_SERVICE" <<EOF
[Unit]
Description=DNS (Unbound) local gateway IP (${gateway})
Before=unbound.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '${ip_bin} addr replace ${gateway}/32 dev lo && ${ip_bin} link set lo up'
ExecStop=/bin/sh -c '${ip_bin} addr del ${gateway}/32 dev lo 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl disable --now "$(basename "$LEGACY_GATEWAY_SERVICE")" >/dev/null 2>&1 || true
    rm -f "$LEGACY_GATEWAY_SERVICE" 2>/dev/null || true
    systemctl enable --now "$(basename "$GATEWAY_SERVICE")" >/dev/null 2>&1
}

prepare_gateway() {
    local gateway="$1" ans
    if ip_on_server "$gateway"; then
        return 0
    fi
    warn "Gateway IP $gateway is not assigned to this server."
    if [[ -t 0 ]]; then
        printf 'Create local gateway %s/32 on lo automatically? [Y/n]: ' "$gateway"
        read -r ans
    else
        ans="y"
    fi
    [[ "${ans,,}" == "n" ]] && die "Gateway is required for VPN DNS"
    ensure_managed_gateway "$gateway"
}

port53_listeners() {
    ss -H -lntup 2>/dev/null | awk '$5 ~ /:53$/ || $5 ~ /:53%/ {print}'
}

disable_resolved_stub_if_needed() {
    if ! systemctl cat systemd-resolved.service >/dev/null 2>&1; then
        return 0
    fi

    if port53_listeners | grep -qi 'systemd-resolve'; then
        log "systemd-resolved DNS stub uses port 53, disabling DNSStubListener"
        mkdir -p "$(dirname "$NO_STUB")"
        backup_file "$NO_STUB"
        cat > "$NO_STUB" <<'EOF'
[Resolve]
DNSStubListener=no
EOF
        systemctl restart systemd-resolved || true
        sleep 1
    fi
}

check_port53() {
    local conflicts
    conflicts=$(port53_listeners | grep -Ev 'unbound|systemd-resolve|systemd-resolved' || true)
    if [[ -n "$conflicts" ]]; then
        printf '%s\n' "$conflicts"
        die "Port 53 is busy by another service. Stop it manually, then rerun."
    fi
}

root_controlled_env_file() {
    local env_file="$1" candidate owner_uid mode
    [[ -f "$env_file" && ! -L "$env_file" ]] || return 1
    for candidate in "$env_file" "$(dirname "$env_file")"; do
        owner_uid=$(stat -c '%u' "$candidate" 2>/dev/null || echo -1)
        mode=$(stat -c '%a' "$candidate" 2>/dev/null || echo invalid)
        [[ "$owner_uid" == "0" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 022) == 0 )) || return 1
    done
}

parse_dns_env_value() {
    local raw="$1"
    if [[ "$raw" == \'*\' && ${#raw} -ge 2 ]]; then
        raw="${raw:1:${#raw}-2}"
    elif [[ "$raw" == \"*\" && ${#raw} -ge 2 ]]; then
        raw="${raw:1:${#raw}-2}"
    elif [[ "$raw" == *\'* || "$raw" == *\"* ]]; then
        return 1
    fi
    printf '%s\n' "$raw"
}

load_legacy_env_if_safe() {
    [[ -f "$ENV_FILE" || -f "$LEGACY_ENV_FILE" ]] || return 0
    local env_file="$ENV_FILE" line key raw value gateway="" cidrs="" normalized_cidrs
    local seen_gateway=0 seen_cidrs=0
    [[ -f "$env_file" ]] || env_file="$LEGACY_ENV_FILE"
    root_controlled_env_file "$env_file" || { warn "Skip unsafe DNS env file: $env_file"; return 0; }

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ ^(YURICH_DNS_GATEWAY|YURICH_DNS_CIDRS)=(.*)$ ]] || { warn "Skip invalid DNS env syntax: $env_file"; return 0; }
        key="${BASH_REMATCH[1]}"
        raw="${BASH_REMATCH[2]}"
        value=$(parse_dns_env_value "$raw") || { warn "Skip unsafe DNS env value: $key"; return 0; }
        case "$key" in
            YURICH_DNS_GATEWAY)
                (( seen_gateway == 0 )) || { warn "Duplicate DNS env key: $key"; return 0; }
                [[ -z "$value" ]] || is_ipv4 "$value" || { warn "Invalid DNS gateway in $env_file"; return 0; }
                gateway="$value"; seen_gateway=1
                ;;
            YURICH_DNS_CIDRS)
                (( seen_cidrs == 0 )) || { warn "Duplicate DNS env key: $key"; return 0; }
                normalized_cidrs=$(normalize_cidrs "$value") || { warn "Invalid DNS CIDRs in $env_file"; return 0; }
                cidrs="$normalized_cidrs"; seen_cidrs=1
                ;;
        esac
    done < "$env_file"

    (( seen_gateway == 0 )) || YURICH_DNS_GATEWAY="$gateway"
    (( seen_cidrs == 0 )) || YURICH_DNS_CIDRS="$cidrs"
}

cleanup_legacy_files() {
    local legacy_path
    for legacy_path in "$LEGACY_CONF" "$LEGACY_NAIVE_CONF" "$LEGACY_BLOCKLIST" "$LEGACY_WHITELIST"; do
        if [[ -f "$legacy_path" ]]; then
            backup_file "$legacy_path"
            rm -f "$legacy_path"
        fi
    done
    if [[ -f "$LEGACY_GATEWAY_SERVICE" ]]; then
        systemctl disable --now "$(basename "$LEGACY_GATEWAY_SERVICE")" >/dev/null 2>&1 || true
        rm -f "$LEGACY_GATEWAY_SERVICE"
        systemctl daemon-reload
    fi
}

write_env() {
    local gateway="$1" cidrs="$2" tmp
    install -d -m 700 "$ENV_DIR"
    tmp=$(mktemp "${ENV_DIR}/.yurich-dns.env.XXXXXX")
    {
        printf 'YURICH_DNS_GATEWAY=%q\n' "$gateway"
        printf 'YURICH_DNS_CIDRS=%q\n' "$cidrs"
    } > "$tmp"
    install -m 600 "$tmp" "$ENV_FILE"
    rm -f "$tmp"
}

write_unbound_config() {
    local gateway="$1" cidrs="$2" cidr candidate
    local -a cidr_list
    mkdir -p "$(dirname "$CONF")" /var/lib/unbound
    backup_file "$CONF"
    candidate=$(mktemp "$(dirname "$CONF")/.yurich-dns.conf.XXXXXX")

    cat > "$candidate" <<EOF
server:
    # DNS (Unbound): private recursive resolver for VPN clients.
    # Security rule: never bind 0.0.0.0 here.
    interface: 127.0.0.1
EOF

    if [[ -n "$gateway" ]]; then
        printf '    interface: %s\n' "$gateway" >> "$candidate"
    fi

    cat >> "$candidate" <<'EOF'
    port: 53

    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
EOF

    IFS=',' read -r -a cidr_list <<< "$cidrs"
    for cidr in "${cidr_list[@]}"; do
        [[ -n "$cidr" ]] && printf '    access-control: %s allow\n' "$cidr" >> "$candidate"
    done

    cat >> "$candidate" <<'EOF'

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    qname-minimisation: yes
    aggressive-nsec: yes
    val-clean-additional: yes

    # DNSSEC trust anchor is managed by Ubuntu's Unbound package.
    # Do not duplicate auto-trust-anchor-file here.
    root-hints: "/usr/share/dns/root.hints"

    prefetch: yes
    prefetch-key: yes
    cache-min-ttl: 300
    cache-max-ttl: 86400
    rrset-cache-size: 128m
    msg-cache-size: 64m
    so-rcvbuf: 256k
    ip-ratelimit: 200

    log-queries: no
    statistics-interval: 0
    verbosity: 1
EOF
    install -m 644 "$candidate" "$CONF"
    rm -f "$candidate"
}

apply_ufw() {
    local cidrs="$1" cidr
    local -a cidr_list
    command -v ufw >/dev/null 2>&1 || return 0
    IFS=',' read -r -a cidr_list <<< "$cidrs"
    for cidr in "${cidr_list[@]}"; do
        [[ -z "$cidr" ]] && continue
        ufw allow from "$cidr" to any port 53 proto udp comment "DNS (Unbound) VPN" >/dev/null 2>&1 || true
        ufw allow from "$cidr" to any port 53 proto tcp comment "DNS (Unbound) VPN" >/dev/null 2>&1 || true
    done
}

install_commands() {
    install -m 755 "${SCRIPT_DIR}/scripts/yurich-dns-status" /usr/local/bin/yurich-dns-status
    install -m 755 "${SCRIPT_DIR}/scripts/yurich-dns-test" /usr/local/bin/yurich-dns-test
    install -m 755 "${SCRIPT_DIR}/scripts/yurich-dns-restart" /usr/local/bin/yurich-dns-restart
    ln -sf /usr/local/bin/yurich-dns-status /usr/local/bin/aurum-dns-status 2>/dev/null || true
    ln -sf /usr/local/bin/yurich-dns-test /usr/local/bin/aurum-dns-test 2>/dev/null || true
    ln -sf /usr/local/bin/yurich-dns-restart /usr/local/bin/aurum-dns-restart 2>/dev/null || true
}

run_tests() {
    local valid_status invalid_status
    unbound-checkconf
    systemctl enable unbound --quiet
    systemctl reset-failed unbound 2>/dev/null || true
    systemctl restart unbound
    systemctl status unbound --no-pager || true
    dig @127.0.0.1 google.com +time=3 +tries=1
    dig @127.0.0.1 cloudflare.com +time=3 +tries=1
    valid_status=$(dig @127.0.0.1 sigok.verteiltesysteme.net A +time=4 +tries=2 2>/dev/null \
        | awk -F'status: ' '/status:/ {split($2,a,","); print a[1]; exit}' || true)
    invalid_status=$(dig @127.0.0.1 dnssec-failed.org A +time=4 +tries=2 2>/dev/null \
        | awk -F'status: ' '/status:/ {split($2,a,","); print a[1]; exit}' || true)
    [[ "$valid_status" == "NOERROR" ]] || die "DNSSEC valid-domain test failed: ${valid_status:-no response}"
    [[ "$invalid_status" == "SERVFAIL" ]] || die "DNSSEC invalid-domain test failed: ${invalid_status:-no response}"
    ok "DNSSEC validation passed (NOERROR/SERVFAIL)"
}

main() {
    require_root
    snapshot_install_state
    trap cleanup_on_exit EXIT
    load_legacy_env_if_safe
    apt-get update -qq
    apt-get install -y -q unbound unbound-anchor dnsutils dns-root-data curl ca-certificates

    local gateway="${YURICH_DNS_GATEWAY:-}" cidrs="${YURICH_DNS_CIDRS:-}"
    local detected
    detected=$(detect_gateway || true)

    if [[ -t 0 && -z "$gateway" ]]; then
        printf 'VPN gateway IP [%s, 0 = local only]: ' "${detected:-$DEFAULT_GATEWAY}"
        read -r gateway
        gateway="${gateway:-${detected:-$DEFAULT_GATEWAY}}"
    fi

    if [[ "$gateway" =~ ^(0|local|none)$ ]]; then
        gateway=""
    elif [[ -n "$gateway" ]]; then
        is_ipv4 "$gateway" || die "Invalid gateway IP: $gateway"
        if ! is_private_vpn_ipv4 "$gateway" && [[ "${YURICH_DNS_ALLOW_PUBLIC_GATEWAY:-0}" != "1" ]]; then
            die "Public DNS gateway is forbidden without YURICH_DNS_ALLOW_PUBLIC_GATEWAY=1: $gateway"
        fi
        prepare_gateway "$gateway"
    fi

    if [[ -t 0 && -z "$cidrs" ]]; then
        printf 'VPN CIDR [%s]: ' "$DEFAULT_CIDRS"
        read -r cidrs
    fi
    cidrs=$(normalize_cidrs "${cidrs:-$DEFAULT_CIDRS}")
    ROLLBACK_CIDRS="$cidrs"

    disable_resolved_stub_if_needed
    check_port53
    cleanup_legacy_files
    write_env "$gateway" "$cidrs"
    write_unbound_config "$gateway" "$cidrs"
    apply_ufw "$cidrs"
    install_commands
    run_tests
    ROLLBACK_ARMED=0
    ok "DNS (Unbound) installed. Commands: yurich-dns-status, yurich-dns-test, yurich-dns-restart"
}

main "$@"
