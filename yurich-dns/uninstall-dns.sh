#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/unbound/unbound.conf.d/yurich-dns.conf"
LEGACY_CONF="/etc/unbound/unbound.conf.d/aurum-vpn.conf"
LEGACY_NAIVE_CONF="/etc/unbound/unbound.conf.d/naiveproxy-dns.conf"
LEGACY_BLOCKLIST="/etc/unbound/blocklist.conf"
LEGACY_WHITELIST="/etc/unbound/whitelist.txt"
ENV_FILE="/etc/yurich-dns/yurich-dns.env"
LEGACY_ENV_FILE="/etc/aurum-dns/aurum-dns.env"
NO_STUB="/etc/systemd/resolved.conf.d/no-stub.conf"
GATEWAY_SERVICE="/etc/systemd/system/yurich-dns-gateway.service"
LEGACY_GATEWAY_SERVICE="/etc/systemd/system/aurum-dns-gateway.service"

log() { printf '[i] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERR] %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash uninstall-dns.sh"
}

backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    cp -a "$file" "${file}.bak.$(date '+%Y%m%d-%H%M%S')" || true
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
    local cidr="$1" ip
    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || return 1
    ip="${cidr%/*}"
    is_ipv4 "$ip"
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

load_env_if_safe() {
    local env_file="$ENV_FILE"
    [[ -f "$env_file" ]] || env_file="$LEGACY_ENV_FILE"
    [[ -f "$env_file" ]] || return 0
    root_controlled_env_file "$env_file" || { warn "Skip unsafe DNS env file: $env_file"; return 0; }

    local line key raw value cidr
    local cidrs="" seen_gateway=0 seen_cidrs=0
    local -a cidr_list
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ ^(YURICH_DNS_GATEWAY|YURICH_DNS_CIDRS)=(.*)$ ]] || { warn "Skip invalid DNS env syntax: $env_file"; return 0; }
        key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
        value=$(parse_dns_env_value "$raw") || { warn "Skip unsafe DNS env value: $key"; return 0; }
        case "$key" in
            YURICH_DNS_GATEWAY)
                (( seen_gateway == 0 )) || { warn "Duplicate DNS env key: $key"; return 0; }
                [[ -z "$value" ]] || is_ipv4 "$value" || { warn "Invalid DNS gateway in $env_file"; return 0; }
                seen_gateway=1
                ;;
            YURICH_DNS_CIDRS)
                (( seen_cidrs == 0 )) || { warn "Duplicate DNS env key: $key"; return 0; }
                IFS=',' read -r -a cidr_list <<< "$value"
                [[ "${#cidr_list[@]}" -gt 0 && "${#cidr_list[@]}" -le 32 ]] || { warn "Invalid DNS CIDR count in $env_file"; return 0; }
                for cidr in "${cidr_list[@]}"; do is_cidr4 "$cidr" || { warn "Invalid DNS CIDR in $env_file"; return 0; }; done
                cidrs="$value"; seen_cidrs=1
                ;;
        esac
    done < "$env_file"
    (( seen_cidrs == 0 )) || YURICH_DNS_CIDRS="$cidrs"
}

remove_ufw_rules() {
    local cidr cidrs="${YURICH_DNS_CIDRS:-10.0.0.0/24}"
    local -a cidr_list
    command -v ufw >/dev/null 2>&1 || return 0
    IFS=',' read -r -a cidr_list <<< "$cidrs"
    for cidr in "${cidr_list[@]}"; do
        [[ -z "$cidr" ]] && continue
        ufw delete allow from "$cidr" to any port 53 proto udp >/dev/null 2>&1 || true
        ufw delete allow from "$cidr" to any port 53 proto tcp >/dev/null 2>&1 || true
    done
}

main() {
    require_root

    load_env_if_safe

    systemctl stop unbound 2>/dev/null || true
    systemctl disable unbound 2>/dev/null || true
    systemctl disable --now "$(basename "$GATEWAY_SERVICE")" 2>/dev/null || true
    systemctl disable --now "$(basename "$LEGACY_GATEWAY_SERVICE")" 2>/dev/null || true
    rm -f "$GATEWAY_SERVICE" "$LEGACY_GATEWAY_SERVICE"
    remove_ufw_rules

    backup_file "$CONF"
    backup_file "$LEGACY_CONF"
    backup_file "$LEGACY_NAIVE_CONF"
    backup_file "$LEGACY_BLOCKLIST"
    backup_file "$LEGACY_WHITELIST"
    rm -f "$CONF" "$LEGACY_CONF" "$LEGACY_NAIVE_CONF" "$LEGACY_BLOCKLIST" "$LEGACY_WHITELIST"
    rm -f /usr/local/bin/yurich-dns-status /usr/local/bin/yurich-dns-test /usr/local/bin/yurich-dns-restart
    rm -f /usr/local/bin/aurum-dns-status /usr/local/bin/aurum-dns-test /usr/local/bin/aurum-dns-restart

    if [[ -f "$NO_STUB" ]]; then
        backup_file "$NO_STUB"
        rm -f "$NO_STUB"
        systemctl restart systemd-resolved 2>/dev/null || true
    fi

    rm -f "$ENV_FILE" "$LEGACY_ENV_FILE"
    rmdir /etc/yurich-dns 2>/dev/null || true
    rmdir /etc/aurum-dns 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    ok "DNS (Unbound) config removed. VPN config was not touched."
    if [[ -t 0 ]]; then
        printf 'Remove packages unbound/dnsutils too? [y/N]: '
        read -r ans
        if [[ "${ans,,}" == "y" ]]; then
            apt-get remove -y unbound dnsutils || true
            ok "Packages removed"
        else
            log "Packages kept"
        fi
    else
        log "Packages kept. Remove manually if needed: apt-get remove unbound dnsutils"
    fi
}

main "$@"
