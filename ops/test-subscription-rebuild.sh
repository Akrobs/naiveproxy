#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="${1:-$ROOT/yurich-panel.sh}"
[[ -f "$SCRIPT" ]] || { echo "Script not found: $SCRIPT" >&2; exit 1; }

# shellcheck source=/dev/null
source "$SCRIPT"

tmp=$(mktemp -d)
cleanup() {
    rm -rf -- "$tmp"
}
trap cleanup EXIT

# Auto mode is deliberately conservative, while an explicit value remains available
# for larger hosts and a value of 1 provides an immediate rollback to serial builds.
nproc() { printf '32\n'; }
SUBSCRIPTION_REBUILD_JOBS=0
[[ "$(subscription_rebuild_worker_count)" == "4" ]]
SUBSCRIPTION_REBUILD_JOBS=3
[[ "$(subscription_rebuild_worker_count)" == "3" ]]
SUBSCRIPTION_REBUILD_JOBS=99
[[ "$(subscription_rebuild_worker_count)" == "4" ]]
unset -f nproc

# HTTPS node sources are root-configured, strictly parsed and may only publish
# profiles whose endpoint matches the configured node domain.
subscription_http_node_sources_is_valid 'uk2|uk2.example.test|203.0.113.10'
! subscription_http_node_sources_is_valid 'uk2|uk2.example.test|not-an-ip'
! subscription_http_node_sources_is_valid 'bad name|uk2.example.test|203.0.113.10'
SUBS_DIR="$tmp/subscriptions"
mkdir -p "$SUBS_DIR"
printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' > "$SUBS_DIR/active.token"
SUBSCRIPTION_HTTP_NODE_SOURCES='uk2|uk2.example.test|203.0.113.10'
protocol_line_allowed() { [[ "$1" == naive+https://* ]]; }
curl() {
    local output=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    printf '%s\n' \
        'naive+https://active:secret@uk2.example.test:443#valid' \
        'naive+https://active:secret@evil.example.test:443#rejected' > "$output"
}
http_links=$(subscription_http_node_links_for_user active)
[[ "$(grep -c 'uk2[.]example[.]test' <<< "$http_links")" -eq 1 ]]
! grep -q 'evil[.]example[.]test' <<< "$http_links"
curl() { return 7; }
if subscription_http_node_links_for_user active >/dev/null; then
    echo "An unreachable HTTPS node must fail subscription generation" >&2
    exit 1
fi
curl() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) : > "$2"; return 0 ;;
            *) shift ;;
        esac
    done
}
if subscription_http_node_links_for_user active >/dev/null; then
    echo "An empty HTTPS node response must fail subscription generation" >&2
    exit 1
fi
unset -f curl protocol_line_allowed
unset SUBSCRIPTION_HTTP_NODE_SOURCES

# A failed edge SSH fallback must not publish a subscription without that node.
NODES_FILE="$tmp/nodes.conf"
printf 'edge|192.0.2.10|22|root|edge.example.test|edge|100|1\n' > "$NODES_FILE"
SUBSCRIPTION_XHTTP_MAIN_ENABLED=0
SUBSCRIPTION_NODE_LINK_CACHE_DIR=""
sleep() { :; }
nodes_ssh() {
    printf 'attempt\n' >> "$tmp/ssh-calls"
    return 255
}
if node_app_links_for_user active >/dev/null 2>&1; then
    echo "An unreachable edge node must fail subscription generation" >&2
    exit 1
fi
[[ "$(wc -l < "$tmp/ssh-calls")" -eq 3 ]]

: > "$tmp/ssh-calls"
nodes_ssh() {
    printf 'attempt\n' >> "$tmp/ssh-calls"
    if [[ "$(wc -l < "$tmp/ssh-calls")" -lt 2 ]]; then
        return 255
    fi
    printf 'vless://user@edge.example.test:443?security=reality&type=tcp#edge\n'
}
node_links=$(node_app_links_for_user active)
[[ "$node_links" == *'@edge.example.test:443'* ]]
[[ "$(wc -l < "$tmp/ssh-calls")" -eq 2 ]]

cache_dir="$tmp/node-cache"
mkdir -p "$cache_dir"
: > "$cache_dir/.ready.edge"
printf 'edge\tvless://user@edge.example.test:443?security=reality&type=tcp#edge\n' > "$cache_dir/active.links"
SUBSCRIPTION_NODE_LINK_CACHE_DIR="$cache_dir"
: > "$tmp/ssh-calls"
cached_links=$(node_app_links_for_user active)
[[ "$cached_links" == *'@edge.example.test:443'* ]]
[[ ! -s "$tmp/ssh-calls" ]]
unset -f nodes_ssh sleep
unset SUBSCRIPTION_NODE_LINK_CACHE_DIR SUBSCRIPTION_XHTTP_MAIN_ENABLED

# The machine-readable edge export must not rebuild HTML pages and must exclude
# expired users. Runtime dependencies are stubbed so this test never touches a host.
load_config() { :; }
load_users() { :; }
list_subscription_users() { printf 'active\nexpired\n'; }
subscription_user_exists() { [[ "$1" == "active" || "$1" == "expired" ]]; }
user_is_expired() { [[ "$1" == "expired" ]]; }
systemctl() { [[ "${1:-}" == "is-active" ]]; }
hysteria_uri_for_user() { printf 'hy2://%s:secret@example.test:443/?sni=example.test#old\n' "$1"; }
xray_reality_public_port() { printf '443\n'; }
get_xray_user_uuid() { printf '11111111-1111-4111-8111-111111111111\n'; }
pretty_profile_name() { printf '%s-%s\n' "$2" "$1"; }
uri_with_profile_name() { printf '%s#%s\n' "${1%%#*}" "$2"; }

DOMAIN=example.test
HYSTERIA_OBFS_PASSWORD=test-obfs
XRAY_REALITY_PUBLIC_KEY=test-public-key
XRAY_REALITY_SHORT_ID=1234567890abcdef
XRAY_REALITY_SERVER_NAME=github.com
export_output=$(cmd_node_subscription_export)
[[ "$(grep -c $'^active\t' <<< "$export_output")" -eq 2 ]]
! grep -q $'^expired\t' <<< "$export_output"
selected_output=$(cmd_node_subscription_export active)
[[ "$(grep -c $'^active\t' <<< "$selected_output")" -eq 2 ]]

# Worker failures are reported per user without cancelling successful atomic builds.
generate_subscription_page() {
    [[ "$1" != "broken" ]]
}
users_file="$tmp/users"
log_dir="$tmp/logs"
mkdir "$log_dir"
chmod 700 "$log_dir" 2>/dev/null || true
printf 'one\nbroken\n../invalid\ntwo\n' > "$users_file"
set +e
worker_output=$(subscription_generate_pages_parallel 2 "$log_dir" "$users_file")
worker_rc=$?
set -e
[[ "$worker_rc" -eq 1 ]]
grep -q $'^OK\tone$' <<< "$worker_output"
grep -q $'^FAIL\tbroken$' <<< "$worker_output"
grep -q $'^FAIL\tinvalid-entry-3$' <<< "$worker_output"
grep -q $'^OK\ttwo$' <<< "$worker_output"

# Reusing a QR is permitted only when the private checksum sidecar matches the
# exact URL. A changed subscription domain or token forces regeneration.
ensure_qrencode_for_subscriptions() { :; }
qrencode() {
    local output="" value=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) output="$2"; shift 2 ;;
            --) value="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    printf 'generated\n' >> "$tmp/qr-calls"
    printf 'QR:%s\n' "$value" > "$output"
}

first_qr="$tmp/first.png"
second_qr="$tmp/second.png"
third_qr="$tmp/third.png"
write_subscription_qr 'https://sub.example/a/links.txt' "$first_qr"
write_subscription_qr 'https://sub.example/a/links.txt' "$second_qr" "$first_qr"
[[ "$(wc -l < "$tmp/qr-calls")" -eq 1 ]]
cmp -s "$first_qr" "$second_qr"
write_subscription_qr 'https://sub.example/b/links.txt' "$third_qr" "$first_qr"
[[ "$(wc -l < "$tmp/qr-calls")" -eq 2 ]]
if [[ "$(uname -s)" != MINGW* ]]; then
    [[ "$(stat -c '%a' "${second_qr}.sha256")" == "600" ]]
fi

grep -q "node-subscription-export)" "$SCRIPT"
grep -q 'SUBSCRIPTION_REBUILD_WORKER=1' "$SCRIPT"
grep -q 'SUBSCRIPTION_REBUILD_JOBS' "$SCRIPT"

echo "SUBSCRIPTION_REBUILD_TEST=ok"
