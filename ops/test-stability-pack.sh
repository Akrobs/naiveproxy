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

NODES_FILE="$tmp/nodes.conf"
cat > "$NODES_FILE" <<'EOF'
# format: name|host|ssh_port|ssh_user|domain|role|weight|enabled
poland|192.0.2.10|22|root|poland.example.com|edge|100|1
france|192.0.2.11|22|root|loc1.example.com|edge|100|0
EOF
BROWSER_SUBSCRIPTION_PROFILES='poland.example.com|poland;loc1.example.com|france;loc1.example.com|legacy_label;custom.example.com|custom'
browser_output=$(browser_subscription_links_for_user testuser safePassword123)
grep -q '@poland.example.com:443' <<< "$browser_output"
grep -q '@custom.example.com:443' <<< "$browser_output"
if grep -q '@loc1.example.com:443' <<< "$browser_output"; then
    echo "Disabled node leaked into browser subscription" >&2
    exit 1
fi

SUBS_WEB_DIR="$tmp/web"
mkdir -p "$SUBS_WEB_DIR"
token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
final="$SUBS_WEB_DIR/$token"
mkdir -p "$final"
printf 'old\n' > "$final/index.html"

build=$(mktemp -d "$SUBS_WEB_DIR/.${token}.build.XXXXXX")
printf 'new\n' > "$build/index.html"
profile='vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&security=reality&type=tcp#test'
for file in links.txt hiddify.txt streisand.txt happ.txt nekobox.txt karing.txt v2rayng.txt; do
    printf '%s\n' "$profile" > "$build/$file"
done
subscription_validate_build_dir "$build"
subscription_publish_page_dir "$build" "$final"
[[ "$(cat "$final/index.html")" == "new" ]]
[[ ! -e "$build" ]]

invalid=$(mktemp -d "$SUBS_WEB_DIR/.${token}.build.XXXXXX")
printf 'broken\n' > "$invalid/index.html"
if subscription_validate_build_dir "$invalid"; then
    echo "Invalid subscription build unexpectedly passed" >&2
    exit 1
fi
[[ "$(cat "$final/index.html")" == "new" ]]
subscription_discard_build_dir "$invalid"

minimal=$(mktemp -d "$SUBS_WEB_DIR/.${token}.build.XXXXXX")
printf 'minimal\n' > "$minimal/index.html"
minimal_profile='naive+https://testuser:safePassword123@example.com:443#test'
printf '%s\n' "$minimal_profile" > "$minimal/links.txt"
printf '%s\n' "$minimal_profile" > "$minimal/karing.txt"
for file in hiddify.txt streisand.txt happ.txt nekobox.txt v2rayng.txt; do
    : > "$minimal/$file"
done
subscription_validate_build_dir "$minimal"
subscription_discard_build_dir "$minimal"

grep -q 'PROTOCOL_BENCHMARK_HARD_ALERT_REPEAT' "$SCRIPT"
grep -q 'PROTOCOL_MONITOR_ALERT_REPEAT' "$SCRIPT"
grep -q 'DNS_MONITOR_ALERT_REPEAT' "$SCRIPT"
grep -q 'serve-expired: yes' "$SCRIPT"
grep -q 'module-config: "validator iterator"' "$SCRIPT"
grep -q 'jitter_ms' "$SCRIPT"
grep -q 'loss_pct' "$SCRIPT"
grep -q 'monitor_issue_fingerprint' "$SCRIPT"
finalize_calls=$(grep -c 'subscription_finalize_generated_page "\$build_page_dir" "\$final_page_dir" "\$user"' "$SCRIPT")
[[ "$finalize_calls" -eq 4 ]] || {
    echo "Atomic finalization is not wired into all subscription templates" >&2
    exit 1
}

PROTOCOL_BENCHMARK_ALERT_REPEAT=2
PROTOCOL_BENCHMARK_HARD_ALERT_REPEAT=""
PROTOCOL_BENCHMARK_ALERT_COOLDOWN_MINUTES=30
PROTOCOL_MONITOR_ALERT_REPEAT=9
PROTOCOL_MONITOR_ALERT_COOLDOWN_MINUTES=10
DNS_MONITOR_ALERT_REPEAT=1
DNS_MONITOR_ALERT_COOLDOWN_MINUTES=90
normalize_monitor_noise_settings
[[ "$PROTOCOL_BENCHMARK_ALERT_REPEAT" -eq 3 ]]
[[ "$PROTOCOL_BENCHMARK_HARD_ALERT_REPEAT" -eq 3 ]]
[[ "$PROTOCOL_BENCHMARK_ALERT_COOLDOWN_MINUTES" -eq 60 ]]
[[ "$PROTOCOL_MONITOR_ALERT_REPEAT" -eq 9 ]]
[[ "$PROTOCOL_MONITOR_ALERT_COOLDOWN_MINUTES" -eq 60 ]]
[[ "$DNS_MONITOR_ALERT_REPEAT" -eq 3 ]]
[[ "$DNS_MONITOR_ALERT_COOLDOWN_MINUTES" -eq 180 ]]

echo "STABILITY_PACK_TEST=ok"
