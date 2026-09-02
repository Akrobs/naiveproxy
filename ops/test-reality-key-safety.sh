#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/yurich-panel.sh}"
[[ -f "$TARGET_SCRIPT" ]] || { echo "Script not found: $TARGET_SCRIPT" >&2; exit 1; }

# shellcheck source=/dev/null
source "$TARGET_SCRIPT"

# Public interoperability fixture from the Xray x25519 documentation.
fixture_private="6J_yLC6sSBFtBbOetlC2MsCj29Na2jnBPctA8M4NYFs"
fixture_public="g_-bdFZMyCxZsfsWQo0B1_0zPvBxjxKPeB8VhS_L5zY"
derived=$(xray_derive_reality_public_key "$fixture_private")
[[ "$derived" == "$fixture_public" ]] || {
    echo "REALITY public-key derivation mismatch" >&2
    exit 1
}

xray_reality_key_valid "$fixture_private"
if xray_reality_key_valid "invalid-key"; then
    echo "Invalid REALITY key was accepted" >&2
    exit 1
fi
if grep -Eq 'x25519[[:space:]]+-i' "$TARGET_SCRIPT"; then
    echo "Unsafe Xray private-key argv path is still present" >&2
    exit 1
fi

mock_dir=$(mktemp -d)
trap 'rm -rf "$mock_dir"' EXIT
cat > "$mock_dir/xray" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_ARGS_FILE"
if [[ "${MOCK_MODE:-valid}" == "partial" ]]; then
    printf 'Unrecognized key output: %s\n' "$MOCK_PRIVATE"
else
    printf 'Private key: %s\nPublic key: %s\n' "$MOCK_PRIVATE" "$MOCK_PUBLIC"
fi
EOF
chmod 700 "$mock_dir/xray"
export MOCK_ARGS_FILE="$mock_dir/args"
export MOCK_PRIVATE="$fixture_private"
export MOCK_PUBLIC="$fixture_public"
export XRAY_BIN="$mock_dir/xray"

: > "$MOCK_ARGS_FILE"
export XRAY_REALITY_PRIVATE_KEY="$fixture_private"
export XRAY_REALITY_PUBLIC_KEY="$fixture_public"
export XRAY_REALITY_SHORT_ID="0011223344556677"
stored_output=$(ensure_xray_reality_keys 2>&1)
[[ "$stored_output" != *"$fixture_private"* && "$stored_output" != *"$fixture_public"* ]] || {
    echo "Stored REALITY key leaked to diagnostics" >&2
    exit 1
}
[[ ! -s "$MOCK_ARGS_FILE" ]] || {
    echo "Stored REALITY key unexpectedly reached Xray argv" >&2
    exit 1
}

: > "$MOCK_ARGS_FILE"
export MOCK_MODE="valid"
export XRAY_REALITY_PRIVATE_KEY=""
export XRAY_REALITY_PUBLIC_KEY=""
keygen_output=$(ensure_xray_reality_keys 2>&1)
[[ "$keygen_output" != *"$fixture_private"* && "$keygen_output" != *"$fixture_public"* ]] || {
    echo "REALITY key material leaked to diagnostics" >&2
    exit 1
}
[[ "$(cat "$MOCK_ARGS_FILE")" == "x25519" ]] || {
    echo "Unexpected Xray key-generation argv" >&2
    exit 1
}

: > "$MOCK_ARGS_FILE"
export MOCK_MODE="partial"
export XRAY_REALITY_PRIVATE_KEY=""
export XRAY_REALITY_PUBLIC_KEY=""
set +e
unexpected_output=$(ensure_xray_reality_keys 2>&1)
unexpected_rc=$?
set -e
[[ "$unexpected_rc" -ne 0 ]] || {
    echo "Unexpected Xray output was accepted" >&2
    exit 1
}
[[ "$unexpected_output" != *"$fixture_private"* && "$unexpected_output" != *"$fixture_public"* ]] || {
    echo "Unexpected Xray output leaked REALITY key material" >&2
    exit 1
}
[[ "$unexpected_output" == *"ключевой материал скрыт"* ]] || {
    echo "Unexpected Xray output did not use the redacted diagnostic" >&2
    exit 1
}
[[ "$(cat "$MOCK_ARGS_FILE")" == "x25519" ]] || {
    echo "Unexpected Xray output path used unsafe argv" >&2
    exit 1
}

domain_in_space_list_ci 'Main.Example other.example' 'main.example'
if domain_in_space_list_ci 'Main.Example other.example' 'unrelated.example'; then
    echo "Unrelated SNI was treated as a conflict" >&2
    exit 1
fi

export BROWSER_SUBSCRIPTION_PROFILES='proxy.example.com|edge1'
[[ -z "$(browser_subscription_links_for_user 'alice' '')" ]]
export BROWSER_SUBSCRIPTION_PROFILES='malformed-entry'
if browser_subscription_links_for_user 'alice' '' >/dev/null 2>&1; then
    echo "Malformed browser subscription profile was accepted" >&2
    exit 1
fi

mock_systemctl_ready=1
mock_tcp_ready=1
systemctl() { [[ "$mock_systemctl_ready" == "1" ]]; }
local_tcp_endpoint_ready() { [[ "$mock_tcp_ready" == "1" && "${1:-}" == "53" ]]; }
export UNBOUND_ENABLED=1
xray_local_dns_ready
mock_systemctl_ready=0
if xray_local_dns_ready; then
    echo "Inactive Unbound was selected for Xray" >&2
    exit 1
fi
mock_systemctl_ready=1
mock_tcp_ready=0
if xray_local_dns_ready; then
    echo "Unavailable DNS listener was selected for Xray" >&2
    exit 1
fi
mock_tcp_ready=1
export UNBOUND_ENABLED=0
if xray_local_dns_ready; then
    echo "Disabled Unbound was selected for Xray" >&2
    exit 1
fi

echo "REALITY_KEY_SAFETY=ok script=$TARGET_SCRIPT"
