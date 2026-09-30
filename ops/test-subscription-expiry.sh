#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="${1:-$ROOT/yurich-panel.sh}"
[[ -f "$SCRIPT" ]] || { echo "Script not found: $SCRIPT" >&2; exit 1; }

# shellcheck source=/dev/null
source "$SCRIPT"

[[ "$(add_calendar_months_utc 2026-01-31 1)" == "2026-02-28" ]]
[[ "$(add_calendar_months_utc 2028-01-31 1)" == "2028-02-29" ]]
[[ "$(add_calendar_months_utc 2026-11-30 3)" == "2027-02-28" ]]
[[ "$(add_calendar_months_utc 2026-12-31 2)" == "2027-02-28" ]]
[[ "$(add_calendar_months_utc 2026-09-13 3)" == "2026-12-13" ]]
if add_calendar_months_utc 2026-02-30 1 >/dev/null; then
    echo "Invalid source date was accepted" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
USER_META_DIR="$tmp/users.d"
mkdir -p "$USER_META_DIR"
date() {
    if [[ "$#" -eq 2 && "$1" == "-u" && "$2" == "+%Y-%m-%d" ]]; then
        printf '%s\n' "$test_today"
    else
        command date "$@"
    fi
}
test_today=2026-01-31
set_user_expiry_months newuser 1
[[ "$(get_user_expiry newuser)" == "2026-02-28" ]]
test_today=2026-01-01
printf 'USER=demo\nEXPIRES_AT=2026-01-31\n' > "$USER_META_DIR/demo.env"
set_user_expiry_extend_months demo 1
[[ "$(get_user_expiry demo)" == "2026-02-28" ]]
printf 'USER=demo\nEXPIRES_AT=2028-01-31\n' > "$USER_META_DIR/demo.env"
set_user_expiry_extend_term demo 1m
[[ "$(get_user_expiry demo)" == "2028-02-29" ]]
unset -f date

echo "SUBSCRIPTION_EXPIRY_TEST=ok"
