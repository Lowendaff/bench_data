#!/bin/sh
# Cases for scripts/tcping-targets.sh: every fixture in tests/fixtures/tcping-lists, which the
# program's reader checks too, gets the verdict that its name gives; then size limits, primary and
# backup endpoint rules, and command checks in a scratch directory.
#
# Usage: scripts/tcping-targets-cases.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
script=$here/tcping-targets.sh
fixtures=$here/../tests/fixtures/tcping-lists
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

failures=0
cases=0

verdict() {
    cases=$((cases + 1))
    expected=$1 name=$2 part=$3
    shift 3
    if output=$("$@" 2>&1); then
        got=accept
    else
        got=reject
    fi
    if [ "$got" != "$expected" ]; then
        echo "FAIL: $name: expected $expected, got $got: $output" >&2
        failures=$((failures + 1))
    elif [ -n "$part" ] && ! printf '%s\n' "$output" | grep -q -F -e "$part"; then
        echo "FAIL: $name: the output lacks \"$part\": $output" >&2
        failures=$((failures + 1))
    else
        echo "ok: $name"
    fi
}

seen=0
for fixture in "$fixtures"/*.json; do
    name=$(basename "$fixture")
    case $name in
        good-*) expected=accept ;;
        bad-*) expected=reject ;;
        *) echo "FAIL: $name names no verdict" >&2; failures=$((failures + 1)); continue ;;
    esac
    verdict "$expected" "fixture $name" '' sh "$script" check-list "$fixture"
    seen=$((seen + 1))
done
[ "$seen" -ge 28 ] || { echo "FAIL: only $seen fixtures" >&2; failures=$((failures + 1)); }

cd "$scratch"
mkdir servers

padded() {
    printf '{"version": 1, "targets": [{"id": "cn-bj-ct", "group": "china", "region": "Beijing", "city": "Beijing", "name": "Beijing Telecom", "operator": "telecom", "asn": 4134, "ipv4": [{"host": "192.0.2.1", "port": 443}]}]}' > "$2"
    size=$(wc -c < "$2" | tr -d ' ')
    head -c $(($1 - size)) /dev/zero | tr '\0' ' ' >> "$2"
}
padded 131072 limit.json
verdict accept "a list of 128 KiB" '' sh "$script" check-list limit.json
padded 131073 large.json
verdict reject "a list of 128 KiB and a byte" 'more than 131072' sh "$script" check-list large.json
verdict reject "no list" 'no list' sh "$script" check-list missing.json

list() {
    jq -n --argjson set "{$1}" '{version: 1, targets: [{
        id: "cn-bj-ct",
        group: "china",
        region: "Beijing",
        city: "Beijing",
        name: "Beijing Telecom",
        operator: "telecom",
        asn: 4134,
        default: true,
        ipv4: [{host: "192.0.2.1", port: 443}]
    } + $set]}' > case.json
}
case_of() {
    list "$4"
    verdict "$1" "$2" "$3" sh "$script" check-list case.json
}

case_of accept "primary and backup IPv4 endpoints" '' \
    '"ipv4": [{"host": "192.0.2.1", "port": 443}, {"host": "198.51.100.2", "port": 65499}]'
case_of accept "IPv6-only target" '' \
    '"ipv4": null, "ipv6": [{"host": "2001:db8::1", "port": 443}]'
case_of accept "china_premium group" '' '"group": "china_premium", "asn": 4809'
case_of accept "global group with DNS hostnames" '' \
    '"group": "global", "operator": "other", "ipv4": [{"host": "s3.ap-northeast-1.amazonaws.com", "port": 443}]'
case_of reject "three IPv4 endpoints" 'target 1: ipv4' \
    '"ipv4": [{"host": "192.0.2.1", "port": 443}, {"host": "192.0.2.2", "port": 443}, {"host": "192.0.2.3", "port": 443}]'
case_of reject "duplicate IPv4 host:port case-insensitively" 'target 1: ipv4' \
    '"ipv4": [{"host": "Example.COM", "port": 443}, {"host": "example.com", "port": 443}]'
case_of reject "neither ipv4 nor ipv6" 'target 1: endpoints' '"ipv4": null, "ipv6": null'
case_of reject "IPv6 literal inside ipv4" 'target 1: ipv4' \
    '"ipv4": [{"host": "2001:db8::1", "port": 443}]'
case_of reject "IPv4 literal inside ipv6" 'target 1: ipv6' \
    '"ipv6": [{"host": "192.0.2.1", "port": 443}]'
case_of reject "port zero" 'target 1: ipv4' '"ipv4": [{"host": "192.0.2.1", "port": 0}]'
case_of reject "port above 65535" 'target 1: ipv4' '"ipv4": [{"host": "192.0.2.1", "port": 65536}]'
case_of reject "reserved id all" 'target 1: id' '"id": "all"'
case_of reject "unknown group" 'target 1: group' '"group": "international"'
case_of reject "unknown operator" 'target 1: operator' '"operator": "isp"'
case_of reject "region over 40 chars" 'target 1: region' \
    "\"region\": \"$(printf '%041d' 0 | tr 0 R)\""

verdict reject "check without a list" 'no list at servers/tcping.json' sh "$script" check
cp "$fixtures/good-every-shape.json" servers/tcping.json
verdict accept "check of a good list" 'follows the rules' sh "$script" check
cp "$fixtures/bad-duplicate-id.json" servers/tcping.json
verdict reject "check of duplicate id list" 'id cn-bj-ct twice' sh "$script" check
verdict reject "unknown subcommand" 'usage' sh "$script" update

if [ "$failures" -gt 0 ]; then
    echo "tcping-targets-cases: $failures of $cases cases failed" >&2
    exit 1
fi
echo "tcping-targets-cases: all $cases cases passed"
