#!/bin/sh
# Target list for the TCP handshake latency item (network.tcping): servers/tcping.json, which the
# program downloads at run time. Refreshed every four hours by scripts/tcping-collect.py from the
# probed candidate pool (servers/tcping-pool.json).
#
# Usage: scripts/tcping-targets.sh check
#            checks servers/tcping.json against the rules
#        scripts/tcping-targets.sh check-list <file>
#            checks a list in the program's format against the rules that the program checks
#
# The rules match the program's reader (plugins/network/src/tcping/targets.rs): at most 128 KiB
# and 1 to 300 targets of version 1; unique ids of 1 to 40 characters of a to z, digits and -,
# other than "all"; group in china, china_premium or global; printable ASCII region, city and name
# of 1 to 40 characters; operator in telecom, unicom, mobile, cernet, cbn or other; an AS number
# from 1 to 4294967295; optional boolean default; and ipv4 and/or ipv6 endpoint arrays of 1 to 2
# {host, port} entries each (primary and optional backup), with ports from 1 to 65535 and no
# duplicate host:port pairs inside a family. Both read tests/fixtures/tcping-lists/.
set -eu

LIST=servers/tcping.json
LIMIT=131072

fail() {
    echo "tcping-targets: $*" >&2
    exit 1
}

# shellcheck disable=SC2016 # jq's variables and interpolations, not the shell's
RULES=$(cat "$(dirname "$0")/list-rules.jq")'
def ascii_printable($longest):
    type == "string" and length >= 1 and length <= $longest and whole("[ -~]+");
def name_of(family):
    type == "string"
    and (if family == "ipv4" then ipv4 or (ipv6 | not) and dns_name
         else ipv6 or (ipv4 | not) and dns_name end);
def id_rule:
    type == "string" and whole("[a-z0-9-]{1,40}") and . != "all";
def group_rule:
    . == "china" or . == "china_premium" or . == "global";
def operator_rule:
    . == "telecom" or . == "unicom" or . == "mobile"
    or . == "cernet" or . == "cbn" or . == "other";
def asn_rule:
    type == "number" and (tojson | whole("[0-9]+")) and . >= 1 and . <= 4294967295;
def default_rule:
    . == null or type == "boolean";
def port_rule:
    type == "number" and (tojson | whole("[0-9]+")) and . >= 1 and . <= 65535;
def endpoint_ok(family):
    type == "object"
    and (.host | name_of(family))
    and (.port | port_rule);
def endpoints_rule(family):
    if . == null then true
    elif type != "array" or length < 1 or length > 2 then false
    elif (all(.[]; endpoint_ok(family)) | not) then false
    elif ([.[] | "\(.host | ascii_downcase):\(.port)"] | length != (unique | length)) then false
    else true end;
def target_problems:
    [ (if .id | id_rule then empty else "id" end),
      (if .group | group_rule then empty else "group" end),
      (if .region | ascii_printable(40) then empty else "region" end),
      (if .city | ascii_printable(40) then empty else "city" end),
      (if .name | ascii_printable(40) then empty else "name" end),
      (if .operator | operator_rule then empty else "operator" end),
      (if .asn | asn_rule then empty else "asn" end),
      (if .default | default_rule then empty else "default" end),
      (if .ipv4 == null and .ipv6 == null then "endpoints" else empty end),
      (if .ipv4 | endpoints_rule("ipv4") then empty else "ipv4" end),
      (if .ipv6 | endpoints_rule("ipv6") then empty else "ipv6" end) ];
def list_problems:
    if type != "object" then ["not an object"]
    elif .version != 1 then ["version \(.version) is not 1"]
    elif .targets | type != "array" then ["no targets"]
    elif .targets | length == 0 then ["empty targets"]
    elif .targets | length > 300 then ["\(.targets | length) targets, more than 300"]
    else
        [ .targets | to_entries[]
          | .key as $index
          | .value | if type == "object" then target_problems else ["not an object"] end
          | .[] | "target \($index + 1): \(.)" ]
        + [ [.targets[] | select(type == "object") | .id | select(type == "string")]
            | group_by(.)[] | select(length > 1) | "id \(.[0]) twice" ]
    end;
'

check_list() {
    [ -f "$1" ] || fail "no list at $1"
    size=$(wc -c < "$1" | tr -d ' ')
    [ "$size" -le "$LIMIT" ] || fail "$1 has $size bytes, more than $LIMIT"
    problems=$(jq -r "$RULES list_problems[]" "$1" 2>&1) || fail "$1 is not JSON: $problems"
    [ -z "$problems" ] || fail "$1 breaks the rules: $(printf '%s' "$problems" | tr '\n' ';')"
}

case ${1:-} in
    check)
        check_list "$LIST"
        echo "tcping-targets: $LIST follows the rules"
        ;;
    check-list)
        [ $# -eq 2 ] || fail "usage: scripts/tcping-targets.sh check-list <file>"
        check_list "$2"
        ;;
    *)
        echo "usage: scripts/tcping-targets.sh check | check-list <file>" >&2
        exit 2
        ;;
esac
