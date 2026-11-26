#!/usr/bin/env python3
"""Collects, BGP-verifies, and health-probes dual-stack TCP latency and China trace targets.

Maintains an incremental health pool (`servers/tcping-pool.json`) fed from:
1. `servers/taier.json` and `servers/taier-ipv6.json` (CAICT GlobalSpeed carrier nodes across all
   31 mainland China provinces).
2. `servers/tcping-seeds.json` (provincial carrier CDN/cloud fallbacks, Beijing/Shanghai/Guangzhou
   premium `4809`/`9929`/`58807` seeds, and 17 global single-region hub seeds).

Every four hours (`data.yml`), probes TCP handshake (`SYN -> SYN-ACK` / `RST`), ICMP echo, and
RIPEstat international BGP entry ASNs (cached per `/24` and `/48`), then writes:
- `servers/tcping.json` (`version: 1`, `primary` + `backup` per address family), and
- refreshes the 18 mainland China targets in `servers/traceroute.json` whenever a candidate passes
  `tcp_ok && icmp_ok && bgp_ok` without changing the `traceroute.json` v1 schema.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

EMA_ALPHA = 0.25
DEMOTE_FAILURES = 3
MAX_FAILURES = 14
BGP_TTL_SECS = 86400
MAX_BGP_REFRESH = 96
PROBE_WORKERS = 40
BGP_WORKERS = 8
TCP_TIMEOUT_SECS = 2.2

CN_BACKBONES = (4134, 4809, 4837, 9929, 9808, 58807)
CN_DOMESTIC_PEERS = {
    4134, 4809, 4837, 9929, 9808, 58453, 58807, 4847, 4811, 4812, 4816,
    4808, 17621, 17622, 17623, 17816, 24400, 56040, 56041, 56042, 56044,
    56046, 56047, 56048, 4538, 23910, 37963, 45090, 55990, 132203, 59019,
    134773, 135061, 138421,
}
ANYCAST_CDN_ASNS = {13335, 54113, 20940, 16625, 19551, 54994, 151326, 151397}

PROVINCE_ZH_TO_EN = {
    "\u5317\u4eac": "Beijing",
    "\u4e0a\u6d77": "Shanghai",
    "\u5929\u6d25": "Tianjin",
    "\u91cd\u5e86": "Chongqing",
    "\u6cb3\u5317": "Hebei",
    "\u5c71\u897f": "Shanxi",
    "\u5185\u8499\u53e4": "Inner Mongolia",
    "\u8fbd\u5b81": "Liaoning",
    "\u5409\u6797": "Jilin",
    "\u9ed1\u9f99\u6c5f": "Heilongjiang",
    "\u6c5f\u82cf": "Jiangsu",
    "\u6d59\u6c5f": "Zhejiang",
    "\u5b89\u5fbd": "Anhui",
    "\u798f\u5efa": "Fujian",
    "\u6c5f\u897f": "Jiangxi",
    "\u5c71\u4e1c": "Shandong",
    "\u6cb3\u5357": "Henan",
    "\u6e56\u5317": "Hubei",
    "\u6e56\u5357": "Hunan",
    "\u5e7f\u4e1c": "Guangdong",
    "\u5e7f\u897f": "Guangxi",
    "\u6d77\u5357": "Hainan",
    "\u56db\u5ddd": "Sichuan",
    "\u8d35\u5dde": "Guizhou",
    "\u4e91\u5357": "Yunnan",
    "\u897f\u85cf": "Tibet",
    "\u9655\u897f": "Shaanxi",
    "\u7518\u8083": "Gansu",
    "\u9752\u6d77": "Qinghai",
    "\u5b81\u590f": "Ningxia",
    "\u65b0\u7586": "Xinjiang",
}

OPER_ZH_TO_EN = {
    "\u7535\u4fe1": "telecom",
    "\u4e2d\u56fd\u7535\u4fe1": "telecom",
    "\u8054\u901a": "unicom",
    "\u4e2d\u56fd\u8054\u901a": "unicom",
    "\u79fb\u52a8": "mobile",
    "\u4e2d\u56fd\u79fb\u52a8": "mobile",
}

CARRIER_SPECS = (
    ("ct", "telecom", "Telecom", 4134),
    ("cu", "unicom", "Unicom", 4837),
    ("cm", "mobile", "Mobile", 9808),
)

TRACEROUTE_STD_MAP = {
    "pek-4134": "cn-bj-ct",
    "pek-4837": "cn-bj-cu",
    "pek-9808": "cn-bj-cm",
    "sha-4134": "cn-sh-ct",
    "sha-4837": "cn-sh-cu",
    "sha-9808": "cn-sh-cm",
    "can-4134": "cn-gd-ct",
    "can-4837": "cn-gd-cu",
    "can-9808": "cn-gd-cm",
}

STRICT_BSG_SLOTS = frozenset(TRACEROUTE_STD_MAP.values())

OPERATOR_BACKBONE_SET = {
    "telecom": {4134, 4809},
    "unicom": {4837, 9929},
    "mobile": {9808, 58807},
}

CMIN2_REGION_TO_PREMIUM = {
    "Beijing": "cn-bj-cmin2-58807",
    "Tianjin": "cn-bj-cmin2-58807",
    "Hebei": "cn-bj-cmin2-58807",
    "Shanghai": "cn-sh-cmin2-58807",
    "Jiangsu": "cn-sh-cmin2-58807",
    "Zhejiang": "cn-sh-cmin2-58807",
    "Guangdong": "cn-gd-cmin2-58807",
    "Guangxi": "cn-gd-cmin2-58807",
}


def is_public_routable_ip(raw: str, version: int) -> str | None:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if addr.version != version:
        return None
    if (
        addr.is_unspecified
        or addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    ):
        return None
    if version == 4:
        octs = addr.packed
        a, b, c = octs[0], octs[1], octs[2]
        if (
            a == 0
            or a >= 224
            or (a == 100 and 64 <= b < 128)
            or (a == 192 and b == 0 and c in (0, 2))
            or (a == 192 and b == 88 and c == 99)
            or (a == 198 and b in (18, 19))
            or (a == 198 and b == 51 and c == 100)
            or (a == 203 and b == 0 and c == 113)
        ):
            return None
    else:
        hextets = [int(x, 16) for x in addr.exploded.split(":")]
        first, second, third = hextets[0], hextets[1], hextets[2]
        if (first & 0xE000) != 0x2000 or first == 0x2002:
            return None
        if first == 0x2001 and (
            second == 0
            or second == 0x0DB8
            or (second == 2 and third == 0)
            or (0x0010 <= second <= 0x002F)
        ):
            return None
    return addr.compressed


def has_ipv6_outbound() -> bool:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect(("2606:4700:4700::1111", 53))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def prefix_key(ip_str: str) -> str:
    addr = ipaddress.ip_address(ip_str)
    if addr.version == 4:
        net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
    else:
        net = ipaddress.ip_network(f"{ip_str}/48", strict=False)
    return str(net.network_address)


def resolve_public(host: str, family: str) -> str | None:
    ver = 6 if family == "ipv6" else 4
    direct = is_public_routable_ip(host, ver)
    if direct:
        return direct
    af = socket.AF_INET6 if ver == 6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(host, None, af, socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        cand = is_public_routable_ip(str(info[4][0]), ver)
        if cand:
            return cand
    return None


def probe_tcp(ip_str: str, port: int, family: str) -> tuple[bool, str, float | None]:
    af = socket.AF_INET6 if family == "ipv6" else socket.AF_INET
    sock = socket.socket(af, socket.SOCK_STREAM)
    sock.settimeout(TCP_TIMEOUT_SECS)
    t0 = time.perf_counter()
    try:
        sock.connect((ip_str, port))
        ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return True, "open", ms
    except ConnectionRefusedError:
        ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if ms >= 0.2:
            return True, "rst", ms
        return False, "down", None
    except OSError as err:
        if err.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL):
            return False, "unreach", None
        return False, "down", None
    finally:
        sock.close()


def probe_icmp(ip_str: str, family: str) -> bool:
    if family == "ipv6":
        cmd = ["ping", "-6", "-c", "1", "-W", "1", ip_str]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip_str]
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.2,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def query_ripestat_bgp(ip_or_net: str) -> dict | None:
    url = f"https://stat.ripe.net/data/bgp-state/data.json?resource={ip_or_net}"
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "lowendaff-bench-data/1.0"})
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read(4 * 1024 * 1024).decode("utf-8"))["data"]
            origins: set[int] = set()
            intl_cn: dict[int, int] = {}
            total_intl = 0
            for row in data.get("bgp_state", []):
                path = row.get("path") or []
                if not path:
                    continue
                origins.add(int(path[-1]))
                if int(path[0]) in CN_DOMESTIC_PEERS:
                    continue
                total_intl += 1
                for hop_asn in path:
                    hop_int = int(hop_asn)
                    if hop_int in CN_BACKBONES:
                        intl_cn[hop_int] = intl_cn.get(hop_int, 0) + 1
                        break
            dom_cn: int | None = None
            if intl_cn and total_intl > 0:
                best_asn, best_cnt = max(intl_cn.items(), key=lambda kv: kv[1])
                share = best_cnt / total_intl
                if (best_cnt >= 20 and share >= 0.45) or (best_cnt >= 5 and share >= 0.60):
                    dom_cn = best_asn
            return {
                "origins": sorted(origins),
                "dom_cn": dom_cn,
                "checked_at": int(time.time()),
            }
        except Exception:
            if attempt == 0:
                time.sleep(0.3)
    return None


def evaluate_bgp_ok(
    slot_id: str,
    group: str,
    operator: str,
    expected_asn: int,
    bgp_info: dict | None,
) -> bool:
    if not bgp_info:
        return True
    origins = set(bgp_info.get("origins") or [])
    dom_cn = bgp_info.get("dom_cn")
    if origins & ANYCAST_CDN_ASNS:
        return False
    if group == "china_premium":
        return (dom_cn == expected_asn) or (expected_asn in origins)
    if group == "china":
        if slot_id in STRICT_BSG_SLOTS:
            if dom_cn is not None:
                return dom_cn == expected_asn
            return bool(origins) and not (origins & {4809, 9929, 58807})
        allowed = OPERATOR_BACKBONE_SET.get(operator, {expected_asn})
        if dom_cn is not None:
            return dom_cn in allowed
        return bool(origins)
    return bool(origins)


def build_slots_and_candidates(
    seeds: dict,
    taier_v4: dict,
    taier_v6: dict,
) -> tuple[list[dict], list[dict], dict[str, str]]:
    slots: list[dict] = []
    candidates: list[dict] = []
    traceroute_map: dict[str, str] = dict(TRACEROUTE_STD_MAP)

    prov_by_region: dict[str, dict] = {}
    for p in seeds["provinces"]:
        prov_by_region[p["region"]] = p
        code = p["code"]
        for suffix, op_code, op_label, asn in CARRIER_SPECS:
            slot_id = f"cn-{code}-{suffix}"
            slots.append(
                {
                    "id": slot_id,
                    "group": "china",
                    "region": p["region"],
                    "city": p["city"],
                    "name": f"{p['city']} {op_label}",
                    "operator": op_code,
                    "asn": asn,
                    "default": bool(p.get("default", False)),
                }
            )
            candidates.append(
                {
                    "slot": slot_id,
                    "family": "ipv4",
                    "host": f"{code}-{suffix}-v4.ip.zstaticcdn.com",
                    "port": 443,
                    "source": "zstatic",
                    "capital_match": True,
                }
            )
            candidates.append(
                {
                    "slot": slot_id,
                    "family": "ipv6",
                    "host": f"{code}-{suffix}-v6.ip.zstaticcdn.com",
                    "port": 443,
                    "source": "zstatic",
                    "capital_match": True,
                }
            )

    for item in seeds.get("china_extra_seeds", []):
        candidates.append(
            {
                "slot": item["slot"],
                "family": item["family"],
                "host": item["host"],
                "port": int(item["port"]),
                "source": "seed",
                "capital_match": True,
            }
        )

    # Ingest IPv4 nodes from servers/taier.json (picking up to 3 per province+carrier, capital first).
    per_slot_taier4: dict[str, list[tuple[bool, str, int, str]]] = {}
    for loc in taier_v4.get("locations", []):
        region = str(loc.get("province", ""))
        prov = prov_by_region.get(region)
        if not prov:
            continue
        is_cap = str(loc.get("city", "")).lower() == prov["city"].lower()
        code = prov["code"]
        for node in loc.get("nodes", []):
            op = str(node.get("operator", ""))
            suffix = {"telecom": "ct", "unicom": "cu", "mobile": "cm"}.get(op)
            if not suffix:
                continue
            slot_id = f"cn-{code}-{suffix}"
            per_slot_taier4.setdefault(slot_id, []).append(
                (is_cap, str(node["ip"]), int(node["port"]), region)
            )

    for slot_id, rows in per_slot_taier4.items():
        rows.sort(key=lambda r: (not r[0], r[1], r[2]))
        for is_cap, ip_str, port, region in rows[:3]:
            candidates.append(
                {
                    "slot": slot_id,
                    "family": "ipv4",
                    "host": ip_str,
                    "port": port,
                    "source": "taier",
                    "capital_match": is_cap,
                    "region_hint": region,
                }
            )

    # Ingest IPv6 nodes from servers/taier-ipv6.json.
    per_slot_taier6: dict[str, list[tuple[str, int]]] = {}
    for node in taier_v6.get("nodes", []):
        region = PROVINCE_ZH_TO_EN.get(str(node.get("p", "")).strip())
        op = OPER_ZH_TO_EN.get(str(node.get("o", "")).strip())
        if not region or not op:
            continue
        prov = prov_by_region.get(region)
        suffix = {"telecom": "ct", "unicom": "cu", "mobile": "cm"}.get(op)
        if not prov or not suffix:
            continue
        slot_id = f"cn-{prov['code']}-{suffix}"
        per_slot_taier6.setdefault(slot_id, []).append((str(node["ip"]), int(node["port"])))

    for slot_id, rows6 in per_slot_taier6.items():
        for ip6, port in rows6[:2]:
            candidates.append(
                {
                    "slot": slot_id,
                    "family": "ipv6",
                    "host": ip6,
                    "port": port,
                    "source": "taier-ipv6",
                    "capital_match": True,
                }
            )

    # China premium slots (4809 / 9929 / 58807).
    for item in seeds["china_premium"]:
        slot_id = item["id"]
        if item.get("traceroute_id"):
            traceroute_map[item["traceroute_id"]] = slot_id
        slots.append(
            {
                "id": slot_id,
                "group": "china_premium",
                "region": item["region"],
                "city": item["city"],
                "name": item["name"],
                "operator": item["operator"],
                "asn": int(item["asn"]),
                "default": bool(item.get("default", True)),
            }
        )
        for fam in ("ipv4", "ipv6"):
            for ep in item.get(fam, []):
                candidates.append(
                    {
                        "slot": slot_id,
                        "family": fam,
                        "host": ep["host"],
                        "port": int(ep["port"]),
                        "source": "seed",
                        "capital_match": True,
                    }
                )

    # Global hub slots.
    for item in seeds["global"]:
        slot_id = item["id"]
        slots.append(
            {
                "id": slot_id,
                "group": "global",
                "region": item["region"],
                "city": item["city"],
                "name": item["name"],
                "operator": item["operator"],
                "asn": int(item["asn"]),
                "default": bool(item.get("default", True)),
            }
        )
        for fam in ("ipv4", "ipv6"):
            for ep in item.get(fam, []):
                candidates.append(
                    {
                        "slot": slot_id,
                        "family": fam,
                        "host": ep["host"],
                        "port": int(ep["port"]),
                        "source": "seed",
                        "capital_match": True,
                    }
                )

    return slots, candidates, traceroute_map


def rank_key(entry: dict) -> tuple:
    eligible = entry["bgp_ok"] and (
        entry["tcp_ok"] or (entry["ema_up"] >= 0.6 and entry["failures"] < DEMOTE_FAILURES)
    )
    mode_rank = 0 if entry.get("tcp_mode") == "open" else (1 if entry.get("tcp_mode") == "rst" else 2)
    source_rank = 0 if entry.get("source") in ("taier", "taier-ipv6", "seed") else 1
    cap_rank = 0 if entry.get("capital_match", True) else 1
    rtt = float(entry.get("rtt_ms") or 9999.0)
    return (
        0 if eligible else 1,
        mode_rank,
        -round(float(entry.get("ema_up", 0.0)), 2),
        cap_rank,
        source_rank,
        round(rtt, 1),
        entry["host"],
        int(entry["port"]),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", default="servers/tcping-seeds.json")
    parser.add_argument("--taier", default="servers/taier.json")
    parser.add_argument("--taier-ipv6", default="servers/taier-ipv6.json")
    parser.add_argument("--pool", default="servers/tcping-pool.json")
    parser.add_argument("--out", default="servers/tcping.json")
    parser.add_argument("--traceroute", default="servers/traceroute.json")
    parser.add_argument("--max-bgp-refresh", type=int, default=MAX_BGP_REFRESH)
    parser.add_argument("--no-probe", action="store_true")
    args = parser.parse_args()

    with open(args.seeds, encoding="utf-8") as sf:
        seeds = json.load(sf)
    with open(args.taier, encoding="utf-8") as tf:
        taier_v4 = json.load(tf)
    taier_v6 = {"nodes": []}
    if os.path.isfile(args.taier_ipv6):
        with open(args.taier_ipv6, encoding="utf-8") as t6f:
            taier_v6 = json.load(t6f)

    prev_entries: dict[str, dict] = {}
    bgp_cache: dict[str, dict] = {}
    if os.path.isfile(args.pool):
        try:
            with open(args.pool, encoding="utf-8") as pf:
                loaded = json.load(pf)
            for item in loaded.get("entries", []):
                key = f"{item['slot']}|{item['family']}|{item['host'].lower()}:{item['port']}"
                prev_entries[key] = item
            for pfx, binfo in loaded.get("bgp_cache", {}).items():
                if isinstance(binfo, dict):
                    bgp_cache[pfx] = binfo
        except Exception as err:
            print(f"tcping-collect: warning: ignoring unreadable pool: {err}", file=sys.stderr)

    slots, raw_candidates, traceroute_map = build_slots_and_candidates(seeds, taier_v4, taier_v6)
    slot_by_id = {s["id"]: s for s in slots}

    dedup_candidates: dict[str, dict] = {}
    for cand in raw_candidates:
        key = f"{cand['slot']}|{cand['family']}|{cand['host'].lower()}:{cand['port']}"
        if key not in dedup_candidates:
            dedup_candidates[key] = cand

    ipv6_capable = has_ipv6_outbound()
    now_ts = int(time.time())

    def _probe_candidate(item: tuple[str, dict]) -> tuple[str, dict]:
        key, cand = item
        prev = prev_entries.get(key, {})
        fam = cand["family"]
        host = cand["host"]
        port = int(cand["port"])
        resolved = resolve_public(host, fam) if not args.no_probe else (prev.get("resolved_ip") or resolve_public(host, fam))

        if args.no_probe:
            return key, {
                "slot": cand["slot"],
                "family": fam,
                "host": host,
                "port": port,
                "source": cand["source"],
                "capital_match": bool(cand.get("capital_match", True)),
                "region_hint": cand.get("region_hint", ""),
                "resolved_ip": resolved,
                "tcp_ok": bool(prev.get("tcp_ok", resolved is not None)),
                "tcp_mode": str(prev.get("tcp_mode", "open" if resolved else "down")),
                "icmp_ok": bool(prev.get("icmp_ok", False)),
                "ema_up": float(prev.get("ema_up", 1.0 if resolved else 0.0)),
                "rtt_ms": prev.get("rtt_ms"),
                "failures": int(prev.get("failures", 0)),
            }

        if not resolved:
            old_ema = float(prev.get("ema_up", 0.0))
            return key, {
                "slot": cand["slot"],
                "family": fam,
                "host": host,
                "port": port,
                "source": cand["source"],
                "capital_match": bool(cand.get("capital_match", True)),
                "region_hint": cand.get("region_hint", ""),
                "resolved_ip": None,
                "tcp_ok": False,
                "tcp_mode": "down",
                "icmp_ok": False,
                "ema_up": round((1.0 - EMA_ALPHA) * old_ema, 4),
                "rtt_ms": prev.get("rtt_ms"),
                "failures": min(MAX_FAILURES, int(prev.get("failures", 0)) + 1),
            }

        if fam == "ipv6" and not ipv6_capable:
            # Standard GitHub-hosted runners have no IPv6 default route; validate DNS AAAA
            # resolution and BGP over IPv4 without penalizing unreachable local AF_INET6 sockets.
            return key, {
                "slot": cand["slot"],
                "family": fam,
                "host": host,
                "port": port,
                "source": cand["source"],
                "capital_match": bool(cand.get("capital_match", True)),
                "region_hint": cand.get("region_hint", ""),
                "resolved_ip": resolved,
                "tcp_ok": bool(prev.get("tcp_ok", True)),
                "tcp_mode": str(prev.get("tcp_mode", "open")),
                "icmp_ok": bool(prev.get("icmp_ok", False)),
                "ema_up": float(prev.get("ema_up", 1.0)),
                "rtt_ms": prev.get("rtt_ms"),
                "failures": int(prev.get("failures", 0)),
            }

        tcp_ok, tcp_mode, rtt = probe_tcp(resolved, port, fam)
        icmp_ok = probe_icmp(resolved, fam) if fam == "ipv4" else False
        if key in prev_entries:
            old_ema = float(prev.get("ema_up", 1.0 if tcp_ok else 0.0))
            new_ema = round((1.0 - EMA_ALPHA) * old_ema + EMA_ALPHA * (1.0 if tcp_ok else 0.0), 4)
        else:
            new_ema = 1.0 if tcp_ok else 0.0
        old_rtt = prev.get("rtt_ms")
        if rtt is not None:
            merged_rtt = (
                round((1.0 - EMA_ALPHA) * float(old_rtt) + EMA_ALPHA * rtt, 2)
                if old_rtt is not None
                else rtt
            )
        else:
            merged_rtt = old_rtt
        failures = 0 if tcp_ok else min(MAX_FAILURES, int(prev.get("failures", 0)) + 1)
        return key, {
            "slot": cand["slot"],
            "family": fam,
            "host": host,
            "port": port,
            "source": cand["source"],
            "capital_match": bool(cand.get("capital_match", True)),
            "region_hint": cand.get("region_hint", ""),
            "resolved_ip": resolved,
            "tcp_ok": tcp_ok,
            "tcp_mode": tcp_mode,
            "icmp_ok": icmp_ok,
            "ema_up": new_ema,
            "rtt_ms": merged_rtt,
            "failures": failures,
        }

    probed_map: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        for key, result in ex.map(_probe_candidate, sorted(dedup_candidates.items())):
            probed_map[key] = result

    # Refresh stale or missing BGP prefix classifications (bounded per run so RIPEstat stays fast).
    if not args.no_probe:
        needed_prefixes: list[str] = []
        seen_pfx: set[str] = set()
        for entry in probed_map.values():
            rip = entry.get("resolved_ip")
            if not rip:
                continue
            pfx = prefix_key(rip)
            if pfx in seen_pfx:
                continue
            seen_pfx.add(pfx)
            cached = bgp_cache.get(pfx)
            if not cached or (now_ts - int(cached.get("checked_at", 0))) >= BGP_TTL_SECS:
                needed_prefixes.append(pfx)
        to_query = needed_prefixes[: args.max_bgp_refresh]
        if to_query:
            with concurrent.futures.ThreadPoolExecutor(max_workers=BGP_WORKERS) as ex:
                for pfx, binfo in zip(to_query, ex.map(query_ripestat_bgp, to_query)):
                    if binfo is not None:
                        bgp_cache[pfx] = binfo

    # Promote any Taier Mobile node verified as AS58807 into its regional CMIN2 premium slot too.
    extra_cmin2: list[tuple[str, dict]] = []
    for entry in probed_map.values():
        rip = entry.get("resolved_ip")
        slot_meta = slot_by_id.get(entry["slot"])
        if not rip or not slot_meta:
            entry["bgp_ok"] = False
            continue
        binfo = bgp_cache.get(prefix_key(rip))
        entry["bgp_dom"] = binfo.get("dom_cn") if binfo else None
        entry["bgp_ok"] = evaluate_bgp_ok(
            slot_meta["id"],
            slot_meta["group"],
            slot_meta["operator"],
            int(slot_meta["asn"]),
            binfo,
        )
        if (
            slot_meta["group"] == "china"
            and slot_meta["operator"] == "mobile"
            and entry["family"] == "ipv4"
            and entry.get("bgp_dom") == 58807
        ):
            prem_slot = CMIN2_REGION_TO_PREMIUM.get(slot_meta["region"])
            if prem_slot:
                cloned = dict(entry)
                cloned["slot"] = prem_slot
                cloned["bgp_ok"] = True
                pkey = f"{prem_slot}|ipv4|{cloned['host'].lower()}:{cloned['port']}"
                if pkey not in probed_map:
                    extra_cmin2.append((pkey, cloned))

    for pkey, cloned in extra_cmin2:
        probed_map[pkey] = cloned

    # Group candidates by (slot, family) and emit servers/tcping.json.
    grouped: dict[tuple[str, str], list[dict]] = {}
    for entry in probed_map.values():
        grouped.setdefault((entry["slot"], entry["family"]), []).append(entry)

    published_targets: list[dict] = []
    for slot in slots:
        sid = slot["id"]
        fam_out: dict[str, list[dict]] = {}
        for fam in ("ipv4", "ipv6"):
            cands = grouped.get((sid, fam), [])
            eligible = [
                c
                for c in cands
                if c.get("resolved_ip")
                and c["bgp_ok"]
                and (c["tcp_ok"] or (c["ema_up"] >= 0.6 and c["failures"] < DEMOTE_FAILURES))
            ]
            eligible.sort(key=rank_key)
            picked: list[dict] = []
            seen_ips: set[str] = set()
            seen_hp: set[str] = set()
            for c in eligible:
                hp = f"{c['host'].lower()}:{c['port']}"
                rip = str(c["resolved_ip"])
                if hp in seen_hp or rip in seen_ips:
                    continue
                seen_hp.add(hp)
                seen_ips.add(rip)
                picked.append({"host": c["host"], "port": int(c["port"])})
                if len(picked) >= 2:
                    break
            if picked:
                fam_out[fam] = picked

        if not fam_out:
            continue
        target_obj: dict = {
            "id": sid,
            "group": slot["group"],
            "region": slot["region"],
            "city": slot["city"],
            "name": slot["name"],
            "operator": slot["operator"],
            "asn": int(slot["asn"]),
        }
        if slot.get("default"):
            target_obj["default"] = True
        if "ipv4" in fam_out:
            target_obj["ipv4"] = fam_out["ipv4"]
        if "ipv6" in fam_out:
            target_obj["ipv6"] = fam_out["ipv6"]
        published_targets.append(target_obj)

    if len(published_targets) < 90:
        print(
            f"tcping-collect: only {len(published_targets)} targets survived; aborting",
            file=sys.stderr,
        )
        return 1

    # Write compact 1-line-per-target servers/tcping.json (matching servers/taier.json style).
    lines = ['{"version": 1, "targets": [']
    for idx, t in enumerate(published_targets):
        comma = "," if idx + 1 < len(published_targets) else ""
        lines.append(json.dumps(t, separators=(",", ":"), ensure_ascii=True) + comma)
    lines.append("]}\n")
    with open(args.out, "w", encoding="utf-8") as of:
        of.write("\n".join(lines))

    # Persist servers/tcping-pool.json.
    pool_entries = sorted(
        (
            {
                "slot": e["slot"],
                "family": e["family"],
                "host": e["host"],
                "port": int(e["port"]),
                "source": e["source"],
                "resolved_ip": e.get("resolved_ip"),
                "tcp_ok": bool(e["tcp_ok"]),
                "tcp_mode": e["tcp_mode"],
                "icmp_ok": bool(e["icmp_ok"]),
                "bgp_ok": bool(e["bgp_ok"]),
                "bgp_dom": e.get("bgp_dom"),
                "ema_up": float(e["ema_up"]),
                "rtt_ms": e.get("rtt_ms"),
                "failures": int(e["failures"]),
            }
            for e in probed_map.values()
        ),
        key=lambda x: (x["slot"], x["family"], x["host"], x["port"]),
    )
    active_pfxs = {
        prefix_key(e["resolved_ip"]) for e in pool_entries if e.get("resolved_ip")
    }
    trimmed_bgp = {k: bgp_cache[k] for k in sorted(bgp_cache) if k in active_pfxs}
    with open(args.pool, "w", encoding="utf-8") as pf:
        json.dump(
            {"version": 1, "entries": pool_entries, "bgp_cache": trimmed_bgp},
            pf,
            ensure_ascii=True,
            indent=2,
        )
        pf.write("\n")

    # Sync the 18 mainland China targets in servers/traceroute.json when a dual-capable
    # (icmp_ok && tcp_ok && bgp_ok) IPv4 endpoint is available.
    trace_updated = 0
    if os.path.isfile(args.traceroute):
        with open(args.traceroute, encoding="utf-8") as trf:
            trace_doc = json.load(trf)
        changed = False
        for target in trace_doc.get("targets", []):
            if target.get("group") != "china":
                continue
            tid = str(target.get("id", ""))
            mapped_slot = traceroute_map.get(tid)
            if not mapped_slot:
                continue
            cands4 = [
                c
                for c in grouped.get((mapped_slot, "ipv4"), [])
                if c.get("resolved_ip")
                and c["tcp_ok"]
                and c["icmp_ok"]
                and c["bgp_ok"]
                and c["failures"] < DEMOTE_FAILURES
            ]
            cands4.sort(key=rank_key)
            if not cands4:
                continue
            best = cands4[0]
            new_host = best["host"]
            new_port = int(best["port"])
            old_tcp = dict(target.get("tcp") or {})
            new_tcp = dict(old_tcp)
            new_tcp["ipv4"] = new_port
            if target.get("ipv4") != new_host or target.get("tcp") != new_tcp:
                target["ipv4"] = new_host
                target["tcp"] = new_tcp
                changed = True
                trace_updated += 1
        if changed:
            with open(args.traceroute, "w", encoding="utf-8") as trf:
                json.dump(trace_doc, trf, ensure_ascii=True, indent=2)
                trf.write("\n")

    tcp_alive = sum(1 for e in pool_entries if e["tcp_ok"])
    icmp_alive = sum(1 for e in pool_entries if e["icmp_ok"])
    bgp_valid = sum(1 for e in pool_entries if e["bgp_ok"])
    defaults = sum(1 for t in published_targets if t.get("default"))
    print(
        f"tcping-collect: targets={len(published_targets)} defaults={defaults} "
        f"candidates={len(pool_entries)} tcp_ok={tcp_alive} icmp_ok={icmp_alive} "
        f"bgp_ok={bgp_valid} ipv6_probe={ipv6_capable} traceroute_updated={trace_updated}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
