#!/usr/bin/env python3
"""Collects, merges, and health-probes CAICT GlobalSpeed (Taier) nodes.

Combines two complementary mechanisms without external dependencies:
1. Direct official directory collection from CAICT control servers (`ConfigMD5.php` ->
   `serverlist_encrypt.json` for IPv4 and `serverlist_encrypt_v6.json` for IPv6, verified by MD5
   and decoded with the public open-source 8-byte DES directory key), merged with
   `transflo/speedtaier`'s public export as an additional feed.
2. Incremental candidate pool (`servers/taier-pool.json`) + concurrent zero-traffic `dovalid`
   handshake probing (with immediate `POST /speed/dovalid?key=<uuid>` lease release) to rank live
   responsive nodes (`tier=0`) ahead of busy (`tier=1`) and unreachable (`tier=2`) nodes, evicting
   persistently dead duplicates after `MAX_FAILURES` consecutive failed runs.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import random
import ssl
import sys
import time
import urllib.parse
import urllib.request

CONTROL_BASES = (
    "https://dlcv2.cnspeedtest.cn:8443",
    "http://dlc.duoweisoft.com:8096",
    "http://dlcv2.duoweisoft.com:8088",
)
FALLBACK_EXPORT_URL = (
    "https://raw.githubusercontent.com/transflo/speedtaier/main/serverlist_decrypted.json"
)
DIRECTORY_KEY = b"dw!@#$%^"
RAND_CONST = "12345555"
APP = "globalspeed"
PKG = "com.cnspeedtest.globalspeed"
UA_CONTROL = "Dalvik/2.1.0 (Linux; U; Android 14; NE2210 Build/TP1A.220624.014)"
MAX_FAILURES = 14
PROBE_WORKERS = 48
PROBE_TIMEOUT_SECS = 3.5

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_S = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 2, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 4, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]
# Fix standard FIPS 46-3 S4[0][13]=12 and S6[2][1]=14 entries explicitly:
_S[3][13] = 12
_S[5][33] = 14

_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _int64_permute(val: int, table: list[int], in_bits: int) -> int:
    out = 0
    for pos in table:
        out = (out << 1) | ((val >> (in_bits - pos)) & 1)
    return out


def _des_subkeys(key8: bytes) -> list[int]:
    k64 = int.from_bytes(key8, "big")
    k56 = _int64_permute(k64, _PC1, 64)
    c = (k56 >> 28) & 0x0FFFFFFF
    d = k56 & 0x0FFFFFFF
    subkeys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_int64_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _feistel(r32: int, subkey48: int) -> int:
    x48 = _int64_permute(r32, _E, 32) ^ subkey48
    s_out = 0
    for i in range(8):
        b6 = (x48 >> (42 - i * 6)) & 0x3F
        row = ((b6 >> 4) & 2) | (b6 & 1)
        col = (b6 >> 1) & 0x0F
        s_out = (s_out << 4) | _S[i][row * 16 + col]
    return _int64_permute(s_out, _P, 32)


def des_ecb_decrypt(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError("invalid DES ciphertext length")
    rev_keys = list(reversed(_des_subkeys(key8)))
    out = bytearray(len(ciphertext))
    for off in range(0, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[off : off + 8], "big")
        ip = _int64_permute(block, _IP, 64)
        left = (ip >> 32) & 0xFFFFFFFF
        right = ip & 0xFFFFFFFF
        for sk in rev_keys:
            left, right = right, left ^ _feistel(right, sk)
        fp = _int64_permute((right << 32) | left, _FP, 64)
        out[off : off + 8] = fp.to_bytes(8, "big")
    return bytes(out)


def decode_directory(hex_bytes: bytes) -> list[dict]:
    hex_bytes = hex_bytes.strip()
    raw = des_ecb_decrypt(bytes.fromhex(hex_bytes.decode("ascii")), DIRECTORY_KEY)
    pad = raw[-1]
    if pad < 1 or pad > 8 or any(b != pad for b in raw[-pad:]):
        raise ValueError("invalid outer PKCS#5 padding")
    raw = raw[:-pad]
    if raw and 1 <= raw[-1] < 8:
        inner = raw[-1]
        if len(raw) >= inner and all(b == inner for b in raw[-inner:]):
            raw = raw[:-inner]
    raw = raw.rstrip(b"\x00\t\n\r ")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("decoded directory is empty")
    return parsed


def http_get_bytes(url: str, timeout: float = 20.0, insecure_caict_tls: bool = False) -> bytes:
    ctx = None
    if url.startswith("https://") and insecure_caict_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA_CONTROL})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read(8 * 1024 * 1024)


def fetch_official_catalog(ipv6: bool) -> list[dict]:
    flag = "1" if ipv6 else "0"
    want_name = "serverlist_encrypt" if ipv6 else "serverlist_encrypt_url"
    query = urllib.parse.urlencode(
        {
            "province": "",
            "city": "",
            "imei": "",
            "appname": "GlobalSpeed",
            "vercode": "40408",
            "type": APP,
            "ipv6": flag,
        }
    )
    last_err: Exception | None = None
    for base in CONTROL_BASES:
        try:
            idx_raw = http_get_bytes(
                f"{base}/TaierAndroid/Config/ConfigMD5.php?{query}",
                timeout=12.0,
                insecure_caict_tls=True,
            )
            entries = json.loads(idx_raw.decode("utf-8", "replace"))
            by_name = {e.get("name"): e for e in entries if isinstance(e, dict)}
            base_url_entry = by_name.get("serverlist_encrypt_url") or {}
            base_dl = str(base_url_entry.get("filename", "")).rsplit("/", 1)[0]
            if ipv6:
                entry = by_name.get("serverlist_encrypt") or {}
                fname = str(entry.get("filename", "serverlist_encrypt_v6.json"))
                dl_url = fname if fname.startswith("http") else f"{base_dl}/{fname}"
                expected_md5 = str(entry.get("md5", "")).lower()
            else:
                entry = base_url_entry
                dl_url = str(entry.get("filename", ""))
                expected_md5 = str(entry.get("md5", "")).lower()
            if not dl_url:
                raise RuntimeError("missing download URL in ConfigMD5.php")
            enc = http_get_bytes(dl_url, timeout=20.0, insecure_caict_tls=True).strip()
            got_md5 = hashlib.md5(enc).hexdigest().lower()
            if expected_md5 and got_md5 != expected_md5:
                raise RuntimeError(f"MD5 mismatch: {got_md5} != {expected_md5}")
            rows = decode_directory(enc)
            out = []
            for n in rows:
                out.append(
                    {
                        "ip": str(n.get("hostip", "")).strip(),
                        "port": str(n.get("port", "65499")).strip(),
                        "name": str(n.get("hostname", "")).strip(),
                        "p": str(n.get("pname", "")).strip(),
                        "c": str(n.get("location", "")).strip(),
                        "o": str(n.get("oper", "")).strip(),
                    }
                )
            return out
        except Exception as err:
            last_err = err
    raise RuntimeError(f"official catalog fetch failed (ipv6={ipv6}): {last_err}")


def make_luhn_imei(rng: random.Random) -> str:
    body = "86309606" + f"{rng.randint(0, 999999):06d}"
    total = 0
    for idx, ch in enumerate(reversed(body)):
        d = int(ch)
        if idx % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - (total % 10)) % 10)


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("ascii")).hexdigest()


def probe_dovalid(ip: str, port: int, imei: str) -> int:
    """Returns liveness tier: 0 = READY (1-<uuid>), 1 = BUSY/HTTP-200, 2 = UNREACHABLE."""
    ts = int(time.time())
    h1 = md5_hex(f"model=Android&imei={imei}")
    h2 = md5_hex(f"stime={ts}&band=200&rand={RAND_CONST}")
    tok = md5_hex(f"{h1}{h2}")
    path = (
        f"/speed/dovalid?key=&flag=true&bandwidth=200&model=Android"
        f"&imei={imei}&time={ts}&app={APP}&token={tok}&pkg={PKG}"
    )
    try:
        req = urllib.request.Request(
            f"http://{ip}:{port}{path}",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT_SECS) as resp:
            if resp.status != 200:
                return 2
            body = resp.read(256).decode("utf-8", "replace").strip()
        if body.startswith("1-"):
            lease = body[2:].strip()
            if lease:
                rel = urllib.request.Request(
                    f"http://{ip}:{port}/speed/dovalid?key={lease}",
                    data=b"",
                    method="POST",
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                try:
                    urllib.request.urlopen(rel, timeout=2.0).close()
                except Exception:
                    pass
            return 0
        return 1
    except Exception:
        return 2


def valid_public_ip(raw: str, version: int) -> str | None:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if addr.version != version or not addr.is_global or addr.is_multicast:
        return None
    return addr.compressed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", default="servers/taier-pool.json")
    parser.add_argument("--ipv6-out", default="servers/taier-ipv6.json")
    parser.add_argument("--export-out", required=True)
    parser.add_argument("--no-probe", action="store_true")
    args = parser.parse_args()

    sources_used: list[str] = []
    fresh_v4: list[dict] = []
    try:
        fresh_v4.extend(fetch_official_catalog(ipv6=False))
        sources_used.append("caict-official-v4")
    except Exception as err:
        print(f"taier-collect: warning: {err}", file=sys.stderr)

    try:
        raw_fb = http_get_bytes(FALLBACK_EXPORT_URL, timeout=20.0)
        fb_nodes = json.loads(raw_fb.decode("utf-8"))
        if isinstance(fb_nodes, list):
            fresh_v4.extend(fb_nodes)
            sources_used.append("speedtaier-fallback")
    except Exception as err:
        print(f"taier-collect: warning: fallback fetch failed: {err}", file=sys.stderr)

    if len(fresh_v4) < 50:
        print("taier-collect: fewer than 50 fresh IPv4 nodes collected; aborting", file=sys.stderr)
        return 1

    # Collect official IPv6 catalog when reachable.
    try:
        fresh_v6 = fetch_official_catalog(ipv6=True)
        clean_v6 = []
        seen_v6: set[str] = set()
        for n in fresh_v6:
            ip6 = valid_public_ip(str(n.get("ip", "")), 6)
            try:
                port = int(str(n.get("port", "65499")))
            except ValueError:
                continue
            if not ip6 or not (1024 <= port <= 65535):
                continue
            ep = f"[{ip6}]:{port}"
            if ep in seen_v6:
                continue
            seen_v6.add(ep)
            clean_v6.append(
                {
                    "ip": ip6,
                    "port": port,
                    "name": str(n.get("name", "")),
                    "p": str(n.get("p", "")),
                    "c": str(n.get("c", "")),
                    "o": str(n.get("o", "")),
                }
            )
        clean_v6.sort(key=lambda x: (x["p"], x["c"], x["o"], x["ip"], x["port"]))
        if len(clean_v6) >= 20:
            with open(args.ipv6_out, "w", encoding="utf-8") as f6:
                json.dump({"version": 1, "nodes": clean_v6}, f6, ensure_ascii=False, indent=2)
                f6.write("\n")
            sources_used.append(f"caict-official-v6({len(clean_v6)})")
    except Exception as err:
        print(f"taier-collect: warning: IPv6 catalog skipped: {err}", file=sys.stderr)

    # Load historical pool and merge fresh IPv4 nodes.
    pool: dict[str, dict] = {}
    if os.path.isfile(args.pool):
        try:
            with open(args.pool, encoding="utf-8") as pf:
                loaded = json.load(pf)
            for item in loaded.get("nodes", []):
                ep = f"{item['ip']}:{item['port']}"
                pool[ep] = item
        except Exception as err:
            print(f"taier-collect: warning: ignoring unreadable pool: {err}", file=sys.stderr)

    seen_in_upstream: set[str] = set()
    for n in fresh_v4:
        ip4 = valid_public_ip(str(n.get("ip", "")).strip(), 4)
        try:
            port = int(str(n.get("port", "65499")).strip())
        except ValueError:
            continue
        if not ip4 or not (1024 <= port <= 65535):
            continue
        ep = f"{ip4}:{port}"
        seen_in_upstream.add(ep)
        prev = pool.get(ep, {})
        pool[ep] = {
            "ip": ip4,
            "port": port,
            "name": str(n.get("name") or prev.get("name") or "").strip(),
            "p": str(n.get("p") or prev.get("p") or "").strip(),
            "c": str(n.get("c") or prev.get("c") or "").strip(),
            "o": str(n.get("o") or prev.get("o") or "").strip(),
            "tier": int(prev.get("tier", 1)),
            "failures": int(prev.get("failures", 0)),
        }

    # Concurrent zero-traffic dovalid health probe across all pooled endpoints.
    if not args.no_probe:
        rng = random.Random(int(time.time()))
        endpoints = sorted(pool.keys())
        imeis = [make_luhn_imei(rng) for _ in endpoints]

        def _probe_one(pair: tuple[str, str]) -> tuple[str, int]:
            ep, imei = pair
            entry = pool[ep]
            return ep, probe_dovalid(entry["ip"], int(entry["port"]), imei)

        with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
            for ep, tier in ex.map(_probe_one, zip(endpoints, imeis)):
                entry = pool[ep]
                entry["tier"] = tier
                if tier in (0, 1):
                    entry["failures"] = 0
                else:
                    entry["failures"] = min(MAX_FAILURES, int(entry.get("failures", 0)) + 1)

    # Group by (p, c, o) so we never evict the sole node of a slot, only dead duplicates/stale nodes.
    slot_counts: dict[tuple[str, str, str], int] = {}
    for entry in pool.values():
        key = (entry["p"], entry["c"], entry["o"])
        slot_counts[key] = slot_counts.get(key, 0) + 1

    kept: list[dict] = []
    evicted = 0
    for ep in sorted(pool.keys()):
        entry = pool[ep]
        slot_key = (entry["p"], entry["c"], entry["o"])
        if (
            entry["failures"] >= MAX_FAILURES
            and ep not in seen_in_upstream
            and slot_counts[slot_key] > 1
        ):
            slot_counts[slot_key] -= 1
            evicted += 1
            continue
        kept.append(entry)

    kept.sort(key=lambda x: (x["p"], x["c"], x["o"], x["tier"], x["ip"], x["port"]))
    with open(args.pool, "w", encoding="utf-8") as pf:
        json.dump({"version": 1, "nodes": kept}, pf, ensure_ascii=False, indent=2)
        pf.write("\n")

    export_rows = [
        {
            "ip": e["ip"],
            "port": str(e["port"]),
            "name": e["name"],
            "p": e["p"],
            "c": e["c"],
            "o": e["o"],
            "tier": e["tier"],
        }
        for e in kept
    ]
    with open(args.export_out, "w", encoding="utf-8") as ef:
        json.dump(export_rows, ef, ensure_ascii=False, indent=2)
        ef.write("\n")

    t0 = sum(1 for e in kept if e["tier"] == 0)
    t1 = sum(1 for e in kept if e["tier"] == 1)
    t2 = sum(1 for e in kept if e["tier"] == 2)
    print(
        f"taier-collect: sources={','.join(sources_used)} total={len(kept)} "
        f"ready={t0} busy={t1} unreachable={t2} evicted={evicted}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
