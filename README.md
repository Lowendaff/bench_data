# bench_data

Companion data and static tool release repository for
[`lowendaff_bench`](https://github.com/Lowendaff/lowendaff_bench).

## Contents

- `servers/` — Runtime node and exchange lists downloaded over HTTPS by `lowendaff-bench`:
  - `servers/iperf3-candidates.json` & `servers/iperf3.json` — Reviewed `network.iperf3` server
    candidates and the active list refreshed twice daily from `iperf3serverlist.net`.
  - `servers/taier.json`, `servers/taier-pool.json` & `servers/taier-ipv6.json` — Normalized ASCII
    CAICT GlobalSpeed (`network.taier`) carrier nodes across China, collected directly from CAICT's
    official directory (`ConfigMD5.php` + MD5-verified DES directory) merged with public feeds,
    maintained in an incremental historical pool, and ranked twice daily by concurrent zero-traffic
    `dovalid` liveness probing (`scripts/taier-collect.py`).
  - `servers/traceroute.json` — Curated `network.trace` targets across China and international
    routes.
  - `servers/netflix-ix.json` — Netflix internet exchange peering ports (`net_id=457` from
    PeeringDB) used by `network.trace` to annotate IX hops, refreshed twice daily.
- `scripts/build-*.sh` & `.github/workflows/tools.yml` — Reproducible static Linux (`x86_64` and
  `aarch64`) build scripts for open-source benchmark tools (`7zip`, `fio`, `hpl`, `iperf3`,
  `multichase`, `nexttrace`, `passmark-libs`, `smartctl`, `stream`, `sysbench`, `unixbench`),
  published with full source archives, license notices, and `SHA256SUMS` as GitHub releases of this
  repository.
- `scripts/{iperf3-servers,taier-servers,traceroute-targets,netflix-ix}.sh` & `tests/fixtures/` —
  Validation and update scripts with edge-case test suites shared with `lowendaff_bench` readers.

## License

MIT (`LICENSE`). Published tool releases carry the upstream source archives and license texts of
each tool and statically linked library (`COPYING-*`, `COPYRIGHT-*`, `LICENSE-*`).
