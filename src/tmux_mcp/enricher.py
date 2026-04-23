"""Abuse pipeline — watches ``pending/``, debounces, enriches, moves to ``staged/``.

When a per-IP file under ``pending/`` has been quiet for ``quiet_seconds``
(default 60s), enrich it with:

- **ASN + holder** (via RIPE Stat ``prefix-overview``)
- **Country** (via RIPE Stat ``geoloc``)
- **RIR** (derived from country code — static lookup)
- **AbuseIPDB categories** (heuristic on request paths)
- **FirstSeen / LastSeen / RequestCount**

and move it to ``staged/``. If any RIPE lookup fails, the corresponding field
is left as ``unknown`` — enrichment never blocks the pipeline.

The watcher is a pure poll loop (5s tick). No ``watchdog`` dependency, no
inotify — keeps the code portable and testable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv


logger = logging.getLogger("tmux_mcp.enricher")

# ── RIPE Stat endpoints ─────────────────────────────────────────────────────

_RIPE_BASE = "https://stat.ripe.net/data"
_PREFIX_URL = f"{_RIPE_BASE}/prefix-overview/data.json"
_GEOLOC_URL = f"{_RIPE_BASE}/geoloc/data.json"
_RIPE_TIMEOUT = 5.0

# ── AbuseIPDB categories ────────────────────────────────────────────────────

CATEGORY_BRUTE_FORCE = 18
CATEGORY_WEB_APP_ATTACK = 19
CATEGORY_PORT_SCAN = 21

# Regex probes for common exploit paths — web-app-attack heuristic.
# Intentionally broad so we catch payment-form scanners, WP/phpMyAdmin probes,
# dotfile exfil attempts, and webshell drops.
_WEB_ATTACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/wp-(login|admin|config|content)", re.I),
    re.compile(r"/phpmyadmin", re.I),
    re.compile(r"/\.env(\.|$)"),
    re.compile(r"/\.(git|svn|hg|DS_Store)(/|$)"),
    re.compile(r"/(admin|administrator|manage|console)(\.php|/|$)", re.I),
    re.compile(r"/(shell|cmd|phpshell|r57|c99|webshell)\.(php|jsp|asp)", re.I),
    re.compile(r"\.(bak|sql|log|env|old)$", re.I),
    re.compile(
        r"/(cart|checkout|payment|billing|order).*(cc|card|ccnum|cvv|cvc|expir|"
        r"security.?code|pan)",
        re.I,
    ),
    re.compile(r"/api/v\d+/admin", re.I),
    re.compile(r"/(xmlrpc|wlwmanifest|wp-includes)", re.I),
    re.compile(r"/config\.(json|yaml|yml|php|ini)$", re.I),
)

# Country ISO-3166 alpha-2 → RIR. Not perfect (legacy space can cross RIRs) but
# a reasonable default for routing abuse reports. Default ARIN for anything not
# listed.
_COUNTRY_TO_RIR: dict[str, str] = {
    # RIPE NCC — Europe + Middle East + Central Asia
    **dict.fromkeys(
        "AD AE AL AM AT AZ BA BE BG BH BY CH CY CZ DE DK EE ES FI FO FR GB GE GG "
        "GI GR HR HU IE IL IM IQ IR IS IT JE JO KG KW KZ LB LI LT LU LV MC MD ME "
        "MK MT NL NO OM PL PS PT QA RO RS RU SA SE SI SJ SK SM SY TJ TM TR UA UZ "
        "VA XK YE".split(),
        "RIPE NCC",
    ),
    # APNIC — Asia-Pacific
    **dict.fromkeys(
        "AF AS AU BD BN BT CC CK CN CX FJ FM GU HK ID IN JP KH KI KP KR LA LK MH "
        "MM MN MO MP MV MY NC NF NP NR NU NZ PF PG PH PK PN PW SB SG TH TK TL TO "
        "TV TW VN VU WF WS".split(),
        "APNIC",
    ),
    # LACNIC — Latin America + Caribbean
    **dict.fromkeys(
        "AG AI AR AW BB BL BM BO BQ BR BS BZ CL CO CR CU CW DM DO EC FK GD GF GP "
        "GT GY HN HT JM KN KY LC MF MQ MS MX NI PA PE PY SR SV SX TC TT UY VC VE "
        "VG VI".split(),
        "LACNIC",
    ),
    # AFRINIC — Africa
    **dict.fromkeys(
        "AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN GQ GW KE "
        "KM LR LS LY MA MG ML MR MU MW MZ NA NE NG RE RW SC SD SH SL SN SO SS ST "
        "SZ TD TG TN TZ UG YT ZA ZM ZW".split(),
        "AFRINIC",
    ),
}

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<ip>\S+)\s+(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<status>\d+)$"
)


# ── Public data shapes ──────────────────────────────────────────────────────


def parse_log_line(line: str) -> dict | None:
    m = _LINE_RE.match(line.strip())
    return m.groupdict() if m else None


def rir_for_country(country: str | None) -> str:
    if not country:
        return "unknown"
    return _COUNTRY_TO_RIR.get(country.upper(), "ARIN")


def report_to(rir: str) -> str:
    """Comma-separated entity list. AbuseIPDB is always included."""
    if rir and rir != "unknown":
        return f"AbuseIPDB, {rir}"
    return "AbuseIPDB"


# ── Categorization ──────────────────────────────────────────────────────────


def _is_web_app_attack(path: str) -> bool:
    return any(p.search(path) for p in _WEB_ATTACK_PATTERNS)


def detect_categories(requests: list[dict]) -> list[int]:
    """Return AbuseIPDB category IDs triggered by this request set.

    - **19 Web App Attack**: any single request hits an exploit pattern.
    - **21 Port Scan**: ≥ 3 distinct paths (sign of broad probing).
    - **18 Brute Force**: ≥ 5 requests to the same path.
    """
    cats: set[int] = set()
    if any(_is_web_app_attack(r["path"]) for r in requests):
        cats.add(CATEGORY_WEB_APP_ATTACK)

    paths = [r["path"] for r in requests]
    if len(set(paths)) >= 3:
        cats.add(CATEGORY_PORT_SCAN)

    if any(c >= 5 for c in Counter(paths).values()):
        cats.add(CATEGORY_BRUTE_FORCE)

    return sorted(cats)


# ── RIPE Stat lookups ───────────────────────────────────────────────────────


async def _ripe_lookup(client: httpx.AsyncClient, ip: str) -> dict:
    """Query RIPE Stat for ASN + country. Returns a dict with whatever fields
    succeeded; missing lookups leave their keys unset.
    """
    out: dict[str, str] = {}

    async def _prefix():
        try:
            r = await client.get(
                _PREFIX_URL, params={"resource": ip}, timeout=_RIPE_TIMEOUT
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            asns = data.get("asns") or []
            if asns:
                asn = asns[0]
                out["asn"] = f"AS{asn['asn']}"
                holder = asn.get("holder")
                if holder:
                    out["asn_holder"] = holder
        except Exception as e:  # any network / parse failure — graceful skip
            logger.info("RIPE prefix-overview failed for %s: %s", ip, e)

    async def _geo():
        try:
            r = await client.get(
                _GEOLOC_URL, params={"resource": ip}, timeout=_RIPE_TIMEOUT
            )
            r.raise_for_status()
            locs = r.json().get("data", {}).get("locations") or []
            if locs:
                country = locs[0].get("country")
                if country:
                    out["country"] = country.upper()
        except Exception as e:  # any network / parse failure — graceful skip
            logger.info("RIPE geoloc failed for %s: %s", ip, e)

    await asyncio.gather(_prefix(), _geo())
    return out


# ── Promote one pending file ────────────────────────────────────────────────


async def promote_file(
    pending_path: Path,
    staged_dir: Path,
    client: httpx.AsyncClient,
) -> Path | None:
    """Read a pending file, enrich it, write the staged file, delete pending.

    Returns the staged path on success, ``None`` if the file is empty or
    malformed.
    """
    try:
        lines = [ln for ln in pending_path.read_text().splitlines() if ln.strip()]
    except OSError as e:
        logger.warning("cannot read pending file %s: %s", pending_path, e)
        return None

    requests: list[dict] = []
    ip: str | None = None
    for ln in lines:
        parsed = parse_log_line(ln)
        if not parsed:
            continue
        if ip is None:
            ip = parsed["ip"]
        requests.append(parsed)

    if not requests or ip is None:
        logger.info("skipping empty or malformed pending file: %s", pending_path)
        pending_path.unlink(missing_ok=True)
        return None

    ripe = await _ripe_lookup(client, ip)
    asn = ripe.get("asn", "unknown")
    holder = ripe.get("asn_holder")
    asn_field = f"{asn} ({holder})" if holder else asn
    country = ripe.get("country", "unknown")
    rir = rir_for_country(ripe.get("country"))
    cats = detect_categories(requests)
    first_seen = requests[0]["ts"]
    last_seen = requests[-1]["ts"]

    staged_dir.mkdir(parents=True, exist_ok=True)
    staged_path = staged_dir / pending_path.name
    header = (
        f"IP: {ip}\n"
        f"ASN: {asn_field}\n"
        f"Country: {country}\n"
        f"RIR: {rir}\n"
        f"ReportTo: {report_to(rir)}\n"
        f"AbuseIPDB-Categories: {','.join(str(c) for c in cats) or 'none'}\n"
        f"FirstSeen: {first_seen}\n"
        f"LastSeen: {last_seen}\n"
        f"RequestCount: {len(requests)}\n"
        f"\n"
        f"Requests:\n"
    )
    body = "\n".join(
        f"{r['ts']} {r['method']} {r['path']} {r['status']}" for r in requests
    )
    staged_path.write_text(header + body + "\n")
    pending_path.unlink(missing_ok=True)
    logger.info(
        "staged %s ip=%s requests=%d categories=%s",
        staged_path.name,
        ip,
        len(requests),
        cats,
    )
    return staged_path


# ── Watcher loop ────────────────────────────────────────────────────────────


async def run_watcher(
    pending_dir: Path,
    staged_dir: Path,
    *,
    quiet_seconds: float = 60.0,
    tick_seconds: float = 5.0,
    client: httpx.AsyncClient | None = None,
) -> None:
    """Poll ``pending_dir`` forever; promote any file idle for ``quiet_seconds``.

    If ``client`` is None, an internal ``httpx.AsyncClient`` is created.
    """
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient()
    logger.info(
        "enricher watcher started pending=%s staged=%s quiet=%.0fs tick=%.0fs",
        pending_dir,
        staged_dir,
        quiet_seconds,
        tick_seconds,
    )
    try:
        while True:
            try:
                await _tick(pending_dir, staged_dir, quiet_seconds, client)
            except Exception as e:  # defensive — never let the loop die
                logger.warning("enricher tick failed: %s", e)
            await asyncio.sleep(tick_seconds)
    finally:
        if owns_client:
            await client.aclose()


# ── CLI entry point ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the enricher as a standalone process.

    Reads ``TMUX_MCP_LOG_DIR`` (default ``./logs``) and watches ``pending/``
    forever. Runs independently of the MCP server — start it alongside via
    systemd, supervisor, tmux, or anything else.
    """
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log_root = Path(os.environ.get("TMUX_MCP_LOG_DIR", "./logs")).expanduser()
    pending = log_root / "pending"
    staged = log_root / "staged"
    print(f"tmux-mcp-enricher: watching {pending} → {staged}")
    try:
        asyncio.run(run_watcher(pending, staged))
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()


async def _tick(
    pending_dir: Path,
    staged_dir: Path,
    quiet_seconds: float,
    client: httpx.AsyncClient,
) -> None:
    if not pending_dir.is_dir():
        return
    now = datetime.now(timezone.utc).timestamp()
    for entry in pending_dir.iterdir():
        if not entry.is_file() or not entry.name.endswith(".log"):
            continue
        try:
            mtime = entry.stat().st_mtime
        except FileNotFoundError:
            continue
        if now - mtime < quiet_seconds:
            continue
        await promote_file(entry, staged_dir, client)
