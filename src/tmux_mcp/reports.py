# PYTHON_ARGCOMPLETE_OK
"""Abuse-pipeline reporting — MCP tool implementations and CLI.

Four tools expose the pipeline state and let the agent submit reports:

- ``abuse_get_pending(period?)`` — IPs still accumulating in ``pending/``
- ``abuse_get_staged(period?)`` — enriched reports ready to send in ``staged/``
- ``abuse_list_reported(period)`` — submitted archive (period required)
- ``abuse_send_report(filename)`` — POST to AbuseIPDB, archive to ``reported/``

Each tool returns a plain-text summary suitable for an LLM to read. Missing or
empty folders render a polite empty-state string — never an error.

The module is a library: tests drive these functions directly against temp
directories. ``server.py`` registers the thin ``@mcp.tool`` wrappers.

The ``cli_main`` entry point exposes the same submission surface as a shell
command (``tmux-mcp-report``) for operators who want to fire reports without
going through the MCP server.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import argcomplete
import httpx
from dotenv import load_dotenv

from tmux_mcp.enricher import promote_file


logger = logging.getLogger("tmux_mcp.reports")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/report"
ABUSEIPDB_TIMEOUT = 10.0

# Report filename pattern: {ip}-{YYYYMMDDTHHMMSSZ}.log — IPv6 colons already
# replaced with underscores upstream (see ratelimit.py).
_REPORTED_FILENAME_RE = re.compile(
    r"^(?P<ip>[^-]+(?:-[^-]+)*?)-(?P<ts>\d{8}T\d{6}Z)\.log$"
)
_REPORTED_TS_FMT = "%Y%m%dT%H%M%SZ"


# ── Empty-state strings (exact per issue #13 spec) ─────────────────────────

EMPTY_PENDING = "No scanning attempts available"
EMPTY_STAGED = "No staged error reports found"
EMPTY_REPORTED = "No reports filed"


# ── Period parser ──────────────────────────────────────────────────────────


def parse_period(period: str | None) -> datetime | None:
    """Parse a period spec into a UTC cutoff datetime.

    Accepts:
    - ``None`` or ``""`` → no filter (returns ``None``)
    - ``last_day`` → 24h ago
    - ``last_week`` → 7d ago
    - ``since:YYYY-MM-DD`` → midnight UTC of that date
    """
    if not period:
        return None
    now = datetime.now(timezone.utc)
    if period == "last_day":
        return now - timedelta(days=1)
    if period == "last_week":
        return now - timedelta(days=7)
    if period.startswith("since:"):
        try:
            d = datetime.strptime(period[6:], "%Y-%m-%d")
            return d.replace(tzinfo=timezone.utc)
        except ValueError as e:
            raise ValueError(
                f"invalid since: date '{period[6:]}' (expected YYYY-MM-DD)"
            ) from e
    raise ValueError(
        f"unknown period '{period}' (expected last_day, last_week, since:YYYY-MM-DD)"
    )


def _parse_iso_z(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── get_pending ─────────────────────────────────────────────────────────────


def get_pending(log_root: Path, period: str | None = None) -> str:
    cutoff = parse_period(period)
    pending = log_root / "pending"
    if not pending.is_dir():
        return EMPTY_PENDING

    rows: list[tuple[str, int, str]] = []
    for f in sorted(pending.glob("*.log")):
        try:
            lines = [ln for ln in f.read_text().splitlines() if ln.strip()]
        except OSError:
            continue
        if not lines:
            continue
        last_line = lines[-1]
        last_ts = last_line.split()[0] if last_line else ""
        if cutoff is not None:
            dt = _parse_iso_z(last_ts) or datetime.fromtimestamp(
                f.stat().st_mtime, timezone.utc
            )
            if dt < cutoff:
                continue
        ip = f.stem.replace("_", ":") if "_" in f.stem else f.stem
        rows.append((ip, len(lines), last_ts))

    if not rows:
        return EMPTY_PENDING

    header = f"{len(rows)} pending IP(s):"
    body = "\n".join(
        f"  {ip} — {count} entries, last seen {ts}" for ip, count, ts in rows
    )
    return f"{header}\n{body}"


# ── get_staged ─────────────────────────────────────────────────────────────


def _parse_staged_header(path: Path) -> dict | None:
    try:
        text = path.read_text()
    except OSError:
        return None
    head, _, _ = text.partition("\nRequests:\n")
    out: dict[str, str] = {}
    for line in head.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out if out else None


def get_staged(log_root: Path, period: str | None = None) -> str:
    cutoff = parse_period(period)
    staged = log_root / "staged"
    if not staged.is_dir():
        return EMPTY_STAGED

    rows: list[tuple[str, dict]] = []
    for f in sorted(staged.glob("*.log")):
        hdr = _parse_staged_header(f)
        if not hdr:
            continue
        last_seen = hdr.get("LastSeen", "")
        if cutoff is not None:
            dt = _parse_iso_z(last_seen) or datetime.fromtimestamp(
                f.stat().st_mtime, timezone.utc
            )
            if dt < cutoff:
                continue
        rows.append((f.name, hdr))

    if not rows:
        return EMPTY_STAGED

    header = f"{len(rows)} staged report(s):"
    lines = [header]
    for name, hdr in rows:
        lines.append(
            f"  {name} — {hdr.get('IP', '?')} | "
            f"{hdr.get('RIR', 'unknown')} | "
            f"cats={hdr.get('AbuseIPDB-Categories', 'none')} | "
            f"{hdr.get('RequestCount', '?')} requests | "
            f"last={hdr.get('LastSeen', '?')}"
        )
    return "\n".join(lines)


# ── list_reported ───────────────────────────────────────────────────────────


def list_reported(log_root: Path, period: str) -> str:
    if not period:
        raise ValueError("period is required for list_reported")
    cutoff = parse_period(period)
    reported = log_root / "reported"
    if not reported.is_dir():
        return EMPTY_REPORTED

    rows: list[tuple[str, datetime | None]] = []
    for f in sorted(reported.glob("*.log")):
        m = _REPORTED_FILENAME_RE.match(f.name)
        if not m:
            continue
        try:
            dt = datetime.strptime(m.group("ts"), _REPORTED_TS_FMT).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            dt = None
        if cutoff is not None and dt is not None and dt < cutoff:
            continue
        rows.append((f.name, dt))

    if not rows:
        return EMPTY_REPORTED

    header = f"{len(rows)} reported submission(s):"
    body = "\n".join(
        f"  {name} — submitted {dt.isoformat() if dt else '?'}" for name, dt in rows
    )
    return f"{header}\n{body}"


# ── send_report ─────────────────────────────────────────────────────────────


async def _submit_abuseipdb(
    client: httpx.AsyncClient,
    api_key: str,
    ip: str,
    categories: list[int],
    comment: str,
) -> tuple[bool, str]:
    """POST a report to AbuseIPDB. Returns (ok, message).

    Non-2xx responses are treated as submission failures; the caller should
    not archive the file so it stays available for retry. Network errors
    raise httpx exceptions — caller catches and formats.
    """
    try:
        r = await client.post(
            ABUSEIPDB_URL,
            data={
                "ip": ip,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment,
            },
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=ABUSEIPDB_TIMEOUT,
        )
    except httpx.HTTPError as e:
        return False, f"AbuseIPDB request failed: {e}"
    if r.status_code >= 400:
        return False, f"AbuseIPDB rejected submission (HTTP {r.status_code}): {r.text}"
    return True, f"AbuseIPDB accepted submission (HTTP {r.status_code})"


def _reported_name(ip: str) -> str:
    ts = datetime.now(timezone.utc).strftime(_REPORTED_TS_FMT)
    safe_ip = ip.replace(":", "_")
    return f"{safe_ip}-{ts}.log"


async def send_report(
    log_root: Path,
    filename: str,
    api_key: str | None,
    client: httpx.AsyncClient | None = None,
) -> str:
    if not api_key:
        return (
            "Cannot submit: TMUX_MCP_ABUSEIPDB_KEY is not set. "
            "Configure it and try again."
        )

    # Reject path traversal — filename must be a bare *.log, no slashes.
    if "/" in filename or "\\" in filename or not filename.endswith(".log"):
        return f"Invalid filename '{filename}': expected a bare *.log name."

    staged = log_root / "staged" / filename
    pending = log_root / "pending" / filename
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient()

    try:
        source = None
        if staged.exists():
            source = staged
        elif pending.exists():
            # Inline enrichment before submission.
            promoted = await promote_file(
                pending, log_root / "staged", log_root / "saved", client
            )
            if promoted is None:
                return f"File '{filename}' is empty or malformed."
            if promoted.parent.name != "staged":
                return (
                    f"File '{filename}' enriched to {promoted.parent.name}/ — "
                    "no AbuseIPDB categories detected, cannot submit."
                )
            source = promoted
        else:
            return (
                f"File '{filename}' not found in staged/ or pending/. "
                "Check abuse_get_staged / abuse_get_pending."
            )

        hdr = _parse_staged_header(source) or {}
        ip = hdr.get("IP")
        if not ip:
            return f"Staged file '{source.name}' has no IP header — cannot submit."
        cats_str = hdr.get("AbuseIPDB-Categories", "")
        try:
            categories = [
                int(c) for c in cats_str.split(",") if c.strip() and c != "none"
            ]
        except ValueError:
            categories = []
        if not categories:
            return (
                f"Staged file '{source.name}' has no categories — nothing to "
                "submit. Re-run the enricher or edit the header."
            )

        comment = (
            f"Automated report from tmux-mcp abuse pipeline. "
            f"RequestCount={hdr.get('RequestCount', '?')}, "
            f"FirstSeen={hdr.get('FirstSeen', '?')}, "
            f"LastSeen={hdr.get('LastSeen', '?')}."
        )
        ok, message = await _submit_abuseipdb(client, api_key, ip, categories, comment)
        if not ok:
            return f"{message}\nFile left in place for retry: {source}"

        # Archive — move staged → reported. Only after a successful submit.
        reported_dir = log_root / "reported"
        reported_dir.mkdir(parents=True, exist_ok=True)
        dest = reported_dir / _reported_name(ip)
        shutil.move(str(source), str(dest))
        logger.info("reported ip=%s categories=%s -> %s", ip, categories, dest.name)
        return f"{message}\nArchived to {dest.name}."
    finally:
        if owns_client:
            await client.aclose()


# ── CLI ─────────────────────────────────────────────────────────────────────


def _list_staged(log_root: Path) -> str:
    staged = log_root / "staged"
    if not staged.is_dir():
        return EMPTY_STAGED
    files = sorted(
        f.name for f in staged.iterdir() if f.is_file() and f.suffix == ".log"
    )
    if not files:
        return EMPTY_STAGED
    return "\n".join(files)


async def _send_many(log_root: Path, filenames: list[str], api_key: str | None) -> int:
    """Submit each filename in turn. Returns 0 if all succeeded, 1 otherwise."""
    failures = 0
    async with httpx.AsyncClient() as client:
        for fn in filenames:
            print(f"=== {fn} ===")
            result = await send_report(log_root, fn, api_key, client=client)
            print(result)
            print()
            # send_report returns a string; submission failure paths all
            # contain "Cannot", "Invalid", "not found", "rejected", or
            # "request failed" — anything that isn't a successful HTTP 200
            # archive. The successful path always says "Archived to".
            if "Archived to" not in result:
                failures += 1
    return 0 if failures == 0 else 1


def _staged_completer(prefix: str, **_kwargs) -> list[str]:
    """argcomplete completer that lists matching staged filenames.

    Reads ``TMUX_MCP_LOG_DIR`` directly (no .env load) so completion stays
    fast and side-effect-free.
    """
    log_root = Path(os.environ.get("TMUX_MCP_LOG_DIR", "./logs")).expanduser()
    staged = log_root / "staged"
    if not staged.is_dir():
        return []
    return [
        f.name
        for f in staged.iterdir()
        if f.is_file() and f.suffix == ".log" and f.name.startswith(prefix)
    ]


def cli_main() -> int:
    """Console-script entry point for ``tmux-mcp-report``."""
    parser = argparse.ArgumentParser(
        prog="tmux-mcp-report",
        description="Submit staged abuse reports to AbuseIPDB.",
    )
    group = parser.add_mutually_exclusive_group()
    filename_arg = group.add_argument(
        "filename",
        nargs="?",
        help="Bare *.log filename in logs/staged/ (e.g. 1.2.3.4.log).",
    )
    filename_arg.completer = _staged_completer  # type: ignore[attr-defined]
    group.add_argument(
        "--all",
        action="store_true",
        help="Submit every staged file in turn.",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List staged filenames and exit.",
    )
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    load_dotenv()
    log_root = Path(os.environ.get("TMUX_MCP_LOG_DIR", "./logs")).expanduser()
    api_key = os.environ.get("TMUX_MCP_ABUSEIPDB_KEY")

    if args.list:
        print(_list_staged(log_root))
        return 0

    if args.all:
        staged = log_root / "staged"
        if not staged.is_dir():
            print(EMPTY_STAGED)
            return 0
        files = sorted(
            f.name for f in staged.iterdir() if f.is_file() and f.suffix == ".log"
        )
        if not files:
            print(EMPTY_STAGED)
            return 0
        return asyncio.run(_send_many(log_root, files, api_key))

    if not args.filename:
        parser.error("provide a filename, --all, or --list")

    return asyncio.run(_send_many(log_root, [args.filename], api_key))


if __name__ == "__main__":
    sys.exit(cli_main())
