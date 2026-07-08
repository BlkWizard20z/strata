#!/usr/bin/env python3
"""
fetch_threatfox.py

Pulls RECENT indicators of compromise (IOCs) from ThreatFox (abuse.ch), groups
them by malware family, ranks families by how many IOCs each has, and writes:
  1. data/threatfox/latest.json  -- current snapshot the dashboard reads
  2. data/threatfox/YYYY-MM-DD.json -- dated history (CI only, like the KEV fetcher)

Requires a free ThreatFox Auth-Key (https://auth.abuse.ch/), provided via the
THREATFOX_AUTH_KEY environment variable:
  - Locally: put it in a .env file (already gitignored).
  - In GitHub Actions: store it as an encrypted repository secret.

Docs: https://threatfox.abuse.ch/api/
"""

import json
import os
import sys
import urllib.request
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

import certifi

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# How many days of recent IOCs to pull. ThreatFox allows a maximum of 7.
DAYS = 7

# How many top IOCs to keep per family in the summary.
TOP_IOCS_PER_FAMILY = 5

DATA_DIR = Path("data/threatfox")
LATEST_PATH = DATA_DIR / "latest.json"


def load_env(path: str = ".env") -> None:
    """Minimal .env loader so we don't need the python-dotenv dependency.

    Reads simple KEY=VALUE lines into the environment (skipping blanks and
    # comments). Uses setdefault so a value already set in the real environment
    (e.g. a GitHub Actions secret) always wins over the .env file.
    """
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Strip surrounding quotes if the user wrote KEY="value".
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_auth_key() -> str:
    """Return the ThreatFox Auth-Key, or exit with a clear message if missing."""
    key = os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        print(
            "ERROR: THREATFOX_AUTH_KEY is not set.\n"
            "  - Locally: add THREATFOX_AUTH_KEY=your-key to a .env file.\n"
            "  - In CI: add it as a GitHub repository secret.\n"
            "  Get a free key at https://auth.abuse.ch/",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


def fetch_recent_iocs(auth_key: str, days: int) -> list:
    """POST to ThreatFox for all IOCs added in the last `days` days."""
    payload = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,  # supplying data makes urllib send a POST instead of a GET
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
            "User-Agent": "strata/0.1 (personal security research project)",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    status = result.get("query_status")
    if status != "ok":
        # e.g. "no_result" (nothing in window) or an auth/format error.
        if status == "no_result":
            return []
        raise RuntimeError(f"ThreatFox API returned query_status={status!r}")
    return result.get("data", [])


def group_by_family(iocs: list) -> dict:
    """Bucket a flat list of IOCs into {family_name: [iocs...]}."""
    families = defaultdict(list)
    for ioc in iocs:
        # Prefer the human-readable name; fall back to the raw name, then Unknown.
        name = ioc.get("malware_printable") or ioc.get("malware") or "Unknown"
        families[name].append(ioc)
    return families


def summarize_families(families: dict) -> list:
    """Turn the grouped IOCs into ranked per-family summary objects."""
    summaries = []
    for name, iocs in families.items():
        # Count IOCs by type (url, domain, ip:port, sha256_hash, etc.).
        type_counts = defaultdict(int)
        for ioc in iocs:
            type_counts[ioc.get("ioc_type", "unknown")] += 1

        # Top IOCs: highest confidence first, then most recently seen.
        top = sorted(
            iocs,
            key=lambda x: (x.get("confidence_level", 0), x.get("first_seen", "")),
            reverse=True,
        )[:TOP_IOCS_PER_FAMILY]
        top_iocs = [
            {
                "ioc": i.get("ioc"),
                "type": i.get("ioc_type"),
                "confidence": i.get("confidence_level"),
                "first_seen": i.get("first_seen"),
            }
            for i in top
        ]

        # Malpedia link (used later to enrich with a real description).
        malpedia_url = next(
            (i.get("malware_malpedia") for i in iocs if i.get("malware_malpedia")),
            None,
        )

        # Malpedia family id (e.g. "win.cobalt_strike") -- ThreatFox's raw `malware`
        # field IS the Malpedia id, so this is our clean join key for enrichment.
        malware_id = next((i.get("malware") for i in iocs if i.get("malware")), None)

        # Collect any tags across this family's IOCs -- best-effort "hints" only,
        # NOT authoritative actor attribution.
        tag_hints = sorted({t for i in iocs for t in (i.get("tags") or [])})

        summaries.append(
            {
                "family": name,
                "malware_id": malware_id,
                "ioc_count": len(iocs),
                "ioc_type_breakdown": dict(type_counts),
                "top_iocs": top_iocs,
                "malpedia_url": malpedia_url,
                "tag_hints": tag_hints,
                # --- Phase-B enrichment slots (populated from Malpedia / MITRE later) ---
                "description": None,        # prose description of the family
                "associated_groups": [],   # threat actor groups known to use it
            }
        )

    # Rank: most IOCs first. This is your "top families being used" leaderboard.
    summaries.sort(key=lambda s: s["ioc_count"], reverse=True)
    return summaries


def main() -> int:
    load_env()
    auth_key = get_auth_key()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        iocs = fetch_recent_iocs(auth_key, DAYS)
    except Exception as e:
        print(f"ERROR: failed to fetch ThreatFox IOCs: {e}", file=sys.stderr)
        return 1

    families = group_by_family(iocs)
    summaries = summarize_families(families)

    output = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "window_days": DAYS,
        "total_iocs": len(iocs),
        "total_families": len(summaries),
        "families": summaries,
    }

    # latest.json -- written both locally and in CI so you can preview the dashboard.
    with open(LATEST_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # Dated snapshot -- CI only, so local test runs don't collide with Actions.
    if os.environ.get("CI") == "true":
        dated_path = DATA_DIR / f"{date.today().isoformat()}.json"
        with open(dated_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"[CI] Wrote dated snapshot: {dated_path}")
    else:
        print("[local] Skipping dated snapshot (only written in CI).")

    # Print the leaderboard, reusing the cap-and-"...and N more" pattern from KEV.
    print(f"Fetched {len(iocs)} IOCs across {len(summaries)} families (last {DAYS} days).")
    if summaries:
        print("Top families by IOC count:")
        for s in summaries[:20]:
            print(f"  {s['ioc_count']:>4}  {s['family']}")
        extra = len(summaries) - 20
        if extra > 0:
            print(f"  ...and {extra} more families.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
