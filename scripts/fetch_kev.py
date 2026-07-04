#!/usr/bin/env python3
"""
fetch_kev.py

Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog and:
  1. Saves a dated snapshot to data/kev/YYYY-MM-DD.json (for history/diffing later)
  2. Saves/overwrites data/kev/latest.json (what the dashboard reads)
  3. Prints a short summary of new entries since the last run

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import json
import os
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Paths are relative to the repo root, not this script's location,
# because GitHub Actions runs from the repo root by default.
DATA_DIR = Path("data/kev")
LATEST_PATH = DATA_DIR / "latest.json"


def fetch_kev() -> dict:
    """Download the raw KEV JSON catalog from CISA."""
    req = urllib.request.Request(
        KEV_URL,
        headers={"User-Agent": "strata/0.1 (personal security research project)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_previous_ids() -> set:
    """Return the set of CVE IDs from the last saved snapshot, if any."""
    if not LATEST_PATH.exists():
        return set()
    try:
        with open(LATEST_PATH, "r", encoding="utf-8") as f:
            prev = json.load(f)
        return {vuln["cveID"] for vuln in prev.get("vulnerabilities", [])}
    except (json.JSONDecodeError, KeyError):
        return set()


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    previous_ids = load_previous_ids()

    try:
        catalog = fetch_kev()
    except Exception as e:
        print(f"ERROR: failed to fetch KEV catalog: {e}", file=sys.stderr)
        return 1

    current_ids = {vuln["cveID"] for vuln in catalog.get("vulnerabilities", [])}
    new_ids = current_ids - previous_ids

# Dated snapshot -- our permanent history, used later for "diff over time" features.
    # Only written in CI (GitHub Actions) so that LOCAL test runs don't create dated
    # files that collide with the ones Actions commits. GitHub sets CI=true automatically
    # on every Actions run; it's unset on your machine, so this block is skipped locally.
    if os.environ.get("CI") == "true":
        today_str = date.today().isoformat()
        dated_path = DATA_DIR / f"{today_str}.json"
        with open(dated_path, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=2)
        print(f"[CI] Wrote dated snapshot: {dated_path}")
    else:
        print("[local] Skipping dated snapshot (only written in CI).")

    # Overwrite "latest" -- this is what the static dashboard fetches at runtime.
    with open(LATEST_PATH, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"Fetched {len(current_ids)} total KEV entries.")
    if new_ids:
        print(f"{len(new_ids)} new entries since last run:")
        for vuln in catalog["vulnerabilities"]:
            if vuln["cveID"] in new_ids:
                print(f"  - {vuln['cveID']}: {vuln.get('vulnerabilityName', 'N/A')}")
    else:
        print("No new entries since last run.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
