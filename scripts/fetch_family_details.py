#!/usr/bin/env python3
"""
fetch_family_details.py

Builds a per-family "deep dive" for the most active families: pulls each family's
deeper IOC history from ThreatFox (further back than the 7-day recent window),
computes statistics, attaches Malpedia enrichment, and writes one JSON profile per
family that the family.html page renders.

Flow:
  1. Read data/threatfox/latest.json -> take the top N families by IOC count.
  2. For each, query ThreatFox's "malwareinfo" endpoint for its recent history.
  3. Compute stats (type breakdown, confidence spread, activity timeline, top ports).
  4. Attach description/aliases/actors from the Malpedia enrichment cache.
  5. Write data/threatfox/families/<malware_id>.json (one per family)
     plus data/threatfox/families/_index.json (list of generated families).

Requires THREATFOX_AUTH_KEY (same key as fetch_threatfox.py).
"""

import json
import os
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import certifi

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# How many of the top families (by IOC count) to build deep dives for each run.
TOP_N = 25
# How many IOCs to request per family (their deeper history).
DETAIL_LIMIT = 500
# Politeness delay between family queries.
REQUEST_DELAY_SECONDS = 0.5

THREATFOX_LATEST = Path("data/threatfox/latest.json")
ENRICH_CACHE = Path("data/enrichment/families.json")
OUT_DIR = Path("data/threatfox/families")


def load_env(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_auth_key() -> str:
    key = os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        print("ERROR: THREATFOX_AUTH_KEY is not set (see fetch_threatfox.py).", file=sys.stderr)
        sys.exit(1)
    return key


def fetch_family_iocs(auth_key: str, family_id: str, limit: int) -> list:
    """Query ThreatFox for one family's recent IOC history."""
    payload = json.dumps({"query": "malwareinfo", "malware": family_id, "limit": limit}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
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
        if status in ("no_result", "illegal_search_term"):
            return []
        raise RuntimeError(f"ThreatFox malwareinfo returned query_status={status!r}")
    return result.get("data", [])


def compute_stats(iocs: list) -> dict:
    """Turn a family's raw IOC list into summary statistics."""
    type_counts = defaultdict(int)
    conf = {"high": 0, "medium": 0, "low": 0}
    timeline = defaultdict(int)     # date -> count of IOCs first seen that day
    port_counts = defaultdict(int)
    first_seen_dates = []

    for ioc in iocs:
        type_counts[ioc.get("ioc_type", "unknown")] += 1

        c = ioc.get("confidence_level", 0) or 0
        if c >= 75:
            conf["high"] += 1
        elif c >= 50:
            conf["medium"] += 1
        else:
            conf["low"] += 1

        fs = ioc.get("first_seen")
        if fs:
            day = fs[:10]  # "2026-07-04 09:12:33" -> "2026-07-04"
            timeline[day] += 1
            first_seen_dates.append(day)

        # Pull the port from ip:port style indicators.
        if ioc.get("ioc_type") == "ip:port" and ioc.get("ioc"):
            port = str(ioc["ioc"]).rsplit(":", 1)[-1]
            if port.isdigit():
                port_counts[port] += 1

    # Most recent IOCs as a small sample (sorted newest first).
    sample = sorted(iocs, key=lambda x: x.get("first_seen", ""), reverse=True)[:15]
    sample_iocs = [
        {
            "ioc": i.get("ioc"),
            "type": i.get("ioc_type"),
            "confidence": i.get("confidence_level"),
            "first_seen": i.get("first_seen"),
        }
        for i in sample
    ]

    top_ports = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        "total_iocs": len(iocs),
        "date_range": {
            "earliest": min(first_seen_dates) if first_seen_dates else None,
            "latest": max(first_seen_dates) if first_seen_dates else None,
        },
        "ioc_type_breakdown": dict(sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)),
        "confidence_distribution": conf,
        "activity_timeline": dict(sorted(timeline.items())),  # chronological
        "top_ports": [{"port": p, "count": n} for p, n in top_ports],
        "sample_iocs": sample_iocs,
    }


def load_enrichment() -> dict:
    if not ENRICH_CACHE.exists():
        return {}
    try:
        with open(ENRICH_CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def main() -> int:
    load_env()
    auth_key = get_auth_key()

    if not THREATFOX_LATEST.exists():
        print(f"ERROR: {THREATFOX_LATEST} not found. Run fetch_threatfox.py first.", file=sys.stderr)
        return 1

    with open(THREATFOX_LATEST, "r", encoding="utf-8") as f:
        tf = json.load(f)

    enrichment = load_enrichment()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Top N families that actually have a Malpedia id to query by.
    targets = [
        fam for fam in tf.get("families", [])
        if fam.get("malware_id")
    ][:TOP_N]

    generated = []
    for fam in targets:
        fid = fam["malware_id"]
        try:
            iocs = fetch_family_iocs(auth_key, fid, DETAIL_LIMIT)
        except Exception as e:
            print(f"  WARN: failed to fetch {fid}: {e}", file=sys.stderr)
            continue

        stats = compute_stats(iocs)
        enr = enrichment.get(fid, {})

        profile = {
            "malware_id": fid,
            "family": fam.get("family"),
            "generated": datetime.now(timezone.utc).isoformat(),
            "recent_window_ioc_count": fam.get("ioc_count"),  # from the 7-day leaderboard
            "malpedia_url": fam.get("malpedia_url"),
            "description": enr.get("description"),
            "alt_names": enr.get("alt_names", []),
            "associated_groups": enr.get("associated_groups", []),
            "stats": stats,
        }

        out_path = OUT_DIR / f"{fid}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)

        generated.append({"malware_id": fid, "family": fam.get("family")})
        print(f"  built deep-dive: {fid} ({stats['total_iocs']} IOCs)")
        time.sleep(REQUEST_DELAY_SECONDS)

    # Index of which families have a deep-dive (dashboard uses this to show links).
    with open(OUT_DIR / "_index.json", "w", encoding="utf-8") as f:
        json.dump({"generated": datetime.now(timezone.utc).isoformat(), "families": generated}, f, indent=2)

    print(f"Deep-dive build complete: {len(generated)} family profiles written to {OUT_DIR}/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
