#!/usr/bin/env python3
"""
enrich_families.py

Enriches the ThreatFox family data with descriptions and threat-actor attribution
from Malpedia (Fraunhofer FKIE), using a persistent local cache so we only ever
query Malpedia once per family.

Flow:
  1. Read data/threatfox/latest.json to see which families appeared.
  2. Load the enrichment cache (data/enrichment/families.json).
  3. For any family NOT already cached, query Malpedia's get/family endpoint.
  4. Save the updated cache.
  5. Inject description + associated_groups back into latest.json's empty slots.

The cache (data/enrichment/families.json) is the persistent knowledge base -- it
grows over time and is committed to the repo. latest.json is just the merged view
the dashboard reads.

Malpedia public data needs no account, but a free API token (MALPEDIA_APITOKEN)
gives fuller access. If the token is set (via .env locally or a repo secret in CI),
it's used; otherwise we query anonymously.

Docs: https://malpedia.caad.fkie.fraunhofer.de/usage/api
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

import certifi

MALPEDIA_FAMILY_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/"

THREATFOX_LATEST = Path("data/threatfox/latest.json")
ENRICH_DIR = Path("data/enrichment")
CACHE_PATH = ENRICH_DIR / "families.json"

# Be polite to a free service: pause between calls for families we haven't cached.
REQUEST_DELAY_SECONDS = 0.5

# Re-check a cached family only if it's older than this many days (descriptions
# rarely change, so this is generous). Families with a "not_found" result are also
# retried after this window in case Malpedia adds them later.
CACHE_TTL_DAYS = 90


def load_env(path: str = ".env") -> None:
    """Minimal .env loader (same pattern as the fetcher) -- no external dependency."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_cache() -> dict:
    """Load the enrichment cache, or return an empty one if it doesn't exist yet."""
    if not CACHE_PATH.exists():
        return {}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def is_fresh(entry: dict) -> bool:
    """True if a cache entry is recent enough to skip re-fetching."""
    ts = entry.get("enriched_at")
    if not ts:
        return False
    try:
        when = datetime.fromisoformat(ts)
    except ValueError:
        return False
    age_days = (datetime.now(timezone.utc) - when).days
    return age_days < CACHE_TTL_DAYS


def fetch_malpedia_family(family_id, token) -> dict:
    """Query Malpedia for one family. Returns a normalized enrichment dict.

    Never raises for an expected 'not found' -- returns a sentinel entry instead,
    so one missing family doesn't abort the whole run.
    """
    headers = {"User-Agent": "strata/0.1 (personal security research project)"}
    if token:
        headers["Authorization"] = f"apitoken {token}"

    req = urllib.request.Request(MALPEDIA_FAMILY_URL + family_id, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 404 = Malpedia doesn't have this family id. Cache that fact so we don't
        # keep retrying it every run (until the TTL expires).
        if e.code == 404:
            return {"status": "not_found", "enriched_at": _now_iso()}
        raise

    # Malpedia's attribution field is a list of actor objects; pull their names.
    actors = []
    for a in data.get("attribution", []) or []:
        name = a.get("value") if isinstance(a, dict) else a
        if name:
            actors.append(name)

    description = (data.get("description") or "").strip() or None

    return {
        "status": "ok",
        "common_name": data.get("common_name"),
        "description": description,
        "alt_names": data.get("alt_names", []) or [],
        "associated_groups": actors,
        "source": "malpedia",
        "enriched_at": _now_iso(),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    load_env()
    token = os.environ.get("MALPEDIA_APITOKEN")  # optional

    if not THREATFOX_LATEST.exists():
        print(
            f"ERROR: {THREATFOX_LATEST} not found. Run fetch_threatfox.py first.",
            file=sys.stderr,
        )
        return 1

    with open(THREATFOX_LATEST, "r", encoding="utf-8") as f:
        tf = json.load(f)

    ENRICH_DIR.mkdir(parents=True, exist_ok=True)
    cache = load_cache()

    # Which family ids are in the current window and need enrichment?
    family_ids = [
        fam["malware_id"]
        for fam in tf.get("families", [])
        if fam.get("malware_id")
    ]

    fetched = 0
    for fid in family_ids:
        cached = cache.get(fid)
        if cached and is_fresh(cached):
            continue  # already known and recent -- skip the API call
        if token is None and cached and cached.get("status") == "ok":
            continue  # keep existing good data if we're anonymous

        try:
            cache[fid] = fetch_malpedia_family(fid, token)
            fetched += 1
            print(f"  enriched {fid}: {cache[fid].get('status')}")
            time.sleep(REQUEST_DELAY_SECONDS)
        except Exception as e:
            print(f"  WARN: failed to enrich {fid}: {e}", file=sys.stderr)

    # Save the updated knowledge base.
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)

    # Inject enrichment into latest.json's slots so the dashboard shows it.
    injected = 0
    for fam in tf.get("families", []):
        entry = cache.get(fam.get("malware_id"))
        if entry and entry.get("status") == "ok":
            fam["description"] = entry.get("description")
            fam["associated_groups"] = entry.get("associated_groups", [])
            injected += 1

    with open(THREATFOX_LATEST, "w", encoding="utf-8") as f:
        json.dump(tf, f, indent=2)

    print(
        f"Enrichment done. Queried Malpedia for {fetched} new/stale families; "
        f"cache now holds {len(cache)}; injected enrichment into {injected} families."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
