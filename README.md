# Strata
- Strata is a threat-intelligence platform that aggregates Known Exploited Vulnerabilities (KEVs) and Indicators of Compromise (IOCs) by malware family. It gives defenders a single, continuously-updated view of the active threat landscape.

**[ Live Demo Link ] https://blkwizard20z.github.io/strata/index.html**
 
# Features
- Separate Data Feeds - CISA KEV and ThreatFox
- KEV Dashboard - searchable table of actively exploited vulnerabilities.
- ThreatFox IOC Dashboard - malware IOCs grouped and ranked by family
- Data Enrichment - family description and threat actor attribution
- Daily Automation - Runs via GitHub Actions

# How it works
- The fetch scripts for each data source reach out via API to pull down the relevant JSON and KEV data. That data is then parsed and grouped based on the malware family. After that the data is enriched to provide a short description of the malware family, defanged IOCs, and several other features to a static dashboard. The enrichment uses a cache so each family is only looked up once; the daily GitHub Actions run keeps everything current.

# Tech Stack
- Python (stdlib + certifi)
- GitHub Actions
- GitHub Pages
- HTML 
- CSS
- JS
- Data Sources CISA KEV, ThreatFox, Malpedia

# Project Structure
strata/
├── .github/workflows/          # Automation (GitHub Actions)
│   ├── fetch-kev.yml           #   daily KEV job
│   └── fetch-threatfox.yml     #   daily ThreatFox job (fetch → enrich → deep-dive → publish)
│
├── scripts/                    # All the Python logic
│   ├── fetch_kev.py            #   pulls CISA KEV
│   ├── fetch_threatfox.py      #   pulls + groups + ranks ThreatFox IOCs
│   ├── enrich_families.py      #   adds Malpedia descriptions/attribution (cached)
│   └── fetch_family_details.py #   builds per-family deep-dive stats
│
├── data/                       # Canonical data archive (owned by automation)
│   ├── kev/
│   │   ├── latest.json         #   current snapshot the dashboard reads
│   │   └── YYYY-MM-DD.json     #   dated history (written only in CI)
│   ├── threatfox/
│   │   ├── latest.json
│   │   ├── YYYY-MM-DD.json
│   │   └── families/           #   per-family deep-dive profiles
│   │       ├── _index.json     #     list of families that have a profile
│   │       └── <malware_id>.json
│   └── enrichment/
│       └── families.json       #   Malpedia cache = the knowledge base
│
├── docs/                       # What GitHub Pages serves (the live site)
│   ├── index.html              #   KEV dashboard
│   ├── threatfox.html          #   ThreatFox family leaderboard
│   ├── family.html             #   per-family deep-dive page
│   └── data/                   #   published copies the live pages fetch
│       ├── kev/latest.json
│       └── threatfox/
│           ├── latest.json
│           └── families/*.json
│
├── .env                        # Local-only secrets (gitignored, never committed)
├── .gitignore
├── requirements.txt            # Python dependencies (certifi)
└── README.md

# Getting Started
- Ensure that you have Python 3.10+ installed
- Get a ThreatFox Auth key which is free!
- Clone the Repo using the following command 
```bash
git clone https://github.com/BlkWizard20z/strata.git
cd strata
```
- Install the requirements file
```bash
pip install -r requirements.txt
```
- Run the following scripts
```bash
python scripts/fetch_kev.py
python scripts/fetch_threatfox.py
python scripts/enrich_families.py
python scripts/fetch_family_details.py
```


# Data Sources and Credit
- CISA
- abuse.ch/ThreatFOX (CCO)
- Malpedia

# Road Map

- Future project expansion includes adding more feeds, an overview page, MITRE ATT&CK, and an artifact knowledge base.