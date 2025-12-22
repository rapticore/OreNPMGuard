# Dynamic Package Collectors

This module automatically collects malicious package data from multiple open-source threat intelligence feeds and organizes it by ecosystem for use with OreNPMGuard.

## Overview

The collector system fetches threat data from multiple sources and aggregates them into unified per-ecosystem files.

### Data Sources

| Source | Status | Description | Package Count |
|--------|--------|-------------|---------------|
| **OpenSSF Malicious Packages** | ✅ Working | OSV-format malicious package reports | ~220k packages |
| **OSV.dev** | ✅ Working | Bulk download, filter MAL- entries | Varies |
| **Phylum.io** | ⚠️ Basic | Blog feed scraping | Limited |
| **Socket.dev** | ⏳ Placeholder | Requires API key | - |

### Data Flow

```
Sources                    Raw Data              Unified Data
┌─────────────────┐       ┌──────────────┐      ┌─────────────────┐
│ OpenSSF Repo    │──────▶│ openssf.json │──┐   │ unified_npm.json│
│ (git clone)     │       └──────────────┘  │   │ unified_pypi.json│
├─────────────────┤       ┌──────────────┐  │   │ unified_go.json │
│ OSV.dev         │──────▶│ osv.json     │──┼──▶│ unified_rubygems│
│ (bulk download) │       └──────────────┘  │   │ unified_maven   │
├─────────────────┤       ┌──────────────┐  │   │ unified_cargo   │
│ Phylum Blog     │──────▶│ phylum.json  │──┘   │ unified_nuget   │
└─────────────────┘       └──────────────┘      └─────────────────┘
                              raw-data/             final-data/
```

## Quick Start

### 1. Install Dependencies

```bash
cd collectors
pip install -r requirements.txt
```

### 2. Run All Collectors

```bash
./run_all.sh
```

Or run individually:

```bash
# OpenSSF - clones repo and parses OSV files (takes a few minutes first time)
python3 collect_openssf.py

# OSV.dev - downloads bulk data and filters MAL- entries
python3 collect_osv.py

# After collecting, build unified indexes
python3 build_unified_index.py
```

## Directory Structure

```
collectors/
├── .cache/                      # Cached downloads (auto-created)
│   ├── ossf-repo/              # Cloned OpenSSF repo
│   └── osv/                    # Downloaded OSV data
│
├── raw-data/                    # Raw data from each source
│   ├── openssf.json
│   ├── osv.json
│   ├── phylum.json
│   └── socketdev.json
│
├── final-data/                  # Unified per-ecosystem files
│   ├── unified_npm.json
│   ├── unified_pypi.json
│   ├── unified_go.json
│   ├── unified_rubygems.json
│   ├── unified_maven.json
│   └── unified_cargo.json
│
├── collect_openssf.py           # OpenSSF malicious-packages collector
├── collect_osv.py               # OSV.dev bulk download collector
├── collect_phylum.py            # Phylum blog scraper
├── collect_socketdev.py         # Socket.dev (placeholder)
├── build_unified_index.py       # Merges raw data into unified files
├── utils.py                     # Shared helper functions
├── config.yaml                  # Configuration
├── requirements.txt             # Python dependencies
└── run_all.sh                   # Run all collectors
```

## Collector Details

### OpenSSF Malicious Packages (`collect_openssf.py`)

**Source:** https://github.com/ossf/malicious-packages

**Method:**
1. Clones the repository (shallow clone, cached locally)
2. Walks through `osv/malicious/{ecosystem}/{package}/` directories
3. Parses OSV-format JSON files

**Ecosystems:** npm, pypi, go, rubygems, maven, crates.io, nuget

**Note:** First run takes ~5 minutes to clone the repo (~220k files). Subsequent runs use cached clone.

### OSV.dev (`collect_osv.py`)

**Source:** https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip

**Method:**
1. Downloads bulk ZIP files for each ecosystem
2. Extracts and parses JSON files
3. Filters for `MAL-` prefixed entries (malware indicators)

**Ecosystems:** npm, PyPI, Go, RubyGems, Maven, crates.io, NuGet

**Note:** Downloads can be large (100MB+ per ecosystem). Only MAL- entries are kept.

### Phylum Blog (`collect_phylum.py`)

**Source:** https://blog.phylum.io/feed

**Method:** Simple regex extraction from RSS feed

**Status:** Basic implementation - may have false positives

### Socket.dev (`collect_socketdev.py`)

**Status:** Placeholder - requires API key and doesn't have bulk query endpoint

## Data Format

### Raw Data (`raw-data/{source}.json`)

```json
{
  "source": "openssf",
  "collected_at": "2025-12-16T10:30:00Z",
  "total_packages": 220000,
  "ecosystems": ["npm", "pypi", "go"],
  "packages": [
    {
      "name": "malicious-package",
      "ecosystem": "npm",
      "versions": ["1.0.0", "1.0.1"],
      "severity": "critical",
      "mal_id": "MAL-2024-12345",
      "description": "Malicious code detected",
      "detected_behaviors": ["malicious_code"],
      "first_seen": "2024-12-15",
      "source_url": "https://..."
    }
  ]
}
```

### Unified Data (`final-data/unified_{ecosystem}.json`)

```json
{
  "ecosystem": "npm",
  "last_updated": "2025-12-16T10:45:00Z",
  "total_packages": 210000,
  "total_versions": 250000,
  "sources": ["openssf", "osv"],
  "packages": [
    {
      "name": "malicious-package",
      "versions": ["1.0.0", "1.0.1"],
      "severity": "critical",
      "sources": ["openssf", "osv"],
      "first_seen": "2024-12-15",
      "last_updated": "2025-12-16T10:30:00Z",
      "description": "Malicious code detected",
      "detected_behaviors": ["malicious_code"],
      "source_details": {
        "openssf": { "mal_id": "MAL-2024-12345", "url": "..." },
        "osv": { "vuln_id": "MAL-2024-12345", "url": "..." }
      }
    }
  ]
}
```

## Configuration

### config.yaml

```yaml
# OpenSSF Malicious Packages
openssf:
  repo_url: "https://github.com/ossf/malicious-packages.git"
  github_token: ""  # Optional - higher rate limits for git clone
  timeout: 600      # Clone timeout in seconds
  ecosystems:
    - npm
    - pypi
    - go
    - rubygems
    - maven
    - crates.io
    - nuget

# OSV.dev Bulk Downloads
osv:
  base_url: "https://osv-vulnerabilities.storage.googleapis.com"
  ecosystems:
    - npm
    - PyPI
    - Go
    - RubyGems
    - Maven
    - crates.io
    - NuGet

# Socket.dev (placeholder)
socketdev:
  api_url: "https://api.socket.dev/v0"
  api_key: ""  # Required for Socket.dev

# Phylum Blog
phylum:
  blog_feed: "https://blog.phylum.io/feed"
```

## Future Enhancements

### Planned Collectors

- [ ] **DataDog Shai-Hulud IoCs** - Attack-specific indicators from DataDog
- [ ] **GitHub Advisory Database** - Requires GitHub token for full access
- [ ] **Abuse.ch ThreatFox** - Malicious domains and IoCs

### Planned Improvements

- [ ] **Scanner Integration** - Update `shai_hulud_scanner.py` to use unified files
- [ ] **Scheduled Sync** - Cron job or systemd timer for automated updates
- [ ] **Incremental Updates** - Only fetch new/changed packages
- [ ] **Validation** - Cross-reference packages across sources
- [ ] **Metrics Dashboard** - Track package counts over time

### Excluded Sources (Competitors)

- Wiz
- Snyk

## Troubleshooting

### Clone Timeout

If OpenSSF repo clone times out:
```bash
# Increase timeout in config.yaml
# Or manually clone:
git clone --depth 1 https://github.com/ossf/malicious-packages.git .cache/ossf-repo
```

### Large Downloads

OSV bulk downloads can be large. If disk space is limited:
```bash
# Edit collect_osv.py to limit ecosystems
ECOSYSTEMS = {'npm': 'npm'}  # Only npm
```

### Cache Cleanup

To force fresh downloads:
```bash
rm -rf .cache/
```

## License

MIT License - Same as main OreNPMGuard project
