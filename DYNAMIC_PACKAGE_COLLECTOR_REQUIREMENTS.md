# Dynamic Package Collector Module - Requirements & Design Specification

**Project**: OreNPMGuard - Shai-Hulud Package Scanner Enhancement
**Version**: 1.0
**Date**: 2025-12-12
**Purpose**: Add dynamic threat intelligence collection capabilities to OreNPMGuard

---

## Table of Contents

1. [Project Context](#project-context)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [Design Principles](#design-principles)
5. [Architecture Overview](#architecture-overview)
6. [Directory Structure](#directory-structure)
7. [Data Sources](#data-sources)
8. [Data Formats](#data-formats)
9. [Implementation Steps](#implementation-steps)
10. [Integration with Scanner](#integration-with-scanner)
11. [Workflow](#workflow)
12. [Success Criteria](#success-criteria)

---

## 1. Project Context

### Current State of OreNPMGuard

**OreNPMGuard** is a security tool that detects compromised npm packages from Shai-Hulud supply chain attacks. It currently uses:

- **Static threat database**: `affected_packages.yaml` with 738 compromised packages
- **Manual updates**: Threat data updated via GitHub commits
- **Single ecosystem focus**: Primarily npm packages
- **Hardcoded IoC patterns**: Fixed detection signatures

### Current Limitations

1. **Manual updates required**: No automatic ingestion of new threats
2. **Limited coverage**: Only 738 packages vs. millions in the ecosystem
3. **Single-source data**: Relies on internal research only
4. **Delayed response**: Hours/days to add new packages after discovery
5. **No cross-ecosystem support**: npm-focused, lacks PyPI, RubyGems, Go modules

---

## 2. Problem Statement

**Gap Identified**: OreNPMGuard needs a module to dynamically collect malicious package data from multiple open-source threat intelligence feeds and organize it by ecosystem.

**Current Workflow**:
```
Manual Research → Update YAML → Git Commit → Users Pull Updates
```

**Desired Workflow**:
```
Automated Collectors → Raw Data → Unified Indexes → Scanner Reads Live Data
```

---

## 3. Objectives

### Primary Objectives

1. **Automate threat data collection** from 4 major open-source feeds:
   - OpenSSF Package Analysis
   - Socket.dev API
   - OSV.dev (Open Source Vulnerability Database)
   - Phylum.io research blog

2. **Organize by ecosystem** to support multiple package registries:
   - npm (Node.js)
   - PyPI (Python)
   - RubyGems (Ruby)
   - Go modules

3. **Maintain data transparency**:
   - Preserve raw data from each source
   - Create unified indexes per ecosystem
   - Track data provenance (which source reported which package)

4. **Enable on-demand updates**:
   - Manual triggering of data collection
   - No automated scheduling (Phase 1)

### Secondary Objectives

1. Deduplicate packages reported by multiple sources
2. Assign severity levels based on source confidence
3. Provide timestamp metadata for freshness tracking
4. Maintain backward compatibility with existing scanner

---

## 4. Design Principles

### Core Principles

1. **Simplicity First**
   - Function-based implementation (NO classes)
   - Simple, readable Python scripts
   - Each collector is a standalone function
   - Easy to understand and maintain

2. **Transparency**
   - Raw data preserved exactly as received from sources
   - Separate files per source for debugging
   - Clear data flow: raw → unified

3. **Ecosystem Separation**
   - One unified file per ecosystem (npm, PyPI, etc.)
   - Scanner loads only relevant ecosystem data
   - Reduces memory footprint and scan time

4. **Flexibility**
   - Can run individual collectors or all at once
   - Each collector fails independently
   - Fallback to existing data if collection fails

5. **No Overengineering**
   - JSON files instead of complex databases
   - Shell scripts for orchestration
   - Standard library wherever possible

---

## 5. Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Sources              │
│  OpenSSF  │  Socket.dev  │  OSV.dev  │  Phylum.io          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      Individual Collectors                   │
│  (Simple Python functions - one per source)                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    raw-data/ Directory                       │
│  openssf.json  │  socketdev.json  │  osv.json  │ phylum.json│
│  (Preserved as-is for transparency)                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  Unified Index Builder                       │
│  (Merges, deduplicates, organizes by ecosystem)            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   final-data/ Directory                      │
│  unified_npm.json  │  unified_pypi.json                     │
│  unified_rubygems.json  │  unified_go.json                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              OreNPMGuard Scanner Integration                │
│  Reads unified_npm.json for npm package scanning            │
└─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Collectors** | Fetch data from external APIs/sources | Python 3.x (simple functions) |
| **raw-data/** | Store unmodified data from sources | JSON files |
| **Unified Builder** | Merge and organize by ecosystem | Python script |
| **final-data/** | Ecosystem-specific unified indexes | JSON files |
| **Orchestrator** | Run all collectors sequentially | Bash script or Python |
| **Utils** | Helper functions (fetch, save, parse) | Python module |

---

## 6. Directory Structure

```
OreNPMGuard/
│
├── collectors/                       # New module (to be created)
│   │
│   ├── raw-data/                    # Raw downloads from sources
│   │   ├── openssf.json             # OpenSSF Package Analysis raw data
│   │   ├── socketdev.json           # Socket.dev raw data
│   │   ├── osv.json                 # OSV.dev raw data
│   │   └── phylum.json              # Phylum.io raw data
│   │
│   ├── final-data/                  # Unified per ecosystem
│   │   ├── unified_npm.json         # All npm packages from all sources
│   │   ├── unified_pypi.json        # All PyPI packages from all sources
│   │   ├── unified_rubygems.json    # All RubyGems packages
│   │   └── unified_go.json          # All Go modules
│   │
│   ├── collect_openssf.py           # OpenSSF collector function
│   ├── collect_socketdev.py         # Socket.dev collector function
│   ├── collect_osv.py               # OSV.dev collector function
│   ├── collect_phylum.py            # Phylum.io collector function
│   │
│   ├── build_unified_index.py       # Merges raw-data → final-data
│   ├── utils.py                     # Helper functions
│   ├── config.yaml                  # API keys, endpoints, settings
│   │
│   ├── run_all.sh                   # Orchestrator script
│   ├── run_all.py                   # (Alternative Python orchestrator)
│   │
│   └── README.md                    # Collector module documentation
│
├── shai_hulud_scanner.js            # Existing scanner (to be updated)
├── shai_hulud_scanner.py            # Existing scanner (to be updated)
├── affected_packages.yaml           # Existing static data (keep for backward compat)
└── ...                              # Other existing files
```

---

## 7. Data Sources

### Source 1: OpenSSF Package Analysis

**Description**: Dynamic sandbox analysis of packages uploaded to npm, PyPI, RubyGems
**URL**: https://github.com/ossf/package-analysis
**Data Access**: GitHub API for analysis results
**Update Frequency**: Continuous (new packages analyzed daily)
**Coverage**: Multi-ecosystem
**Authentication**: GitHub token (optional, higher rate limits)

**What It Provides**:
- Malicious behavior detection via sandboxing
- Network calls made during installation
- File system modifications
- Suspicious process spawning

### Source 2: Socket.dev

**Description**: Risk scoring for 140M+ packages across ecosystems
**URL**: https://socket.dev
**Data Access**: REST API
**Update Frequency**: Real-time
**Coverage**: npm, PyPI, Go, RubyGems
**Authentication**: API key required (free tier available)

**What It Provides**:
- Risk scores (0-100)
- Install scripts detection
- Obfuscation detection
- Network/telemetry behavior
- Known malware flags

### Source 3: OSV.dev (Open Source Vulnerability Database)

**Description**: Aggregated vulnerability database including malicious packages
**URL**: https://osv.dev
**Data Access**: REST API (free, no auth)
**Update Frequency**: Real-time
**Coverage**: Multi-ecosystem
**Authentication**: None required

**What It Provides**:
- Compromised package versions
- Malicious commits in dependencies
- CVE mappings
- Affected version ranges

### Source 4: Phylum.io Research Blog

**Description**: Security research team publishing malware discoveries
**URL**: https://blog.phylum.io
**Data Access**: Web scraping
**Update Frequency**: Weekly blog posts
**Coverage**: npm, PyPI primarily
**Authentication**: None required

**What It Provides**:
- In-depth malware analysis
- Malware family tracking
- Typosquat campaigns
- Supply chain attack patterns

---

## 8. Data Formats

### 8.1 Raw Data Format

**Location**: `collectors/raw-data/{source}.json`

Each source has its own file with standardized structure:

```json
{
  "source": "openssf",
  "collected_at": "2025-12-12T10:30:00Z",
  "total_packages": 1523,
  "ecosystems": ["npm", "pypi", "rubygems", "go"],
  "packages": [
    {
      "name": "malicious-package",
      "ecosystem": "npm",
      "versions": ["1.0.0", "1.0.1", "2.3.4"],
      "severity": "critical",
      "description": "Steals environment variables and credentials",
      "detected_behaviors": [
        "network_exfiltration",
        "credential_theft",
        "suspicious_install_script"
      ],
      "first_seen": "2025-11-15",
      "source_url": "https://github.com/ossf/package-analysis/issues/1234"
    },
    {
      "name": "another-malware",
      "ecosystem": "pypi",
      "versions": ["0.1.0"],
      "severity": "high",
      "description": "Backdoor in setup.py",
      "detected_behaviors": ["reverse_shell"],
      "first_seen": "2025-12-01",
      "source_url": "https://github.com/ossf/package-analysis/issues/1235"
    }
  ]
}
```

**Key Fields**:
- `source`: Which collector generated this data
- `collected_at`: Timestamp of data collection
- `total_packages`: Count of malicious packages in this file
- `ecosystems`: List of ecosystems covered
- `packages`: Array of malicious package objects
  - `name`: Package name exactly as published
  - `ecosystem`: npm, pypi, rubygems, or go
  - `versions`: Array of compromised versions
  - `severity`: critical, high, medium, low
  - `description`: Human-readable description
  - `detected_behaviors`: Array of malicious behaviors
  - `first_seen`: When first detected
  - `source_url`: Link to original report/analysis

### 8.2 Unified Data Format

**Location**: `collectors/final-data/unified_{ecosystem}.json`

Merged data organized by ecosystem:

```json
{
  "ecosystem": "npm",
  "last_updated": "2025-12-12T10:45:00Z",
  "total_packages": 2847,
  "total_versions": 5632,
  "sources": ["openssf", "socketdev", "osv", "phylum"],
  "packages": [
    {
      "name": "malicious-package",
      "versions": ["1.0.0", "1.0.1", "2.3.4"],
      "severity": "critical",
      "sources": ["openssf", "socketdev"],
      "first_seen": "2025-11-15",
      "last_updated": "2025-12-12T10:30:00Z",
      "description": "Steals environment variables and credentials",
      "detected_behaviors": [
        "network_exfiltration",
        "credential_theft",
        "suspicious_install_script"
      ],
      "source_details": {
        "openssf": {
          "severity": "critical",
          "url": "https://github.com/ossf/package-analysis/issues/1234"
        },
        "socketdev": {
          "severity": "critical",
          "risk_score": 95,
          "url": "https://socket.dev/npm/package/malicious-package"
        }
      }
    }
  ]
}
```

**Key Differences from Raw Format**:
- Deduplication: Same package from multiple sources merged
- Ecosystem-specific: Only npm packages in `unified_npm.json`
- Source attribution: `sources` array shows which feeds reported it
- Enriched metadata: `source_details` preserves source-specific info
- Aggregated counts: Total packages and versions

---

## 9. Implementation Steps

### Phase 1: Setup Infrastructure (2-3 hours)

**Step 1.1**: Create directory structure
```bash
mkdir -p collectors/raw-data
mkdir -p collectors/final-data
```

**Step 1.2**: Create `collectors/utils.py` with helper functions

**Required Functions**:
```python
def fetch_json(url, headers=None, timeout=30):
    """Fetch JSON from URL with error handling"""
    # HTTP GET request
    # Timeout handling
    # Error handling (404, 500, network errors)
    # Return parsed JSON or None

def save_json(data, filepath):
    """Save data as formatted JSON file"""
    # Pretty print with indent=2
    # Atomic write (temp file + rename)
    # Create parent directories if needed

def load_json(filepath):
    """Load JSON from file"""
    # Read and parse
    # Return None if file doesn't exist
    # Handle JSON parse errors

def get_timestamp():
    """Get current UTC timestamp in ISO format"""
    # Return: "2025-12-12T10:30:00Z"

def standardize_severity(severity_input):
    """Normalize severity levels from different sources"""
    # Map various formats to: critical, high, medium, low
```

**Step 1.3**: Create `collectors/config.yaml`

```yaml
# API Configuration
openssf:
  github_api_url: "https://api.github.com/repos/ossf/package-analysis"
  github_token: ""  # Optional for higher rate limits

socketdev:
  api_url: "https://api.socket.dev/v0"
  api_key: ""  # Required - get from socket.dev

osv:
  api_url: "https://api.osv.dev/v1"
  # No auth required

phylum:
  blog_url: "https://blog.phylum.io"
  # No auth required

# General settings
timeout: 30
retry_attempts: 3
rate_limit_delay: 1  # seconds between requests
```

### Phase 2: Implement Individual Collectors (6-8 hours)

**Step 2.1**: Create `collectors/collect_openssf.py`

```python
#!/usr/bin/env python3
"""
OpenSSF Package Analysis Collector
Fetches malicious package data from OpenSSF's package analysis project
"""

import utils
import yaml

def fetch_openssf_packages():
    """
    Fetch malicious packages from OpenSSF Package Analysis

    Returns:
        dict: Standardized data structure with packages
    """
    # Load config
    # Fetch from GitHub API
    # Parse issues/analysis results
    # Standardize to common format
    # Return data structure
    pass

def main():
    """Main entry point"""
    # Call fetch_openssf_packages()
    # Save to raw-data/openssf.json
    # Print summary
    pass

if __name__ == "__main__":
    main()
```

**Implementation Requirements**:
- Use GitHub API to query package-analysis repository
- Parse analysis results for malicious behavior
- Extract package names, versions, ecosystems
- Standardize severity levels
- Handle rate limiting
- Error handling for network failures

**Step 2.2**: Create `collectors/collect_socketdev.py`

```python
#!/usr/bin/env python3
"""
Socket.dev Collector
Fetches package risk data from Socket.dev API
"""

import utils
import yaml

def fetch_socketdev_packages():
    """
    Fetch high-risk packages from Socket.dev API

    Returns:
        dict: Standardized data structure with packages
    """
    # Load config and API key
    # Query Socket.dev API for high-risk packages
    # Filter for malware/critical issues
    # Standardize to common format
    # Return data structure
    pass

def main():
    """Main entry point"""
    # Call fetch_socketdev_packages()
    # Save to raw-data/socketdev.json
    # Print summary
    pass

if __name__ == "__main__":
    main()
```

**Implementation Requirements**:
- Requires API key from config.yaml
- Query for packages with risk_score > 80
- Filter for specific issue types (malware, install scripts)
- Support multiple ecosystems (npm, pypi, go, rubygems)
- Handle API pagination
- Respect rate limits

**Step 2.3**: Create `collectors/collect_osv.py`

```python
#!/usr/bin/env python3
"""
OSV.dev Collector
Fetches vulnerability data including malicious packages from OSV.dev
"""

import utils

def fetch_osv_packages():
    """
    Fetch malicious packages from OSV.dev

    Returns:
        dict: Standardized data structure with packages
    """
    # Query OSV.dev API
    # Filter for malicious package advisories
    # Extract affected versions
    # Standardize to common format
    # Return data structure
    pass

def main():
    """Main entry point"""
    # Call fetch_osv_packages()
    # Save to raw-data/osv.json
    # Print summary
    pass

if __name__ == "__main__":
    main()
```

**Implementation Requirements**:
- No authentication required
- Query for malware-related advisories
- Parse affected version ranges
- Support multiple ecosystems
- Handle API pagination

**Step 2.4**: Create `collectors/collect_phylum.py`

```python
#!/usr/bin/env python3
"""
Phylum.io Blog Collector
Scrapes malicious package reports from Phylum's research blog
"""

import utils
import re
from html.parser import HTMLParser

def fetch_phylum_packages():
    """
    Scrape malicious packages from Phylum blog posts

    Returns:
        dict: Standardized data structure with packages
    """
    # Fetch recent blog posts
    # Parse for package mentions
    # Extract package names, versions
    # Standardize to common format
    # Return data structure
    pass

def main():
    """Main entry point"""
    # Call fetch_phylum_packages()
    # Save to raw-data/phylum.json
    # Print summary
    pass

if __name__ == "__main__":
    main()
```

**Implementation Requirements**:
- Web scraping (BeautifulSoup or simple regex)
- Parse blog post content for package names
- Extract context/descriptions
- Handle inconsistent formats
- No authentication required

### Phase 3: Build Unified Index (3-4 hours)

**Step 3.1**: Create `collectors/build_unified_index.py`

```python
#!/usr/bin/env python3
"""
Unified Index Builder
Merges raw data from all sources into ecosystem-specific unified files
"""

import utils
import os
from collections import defaultdict

def load_all_raw_data():
    """Load all raw data files"""
    # Load openssf.json, socketdev.json, osv.json, phylum.json
    # Return list of data dictionaries
    pass

def merge_packages_by_ecosystem(raw_data_list):
    """
    Merge packages from all sources, organized by ecosystem

    Args:
        raw_data_list: List of raw data dictionaries

    Returns:
        dict: Ecosystem -> packages mapping
    """
    # Group packages by ecosystem
    # Deduplicate by package name
    # Merge version arrays
    # Aggregate source information
    # Determine highest severity
    # Return: {"npm": [...], "pypi": [...], ...}
    pass

def build_unified_file(ecosystem, packages):
    """
    Build unified file for a specific ecosystem

    Args:
        ecosystem: "npm", "pypi", "rubygems", or "go"
        packages: List of package dictionaries
    """
    # Create standardized structure
    # Calculate totals
    # Add timestamps
    # Save to final-data/unified_{ecosystem}.json
    pass

def main():
    """Main entry point"""
    # Load all raw data
    # Merge by ecosystem
    # Build unified files for each ecosystem
    # Print summary statistics
    pass

if __name__ == "__main__":
    main()
```

**Implementation Requirements**:

**Deduplication Logic**:
```python
# If same package appears in multiple sources:
# 1. Merge all versions into single array (unique)
# 2. Take highest severity level
# 3. List all sources in "sources" array
# 4. Preserve source-specific details in "source_details"
# 5. Use earliest "first_seen" date
# 6. Use latest "last_updated" date
```

**Ecosystem Mapping**:
```python
# Normalize ecosystem names:
# "NPM", "npm", "Node.js" → "npm"
# "PyPI", "pypi", "Python" → "pypi"
# "RubyGems", "rubygems", "Ruby" → "rubygems"
# "Go", "golang" → "go"
```

### Phase 4: Orchestration (1-2 hours)

**Step 4.1**: Create `collectors/run_all.sh`

```bash
#!/bin/bash
# Run all collectors and build unified indexes

set -e  # Exit on error

echo "Starting package collection..."
echo "================================"

# Run individual collectors
echo "Collecting from OpenSSF..."
python3 collect_openssf.py

echo "Collecting from Socket.dev..."
python3 collect_socketdev.py

echo "Collecting from OSV.dev..."
python3 collect_osv.py

echo "Collecting from Phylum.io..."
python3 collect_phylum.py

echo ""
echo "Building unified indexes..."
python3 build_unified_index.py

echo ""
echo "Collection complete!"
echo "================================"
echo "Raw data: collectors/raw-data/"
echo "Unified data: collectors/final-data/"
```

**Optional**: Create `collectors/run_all.py` for cross-platform support

### Phase 5: Integration with Scanner (2-3 hours)

**Step 5.1**: Update `shai_hulud_scanner.js` to support unified data

**Modifications Needed**:

```javascript
// Add new function to load unified npm data
function loadUnifiedPackageData() {
    const unifiedPath = path.join(__dirname, 'collectors/final-data/unified_npm.json');

    // Try to load unified data first
    if (fs.existsSync(unifiedPath)) {
        const data = JSON.parse(fs.readFileSync(unifiedPath, 'utf8'));
        return convertUnifiedToAffectedPackages(data);
    }

    // Fallback to existing YAML for backward compatibility
    return loadAffectedPackagesFromYAML();
}

// Convert unified format to existing internal format
function convertUnifiedToAffectedPackages(unifiedData) {
    // Transform unified_npm.json structure
    // to match existing affectedPackages format
    // Return array of {name, versions}
}
```

**Backward Compatibility**:
- Keep existing YAML loading as fallback
- Scanner works without collectors module
- Prioritize unified data if available

**Step 5.2**: Update `shai_hulud_scanner.py` similarly

### Phase 6: Documentation & Testing (2-3 hours)

**Step 6.1**: Create `collectors/README.md`

Contents:
- Overview of collector module
- Setup instructions
- Configuration guide (API keys)
- Usage examples
- Troubleshooting

**Step 6.2**: Create test fixtures

```
collectors/test-fixtures/
├── sample_openssf.json
├── sample_socketdev.json
├── sample_osv.json
└── sample_phylum.json
```

**Step 6.3**: Test each component

1. Test individual collectors
2. Test unified index builder
3. Test scanner integration
4. Test error handling (API failures, network issues)
5. Test deduplication logic

---

## 10. Integration with Scanner

### 10.1 Scanner Modifications

**File**: `shai_hulud_scanner.js`

**Changes Required**:

1. Add function to detect and load unified data
2. Convert unified format to existing internal format
3. Maintain backward compatibility with YAML
4. Add CLI flag for data source selection

**Priority Order**:
```
1. Check for collectors/final-data/unified_npm.json
2. If not found, download from GitHub (existing behavior)
3. If download fails, use local affected_packages.yaml
```

### 10.2 Backward Compatibility

**Existing Workflow** (preserved):
```
node shai_hulud_scanner.js /path/to/project
→ Downloads affected_packages.yaml from GitHub
→ Falls back to local file if download fails
```

**New Workflow** (enhanced):
```
node shai_hulud_scanner.js /path/to/project
→ Checks for collectors/final-data/unified_npm.json
→ If exists, uses unified data (more comprehensive)
→ Otherwise, falls back to existing workflow
```

### 10.3 Configuration Options

**Optional CLI Flags**:
```bash
# Use unified data (default if available)
node shai_hulud_scanner.js /path/to/project

# Force YAML data source
node shai_hulud_scanner.js /path/to/project --source=yaml

# Force unified data source (fail if not available)
node shai_hulud_scanner.js /path/to/project --source=unified
```

---

## 11. Workflow

### 11.1 End-to-End Workflow

```
┌─────────────────────────────────────────────────┐
│  Step 1: Run Collectors (On-Demand/Manual)     │
│                                                  │
│  $ cd collectors                                │
│  $ ./run_all.sh                                 │
│                                                  │
│  Duration: 5-10 minutes                         │
│  Output: raw-data/*.json files                  │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Step 2: Build Unified Indexes (Automatic)     │
│                                                  │
│  (Triggered by run_all.sh)                      │
│                                                  │
│  Duration: 10-30 seconds                        │
│  Output: final-data/unified_*.json files        │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│  Step 3: Run Scanner (User Action)             │
│                                                  │
│  $ node shai_hulud_scanner.js /path/to/project  │
│                                                  │
│  Scanner automatically uses unified data        │
│  Duration: 1-5 seconds                          │
│  Output: Scan results with threats detected    │
└─────────────────────────────────────────────────┘
```

### 11.2 Individual Collector Workflow

**Use Case**: Update only specific source

```bash
# Update only OpenSSF data
cd collectors
python3 collect_openssf.py
python3 build_unified_index.py

# Update only Socket.dev data
python3 collect_socketdev.py
python3 build_unified_index.py
```

### 11.3 Maintenance Workflow

**Recommended Schedule**:
- Run collectors: Weekly or before important deployments
- Review new threats: After each collection run
- Update config.yaml: When API keys expire

---

## 12. Success Criteria

### 12.1 Functional Requirements

✅ **Data Collection**:
- [ ] Successfully fetch data from OpenSSF Package Analysis
- [ ] Successfully fetch data from Socket.dev API
- [ ] Successfully fetch data from OSV.dev
- [ ] Successfully fetch data from Phylum.io blog
- [ ] Handle API failures gracefully (continue with available data)
- [ ] Save raw data to separate files per source

✅ **Data Processing**:
- [ ] Merge packages from all sources correctly
- [ ] Deduplicate packages appearing in multiple sources
- [ ] Organize by ecosystem (npm, pypi, rubygems, go)
- [ ] Preserve source attribution for each package
- [ ] Generate unified_*.json files for each ecosystem

✅ **Scanner Integration**:
- [ ] Scanner detects and loads unified_npm.json automatically
- [ ] Scanner falls back to YAML if unified data unavailable
- [ ] No breaking changes to existing scanner behavior
- [ ] Scan results include source information

### 12.2 Quality Requirements

✅ **Code Quality**:
- [ ] All functions are simple and well-documented
- [ ] No class-based implementations (function-based only)
- [ ] Code is readable by non-experts
- [ ] Error handling for all network operations
- [ ] Logging for debugging purposes

✅ **Data Quality**:
- [ ] No duplicate packages in unified files
- [ ] All packages have required fields (name, versions, ecosystem)
- [ ] Severity levels are standardized
- [ ] Timestamps are in ISO 8601 format
- [ ] Raw data preserved exactly as received

✅ **Performance**:
- [ ] Full collection completes in < 10 minutes
- [ ] Unified index building completes in < 1 minute
- [ ] Scanner startup time not significantly impacted

### 12.3 Testing Criteria

✅ **Unit Tests**:
- [ ] Test each collector function independently
- [ ] Test deduplication logic
- [ ] Test ecosystem normalization
- [ ] Test severity standardization
- [ ] Test error handling paths

✅ **Integration Tests**:
- [ ] Test full workflow (collect → merge → scan)
- [ ] Test with API failures (network errors)
- [ ] Test with empty responses
- [ ] Test backward compatibility (YAML fallback)

✅ **Validation Tests**:
- [ ] Verify JSON files are valid
- [ ] Verify no data loss during merging
- [ ] Verify scanner detects packages from unified data
- [ ] Compare results: YAML vs. unified data

---

## Appendix A: Example Commands

### Running Individual Collectors

```bash
# Setup
cd collectors
pip install -r requirements.txt  # if dependencies needed

# Run individual collectors
python3 collect_openssf.py
python3 collect_socketdev.py
python3 collect_osv.py
python3 collect_phylum.py

# Build unified indexes
python3 build_unified_index.py

# Run all at once
./run_all.sh
```

### Using the Scanner

```bash
# Scan with unified data (if available)
node shai_hulud_scanner.js /path/to/project

# Scan with Python version
python3 shai_hulud_scanner.py /path/to/project

# Scan specific file
node shai_hulud_scanner.js /path/to/package.json
```

---

## Appendix B: Configuration Example

**collectors/config.yaml**:

```yaml
# OpenSSF Configuration
openssf:
  github_api_url: "https://api.github.com/repos/ossf/package-analysis"
  github_token: "ghp_xxxxxxxxxxxxxxxxxxxx"  # Optional
  timeout: 30

# Socket.dev Configuration
socketdev:
  api_url: "https://api.socket.dev/v0"
  api_key: "sk_xxxxxxxxxxxxxxxxxxxx"  # Required
  timeout: 30
  min_risk_score: 80  # Only fetch packages with score >= 80

# OSV.dev Configuration
osv:
  api_url: "https://api.osv.dev/v1"
  timeout: 30
  malware_types: ["MALICIOUS", "MALWARE"]

# Phylum.io Configuration
phylum:
  blog_url: "https://blog.phylum.io"
  timeout: 30
  max_posts: 50  # Parse last N blog posts

# General Settings
general:
  retry_attempts: 3
  rate_limit_delay: 1.0  # seconds
  user_agent: "OreNPMGuard-Collector/1.0"
```

---

## Appendix C: Error Handling Requirements

### Network Errors

```python
# Handle timeouts
# Handle connection errors
# Handle HTTP errors (404, 500, etc.)
# Retry logic with exponential backoff
# Fail gracefully (continue with other sources)
```

### Data Errors

```python
# Handle invalid JSON
# Handle missing required fields
# Handle unexpected data types
# Validate ecosystem names
# Validate version formats
```

### File System Errors

```python
# Handle missing directories (create if needed)
# Handle permission errors
# Handle disk space issues
# Atomic writes (temp file + rename)
```

---

## Appendix D: Future Enhancements (Out of Scope for Phase 1)

### Potential Phase 2 Features

1. **Automated Scheduling**
   - Cron job for daily/hourly updates
   - GitHub Actions workflow

2. **Domain Intelligence**
   - Integrate Abuse.ch feeds (URLhaus, ThreatFox)
   - Detect callback domains in install scripts

3. **Advanced Analytics**
   - Trend analysis (new packages per day)
   - Malware family clustering
   - MITRE ATT&CK mapping

4. **Real Database**
   - SQLite or PostgreSQL for better querying
   - Full-text search
   - Historical data retention

5. **Web Dashboard**
   - Visualize threat landscape
   - Search interface
   - Export capabilities

6. **API Server**
   - REST API for unified data
   - Webhook notifications
   - Integration with other tools

---

## Summary

This requirements document specifies a **simple, function-based module** that will:

1. Collect malicious package data from 4 open-source feeds
2. Store raw data per source for transparency
3. Build unified indexes per ecosystem (npm, pypi, etc.)
4. Integrate seamlessly with existing OreNPMGuard scanner
5. Maintain backward compatibility
6. Enable on-demand updates

**Estimated Development Time**: 16-21 hours
**Technology Stack**: Python 3.x, JSON, Bash
**Dependencies**: Minimal (standard library + requests/urllib)
**Deployment**: Simple file-based system, no database required

This design prioritizes **simplicity, transparency, and maintainability** over complexity.
