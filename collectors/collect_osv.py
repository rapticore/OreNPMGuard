#!/usr/bin/env python3
"""
OSV.dev Collector
Fetches malicious package data from OSV.dev bulk downloads
Downloads vulnerability data and filters for MAL- prefixed entries (malware)
Source: https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
"""

import os
import sys
import json
import zipfile
import tempfile
from urllib.request import urlretrieve
from urllib.error import URLError

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils


# OSV bulk download base URL
OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# Ecosystems to fetch (must match OSV ecosystem names exactly)
# Note: OSV uses "npm", "PyPI", "Go", etc. (case-sensitive)
ECOSYSTEMS = {
    'npm': 'npm',
    'pypi': 'PyPI',
    'go': 'Go',
    'rubygems': 'RubyGems',
    'maven': 'Maven',
    'cargo': 'crates.io',
    'nuget': 'NuGet'
}


def download_ecosystem_data(ecosystem_osv_name, cache_dir):
    """
    Download and extract OSV data for an ecosystem

    Args:
        ecosystem_osv_name (str): OSV ecosystem name (e.g., "npm", "PyPI")
        cache_dir (str): Directory to cache downloads

    Returns:
        str: Path to extracted directory, or None on error
    """
    zip_url = f"{OSV_BASE_URL}/{ecosystem_osv_name}/all.zip"
    zip_path = os.path.join(cache_dir, f"{ecosystem_osv_name}.zip")
    extract_dir = os.path.join(cache_dir, ecosystem_osv_name)

    print(f"    Downloading {ecosystem_osv_name}...")

    try:
        # Download zip file
        urlretrieve(zip_url, zip_path)

        # Extract
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)

        # Clean up zip file to save space
        os.remove(zip_path)

        return extract_dir

    except URLError as e:
        print(f"    Error downloading {ecosystem_osv_name}: {e}")
        return None
    except zipfile.BadZipFile as e:
        print(f"    Error extracting {ecosystem_osv_name}: {e}")
        return None
    except Exception as e:
        print(f"    Unexpected error for {ecosystem_osv_name}: {e}")
        return None


def parse_osv_entry(data):
    """
    Parse an OSV vulnerability entry

    Args:
        data (dict): OSV entry data

    Returns:
        dict: Package info or None
    """
    try:
        vuln_id = data.get('id', '')
        summary = data.get('summary', '')
        details = data.get('details', '')  # Full text, no truncation
        published = data.get('published', '')
        modified = data.get('modified', '')

        # Get aliases (GHSA IDs, SNYK IDs, etc.)
        aliases = data.get('aliases', [])

        # Get references (advisory URLs, package links)
        references = data.get('references', [])

        # Get affected packages
        affected = data.get('affected', [])
        if not affected:
            return None

        # Get first affected package
        pkg_info = affected[0]
        package = pkg_info.get('package', {})
        ecosystem = package.get('ecosystem', '')
        name = package.get('name', '')

        if not name or not ecosystem:
            return None

        # Get versions
        versions = pkg_info.get('versions', [])

        # Extract CWEs from affected[].database_specific.cwes (id and name only)
        cwes = []
        db_specific_affected = pkg_info.get('database_specific', {})
        raw_cwes = db_specific_affected.get('cwes', [])
        for c in raw_cwes:
            cwe_id = c.get('cweId', '')
            cwe_name = c.get('name', '')
            if cwe_id:
                cwes.append({"id": cwe_id, "name": cwe_name})

        # Extract origins from database_specific.malicious-packages-origins
        origins = []
        db_specific = data.get('database_specific', {})
        raw_origins = db_specific.get('malicious-packages-origins', [])
        for o in raw_origins:
            origin = {
                "source": o.get('source', ''),
                "id": o.get('id', ''),
                "modified_time": o.get('modified_time', ''),
                "ranges": o.get('ranges')
            }
            if origin['source']:
                origins.append(origin)

        # Normalize ecosystem
        ecosystem_normalized = utils.normalize_ecosystem(ecosystem)
        if not ecosystem_normalized:
            return None

        # Determine severity based on ID prefix
        if vuln_id.startswith('MAL-'):
            severity = 'critical'
            behaviors = ['malicious_code']
        else:
            severity = 'high'
            behaviors = ['vulnerability']

        return {
            "name": name,
            "ecosystem": ecosystem_normalized,
            "versions": versions,
            "severity": severity,
            "vuln_id": vuln_id,
            "description": summary or f"Vulnerability in {name}",
            "full_details": details,  # Complete text
            "modified": modified,
            "aliases": aliases,
            "references": references,
            "cwes": cwes,
            "origins": origins,
            "detected_behaviors": behaviors,
            "first_seen": published.split('T')[0] if published else "",
            "source_url": f"https://osv.dev/vulnerability/{vuln_id}"
        }

    except Exception as e:
        return None


def collect_ecosystem(extract_dir, ecosystem_name):
    """
    Collect malicious packages from extracted OSV data
    Only includes MAL- prefixed entries (malware indicators)

    Args:
        extract_dir (str): Path to extracted OSV data
        ecosystem_name (str): Normalized ecosystem name

    Returns:
        list: List of malicious package dictionaries
    """
    if not os.path.exists(extract_dir):
        return []

    packages = []
    json_files = [f for f in os.listdir(extract_dir) if f.endswith('.json')]
    total_files = len(json_files)
    mal_count = 0

    print(f"    Processing {total_files} entries...")

    for i, filename in enumerate(json_files):
        filepath = os.path.join(extract_dir, filename)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Only include MAL- prefixed entries (malware)
            vuln_id = data.get('id', '')
            if not vuln_id.startswith('MAL-'):
                continue

            pkg_info = parse_osv_entry(data)
            if pkg_info:
                packages.append(pkg_info)
                mal_count += 1

        except Exception as e:
            continue

        # Progress indicator every 50000 files
        if (i + 1) % 50000 == 0:
            print(f"      processed {i + 1}/{total_files}, found {mal_count} malicious...")

    return packages


def fetch_osv_packages():
    """
    Fetch malicious packages from OSV.dev bulk downloads

    Returns:
        dict: Standardized data structure with packages
    """
    print("Fetching from OSV.dev (bulk download)...")

    # Create cache directory
    cache_dir = os.path.join(os.path.dirname(__file__), '.cache', 'osv')
    os.makedirs(cache_dir, exist_ok=True)

    all_packages = []
    ecosystems_found = []

    for ecosystem_normalized, ecosystem_osv in ECOSYSTEMS.items():
        print(f"  Processing {ecosystem_normalized}...")

        # Download and extract
        extract_dir = download_ecosystem_data(ecosystem_osv, cache_dir)
        if not extract_dir:
            print(f"    Skipping {ecosystem_normalized} (download failed)")
            continue

        # Collect malicious packages
        packages = collect_ecosystem(extract_dir, ecosystem_normalized)

        if packages:
            all_packages.extend(packages)
            ecosystems_found.append(ecosystem_normalized)
            print(f"    {ecosystem_normalized}: {len(packages)} malicious packages found")
        else:
            print(f"    {ecosystem_normalized}: no malicious packages found")

    # Build standardized structure
    result = {
        "source": "osv",
        "collected_at": utils.get_timestamp(),
        "total_packages": len(all_packages),
        "ecosystems": ecosystems_found,
        "packages": all_packages,
        "note": "Only includes MAL- prefixed entries (malware indicators)"
    }

    return result


def main():
    """Main entry point"""
    print("=" * 60)
    print("OSV.dev Malware Collector")
    print("=" * 60)

    data = fetch_osv_packages()

    if data:
        # Save to raw-data
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'osv.json')
        if utils.save_json(data, output_path):
            print(f"\nCollected {data['total_packages']} malicious packages")
            print(f"Ecosystems: {', '.join(data['ecosystems']) if data['ecosystems'] else 'none'}")
            if data.get('note'):
                print(f"Note: {data['note']}")
            print(f"Saved to: {output_path}")
        else:
            print("Error: Failed to save data")
            sys.exit(1)
    else:
        print("Error: Failed to fetch OSV.dev data")
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'osv.json')
        utils.save_json({
            "source": "osv",
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": "Failed to fetch data from OSV.dev"
        }, output_path)
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
