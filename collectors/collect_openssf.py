#!/usr/bin/env python3
"""
OpenSSF Malicious Packages Collector
Fetches malicious package data from OpenSSF's malicious-packages repository
Repository: https://github.com/ossf/malicious-packages
Structure: osv/malicious/{ecosystem}/{package_name}/MAL-*.json
"""

import os
import sys
import json
import subprocess
import shutil

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils


# Repository and cache settings
REPO_URL = "https://github.com/ossf/malicious-packages.git"
CACHE_DIR = os.path.join(os.path.dirname(__file__), '.cache', 'ossf-repo')
MALICIOUS_PATH = "osv/malicious"

# Ecosystems to collect (matches directory names in repo)
ECOSYSTEMS = ['npm', 'pypi', 'go', 'rubygems', 'maven', 'crates.io', 'nuget']


def clone_or_update_repo():
    """
    Clone the OpenSSF malicious-packages repo or update if exists
    Uses shallow clone to save space and time

    Returns:
        str: Path to repo root, or None on error
    """
    if os.path.exists(os.path.join(CACHE_DIR, '.git')):
        print("  Updating existing repo cache...")
        try:
            subprocess.run(
                ['git', 'pull', '--depth', '1'],
                cwd=CACHE_DIR,
                capture_output=True,
                timeout=300
            )
            return CACHE_DIR
        except Exception as e:
            print(f"  Warning: Could not update repo: {e}")
            print("  Using existing cache...")
            return CACHE_DIR

    print("  Cloning repository (this may take a few minutes)...")
    os.makedirs(os.path.dirname(CACHE_DIR), exist_ok=True)

    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', REPO_URL, CACHE_DIR],
            capture_output=True,
            text=True,
            timeout=600
        )
        if result.returncode != 0:
            print(f"  Error cloning repo: {result.stderr}")
            return None
        return CACHE_DIR
    except subprocess.TimeoutExpired:
        print("  Error: Clone timed out")
        return None
    except Exception as e:
        print(f"  Error cloning repo: {e}")
        return None


def parse_osv_file(filepath):
    """
    Parse a single OSV JSON file and extract package info

    Args:
        filepath (str): Path to JSON file

    Returns:
        dict: Package info or None
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Extract from OSV format
        mal_id = data.get('id', '')
        summary = data.get('summary', '')
        details = data.get('details', '')  # Full text, no truncation
        published = data.get('published', '')
        modified = data.get('modified', '')

        # Get aliases (GHSA IDs, SNYK IDs, etc.)
        aliases = data.get('aliases', [])

        # Get references (advisory URLs, package links)
        references = data.get('references', [])

        # Get affected package info
        affected = data.get('affected', [])
        if not affected:
            return None

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
        ecosystem = utils.normalize_ecosystem(ecosystem)
        if not ecosystem:
            return None

        return {
            "name": name,
            "ecosystem": ecosystem,
            "versions": versions,
            "severity": "critical",  # All malicious packages are critical
            "mal_id": mal_id,
            "description": summary or f"Malicious package: {name}",
            "full_details": details,  # Complete text
            "modified": modified,
            "aliases": aliases,
            "references": references,
            "cwes": cwes,
            "origins": origins,
            "detected_behaviors": ["malicious_code"],
            "first_seen": published.split('T')[0] if published else "",
            "source_url": f"https://github.com/ossf/malicious-packages/blob/main/{MALICIOUS_PATH}/{ecosystem}/{name}"
        }

    except json.JSONDecodeError as e:
        print(f"    JSON error in {filepath}: {e}")
        return None
    except Exception as e:
        print(f"    Error parsing {filepath}: {e}")
        return None


def collect_ecosystem(repo_path, ecosystem):
    """
    Collect all malicious packages for a specific ecosystem

    Args:
        repo_path (str): Path to cloned repo
        ecosystem (str): Ecosystem name (npm, pypi, etc.)

    Returns:
        list: List of package dictionaries
    """
    ecosystem_path = os.path.join(repo_path, MALICIOUS_PATH, ecosystem)

    if not os.path.exists(ecosystem_path):
        print(f"    {ecosystem}: directory not found")
        return []

    packages = []
    package_dirs = os.listdir(ecosystem_path)
    total_dirs = len(package_dirs)

    print(f"    {ecosystem}: processing {total_dirs} packages...")

    for i, pkg_name in enumerate(package_dirs):
        pkg_path = os.path.join(ecosystem_path, pkg_name)

        if not os.path.isdir(pkg_path):
            continue

        # Find JSON files in package directory
        for filename in os.listdir(pkg_path):
            if filename.endswith('.json'):
                filepath = os.path.join(pkg_path, filename)
                pkg_info = parse_osv_file(filepath)
                if pkg_info:
                    packages.append(pkg_info)

        # Progress indicator every 10000 packages
        if (i + 1) % 10000 == 0:
            print(f"      processed {i + 1}/{total_dirs}...")

    return packages


def fetch_openssf_packages():
    """
    Fetch malicious packages from OpenSSF malicious-packages repo

    Returns:
        dict: Standardized data structure with packages
    """
    print("Fetching from OpenSSF Malicious Packages Repository...")

    # Clone or update repo
    repo_path = clone_or_update_repo()
    if not repo_path:
        return None

    print("  Collecting packages by ecosystem...")

    all_packages = []
    ecosystems_found = []

    for ecosystem in ECOSYSTEMS:
        packages = collect_ecosystem(repo_path, ecosystem)
        if packages:
            all_packages.extend(packages)
            ecosystems_found.append(ecosystem)
            print(f"    {ecosystem}: {len(packages)} packages collected")

    # Build standardized structure
    result = {
        "source": "openssf",
        "collected_at": utils.get_timestamp(),
        "total_packages": len(all_packages),
        "ecosystems": ecosystems_found,
        "packages": all_packages
    }

    return result


def main():
    """Main entry point"""
    print("=" * 60)
    print("OpenSSF Malicious Packages Collector")
    print("=" * 60)

    data = fetch_openssf_packages()

    if data and data['total_packages'] > 0:
        # Save to raw-data
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'openssf.json')
        if utils.save_json(data, output_path):
            print(f"\nSuccess! Collected {data['total_packages']} packages")
            print(f"Ecosystems: {', '.join(data['ecosystems'])}")
            print(f"Saved to: {output_path}")
        else:
            print("Error: Failed to save data")
            sys.exit(1)
    else:
        print("Error: Failed to fetch OpenSSF data or no packages found")
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'openssf.json')
        utils.save_json({
            "source": "openssf",
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": "Failed to fetch data from OpenSSF"
        }, output_path)
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
