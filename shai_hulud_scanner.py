#!/usr/bin/env python3
"""
Shai-Hulud npm Package Scanner (Python)
Scans package.json files for compromised packages from the Shai-Hulud attack
"""

import json
import sys
import re
import os
from pathlib import Path
from typing import Set, Dict, List, Tuple
import yaml

def load_affected_packages_from_yaml() -> Dict[str, Set[str]]:
    """Load affected packages from YAML configuration file."""
    config_path = Path(__file__).parent / 'affected_packages.yaml'

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        packages = {}
        for pkg in config['affected_packages']:
            packages[pkg['name']] = set(pkg['versions'])

        return packages
    except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
        print(f"❌ Error loading configuration from {config_path}: {e}")
        print("Using fallback hardcoded data...")
        return parse_affected_packages_fallback()


def parse_affected_packages_fallback() -> Dict[str, Set[str]]:
    """Fallback hardcoded package data in case YAML file is unavailable."""
    # Minimal fallback data - in production, the YAML file should always be available
    return {
        '@ctrl/deluge': {'7.2.2', '7.2.1'},
        'ngx-bootstrap': {'18.1.4', '19.0.3', '20.0.4', '20.0.5', '20.0.6', '19.0.4', '20.0.3'},
        # Add more critical packages as needed
    }


def scan_package_json(file_path: str) -> Tuple[List[Dict], List[Dict]]:
    """Scan a package.json file for affected packages."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Error reading {file_path}: {e}")
        return [], []

    affected_db = load_affected_packages_from_yaml()
    found_packages = []
    potential_matches = []

    # Check all dependency sections
    deps_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

    for section in deps_sections:
        if section not in package_data:
            continue

        for pkg_name, installed_version in package_data[section].items():
            # Clean version string (remove ^, ~, etc.)
            clean_version = re.sub(r'^[\^~>=<]', '', installed_version)

            if pkg_name in affected_db:
                # Check if installed version matches any affected version
                if clean_version in affected_db[pkg_name]:
                    found_packages.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': section,
                        'exact_match': True
                    })
                else:
                    # Package name matches but version might be different
                    potential_matches.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': section,
                        'exact_match': False
                    })

    return found_packages, potential_matches


def scan_directory(directory: str) -> None:
    """Recursively scan directory for package.json files."""
    print(f"🔍 Scanning directory: {directory}")
    print("=" * 60)

    found_any = False

    for root, dirs, files in os.walk(directory):
        # Skip node_modules directories
        dirs[:] = [d for d in dirs if d != 'node_modules']

        if 'package.json' in files:
            package_json_path = os.path.join(root, 'package.json')
            relative_path = os.path.relpath(package_json_path, directory)

            print(f"\n📦 Checking: {relative_path}")

            exact_matches, potential_matches = scan_package_json(package_json_path)

            if exact_matches:
                found_any = True
                print(f"🚨 CRITICAL: Found {len(exact_matches)} CONFIRMED compromised packages:")
                for pkg in exact_matches:
                    print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                    print(f"     Affected versions: {', '.join(pkg['affected_versions'])}")

            if potential_matches:
                print(f"⚠️  WARNING: Found {len(potential_matches)} packages with different versions:")
                for pkg in potential_matches:
                    print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                    print(f"     Known affected versions: {', '.join(pkg['affected_versions'])}")

            if not exact_matches and not potential_matches:
                print("✅ No affected packages found")

    print("\n" + "=" * 60)
    if found_any:
        print("🚨 IMMEDIATE ACTION REQUIRED!")
        print("1. Remove compromised packages immediately")
        print("2. Rotate ALL credentials (GitHub tokens, npm tokens, API keys)")
        print("3. Check for 'Shai-Hulud' repos in your GitHub account")
        print("4. Review GitHub audit logs")
    else:
        print("✅ No confirmed compromised packages found in scanned directories")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 shai_hulud_scanner.py <path_to_package.json_or_directory>")
        print("Examples:")
        print("  python3 shai_hulud_scanner.py ./package.json")
        print("  python3 shai_hulud_scanner.py ./my-project")
        print("  python3 shai_hulud_scanner.py .")
        sys.exit(1)

    target_path = sys.argv[1]

    if os.path.isfile(target_path) and target_path.endswith('package.json'):
        print(f"🔍 Scanning file: {target_path}")
        print("=" * 60)

        exact_matches, potential_matches = scan_package_json(target_path)

        if exact_matches:
            print(f"🚨 CRITICAL: Found {len(exact_matches)} CONFIRMED compromised packages:")
            for pkg in exact_matches:
                print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                print(f"     Affected versions: {', '.join(pkg['affected_versions'])}")

        if potential_matches:
            print(f"⚠️  WARNING: Found {len(potential_matches)} packages with different versions:")
            for pkg in potential_matches:
                print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                print(f"     Known affected versions: {', '.join(pkg['affected_versions'])}")

        if not exact_matches and not potential_matches:
            print("✅ No affected packages found")

    elif os.path.isdir(target_path):
        scan_directory(target_path)
    else:
        print(f"❌ Error: {target_path} is not a valid file or directory")
        sys.exit(1)


if __name__ == "__main__":
    main()