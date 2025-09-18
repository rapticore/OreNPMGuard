#!/usr/bin/env python3
"""
Shai-Hulud npm Package Scanner (Python)
Scans package.json and package-lock.json files for compromised packages from the Shai-Hulud attack
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
    """Scan a package.json or package-lock.json file for affected packages."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Error reading {file_path}: {e}")
        return [], []

    affected_db = load_affected_packages_from_yaml()

    # Determine file type and scan accordingly
    if file_path.endswith('package-lock.json'):
        return scan_package_lock_dependencies(package_data, affected_db)
    else:
        return scan_package_json_dependencies(package_data, affected_db)


def scan_package_json_dependencies(package_data: dict, affected_db: Dict[str, Set[str]]) -> Tuple[List[Dict], List[Dict]]:
    """Scan package.json dependency sections."""
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


def scan_package_lock_dependencies(package_data: dict, affected_db: Dict[str, Set[str]]) -> Tuple[List[Dict], List[Dict]]:
    """Scan package-lock.json dependencies (includes nested dependencies)."""
    found_packages = []
    potential_matches = []

    def scan_dependencies_recursive(deps: dict, section: str = 'lockfile', depth: int = 0):
        """Recursively scan dependencies in package-lock.json format."""
        if not deps:
            return

        for pkg_name, pkg_info in deps.items():
            if not isinstance(pkg_info, dict):
                continue

            # Get version from package-lock.json
            installed_version = pkg_info.get('version', '')

            if pkg_name in affected_db and installed_version:
                if installed_version in affected_db[pkg_name]:
                    found_packages.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': f'{section} (depth {depth})',
                        'exact_match': True
                    })
                else:
                    potential_matches.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': f'{section} (depth {depth})',
                        'exact_match': False
                    })

            # Recursively scan nested dependencies
            if 'dependencies' in pkg_info:
                scan_dependencies_recursive(pkg_info['dependencies'], section, depth + 1)

    # Scan top-level dependencies in package-lock.json
    if 'dependencies' in package_data:
        scan_dependencies_recursive(package_data['dependencies'], 'dependencies')

    # Also scan packages section if present (npm v7+ format)
    if 'packages' in package_data:
        for pkg_path, pkg_info in package_data['packages'].items():
            if pkg_path == '':  # Skip root package
                continue

            # Extract package name from node_modules path
            if pkg_path.startswith('node_modules/'):
                pkg_name = pkg_path[len('node_modules/'):]
                # Handle scoped packages
                if pkg_name.count('/') > 1:
                    parts = pkg_name.split('/')
                    if parts[0].startswith('@'):
                        pkg_name = f"{parts[0]}/{parts[1]}"
                    else:
                        pkg_name = parts[0]

                installed_version = pkg_info.get('version', '')

                if pkg_name in affected_db and installed_version:
                    if installed_version in affected_db[pkg_name]:
                        found_packages.append({
                            'name': pkg_name,
                            'installed_version': installed_version,
                            'affected_versions': list(affected_db[pkg_name]),
                            'section': 'packages',
                            'exact_match': True
                        })
                    else:
                        potential_matches.append({
                            'name': pkg_name,
                            'installed_version': installed_version,
                            'affected_versions': list(affected_db[pkg_name]),
                            'section': 'packages',
                            'exact_match': False
                        })

    return found_packages, potential_matches


def scan_directory(directory: str) -> None:
    """Recursively scan directory for package.json and package-lock.json files."""
    print(f"🔍 Scanning directory: {directory}")
    print("=" * 60)

    found_any = False

    for root, dirs, files in os.walk(directory):
        # Skip node_modules directories
        dirs[:] = [d for d in dirs if d != 'node_modules']

        # Check for both package.json and package-lock.json files
        files_to_scan = []
        if 'package.json' in files:
            files_to_scan.append(('package.json', '📦'))
        if 'package-lock.json' in files:
            files_to_scan.append(('package-lock.json', '🔒'))

        for filename, icon in files_to_scan:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, directory)

            print(f"\n{icon} Checking: {relative_path}")

            exact_matches, potential_matches = scan_package_json(file_path)

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
        print("Usage: python3 shai_hulud_scanner.py <path_to_package.json|package-lock.json_or_directory>")
        print("Examples:")
        print("  python3 shai_hulud_scanner.py ./package.json")
        print("  python3 shai_hulud_scanner.py ./package-lock.json")
        print("  python3 shai_hulud_scanner.py ./my-project")
        print("  python3 shai_hulud_scanner.py .")
        sys.exit(1)

    target_path = sys.argv[1]

    if os.path.isfile(target_path) and (target_path.endswith('package.json') or target_path.endswith('package-lock.json')):
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