#!/usr/bin/env python3
"""
YAML Package List Updater for Shai-Hulud Attack
Compares existing YAML package list with updated text list and adds missing packages
"""

import yaml
import re
import sys
from collections import defaultdict
from typing import Dict, Set, List, Tuple


def parse_yaml_packages(yaml_file: str) -> Dict[str, Set[str]]:
    """Parse the YAML file and return a dict of package_name -> set of versions"""
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        packages = {}
        if 'affected_packages' in data:
            for pkg in data['affected_packages']:
                name = pkg['name']
                versions = set(pkg['versions'])
                packages[name] = versions

        return packages
    except Exception as e:
        print(f"Error reading YAML file: {e}")
        return {}


def parse_text_packages(text_file: str) -> Dict[str, Set[str]]:
    """Parse the text file and return a dict of package_name -> set of versions"""
    packages = defaultdict(set)

    try:
        with open(text_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Handle various formats in the text file
        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Handle different formats:
            # 1. package@version
            # 2. @scope/package@version
            # 3. package@version1, @version2 (special case)
            # 4. package@version1, version2 (another special case)

            if '@' in line:
                # Handle special cases with commas
                if ', @' in line or ', ' in line:
                    # Special format like "@ctrl/tinycolor@4.1.1, @4.1.2"
                    if '@' in line and ', @' in line:
                        parts = line.split(', @')
                        if len(parts) == 2:
                            # First part: package@version
                            first_match = re.match(r'^(.+)@([^,]+)$', parts[0])
                            if first_match:
                                pkg_name = first_match.group(1)
                                version1 = first_match.group(2)
                                version2 = parts[1]
                                packages[pkg_name].add(version1)
                                packages[pkg_name].add(version2)
                                continue

                    # Format like "json-rules-engine-simplified@0.2.4, 0.2.1"
                    elif ', ' in line and line.count('@') == 1:
                        parts = line.split(', ')
                        first_part = parts[0]
                        pkg_match = re.match(r'^(.+)@([^,]+)$', first_part)
                        if pkg_match:
                            pkg_name = pkg_match.group(1)
                            version1 = pkg_match.group(2)
                            packages[pkg_name].add(version1)

                            # Add remaining versions
                            for part in parts[1:]:
                                version = part.strip()
                                if version:
                                    packages[pkg_name].add(version)
                            continue

                # Standard format: package@version
                match = re.match(r'^(.+)@([^@]+)$', line)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(2)
                    packages[pkg_name].add(version)
                else:
                    print(f"Warning: Could not parse line: {line}")
            else:
                print(f"Warning: No @ symbol found in line: {line}")

    except Exception as e:
        print(f"Error reading text file: {e}")
        return {}

    return dict(packages)


def find_missing_packages(yaml_packages: Dict[str, Set[str]],
                          text_packages: Dict[str, Set[str]]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Find packages that are missing from YAML and versions that need to be added"""

    completely_missing = {}  # Packages not in YAML at all
    missing_versions = {}  # Packages in YAML but missing some versions

    for pkg_name, text_versions in text_packages.items():
        if pkg_name not in yaml_packages:
            # Package completely missing from YAML
            completely_missing[pkg_name] = text_versions
        else:
            # Package exists, check for missing versions
            yaml_versions = yaml_packages[pkg_name]
            missing_vers = text_versions - yaml_versions
            if missing_vers:
                missing_versions[pkg_name] = missing_vers

    return completely_missing, missing_versions


def update_yaml_file(yaml_file: str, output_file: str,
                     completely_missing: Dict[str, Set[str]],
                     missing_versions: Dict[str, Set[str]]) -> None:
    """Update the YAML file with missing packages and versions"""

    try:
        # Read original YAML
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if 'affected_packages' not in data:
            data['affected_packages'] = []

        # Create a lookup for existing packages
        existing_packages = {}
        for i, pkg in enumerate(data['affected_packages']):
            existing_packages[pkg['name']] = i

        # Add missing versions to existing packages
        for pkg_name, new_versions in missing_versions.items():
            if pkg_name in existing_packages:
                idx = existing_packages[pkg_name]
                current_versions = set(data['affected_packages'][idx]['versions'])
                updated_versions = sorted(list(current_versions | new_versions))
                data['affected_packages'][idx]['versions'] = updated_versions
                print(f"Updated {pkg_name}: added versions {sorted(list(new_versions))}")

        # Add completely missing packages
        for pkg_name, versions in completely_missing.items():
            new_package = {
                'name': pkg_name,
                'versions': sorted(list(versions))
            }
            data['affected_packages'].append(new_package)
            print(f"Added new package {pkg_name} with versions {sorted(list(versions))}")

        # Sort packages alphabetically for consistency
        data['affected_packages'].sort(key=lambda x: x['name'])

        # Write updated YAML with consistent formatting
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header comment
            f.write("# Shai-Hulud Attack - Affected npm Packages\n")
            f.write("# This file contains the centralized list of compromised packages and their affected versions\n")
            f.write("# Both Python and JavaScript scanners read from this file to ensure consistency\n")
            f.write("# Updated automatically with latest threat intelligence\n\n")
            f.write("affected_packages:\n")

            # Write each package manually to maintain exact original formatting
            for pkg in data['affected_packages']:
                name = pkg['name']
                versions = pkg['versions']

                # Format exactly like original: quoted name, inline array for versions
                f.write(f'  - name: "{name}"\n')
                f.write(f'    versions: {versions}\n\n')

        print(f"Updated YAML written to: {output_file}")

    except Exception as e:
        print(f"Error updating YAML file: {e}")


def generate_summary(yaml_packages: Dict[str, Set[str]],
                     text_packages: Dict[str, Set[str]],
                     completely_missing: Dict[str, Set[str]],
                     missing_versions: Dict[str, Set[str]]) -> None:
    """Generate a summary of the comparison"""

    print("\n" + "=" * 60)
    print("PACKAGE COMPARISON SUMMARY")
    print("=" * 60)

    print(f"Packages in original YAML: {len(yaml_packages)}")
    print(f"Packages in text file: {len(text_packages)}")
    print(f"Completely missing packages: {len(completely_missing)}")
    print(f"Packages with missing versions: {len(missing_versions)}")

    total_yaml_versions = sum(len(versions) for versions in yaml_packages.values())
    total_text_versions = sum(len(versions) for versions in text_packages.values())
    total_missing_versions = sum(len(versions) for versions in missing_versions.values())
    total_new_versions = sum(len(versions) for versions in completely_missing.values())

    print(f"Total versions in YAML: {total_yaml_versions}")
    print(f"Total versions in text: {total_text_versions}")
    print(f"Missing versions to add: {total_missing_versions}")
    print(f"New package versions to add: {total_new_versions}")

    if completely_missing:
        print(f"\nCompletely missing packages ({len(completely_missing)}):")
        for pkg_name in sorted(completely_missing.keys()):
            versions = sorted(list(completely_missing[pkg_name]))
            print(f"  - {pkg_name}: {versions}")

    if missing_versions:
        print(f"\nPackages with missing versions ({len(missing_versions)}):")
        for pkg_name in sorted(missing_versions.keys()):
            versions = sorted(list(missing_versions[pkg_name]))
            print(f"  - {pkg_name}: {versions}")

    print("=" * 60)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 package_yaml_updater.py <yaml_file> <text_file> [output_file]")
        print("")
        print("Arguments:")
        print("  yaml_file   - Path to the existing YAML file with affected packages")
        print("  text_file   - Path to the text file with updated package list")
        print("  output_file - Path for the updated YAML file (optional, defaults to 'updated_affected_packages.yaml')")
        print("")
        print("Example:")
        print("  python3 package_yaml_updater.py affected_packages.yaml updated_list.txt")
        sys.exit(1)

    yaml_file = sys.argv[1]
    text_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else 'updated_affected_packages.yaml'

    print("Shai-Hulud Package YAML Updater")
    print("=" * 40)
    print(f"YAML file: {yaml_file}")
    print(f"Text file: {text_file}")
    print(f"Output file: {output_file}")
    print()

    # Parse both files
    print("Parsing YAML file...")
    yaml_packages = parse_yaml_packages(yaml_file)
    print(f"Found {len(yaml_packages)} packages in YAML")

    print("Parsing text file...")
    text_packages = parse_text_packages(text_file)
    print(f"Found {len(text_packages)} packages in text file")

    # Find missing packages and versions
    print("Comparing packages...")
    completely_missing, missing_versions = find_missing_packages(yaml_packages, text_packages)

    # Generate summary
    generate_summary(yaml_packages, text_packages, completely_missing, missing_versions)

    # Update YAML file
    if completely_missing or missing_versions:
        print(f"\nUpdating YAML file...")
        update_yaml_file(yaml_file, output_file, completely_missing, missing_versions)
        print(f"\nUpdate complete! Check {output_file}")
    else:
        print("\nNo updates needed - all packages and versions are already present in YAML!")


if __name__ == "__main__":
    main()