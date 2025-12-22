#!/usr/bin/env python3
"""
Unified Index Builder
Merges raw data from all sources into ecosystem-specific unified files
"""

import os
import sys
from collections import defaultdict

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils
import db


def load_all_raw_data():
    """
    Load all raw data files from raw-data directory

    Returns:
        list: List of data dictionaries from all sources
    """
    raw_data_dir = os.path.join(os.path.dirname(__file__), 'raw-data')
    raw_files = ['openssf.json', 'socketdev.json', 'osv.json', 'phylum.json']

    all_data = []

    for filename in raw_files:
        filepath = os.path.join(raw_data_dir, filename)
        data = utils.load_json(filepath)

        if data:
            print(f"Loaded {filename}: {data.get('total_packages', 0)} packages")
            all_data.append(data)
        else:
            print(f"Warning: Could not load {filename}")

    return all_data


def merge_packages_by_ecosystem(raw_data_list):
    """
    Merge packages from all sources, organized by ecosystem

    Args:
        raw_data_list (list): List of raw data dictionaries

    Returns:
        dict: Ecosystem -> packages mapping
            Example: {"npm": [...], "pypi": [...]}
    """
    # Group by ecosystem
    ecosystem_packages = defaultdict(dict)  # ecosystem -> package_name -> package_data

    for source_data in raw_data_list:
        source = source_data.get('source', 'unknown')
        packages = source_data.get('packages', [])

        for pkg in packages:
            name = pkg.get('name')
            ecosystem = pkg.get('ecosystem')

            if not name or not ecosystem:
                continue

            # Normalize ecosystem
            ecosystem = utils.normalize_ecosystem(ecosystem)
            if not ecosystem:
                continue

            # Create unique key for this package
            key = name.lower()

            # If package already exists, merge data
            if key in ecosystem_packages[ecosystem]:
                existing = ecosystem_packages[ecosystem][key]

                # Merge versions (unique)
                existing_versions = set(existing.get('versions', []))
                new_versions = set(pkg.get('versions', []))
                all_versions = sorted(list(existing_versions | new_versions))
                existing['versions'] = all_versions

                # Add source to sources list
                if source not in existing.get('sources', []):
                    existing['sources'].append(source)

                # Use highest severity
                existing_sev = existing.get('severity', 'low')
                new_sev = pkg.get('severity', 'low')
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
                if severity_order.get(new_sev, 0) > severity_order.get(existing_sev, 0):
                    existing['severity'] = new_sev

                # Merge detected behaviors
                existing_behaviors = set(existing.get('detected_behaviors', []))
                new_behaviors = set(pkg.get('detected_behaviors', []))
                existing['detected_behaviors'] = sorted(list(existing_behaviors | new_behaviors))

                # Store source-specific details
                if 'source_details' not in existing:
                    existing['source_details'] = {}

                existing['source_details'][source] = {
                    'severity': pkg.get('severity'),
                    'url': pkg.get('source_url', ''),
                    'description': pkg.get('description', '')
                }

                # Merge aliases (union, dedupe)
                existing_aliases = set(existing.get('aliases', []))
                new_aliases = set(pkg.get('aliases', []))
                existing['aliases'] = sorted(list(existing_aliases | new_aliases))

                # Merge CWEs (union by id)
                existing_cwes = {c['id']: c for c in existing.get('cwes', [])}
                for cwe in pkg.get('cwes', []):
                    if cwe.get('id'):
                        existing_cwes[cwe['id']] = cwe
                existing['cwes'] = list(existing_cwes.values())

                # Merge references (union by url)
                existing_refs = {r.get('url', ''): r for r in existing.get('references', [])}
                for ref in pkg.get('references', []):
                    if ref.get('url'):
                        existing_refs[ref['url']] = ref
                existing['references'] = list(existing_refs.values())

                # Merge origins (append all)
                existing['origins'] = existing.get('origins', []) + pkg.get('origins', [])

                # Keep longest full_details
                new_details = pkg.get('full_details', '')
                if len(new_details) > len(existing.get('full_details', '')):
                    existing['full_details'] = new_details

                # Keep latest modified timestamp
                new_modified = pkg.get('modified', '')
                if new_modified > existing.get('modified', ''):
                    existing['modified'] = new_modified

                # Update last_updated
                existing['last_updated'] = utils.get_timestamp()

            else:
                # New package
                ecosystem_packages[ecosystem][key] = {
                    'name': name,
                    'versions': pkg.get('versions', []),
                    'severity': pkg.get('severity', 'unknown'),
                    'sources': [source],
                    'first_seen': pkg.get('first_seen', utils.get_timestamp().split('T')[0]),
                    'modified': pkg.get('modified', ''),
                    'last_updated': utils.get_timestamp(),
                    'description': pkg.get('description', ''),
                    'full_details': pkg.get('full_details', ''),
                    'detected_behaviors': pkg.get('detected_behaviors', []),
                    'aliases': pkg.get('aliases', []),
                    'cwes': pkg.get('cwes', []),
                    'references': pkg.get('references', []),
                    'origins': pkg.get('origins', []),
                    'source_details': {
                        source: {
                            'severity': pkg.get('severity'),
                            'url': pkg.get('source_url', ''),
                            'description': pkg.get('description', '')
                        }
                    }
                }

    # Convert dict to list for each ecosystem
    result = {}
    for ecosystem, packages_dict in ecosystem_packages.items():
        result[ecosystem] = list(packages_dict.values())

    return result


def build_unified_database(ecosystem, packages):
    """
    Build SQLite database for a specific ecosystem.

    Args:
        ecosystem (str): Ecosystem name (npm, pypi, etc.)
        packages (list): List of package dictionaries

    Returns:
        bool: True on success
    """
    # Sort packages by name
    packages = sorted(packages, key=lambda p: p.get('name', '').lower())

    output_path = os.path.join(
        os.path.dirname(__file__),
        'final-data',
        f'unified_{ecosystem}.db'
    )

    try:
        # Create database with temp file
        conn, temp_path = db.create_database(output_path)

        # Insert metadata
        db.insert_metadata(conn, ecosystem, packages, utils.get_timestamp())

        # Insert packages
        db.insert_packages(conn, packages)

        # Finalize (create indexes, atomic rename)
        db.finalize_database(conn, temp_path, output_path)

        return True

    except Exception as e:
        print(f"Error building database for {ecosystem}: {e}")
        return False


def main():
    """Main entry point"""
    print("=" * 60)
    print("Unified Index Builder")
    print("=" * 60)
    print()

    # Load all raw data
    print("Loading raw data files...")
    raw_data_list = load_all_raw_data()

    if not raw_data_list:
        print("Error: No raw data files found")
        sys.exit(1)

    print(f"\nLoaded data from {len(raw_data_list)} sources")
    print()

    # Merge by ecosystem
    print("Merging packages by ecosystem...")
    ecosystem_data = merge_packages_by_ecosystem(raw_data_list)

    if not ecosystem_data:
        print("Warning: No packages found to merge")
        # Still create empty databases for each ecosystem
        for ecosystem in ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']:
            build_unified_database(ecosystem, [])
        print("\nCreated empty databases")
        return

    print(f"Found packages in {len(ecosystem_data)} ecosystems")
    print()

    # Build SQLite databases for each ecosystem
    print("Building SQLite databases...")
    total_packages = 0

    for ecosystem, packages in ecosystem_data.items():
        if build_unified_database(ecosystem, packages):
            print(f"  ✓ {ecosystem}: {len(packages)} packages")
            total_packages += len(packages)
        else:
            print(f"  ✗ {ecosystem}: Failed to build")

    # Create empty databases for ecosystems with no data
    all_ecosystems = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
    for ecosystem in all_ecosystems:
        if ecosystem not in ecosystem_data:
            build_unified_database(ecosystem, [])
            print(f"  ✓ {ecosystem}: 0 packages (empty)")

    print()
    print("=" * 60)
    print(f"Summary: {total_packages} total packages")
    print(f"Databases saved to: collectors/final-data/*.db")
    print("=" * 60)


if __name__ == "__main__":
    main()
