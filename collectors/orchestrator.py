#!/usr/bin/env python3
"""
Collector Orchestrator
Programmatically runs all collectors and builds unified databases
"""

import os
import sys
from typing import List, Optional, Dict

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils
import collect_openssf
import collect_osv
import collect_phylum
import collect_socketdev
import build_unified_index


def _get_directories():
    """
    Get the raw-data and final-data directories.
    
    Returns:
        Tuple of (raw_data_dir, final_data_dir)
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    raw_data_dir = os.path.join(script_dir, 'raw-data')
    final_data_dir = os.path.join(script_dir, 'final-data')
    
    # Create directories if they don't exist
    os.makedirs(raw_data_dir, exist_ok=True)
    os.makedirs(final_data_dir, exist_ok=True)
    
    return raw_data_dir, final_data_dir


def run_collector(name: str, fetch_func, output_filename: str) -> bool:
    """
    Run a single collector and save its data.
    
    Args:
        name: Display name of the collector
        fetch_func: Function to call to fetch data
        output_filename: Filename to save data to (in raw-data/)
        
    Returns:
        True if successful, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"Running {name}")
    print('='*60)
    
    raw_data_dir, _ = _get_directories()
    
    try:
        # Call the fetch function
        data = fetch_func()
        
        if not data:
            print(f"⚠ {name} returned no data")
            # Save empty result
            output_path = os.path.join(raw_data_dir, output_filename)
            utils.save_json({
                "source": output_filename.replace('.json', ''),
                "collected_at": utils.get_timestamp(),
                "total_packages": 0,
                "ecosystems": [],
                "packages": [],
                "error": "No data returned"
            }, output_path)
            return False
        
        # Save to raw-data
        output_path = os.path.join(raw_data_dir, output_filename)
        if utils.save_json(data, output_path):
            package_count = data.get('total_packages', 0)
            print(f"✓ {name} completed: {package_count} packages")
            return True
        else:
            print(f"✗ {name} failed to save data")
            return False
            
    except Exception as e:
        print(f"✗ {name} failed with error: {e}")
        # Save error result
        output_path = os.path.join(raw_data_dir, output_filename)
        utils.save_json({
            "source": output_filename.replace('.json', ''),
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": str(e)
        }, output_path)
        return False


def run_all_collectors(sources: Optional[List[str]] = None) -> Dict[str, bool]:
    """
    Run all or selected collectors.
    
    Args:
        sources: List of sources to collect from. 
                Options: 'openssf', 'osv', 'phylum', 'socketdev'
                If None, runs all collectors.
    
    Returns:
        Dict mapping source name to success status
    """
    # Define all available collectors
    all_collectors = {
        'openssf': {
            'name': 'OpenSSF Malicious Packages',
            'func': collect_openssf.fetch_openssf_packages,
            'output': 'openssf.json'
        },
        'osv': {
            'name': 'OSV.dev',
            'func': collect_osv.fetch_osv_packages,
            'output': 'osv.json'
        },
        'phylum': {
            'name': 'Phylum.io Blog',
            'func': collect_phylum.fetch_phylum_packages,
            'output': 'phylum.json'
        },
        'socketdev': {
            'name': 'Socket.dev',
            'func': collect_socketdev.fetch_socketdev_packages,
            'output': 'socketdev.json'
        }
    }
    
    # Filter collectors if sources specified
    if sources:
        collectors = {k: v for k, v in all_collectors.items() if k in sources}
    else:
        collectors = all_collectors
    
    # Run each collector
    results = {}
    for source_key, collector in collectors.items():
        success = run_collector(
            collector['name'],
            collector['func'],
            collector['output']
        )
        results[source_key] = success
    
    return results


def check_databases_exist() -> bool:
    """
    Check if any SQLite database files exist.
    
    Returns:
        True if at least one database file exists, False otherwise
    """
    _, final_data_dir = _get_directories()
    ecosystems = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
    
    for ecosystem in ecosystems:
        db_path = os.path.join(final_data_dir, f'unified_{ecosystem}.db')
        if os.path.exists(db_path):
            return True
    
    return False


def build_databases() -> bool:
    """
    Build unified SQLite databases from raw data.
    
    Returns:
        True if successful, False otherwise
    """
    print(f"\n{'='*60}")
    print("Building Unified SQLite Databases")
    print('='*60)
    
    try:
        # Load all raw data
        print("\nLoading raw data files...")
        raw_data_list = build_unified_index.load_all_raw_data()
        
        if not raw_data_list:
            print("⚠ No raw data files found")
            return False
        
        print(f"Loaded data from {len(raw_data_list)} sources")
        
        # Merge by ecosystem
        print("\nMerging packages by ecosystem...")
        ecosystem_data = build_unified_index.merge_packages_by_ecosystem(raw_data_list)
        
        if not ecosystem_data:
            print("⚠ No packages found to merge")
            # Create empty databases
            for ecosystem in ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']:
                build_unified_index.build_unified_database(ecosystem, [])
            print("Created empty databases")
            return True
        
        print(f"Found packages in {len(ecosystem_data)} ecosystems")
        
        # Build databases
        print("\nBuilding SQLite databases...")
        total_packages = 0
        success = True
        
        for ecosystem, packages in ecosystem_data.items():
            if build_unified_index.build_unified_database(ecosystem, packages):
                print(f"  ✓ {ecosystem}: {len(packages)} packages")
                total_packages += len(packages)
            else:
                print(f"  ✗ {ecosystem}: Failed to build")
                success = False
        
        # Create empty databases for ecosystems with no data
        all_ecosystems = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
        for ecosystem in all_ecosystems:
            if ecosystem not in ecosystem_data:
                build_unified_index.build_unified_database(ecosystem, [])
                print(f"  ✓ {ecosystem}: 0 packages (empty)")
        
        print(f"\n✓ Built databases with {total_packages} total packages")
        return success
        
    except Exception as e:
        print(f"\n✗ Database build failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def collect_all_data(sources: Optional[List[str]] = None, skip_build: bool = False, build_if_missing: bool = False) -> bool:
    """
    Main function to collect data from all sources and build unified databases.
    
    This function can be imported and called programmatically:
        from collectors.orchestrator import collect_all_data
        collect_all_data()
    
    Args:
        sources: Optional list of specific sources to collect from.
                Options: 'openssf', 'osv', 'phylum', 'socketdev'
                If None, collects from all sources.
        skip_build: If True, never builds databases (always skip).
        build_if_missing: If True, only builds databases if they don't exist.
                         Takes precedence over skip_build.
    
    Returns:
        True if successful, False otherwise
    """
    print("="*60)
    print("OreNPMGuard Malicious Package Collector")
    print("="*60)
    
    # Run collectors
    collector_results = run_all_collectors(sources)
    
    # Print collector summary
    print(f"\n{'='*60}")
    print("Collector Summary")
    print('='*60)
    
    successful = [k for k, v in collector_results.items() if v]
    failed = [k for k, v in collector_results.items() if not v]
    
    if successful:
        print(f"✓ Successful: {', '.join(successful)}")
    if failed:
        print(f"⚠ Failed: {', '.join(failed)}")
    
    # Build databases (conditional logic)
    if build_if_missing:
        # Only build if databases don't exist
        if check_databases_exist():
            print("\nDatabases already exist (build_if_missing=True)")
            print("Skipping database build")
            db_success = True
        else:
            print("\nDatabases not found (build_if_missing=True)")
            print("Building databases...")
            db_success = build_databases()
    elif not skip_build:
        # Always build (default behavior)
        db_success = build_databases()
    else:
        # Never build (skip_build=True)
        print("\nSkipping database build (skip_build=True)")
        db_success = True
    
    # Final summary
    print(f"\n{'='*60}")
    if successful and db_success:
        print("✓ Collection Complete!")
        print(f"Raw data: collectors/raw-data/")
        print(f"Databases: collectors/final-data/*.db")
    else:
        print("⚠ Collection completed with some errors")
        if not successful:
            print(f"  Failed collectors: {', '.join(failed)}")
        if not db_success and not skip_build:
            print("  Database build failed")
    print('='*60)
    
    return bool(successful) and db_success


def main():
    """Command-line entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Collect malicious package data from all sources'
    )
    parser.add_argument(
        '--sources',
        nargs='+',
        choices=['openssf', 'osv', 'phylum', 'socketdev'],
        help='Specific sources to collect from (default: all)'
    )
    parser.add_argument(
        '--skip-build',
        action='store_true',
        help='Skip database building step (never build)'
    )
    parser.add_argument(
        '--build-if-missing',
        action='store_true',
        help='Only build databases if they do not exist'
    )
    
    args = parser.parse_args()
    
    success = collect_all_data(
        sources=args.sources,
        skip_build=args.skip_build,
        build_if_missing=args.build_if_missing
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
