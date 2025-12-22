#!/usr/bin/env python3
"""
Example: Using the Refactored Functional Orchestrator

This demonstrates how to use the functional orchestrator to collect malicious package data.
All examples now use standalone functions instead of a class.
"""

import sys
import os

# Add collectors directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))

from orchestrator import (
    collect_all_data,
    check_databases_exist,
    run_all_collectors,
    build_databases
)


def example_1_collect_all():
    """Example 1: Collect from all sources and build databases."""
    print("Example 1: Collecting from all sources")
    print("=" * 60)
    
    # This will run all collectors and build the SQLite databases
    success = collect_all_data()
    
    if success:
        print("\n✓ Collection successful!")
        print("Databases are now available in collectors/final-data/")
    else:
        print("\n⚠ Collection completed with errors")


def example_2_specific_sources():
    """Example 2: Collect only from specific sources."""
    print("\nExample 2: Collecting only from OpenSSF and OSV")
    print("=" * 60)
    
    # Only collect from OpenSSF and OSV
    success = collect_all_data(sources=['openssf', 'osv'])
    
    if success:
        print("\n✓ Selective collection successful!")


def example_3_build_if_missing():
    """Example 3: Build databases only if they don't exist."""
    print("\nExample 3: Build only if missing")
    print("=" * 60)
    
    # Build databases only if they don't exist
    success = collect_all_data(build_if_missing=True)
    
    if success:
        print("\n✓ Smart collection successful!")


def example_4_check_databases():
    """Example 4: Check if databases exist before collecting."""
    print("\nExample 4: Check database status first")
    print("=" * 60)
    
    # Check if databases exist
    if check_databases_exist():
        print("✓ Databases found, skipping collection")
    else:
        print("⚠ Databases missing, collecting data...")
        collect_all_data()


def example_5_collectors_only():
    """Example 5: Run collectors without building databases."""
    print("\nExample 5: Collectors only (no database build)")
    print("=" * 60)
    
    # Run collectors and get results
    results = run_all_collectors(sources=['openssf'])
    
    print(f"\nCollector results: {results}")
    
    # Optionally build databases later
    if all(results.values()):
        print("All collectors succeeded, building databases...")
        build_databases()


if __name__ == "__main__":
    # Uncomment the example you want to run
    
    # example_1_collect_all()
    # example_2_specific_sources()
    # example_3_build_if_missing()
    # example_4_check_databases()
    # example_5_collectors_only()
    
    print("Uncomment one of the examples above to run it")
