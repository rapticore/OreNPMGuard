#!/usr/bin/env python3
"""
Test the build_if_missing functionality
"""

import sys
import os

# Add collectors to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))

from orchestrator import CollectorOrchestrator


def test_database_check():
    """Test the check_databases_exist method."""
    print("Testing database existence check...")
    print("=" * 60)
    
    orchestrator = CollectorOrchestrator()
    
    # Check if databases exist
    exists = orchestrator.check_databases_exist()
    
    if exists:
        print("✓ Databases found in collectors/final-data/")
        
        # List the databases
        ecosystems = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
        for ecosystem in ecosystems:
            db_path = os.path.join(orchestrator.final_data_dir, f'unified_{ecosystem}.db')
            if os.path.exists(db_path):
                size = os.path.getsize(db_path)
                print(f"  - unified_{ecosystem}.db ({size:,} bytes)")
    else:
        print("⚠ No databases found in collectors/final-data/")
    
    return exists


if __name__ == "__main__":
    test_database_check()
