#!/usr/bin/env python3
"""
Sync packages and versions from shai-hulud.txt to affected_packages.txt.

This script:
1. Reads package and version information from shai-hulud.txt
2. Reads existing entries from affected_packages.txt
3. Adds any missing package@version combinations to affected_packages.txt
"""

import re
import sys
from pathlib import Path
from typing import Set, Tuple


def parse_shai_hulud(file_path: Path) -> Set[Tuple[str, str]]:
    """
    Parse shai-hulud.txt and extract all package@version combinations.
    
    Args:
        file_path: Path to shai-hulud.txt
        
    Returns:
        Set of (package_name, version) tuples
    """
    packages_versions = set()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Skip header line
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        # Split by tab
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        
        package_name = parts[0].strip()
        version_str = parts[1].strip()
        
        if not package_name or not version_str:
            continue
        
        # Handle multiple versions separated by commas
        # Example: "0.0.7 ,  0.0.8" or "1.0.2 ,  1.0.1"
        versions = [v.strip() for v in re.split(r',\s*', version_str)]
        
        for version in versions:
            if version:
                packages_versions.add((package_name, version))
    
    return packages_versions


def parse_affected_packages(file_path: Path) -> Set[Tuple[str, str]]:
    """
    Parse affected_packages.txt and extract all package@version combinations.
    
    Args:
        file_path: Path to affected_packages.txt
        
    Returns:
        Set of (package_name, version) tuples
    """
    packages_versions = set()
    
    if not file_path.exists():
        return packages_versions
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Handle lines with multiple versions separated by commas
        # Examples:
        # - "@ctrl/tinycolor@4.1.1, @4.1.2"
        # - "json-rules-engine-simplified@0.2.4, 0.2.1"
        # - "koa2-swagger-ui@5.11.2, 5.11.1"
        # - "@nativescript-community/sentry 4.6.43" (missing @, space instead)
        
        # Handle case like "@nativescript-community/sentry 4.6.43" (space instead of @)
        if '@' not in line or (line.count('@') == 1 and ' ' in line):
            space_match = re.match(r'^([^\s]+)\s+([^\s,]+)', line)
            if space_match:
                package_name = space_match.group(1)
                version = space_match.group(2)
                packages_versions.add((package_name, version))
            continue
        
        # Find the last @ before any comma (this separates package from first version)
        # For scoped packages like "@scope/name@version", we need to find the @ before version
        # Pattern: package@version or @scope/package@version
        match = re.match(r'^(.+?)@([^,@]+)(.*)$', line)
        if not match:
            continue
        
        package_name = match.group(1)
        first_version = match.group(2)
        remaining = match.group(3).strip()
        
        # Add first version
        if first_version:
            packages_versions.add((package_name, first_version))
        
        # Process remaining versions (after commas)
        if remaining:
            # Remove leading comma if present
            if remaining.startswith(','):
                remaining = remaining[1:].strip()
            
            # Split by comma to get all versions
            version_parts = re.split(r',\s*', remaining)
            
            for version_part in version_parts:
                version_part = version_part.strip()
                if not version_part:
                    continue
                
                # Remove leading @ if present (from cases like "@4.1.2")
                if version_part.startswith('@'):
                    version = version_part[1:]
                else:
                    version = version_part
                
                if version:
                    packages_versions.add((package_name, version))
    
    return packages_versions


def write_affected_packages(file_path: Path, packages_versions: Set[Tuple[str, str]]):
    """
    Write all package@version combinations to affected_packages.txt.
    
    Args:
        file_path: Path to affected_packages.txt
        packages_versions: Set of (package_name, version) tuples
    """
    # Sort for consistent output (package name first, then version)
    sorted_entries = sorted(packages_versions, key=lambda x: (x[0].lower(), x[1]))
    
    with open(file_path, 'w', encoding='utf-8') as f:
        for package_name, version in sorted_entries:
            f.write(f"{package_name}@{version}\n")


def main():
    """Main function to sync packages."""
    script_dir = Path(__file__).parent
    shai_hulud_path = script_dir / 'shai-hulud.txt'
    affected_packages_path = script_dir / 'affected_packages.txt'
    
    # Check if shai-hulud.txt exists
    if not shai_hulud_path.exists():
        print(f"Error: {shai_hulud_path} not found", file=sys.stderr)
        sys.exit(1)
    
    # Parse both files
    print("Parsing shai-hulud.txt...")
    shai_hulud_packages = parse_shai_hulud(shai_hulud_path)
    print(f"Found {len(shai_hulud_packages)} package@version combinations in shai-hulud.txt")
    
    print("Parsing affected_packages.txt...")
    existing_packages = parse_affected_packages(affected_packages_path)
    print(f"Found {len(existing_packages)} existing package@version combinations in affected_packages.txt")
    
    # Merge sets to get all unique combinations
    all_packages = shai_hulud_packages | existing_packages
    
    # Find new packages
    new_packages = shai_hulud_packages - existing_packages
    if new_packages:
        print(f"\nFound {len(new_packages)} new package@version combinations to add:")
        for package_name, version in sorted(new_packages, key=lambda x: (x[0].lower(), x[1])):
            print(f"  {package_name}@{version}")
    else:
        print("\nNo new packages to add.")
    
    # Write updated file
    print(f"\nWriting {len(all_packages)} total package@version combinations to affected_packages.txt...")
    write_affected_packages(affected_packages_path, all_packages)
    print("Done!")


if __name__ == '__main__':
    main()

