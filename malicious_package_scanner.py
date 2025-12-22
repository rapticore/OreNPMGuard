#!/usr/bin/env python3
"""
Multi-Ecosystem Malicious Package Scanner
Scans packages from various ecosystems against unified malicious package databases
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Add scanners directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners import ecosystem_detector
from scanners import dependency_parsers
from scanners import file_input_parser
from scanners import malicious_checker
from scanners import report_generator
from scanners import ioc_detector


def scan_directory(directory: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a directory for dependencies and check against malicious database.
    If multiple ecosystems are detected and no ecosystem is specified, scans all detected ecosystems.
    
    Args:
        directory: Path to directory to scan
        ecosystem: Optional ecosystem override
        
    Returns:
        Tuple of (ecosystem_or_list, packages_list, scanned_path, iocs_list)
        If multiple ecosystems, returns list of ecosystems and combined packages list
    """
    iocs = []
    if scan_iocs:
        iocs = ioc_detector.scan_for_iocs(directory)
        if iocs:
            print(f"\n🕵️  Found {len(iocs)} Indicator(s) of Compromise")
    
    # Detect ecosystem(s) if not provided
    if not ecosystem:
        all_ecosystems = ecosystem_detector.detect_all_ecosystems_from_directory(directory)
        if not all_ecosystems:
            print(f"❌ Error: Could not detect ecosystem in directory: {directory}")
            print("Please specify ecosystem with --ecosystem option")
            return None, [], directory
        
        if len(all_ecosystems) == 1:
            ecosystem = all_ecosystems[0]
            print(f"🔍 Detected ecosystem: {ecosystem}")
        else:
            print(f"🔍 Detected multiple ecosystems: {', '.join(all_ecosystems)}")
            print(f"   Scanning all detected ecosystems...")
            # Scan all ecosystems
            all_packages = []
            for eco in all_ecosystems:
                print(f"\n   Scanning {eco}...")
                dep_files = ecosystem_detector.find_dependency_files(directory, eco)
                if dep_files:
                    print(f"   📦 Found {len(dep_files)} dependency file(s) for {eco}")
                    for dep_file in dep_files:
                        print(f"      Parsing: {os.path.relpath(dep_file, directory)}")
                        packages = dependency_parsers.parse_dependencies(dep_file, eco)
                        # Tag packages with ecosystem
                        for pkg in packages:
                            pkg['ecosystem'] = eco
                        all_packages.extend(packages)
            
            # Remove duplicates (same name, version, and ecosystem)
            seen = set()
            unique_packages = []
            for pkg in all_packages:
                key = (pkg.get('name', '').lower(), pkg.get('version', ''), pkg.get('ecosystem', ''))
                if key not in seen:
                    seen.add(key)
                    unique_packages.append(pkg)
            
            print(f"\n✅ Extracted {len(unique_packages)} unique package(s) across {len(all_ecosystems)} ecosystem(s)")
            return all_ecosystems, unique_packages, directory, iocs
    
    # Single ecosystem scan
    print(f"🔍 Using ecosystem: {ecosystem}")
    
    # Find dependency files
    dep_files = ecosystem_detector.find_dependency_files(directory, ecosystem)
    
    if not dep_files:
        print(f"⚠️  Warning: No dependency files found for {ecosystem} in {directory}")
        return ecosystem, [], directory
    
    print(f"📦 Found {len(dep_files)} dependency file(s)")
    
    # Parse dependencies from all files
    all_packages = []
    for dep_file in dep_files:
        print(f"   Parsing: {os.path.relpath(dep_file, directory)}")
        packages = dependency_parsers.parse_dependencies(dep_file, ecosystem)
        all_packages.extend(packages)
    
    # Remove duplicates (same name and version)
    seen = set()
    unique_packages = []
    for pkg in all_packages:
        key = (pkg.get('name', '').lower(), pkg.get('version', ''))
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)
    
    print(f"✅ Extracted {len(unique_packages)} unique package(s)")
    
    return ecosystem, unique_packages, directory, iocs


def scan_file(file_path: str, ecosystem: Optional[str] = None, scan_iocs: bool = True) -> tuple:
    """
    Scan a file for packages and check against malicious database.
    
    Args:
        file_path: Path to file to scan
        ecosystem: Optional ecosystem override
        
    Returns:
        Tuple of (ecosystem, packages_list, scanned_path, iocs_list)
    """
    iocs = []
    if scan_iocs:
        # Scan IoCs in the directory containing the file
        file_dir = os.path.dirname(file_path) if os.path.dirname(file_path) else '.'
        iocs = ioc_detector.scan_for_iocs(file_dir)
        if iocs:
            print(f"\n🕵️  Found {len(iocs)} Indicator(s) of Compromise")
    
    # Detect ecosystem from filename if not provided
    detected_ecosystem = ecosystem_detector.detect_ecosystem_from_filename(file_path)
    
    if not ecosystem:
        ecosystem = detected_ecosystem
    
    if not ecosystem:
        print(f"❌ Error: Could not determine ecosystem for file: {file_path}")
        print("Please specify ecosystem with --ecosystem option")
        return None, [], file_path
    
    print(f"🔍 Using ecosystem: {ecosystem}")
    
    # Check if file is a dependency file
    if detected_ecosystem:
        # Parse as dependency file
        print(f"📦 Parsing dependency file: {os.path.basename(file_path)}")
        packages = dependency_parsers.parse_dependencies(file_path, ecosystem)
    else:
        # Parse as generic file input
        print(f"📄 Parsing generic file: {os.path.basename(file_path)}")
        packages = file_input_parser.parse_file_input(file_path)
    
    print(f"✅ Extracted {len(packages)} package(s)")
    
    return ecosystem, packages, file_path, iocs


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Multi-Ecosystem Malicious Package Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect ecosystem and scan directory
  %(prog)s /path/to/project

  # Scan directory with ecosystem override
  %(prog)s /path/to/project --ecosystem npm

  # Scan dependency file (ecosystem auto-detected)
  %(prog)s --file package.json
  %(prog)s --file requirements.txt

  # Scan generic file with ecosystem
  %(prog)s --file packages.txt --ecosystem pypi

  # Specify output report path
  %(prog)s /path/to/project --output report.json
        """
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        help='Path to directory or file to scan'
    )
    
    parser.add_argument(
        '--file', '-f',
        dest='file_path',
        help='Path to file to scan (skips directory detection)'
    )
    
    parser.add_argument(
        '--ecosystem', '-e',
        choices=['npm', 'pypi', 'maven', 'rubygems', 'go', 'cargo'],
        help='Ecosystem to scan (npm, pypi, maven, rubygems, go, cargo)'
    )
    
    parser.add_argument(
        '--output', '-o',
        dest='output_path',
        help='Output path for report JSON file (default: auto-generated timestamped filename)'
    )
    
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip printing report summary'
    )
    
    parser.add_argument(
        '--no-ioc',
        action='store_true',
        dest='no_ioc',
        help='Skip IoC (Indicators of Compromise) scanning for faster execution'
    )
    
    parser.add_argument(
        '--ioc-only',
        action='store_true',
        dest='ioc_only',
        help='Only scan for IoCs, skip package dependency checking'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.path and not args.file_path:
        parser.error("Either provide a path or use --file option")
    
    if args.path and args.file_path:
        parser.error("Cannot specify both path and --file option")
    
    # Determine scan mode
    scan_iocs = not args.no_ioc
    scan_packages = not args.ioc_only
    
    # Determine what to scan
    if args.ioc_only:
        # IoC-only mode - just scan for IoCs
        if args.file_path:
            scanned_path = args.file_path
            file_dir = os.path.dirname(args.file_path) if os.path.dirname(args.file_path) else '.'
            iocs = ioc_detector.scan_for_iocs(file_dir) if scan_iocs else []
            ecosystem = 'unknown'
        else:
            scanned_path = args.path
            if not os.path.exists(scanned_path):
                print(f"❌ Error: Path not found: {scanned_path}")
                sys.exit(1)
            if not os.path.isdir(scanned_path):
                print(f"❌ Error: Not a directory: {scanned_path}")
                sys.exit(1)
            iocs = ioc_detector.scan_for_iocs(scanned_path) if scan_iocs else []
            # Try to detect ecosystem for reporting
            ecosystem = ecosystem_detector.detect_ecosystem_from_directory(scanned_path) or 'unknown'
        
        packages = []
        
        if not iocs:
            print("✅ No IoCs detected!")
            sys.exit(0)
        
        print(f"🕵️  Found {len(iocs)} Indicator(s) of Compromise")
        
        # Generate report with only IoCs
        report_path = report_generator.generate_report(
            ecosystem=ecosystem,
            scanned_path=scanned_path,
            total_packages_scanned=0,
            malicious_packages=[],
            iocs=iocs,
            output_path=args.output_path
        )
        
        if not args.no_summary:
            report_generator.print_report_summary(report_path)
        
        print(f"\n🚨 {len(iocs)} IoC(s) detected!")
        sys.exit(1)
    
    # Normal scanning mode
    if args.file_path:
        # File input mode
        if not os.path.exists(args.file_path):
            print(f"❌ Error: File not found: {args.file_path}")
            sys.exit(1)
        
        ecosystem, packages, scanned_path, iocs = scan_file(args.file_path, args.ecosystem, scan_iocs=scan_iocs)
    else:
        # Directory mode
        if not os.path.exists(args.path):
            print(f"❌ Error: Path not found: {args.path}")
            sys.exit(1)
        
        if not os.path.isdir(args.path):
            print(f"❌ Error: Not a directory: {args.path}")
            sys.exit(1)
        
        ecosystem, packages, scanned_path, iocs = scan_directory(args.path, args.ecosystem, scan_iocs=scan_iocs)
    
    if not ecosystem:
        sys.exit(1)
    
    if not packages and scan_packages:
        print("⚠️  No packages found to scan")
        if not iocs:
            sys.exit(0)
    
    # Handle multiple ecosystems
    malicious_packages = []
    if scan_packages and packages:
        if isinstance(ecosystem, list):
            # Multiple ecosystems detected - check each separately
            print(f"\n🔍 Checking {len(packages)} package(s) against malicious databases...")
            all_malicious = []
            
            # Group packages by ecosystem
            packages_by_ecosystem = {}
            for pkg in packages:
                pkg_eco = pkg.get('ecosystem', ecosystem[0])  # Default to first ecosystem if not tagged
                if pkg_eco not in packages_by_ecosystem:
                    packages_by_ecosystem[pkg_eco] = []
                packages_by_ecosystem[pkg_eco].append(pkg)
            
            # Check each ecosystem
            for eco in ecosystem:
                eco_packages = packages_by_ecosystem.get(eco, [])
                if eco_packages:
                    print(f"   Checking {len(eco_packages)} {eco} package(s)...")
                    malicious = malicious_checker.check_malicious_packages(eco_packages, eco, include_shai_hulud=True)
                    all_malicious.extend(malicious)
            
            malicious_packages = all_malicious
            ecosystem_str = ', '.join(ecosystem)
        else:
            # Single ecosystem
            print(f"\n🔍 Checking {len(packages)} package(s) against malicious database...")
            malicious_packages = malicious_checker.check_malicious_packages(packages, ecosystem, include_shai_hulud=True)
            ecosystem_str = ecosystem
    else:
        ecosystem_str = ecosystem if isinstance(ecosystem, str) else ', '.join(ecosystem) if isinstance(ecosystem, list) else 'unknown'
    
    # Generate report
    print(f"\n📊 Generating report...")
    report_path = report_generator.generate_report(
        ecosystem=ecosystem_str,
        scanned_path=scanned_path,
        total_packages_scanned=len(packages) if packages else 0,
        malicious_packages=malicious_packages,
        iocs=iocs,
        output_path=args.output_path
    )
    
    # Print summary unless disabled
    if not args.no_summary:
        report_generator.print_report_summary(report_path)
    
    # Exit with error code if malicious packages or IoCs found
    has_issues = bool(malicious_packages) or bool(iocs)
    if malicious_packages:
        print(f"\n🚨 {len(malicious_packages)} malicious package(s) detected!")
    if iocs:
        print(f"\n🚨 {len(iocs)} IoC(s) detected!")
    if not has_issues:
        print(f"\n✅ No malicious packages or IoCs detected!")
    
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()

