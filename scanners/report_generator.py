#!/usr/bin/env python3
"""
Report Generator Module
Generates JSON reports for malicious packages found during scans
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional


def get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO 8601 format.
    
    Returns:
        Timestamp string like "2025-12-17T10:30:00Z"
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _get_project_root() -> str:
    """
    Get the project root directory (where malicious_package_scanner.py is located).
    
    Returns:
        Absolute path to project root
    """
    # Get the directory where this module is located
    current_file = os.path.abspath(__file__)
    scanners_dir = os.path.dirname(current_file)
    # Go up one level to get project root
    project_root = os.path.dirname(scanners_dir)
    return project_root


def generate_report(
    ecosystem: str,
    scanned_path: str,
    total_packages_scanned: int,
    malicious_packages: List[Dict],
    iocs: Optional[List[Dict]] = None,
    output_path: Optional[str] = None
) -> str:
    """
    Generate a JSON report for malicious packages found and IoCs detected.
    
    Args:
        ecosystem: Ecosystem name (npm, pypi, etc.) or comma-separated string for multiple
        scanned_path: Path that was scanned (directory or file)
        total_packages_scanned: Total number of packages scanned
        malicious_packages: List of malicious packages found
        iocs: Optional list of IoCs (Indicators of Compromise) found
        output_path: Optional custom output path (full path). If None, saves to scan-output/ directory.
        
    Returns:
        Path to the generated report file
    """
    if iocs is None:
        iocs = []
    
    report = {
        'scan_timestamp': get_timestamp(),
        'ecosystem': ecosystem,
        'scanned_path': scanned_path,
        'total_packages_scanned': total_packages_scanned,
        'malicious_packages_found': len(malicious_packages),
        'iocs_found': len(iocs),
        'malicious_packages': malicious_packages,
        'iocs': iocs
    }
    
    # Generate output path if not provided
    if output_path is None:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        project_root = _get_project_root()
        scan_output_dir = os.path.join(project_root, 'scan-output')
        output_path = os.path.join(scan_output_dir, f'malicious_packages_report_{timestamp}.json')
    else:
        # If output_path is provided, use it as-is (full path)
        # Ensure it's an absolute path
        if not os.path.isabs(output_path):
            # If relative path, make it relative to current working directory
            output_path = os.path.abspath(output_path)
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Write report
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_path
    except Exception as e:
        print(f"Error writing report to {output_path}: {e}")
        raise


def print_report_summary(report_path: str):
    """
    Print a human-readable summary of the report.
    
    Args:
        report_path: Path to the report file
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report {report_path}: {e}")
        return
    
    print("\n" + "=" * 60)
    print("SCAN REPORT SUMMARY")
    print("=" * 60)
    print(f"Ecosystem: {report.get('ecosystem', 'unknown')}")
    print(f"Scanned Path: {report.get('scanned_path', 'unknown')}")
    print(f"Scan Timestamp: {report.get('scan_timestamp', 'unknown')}")
    print(f"Total Packages Scanned: {report.get('total_packages_scanned', 0)}")
    print(f"Malicious Packages Found: {report.get('malicious_packages_found', 0)}")
    print(f"IoCs Found: {report.get('iocs_found', 0)}")
    print("=" * 60)
    
    malicious_packages = report.get('malicious_packages', [])
    if malicious_packages:
        print("\n🚨 MALICIOUS PACKAGES DETECTED:\n")
        for i, pkg in enumerate(malicious_packages, 1):
            print(f"{i}. {pkg.get('name', 'unknown')}")
            if pkg.get('version'):
                print(f"   Version: {pkg.get('version')}")
            print(f"   Severity: {pkg.get('severity', 'unknown').upper()}")
            if pkg.get('description'):
                print(f"   Description: {pkg.get('description')}")
            if pkg.get('sources'):
                print(f"   Sources: {', '.join(pkg.get('sources', []))}")
            print()
    else:
        print("\n✅ No malicious packages found!")
    
    iocs = report.get('iocs', [])
    if iocs:
        print("\n🚨 INDICATORS OF COMPROMISE (IoCs) DETECTED:\n")
        for i, ioc in enumerate(iocs, 1):
            severity_emoji = "🔴" if ioc.get('severity') == 'CRITICAL' else "🟠"
            variant_info = f" [{ioc.get('variant', 'unknown')}]" if 'variant' in ioc else ""
            print(f"{i}. {severity_emoji} {ioc.get('type', 'unknown').upper()}{variant_info}: {ioc.get('path', 'unknown')}")
            
            if ioc.get('type') == 'malicious_bundle_js' and 'hash' in ioc:
                print(f"   SHA-256: {ioc['hash']}")
            elif ioc.get('type') in ['malicious_postinstall', 'malicious_preinstall'] and 'pattern' in ioc:
                print(f"   Pattern: {ioc['pattern']}")
            elif ioc.get('type') == 'webhook_site_reference' and 'url' in ioc:
                print(f"   URL: {ioc['url']}")
            elif ioc.get('type') == 'malicious_payload_file' and 'filename' in ioc:
                print(f"   Payload file: {ioc['filename']}")
            elif ioc.get('type') == 'shai_hulud_data_file' and 'filename' in ioc:
                print(f"   Data file: {ioc['filename']}")
            elif ioc.get('type') in ['malicious_github_workflow', 'sha1hulud_runner', 'suspicious_runner_config', 'docker_privilege_escalation'] and 'pattern' in ioc:
                print(f"   Pattern: {ioc['pattern']}")
            print()
    else:
        print("\n✅ No IoCs detected!")
    
    print(f"\nFull report saved to: {report_path}")
    print("=" * 60)

