#!/usr/bin/env python3
"""
Shai-Hulud Package Sync Script
Syncs affected_packages.yaml with banned package files while preserving structure
"""

import yaml
import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any, Set


class ShaiHuludPackageSync:
    def __init__(self):
        self.affected_packages = []
        self.banned_yaml = {}
        self.banned_json = {}
        self.banned_csv = []

        # Default values for new packages
        self.default_severity = "medium"
        self.default_weekly_downloads = 1000
        # Determine attack vector - most new packages are Shai-Hulud 2.0
        # Original Shai-Hulud packages (200) were detected Sept 14-18, 2025
        # Shai-Hulud 2.0 packages (738) were detected Nov 21-23, 2025
        self.default_attack_vector = "postinstall or preinstall script (both variants)"
        self.default_first_detected = "2025-11-21"  # Default to Shai-Hulud 2.0 for new packages
        
        # Known original Shai-Hulud packages (detected Sept 2025)
        self.original_shai_hulud_packages = {
            '@ctrl/deluge', '@ctrl/tinycolor', 'ngx-bootstrap',
            'rxnt-authentication', 'angulartics2'
        }

        # Severity mapping based on package patterns
        self.severity_patterns = {
            'critical': [
                '@ctrl/deluge', '@ctrl/tinycolor', 'ngx-bootstrap',
                'rxnt-authentication', 'angulartics2'
            ],
            'high': [
                '@ctrl/', '@nativescript-community/', '@crowdstrike/',
                'ngx-', 'ember-', 'react-'
            ]
        }

        # Download count estimates based on package patterns
        self.download_estimates = {
            '@ctrl/deluge': 2200000,
            '@ctrl/tinycolor': 2200000,
            'ngx-bootstrap': 300000,
            'angulartics2': 200000,
            'rxnt-authentication': 150,
        }

    def load_affected_packages(self, filepath: str):
        """Load the affected packages from YAML file"""
        print(f"📖 Loading affected packages from {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                self.affected_packages = data.get('affected_packages', [])
                print(f"✅ Loaded {len(self.affected_packages)} affected packages")
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            raise
        except Exception as e:
            print(f"❌ Error loading affected packages: {e}")
            raise

    def load_banned_yaml(self, filepath: str):
        """Load existing banned packages YAML"""
        print(f"📖 Loading banned YAML from {filepath}")
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.banned_yaml = yaml.safe_load(f)
                    print(
                        f"✅ Loaded existing banned YAML with {len(self.banned_yaml.get('banned_packages', []))} packages")
            else:
                print(f"⚠️  File not found, will create new: {filepath}")
                self._initialize_banned_yaml()
        except Exception as e:
            print(f"❌ Error loading banned YAML: {e}")
            raise

    def load_banned_json(self, filepath: str):
        """Load existing banned packages JSON"""
        print(f"📖 Loading banned JSON from {filepath}")
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.banned_json = json.load(f)
                    print(
                        f"✅ Loaded existing banned JSON with {len(self.banned_json.get('banned_packages', []))} packages")
            else:
                print(f"⚠️  File not found, will create new: {filepath}")
                self._initialize_banned_json()
        except Exception as e:
            print(f"❌ Error loading banned JSON: {e}")
            raise

    def load_banned_csv(self, filepath: str):
        """Load existing banned packages CSV"""
        print(f"📖 Loading banned CSV from {filepath}")
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    self.banned_csv = list(reader)
                    print(f"✅ Loaded existing banned CSV with {len(self.banned_csv)} packages")
            else:
                print(f"⚠️  File not found, will create new: {filepath}")
                self.banned_csv = []
        except Exception as e:
            print(f"❌ Error loading banned CSV: {e}")
            raise

    def _get_attack_vector(self, package_name: str) -> str:
        """Determine attack vector based on package name"""
        if package_name in self.original_shai_hulud_packages:
            return "postinstall script (original Shai-Hulud)"
        else:
            # Most new packages are Shai-Hulud 2.0
            return "preinstall script (Shai-Hulud 2.0)"
    
    def _get_first_detected(self, package_name: str) -> str:
        """Determine first detected date based on package name"""
        if package_name in self.original_shai_hulud_packages:
            return "2025-09-15"
        else:
            return "2025-11-21"
    
    def _initialize_banned_yaml(self):
        """Initialize banned YAML structure if file doesn't exist"""
        self.banned_yaml = {
            'meta': {
                'name': "Shai-Hulud Attack - Banned npm Packages",
                'description': "Complete list of npm packages compromised during the Shai-Hulud supply chain attacks (Original: September 2025, Shai-Hulud 2.0: November 2025)",
                'version': "2.0.0",
                'last_updated': datetime.now().strftime("%Y-%m-%d"),
                'attack_timeline': {
                    'original_shai_hulud': {
                        'patient_zero': "2025-09-14T17:58:50Z",
                        'detection': "2025-09-15",
                        'peak_spread': "2025-09-15/2025-09-16",
                        'packages_compromised': 200
                    },
                    'shai_hulud_2': {
                        'upload_period': "2025-11-21/2025-11-23",
                        'detection': "2025-11-24",
                        'packages_compromised': 738,
                        'repositories_affected': 25000,
                        'users_affected': 350
                    }
                },
                'total_packages': 0,
                'total_package_versions': 0,
                'severity_distribution': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0
                },
                'source': "https://github.com/rapticore/orenpmpguard",
                'contact': "contact@rapticore.com",
                'reference': "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"
            },
            'critical_packages': [],
            'high_packages': [],
            'banned_packages': [],
            'remediation': {
                'immediate_actions': [
                    "Remove all banned packages immediately: npm uninstall <package-name>",
                    "Clear npm cache: npm cache clean --force",
                    "Delete node_modules: rm -rf node_modules && npm install",
                    "Run OreNPMGuard scanner: npx orenpmpguard ."
                ],
                'credential_rotation': [
                    "GitHub Personal Access Tokens (ghp_*, gho_*)",
                    "npm Authentication Tokens",
                    "SSH Keys",
                    "AWS, GCP, Azure credentials",
                    "API Keys (Atlassian, Datadog, etc.)"
                ]
            }
        }

    def _initialize_banned_json(self):
        """Initialize banned JSON structure if file doesn't exist"""
        self.banned_json = {
            'meta': {
                'name': "Shai-Hulud Attack - Banned npm Packages",
                'description': "Complete list of npm packages compromised during the Shai-Hulud supply chain attacks (Original: September 2025, Shai-Hulud 2.0: November 2025)",
                'version': "2.0.0",
                'last_updated': datetime.now().strftime("%Y-%m-%d"),
                'attack_timeline': {
                    'original_shai_hulud': {
                        'patient_zero': "2025-09-14T17:58:50Z",
                        'detection': "2025-09-15",
                        'peak_spread': "2025-09-15/2025-09-16",
                        'packages_compromised': 200
                    },
                    'shai_hulud_2': {
                        'upload_period': "2025-11-21/2025-11-23",
                        'detection': "2025-11-24",
                        'packages_compromised': 738,
                        'repositories_affected': 25000,
                        'users_affected': 350
                    }
                },
                'total_packages': 0,
                'total_package_versions': 0,
                'severity_distribution': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0
                },
                'source': "https://github.com/rapticore/orenpmpguard",
                'contact': "contact@rapticore.com"
            },
            'banned_packages': []
        }

    def _determine_severity(self, package_name: str) -> str:
        """Determine severity based on package name patterns"""
        # Check critical patterns first
        if package_name in self.severity_patterns['critical']:
            return 'critical'

        # Check high severity patterns
        for pattern in self.severity_patterns['high']:
            if package_name.startswith(pattern):
                return 'high'

        return self.default_severity

    def _estimate_downloads(self, package_name: str) -> int:
        """Estimate weekly downloads based on package name"""
        # Check for specific known packages
        for known_pkg, downloads in self.download_estimates.items():
            if package_name == known_pkg:
                return downloads

        # Estimate based on patterns
        if package_name.startswith('@ctrl/'):
            return 50000
        elif package_name.startswith('@nativescript-community/'):
            return 25000
        elif package_name.startswith('@crowdstrike/'):
            return 15000
        elif package_name.startswith('ngx-'):
            return 20000
        elif package_name.startswith('ember-'):
            return 10000
        elif package_name.startswith('react-'):
            return 15000
        else:
            return self.default_weekly_downloads

    def _is_patient_zero(self, package_name: str) -> bool:
        """Check if package is patient zero"""
        return package_name == "rxnt-authentication"

    def sync_packages(self):
        """Main sync function to update all banned package files"""
        print("\n🔄 Starting package synchronization...")

        # Get existing package names to avoid duplicates
        existing_yaml_packages = {pkg['name'] for pkg in self.banned_yaml.get('banned_packages', [])}
        existing_json_packages = {pkg['name'] for pkg in self.banned_json.get('banned_packages', [])}
        existing_csv_packages = {row['package_name'] for row in self.banned_csv if 'package_name' in row}

        new_packages_added = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0}

        # Process each affected package
        for affected_pkg in self.affected_packages:
            package_name = affected_pkg['name']
            versions = affected_pkg['versions']
            severity = self._determine_severity(package_name)
            severity_counts[severity] += 1

            # Update YAML
            if package_name not in existing_yaml_packages:
                yaml_entry = {
                    'name': package_name,
                    'versions': versions
                }
                self.banned_yaml['banned_packages'].append(yaml_entry)

                # Add to appropriate severity list
                if severity == 'critical':
                    self.banned_yaml.setdefault('critical_packages', []).append(yaml_entry)
                elif severity == 'high':
                    self.banned_yaml.setdefault('high_packages', []).append(yaml_entry)

            # Update JSON
            if package_name not in existing_json_packages:
                json_entry = {
                    'name': package_name,
                    'banned_versions': versions,
                    'severity': severity,
                    'weekly_downloads': self._estimate_downloads(package_name),
                    'first_detected': self._get_first_detected(package_name),
                    'attack_vector': self._get_attack_vector(package_name),
                    'patient_zero': self._is_patient_zero(package_name),
                    'description': f"Compromised package: {package_name}"
                }
                self.banned_json['banned_packages'].append(json_entry)

            # Update CSV
            if package_name not in existing_csv_packages:
                csv_entry = {
                    'package_name': package_name,
                    'banned_versions': ', '.join(versions),
                    'severity': severity,
                    'weekly_downloads': self._estimate_downloads(package_name),
                    'first_detected': self._get_first_detected(package_name),
                    'patient_zero': str(self._is_patient_zero(package_name)).lower(),
                    'description': f"Compromised package: {package_name}",
                    'attack_vector': self._get_attack_vector(package_name),
                    'priority': 1 if severity == 'critical' else (2 if severity == 'high' else 3)
                }
                self.banned_csv.append(csv_entry)
                new_packages_added += 1

        # Update metadata
        total_packages = len(self.banned_yaml['banned_packages'])

        # Update YAML metadata
        self.banned_yaml['meta']['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        self.banned_yaml['meta']['total_packages'] = total_packages
        self.banned_yaml['meta']['severity_distribution'] = severity_counts

        # Update JSON metadata
        self.banned_json['meta']['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        self.banned_json['meta']['total_packages'] = total_packages
        self.banned_json['meta']['severity_distribution'] = severity_counts

        print(f"✅ Synchronization complete!")
        print(f"   📦 Total packages: {total_packages}")
        print(f"   🆕 New packages added: {new_packages_added}")
        print(f"   🔴 Critical: {severity_counts['critical']}")
        print(f"   🟠 High: {severity_counts['high']}")
        print(f"   🟡 Medium: {severity_counts['medium']}")

    def save_banned_yaml(self, filepath: str):
        """Save updated banned packages YAML"""
        print(f"💾 Saving banned YAML to {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(self.banned_yaml, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False, indent=2)
            print("✅ YAML saved successfully")
        except Exception as e:
            print(f"❌ Error saving YAML: {e}")
            raise

    def save_banned_json(self, filepath: str):
        """Save updated banned packages JSON"""
        print(f"💾 Saving banned JSON to {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.banned_json, f, indent=2, ensure_ascii=False)
            print("✅ JSON saved successfully")
        except Exception as e:
            print(f"❌ Error saving JSON: {e}")
            raise

    def save_banned_csv(self, filepath: str):
        """Save updated banned packages CSV"""
        print(f"💾 Saving banned CSV to {filepath}")
        try:
            if self.banned_csv:
                fieldnames = [
                    'package_name', 'banned_versions', 'severity', 'weekly_downloads',
                    'first_detected', 'patient_zero', 'description', 'attack_vector', 'priority'
                ]
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.banned_csv)
                print("✅ CSV saved successfully")
            else:
                print("⚠️  No CSV data to save")
        except Exception as e:
            print(f"❌ Error saving CSV: {e}")
            raise

    def run_sync(self, affected_file: str, yaml_file: str, json_file: str, csv_file: str):
        """Main entry point to run the complete sync process"""
        print("🚀 Shai-Hulud Package Sync Script Started")
        print("=" * 50)

        try:
            # Load all files
            self.load_affected_packages(affected_file)
            self.load_banned_yaml(yaml_file)
            self.load_banned_json(json_file)
            self.load_banned_csv(csv_file)

            # Sync packages
            self.sync_packages()

            # Save updated files
            print("\n💾 Saving updated files...")
            self.save_banned_yaml(yaml_file)
            self.save_banned_json(json_file)
            self.save_banned_csv(csv_file)

            print("\n🎉 Package synchronization completed successfully!")
            print("=" * 50)

        except Exception as e:
            print(f"\n💥 Sync failed: {e}")
            raise


def main():
    """Main function with file paths"""
    sync = ShaiHuludPackageSync()

    # File paths (adjust as needed)
    affected_file = "affected_packages.yaml"
    yaml_file = "banned-packages.yaml"
    json_file = "banned-packages.json"
    csv_file = "banned-packages.csv"

    sync.run_sync(affected_file, yaml_file, json_file, csv_file)


if __name__ == "__main__":
    main()