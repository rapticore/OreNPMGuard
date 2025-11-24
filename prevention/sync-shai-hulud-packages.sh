#!/bin/bash
# Shai-Hulud Package Sync Wrapper Script
# Usage: ./sync-shai-hulud-packages.sh

set -e

echo "🛡️  Shai-Hulud Package Sync Tool"
echo "================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if required Python packages are available
python3 -c "import yaml, json, csv" 2>/dev/null || {
    echo "📦 Installing required Python packages..."
    pip3 install pyyaml || {
        echo "❌ Failed to install PyYAML. Please install manually:"
        echo "   pip3 install pyyaml"
        exit 1
    }
}

# Check if required files exist
AFFECTED_FILE="affected_packages.yaml"
if [[ ! -f "$AFFECTED_FILE" ]]; then
    echo "❌ Required file not found: $AFFECTED_FILE"
    echo "   Please ensure the affected packages YAML file is in the current directory"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Create backup of existing files
echo "📋 Creating backups of existing files..."
for file in "banned-packages.yaml" "banned-packages.json" "bannedpackages.csv"; do
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        echo "   📄 Backed up: $file"
    fi
done

echo ""

# Run the Python sync script
echo "🔄 Running package synchronization..."
python3 - << 'EOF'
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
        self.default_attack_vector = "postinstall script"
        self.default_first_detected = "2025-09-15"

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
                    print(f"✅ Loaded existing banned YAML with {len(self.banned_yaml.get('banned_packages', []))} packages")
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
                    print(f"✅ Loaded existing banned JSON with {len(self.banned_json.get('banned_packages', []))} packages")
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

    def _initialize_banned_yaml(self):
        """Initialize banned YAML structure if file doesn't exist"""
        self.banned_yaml = {
            'meta': {
                'name': "Shai-Hulud Attack - Banned npm Packages",
                'description': "Complete list of npm packages compromised during the Shai-Hulud supply chain attacks (Original: September 2025, Shai-Hulud 2.0: November 2025)",
                'version': "2.0.0",
                'last_updated': datetime.now().strftime("%Y-%m-%d"),
                'attack_timeline': {
                    'patient_zero': "2025-09-14T17:58:50Z",
                    'detection': "2025-09-15",
                    'peak_spread': "2025-09-15/2025-09-16"
                },
                'total_packages': 0,
                'severity_distribution': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0
                },
                'source': "https://github.com/rapticore/orenpmpguard",
                'contact': "contact@rapticore.com"
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
                    'patient_zero': "2025-09-14T17:58:50Z",
                    'detection': "2025-09-15",
                    'peak_spread': "2025-09-15/2025-09-16"
                },
                'total_packages': 0,
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
                    'first_detected': self.default_first_detected,
                    'attack_vector': self.default_attack_vector,
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
                    'first_detected': self.default_first_detected,
                    'patient_zero': str(self._is_patient_zero(package_name)).lower(),
                    'description': f"Compromised package: {package_name}",
                    'attack_vector': self.default_attack_vector,
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
        """Save updated banned packages YAML while preserving exact formatting"""
        print(f"💾 Saving banned YAML to {filepath}")
        try:
            # Read the original file to preserve formatting and comments
            original_content = ""
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    original_content = f.read()

            # If we have original content, modify it carefully to preserve formatting
            if original_content and self.banned_yaml:
                content = self._update_yaml_preserving_format(original_content)
            else:
                # Create new file with proper formatting
                content = self._create_new_yaml_content()

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ YAML saved successfully with preserved formatting")
        except Exception as e:
            print(f"❌ Error saving YAML: {e}")
            raise

    def _update_yaml_preserving_format(self, original_content: str) -> str:
        """Update YAML content while preserving exact formatting, comments, and structure"""
        lines = original_content.split('\n')
        new_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]

            # Update total_packages in meta section
            if '  total_packages:' in line:
                new_lines.append(f"  total_packages: {len(self.banned_yaml['banned_packages'])}")
                i += 1
                continue

            # Update last_updated in meta section
            if '  last_updated:' in line:
                new_lines.append(f'  last_updated: "{datetime.now().strftime("%Y-%m-%d")}"')
                i += 1
                continue

            # Update severity distribution counts
            if '    critical:' in line and 'severity_distribution:' in ''.join(lines[max(0, i-3):i]):
                severity_counts = self._count_severity_levels()
                new_lines.append(f"    critical: {severity_counts['critical']}")
                i += 1
                continue
            if '    high:' in line and 'severity_distribution:' in ''.join(lines[max(0, i-3):i]):
                severity_counts = self._count_severity_levels()
                new_lines.append(f"    high: {severity_counts['high']}")
                i += 1
                continue
            if '    medium:' in line and 'severity_distribution:' in ''.join(lines[max(0, i-3):i]):
                severity_counts = self._count_severity_levels()
                new_lines.append(f"    medium: {severity_counts['medium']}")
                i += 1
                continue

            # Handle banned_packages section - add new packages while preserving format
            if line.strip() == "banned_packages:" or line.strip() == "# Complete banned packages list (for comprehensive scanning)":
                new_lines.append(line)
                if line.strip() == "# Complete banned packages list (for comprehensive scanning)":
                    i += 1
                    new_lines.append(lines[i])  # Add the "banned_packages:" line

                # Add existing packages first (preserve their formatting)
                i += 1
                while i < len(lines) and (lines[i].startswith('  - ') or lines[i].startswith('    ') or lines[i].strip() == ''):
                    new_lines.append(lines[i])
                    i += 1

                # Add new packages that aren't already in the list
                existing_packages = set()
                for line_content in new_lines:
                    if '  - name:' in line_content:
                        pkg_name = line_content.split('"')[1] if '"' in line_content else line_content.split("'")[1]
                        existing_packages.add(pkg_name)

                # Add missing packages with proper formatting
                for pkg in self.banned_yaml['banned_packages']:
                    if pkg['name'] not in existing_packages:
                        new_lines.append(f'  - name: "{pkg["name"]}"')
                        versions_str = ', '.join([f'"{v}"' for v in pkg['versions']])
                        new_lines.append(f'    versions: [{versions_str}]')

                continue

            # Handle critical_packages and high_packages sections similarly
            if line.strip() == "critical_packages:" or line.strip() == "high_packages:":
                section_type = "critical_packages" if "critical" in line else "high_packages"
                new_lines.append(line)

                # Skip existing packages in this section
                i += 1
                while i < len(lines) and (lines[i].startswith('  - ') or lines[i].startswith('    ') or lines[i].strip() == ''):
                    if not lines[i].strip() or lines[i].startswith('#'):
                        new_lines.append(lines[i])
                        i += 1
                        continue
                    if lines[i].strip() and not lines[i].startswith('  '):
                        break
                    new_lines.append(lines[i])
                    i += 1

                continue

            # Copy all other lines as-is to preserve formatting and comments
            new_lines.append(line)
            i += 1

        return '\n'.join(new_lines)

    def _create_new_yaml_content(self) -> str:
        """Create new YAML content with proper formatting when no original file exists"""
        return f'''# Shai-Hulud Attack - Banned npm Packages Configuration
# CI/CD-friendly YAML format for security tools and automated blocking

meta:
  name: "Shai-Hulud Attack - Banned npm Packages"
  description: "Complete list of npm packages compromised during the Shai-Hulud supply chain attacks (Original: September 2025, Shai-Hulud 2.0: November 2025)"
  version: "2.0.0"
  last_updated: "{datetime.now().strftime("%Y-%m-%d")}"
  attack_timeline:
    patient_zero: "2025-09-14T17:58:50Z"
    detection: "2025-09-15"
    peak_spread: "2025-09-15/2025-09-16"
  total_packages: {len(self.banned_yaml['banned_packages'])}
  severity_distribution:
    critical: {self._count_severity_levels()['critical']}
    high: {self._count_severity_levels()['high']}
    medium: {self._count_severity_levels()['medium']}
  source: "https://github.com/rapticore/orenpmpguard"
  contact: "contact@rapticore.com"

# Critical packages with highest impact - block immediately
critical_packages:
{self._format_packages_section([pkg for pkg in self.banned_yaml.get('critical_packages', [])])}

# High severity packages - significant risk
high_packages:
{self._format_packages_section([pkg for pkg in self.banned_yaml.get('high_packages', [])])}

# Complete banned packages list (for comprehensive scanning)
banned_packages:
{self._format_packages_section(self.banned_yaml['banned_packages'])}

# Remediation procedures
remediation:
  immediate_actions:
    - "Remove all banned packages immediately: npm uninstall <package-name>"
    - "Clear npm cache: npm cache clean --force"
    - "Delete node_modules: rm -rf node_modules && npm install"
    - "Run OreNPMGuard scanner: npx orenpmpguard ."

  credential_rotation:
    - "GitHub Personal Access Tokens (ghp_*, gho_*)"
    - "npm Authentication Tokens"
    - "SSH Keys"
    - "AWS, GCP, Azure credentials"
    - "API Keys (Atlassian, Datadog, etc.)"

  investigation_steps:
    - "Check GitHub for public repos named 'Shai-Hulud'"
    - "Look for repos with '-migration' suffix"
    - "Review GitHub audit logs"
    - "Check for branches named 'shai-hulud'"
    - "Scan for malicious GitHub Actions workflows"

# Integration examples for CI/CD systems
integration:
  npm_audit_command: "npm audit --audit-level critical"
  yarn_audit_command: "yarn audit --level critical"

  # Example package.json audit script
  npm_script: |
    {{
      "scripts": {{
        "security:scan": "npx orenpmpguard .",
        "security:block": "npm audit --audit-level critical && npx orenpmpguard .",
        "preinstall": "npx orenpmpguard package.json"
      }}
    }}

  # Example GitHub Actions workflow
  github_actions: |
    name: Security Scan
    on: [push, pull_request]
    jobs:
      security:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-node@v4
          - run: npx orenpmpguard .
          - run: npm audit --audit-level critical

  # Example pre-commit hook
  pre_commit_hook: |
    #!/bin/bash
    echo "🔍 Scanning for Shai-Hulud compromised packages..."
    npx orenpmpguard . || exit 1
    npm audit --audit-level critical || exit 1
    echo "✅ Security scan passed"

# Detection indicators to look for
detection_indicators:
  repositories:
    - "Public GitHub repos named 'Shai-Hulud'"
    - "Repos with '-migration' suffix"
    - "Repos with 'Shai-Hulud Migration' description"

  workflows:
    - ".github/workflows/shai-hulud-workflow.yml"
    - "Workflows that exfiltrate to webhook[.]site"

  branches:
    - "Branches named 'shai-hulud'"

  files:
    - "data.json with base64-encoded secrets"
    - "bundle.js files in postinstall scripts"
    - "TruffleHog configuration files"'''

    def _format_packages_section(self, packages: List[Dict]) -> str:
        """Format packages list maintaining the exact YAML structure"""
        if not packages:
            return ""

        lines = []
        for pkg in packages:
            lines.append(f'  - name: "{pkg["name"]}"')
            versions_str = ', '.join([f'"{v}"' for v in pkg['versions']])
            lines.append(f'    versions: [{versions_str}]')

            # Add additional fields if they exist
            if 'weekly_downloads' in pkg:
                lines.append(f'    weekly_downloads: {pkg["weekly_downloads"]}')
            if 'description' in pkg:
                lines.append(f'    description: "{pkg["description"]}"')
            if 'patient_zero' in pkg:
                lines.append(f'    patient_zero: {str(pkg["patient_zero"]).lower()}')

        return '\n'.join(lines)

    def _count_severity_levels(self) -> Dict[str, int]:
        """Count packages by severity level for metadata"""
        counts = {'critical': 0, 'high': 0, 'medium': 0}

        for pkg in self.affected_packages:
            severity = self._determine_severity(pkg['name'])
            counts[severity] += 1

        return counts

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
    csv_file = "bannedpackages.csv"

    sync.run_sync(affected_file, yaml_file, json_file, csv_file)


if __name__ == "__main__":
    main()
EOF

echo ""
echo "🎯 Sync completed! Check the updated files:"
echo "   📄 banned-packages.yaml"
echo "   📄 banned-packages.json"
echo "   📄 bannedpackages.csv"
echo ""
echo "📋 Backup files created with timestamp for safety"
echo "🛡️  Your banned package lists are now synchronized!"