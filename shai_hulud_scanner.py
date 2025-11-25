#!/usr/bin/env python3
"""
Shai-Hulud npm Package Scanner (Python) - Enhanced Version
Scans package.json and package-lock.json files for compromised packages from the Shai-Hulud attack
Includes IoC detection and downloads latest package data from GitHub
"""

import json
import sys
import re
import os
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional
import yaml

# Shai-Hulud IoCs (Indicators of Compromise)
# Includes both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) patterns
SHAI_HULUD_IOCS = {
    # Original Shai-Hulud IoCs
    'webhook_url': 'https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
    'bundle_js_hashes': {
        '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09',
        '81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3',
        'dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c'
    },
    'postinstall_pattern': r'"postinstall":\s*"node\s+bundle\.js"',
    
    # Shai-Hulud 2.0 IoCs (November 2025)
    'preinstall_pattern': r'"preinstall":\s*"node\s+(bundle|setup_bun|bun_environment)\.js"',
    'payload_files': ['bundle.js', 'setup_bun.js', 'bun_environment.js'],
    'data_files': ['cloud.json', 'contents.json', 'environment.json', 'truffleSecrets.json', 'actionsSecrets.json'],
    'github_workflow_patterns': {
        'discussion_yaml': r'\.github/workflows/discussion\.yaml',
        'formatter_yml': r'\.github/workflows/formatter_\d+\.yml',
        'shai_hulud_workflow': r'\.github/workflows/shai-hulud-workflow\.yml'  # Original
    },
    'self_hosted_runner_pattern': r'runs-on:\s*self-hosted',
    'sha1hulud_runner_pattern': r'SHA1HULUD',
    'runner_tracking_id_pattern': r'RUNNER_TRACKING_ID:\s*0',
    'docker_privilege_escalation_pattern': r'docker\s+run\s+--rm\s+--privileged\s+-v\s+/:/host'
}

GITHUB_YAML_URL = "https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml"

# Global cache for affected packages data
_affected_packages_cache = None
_cache_loaded = False

def download_affected_packages_yaml() -> Optional[Dict]:
    """Download the latest affected packages YAML from GitHub."""
    try:
        print("Downloading latest package data from GitHub...")

        # Create request with user agent to avoid GitHub blocking
        req = urllib.request.Request(
            GITHUB_YAML_URL,
            headers={'User-Agent': 'Shai-Hulud-Scanner/1.0'}
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            yaml_content = response.read().decode('utf-8')
            config = yaml.safe_load(yaml_content)
            print(f"✅ Successfully downloaded data for {len(config.get('affected_packages', []))} packages")
            return config

    except (urllib.error.URLError, urllib.error.HTTPError, yaml.YAMLError, KeyError) as e:
        print(f"❌ Error downloading from GitHub: {e}")
        print("Falling back to local file...")
        return None
    except Exception as e:
        print(f"❌ Unexpected error downloading: {e}")
        print("Falling back to local file...")
        return None


def load_affected_packages_from_yaml() -> Dict[str, Set[str]]:
    """Load affected packages from GitHub or local YAML configuration file (with caching)."""
    global _affected_packages_cache, _cache_loaded

    # Return cached data if already loaded
    if _cache_loaded and _affected_packages_cache is not None:
        return _affected_packages_cache

    # First try to download from GitHub
    config = download_affected_packages_yaml()

    # If download failed, try local file
    if config is None:
        config_path = Path(__file__).parent / 'affected_packages.yaml'
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                print(f"✅ Loaded local configuration with {len(config.get('affected_packages', []))} packages")
        except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
            print(f"❌ Error loading local configuration from {config_path}: {e}")
            print("Using minimal fallback data...")
            _affected_packages_cache = parse_affected_packages_fallback()
            _cache_loaded = True
            return _affected_packages_cache

    # Parse the configuration and cache it
    packages = {}
    for pkg in config.get('affected_packages', []):
        packages[pkg['name']] = set(pkg['versions'])

    _affected_packages_cache = packages
    _cache_loaded = True
    return packages


def parse_affected_packages_fallback() -> Dict[str, Set[str]]:
    """Fallback hardcoded package data in case both GitHub and local files are unavailable."""
    print("⚠️  Using minimal fallback package data")
    return {
        '@ctrl/deluge': {'7.2.2', '7.2.1'},
        'ngx-bootstrap': {'18.1.4', '19.0.3', '20.0.4', '20.0.5', '20.0.6', '19.0.4', '20.0.3'},
        '@ctrl/tinycolor': {'4.1.1', '4.1.2'},
        'rxnt-authentication': {'0.0.5', '0.0.6', '0.0.3', '0.0.4'},
        'angulartics2': {'14.1.2', '14.1.1'}
    }


def calculate_file_hash(file_path: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"❌ Error calculating hash for {file_path}: {e}")
        return None


def scan_for_iocs(directory: str) -> List[Dict]:
    """Scan directory for Shai-Hulud IoCs (Indicators of Compromise).
    
    Detects both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) indicators.
    """
    iocs_found = []

    for root, dirs, files in os.walk(directory):
        # Skip node_modules for performance, but scan other directories
        if 'node_modules' in dirs:
            dirs.remove('node_modules')

        # Check for malicious payload files (original and Shai-Hulud 2.0)
        for payload_file in SHAI_HULUD_IOCS['payload_files']:
            if payload_file in files:
                payload_path = os.path.join(root, payload_file)
                
                # For bundle.js, check hash against known malicious hashes
                if payload_file == 'bundle.js':
                    file_hash = calculate_file_hash(payload_path)
                    if file_hash and file_hash in SHAI_HULUD_IOCS['bundle_js_hashes']:
                        iocs_found.append({
                            'type': 'malicious_bundle_js',
                            'path': os.path.relpath(payload_path, directory),
                            'hash': file_hash,
                            'severity': 'CRITICAL',
                            'variant': 'original'
                        })
                else:
                    # For Shai-Hulud 2.0 payload files, presence is suspicious
                    iocs_found.append({
                        'type': 'malicious_payload_file',
                        'path': os.path.relpath(payload_path, directory),
                        'filename': payload_file,
                        'severity': 'CRITICAL',
                        'variant': '2.0'
                    })

        # Check for Shai-Hulud 2.0 data files
        for data_file in SHAI_HULUD_IOCS['data_files']:
            if data_file in files:
                data_path = os.path.join(root, data_file)
                iocs_found.append({
                    'type': 'shai_hulud_data_file',
                    'path': os.path.relpath(data_path, directory),
                    'filename': data_file,
                    'severity': 'HIGH',
                    'variant': '2.0'
                })

        # Check package.json files for malicious hooks
        if 'package.json' in files:
            package_json_path = os.path.join(root, 'package.json')
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for malicious postinstall pattern (original Shai-Hulud)
                    if re.search(SHAI_HULUD_IOCS['postinstall_pattern'], content):
                        iocs_found.append({
                            'type': 'malicious_postinstall',
                            'path': os.path.relpath(package_json_path, directory),
                            'pattern': 'node bundle.js',
                            'severity': 'CRITICAL',
                            'variant': 'original'
                        })

                    # Check for malicious preinstall pattern (Shai-Hulud 2.0)
                    if re.search(SHAI_HULUD_IOCS['preinstall_pattern'], content):
                        iocs_found.append({
                            'type': 'malicious_preinstall',
                            'path': os.path.relpath(package_json_path, directory),
                            'pattern': 'preinstall hook with suspicious payload',
                            'severity': 'CRITICAL',
                            'variant': '2.0'
                        })

                    # Check for webhook.site URL references
                    if SHAI_HULUD_IOCS['webhook_url'] in content:
                        iocs_found.append({
                            'type': 'webhook_site_reference',
                            'path': os.path.relpath(package_json_path, directory),
                            'url': SHAI_HULUD_IOCS['webhook_url'],
                            'severity': 'HIGH'
                        })

            except Exception as e:
                print(f"❌ Error reading {package_json_path}: {e}")

        # Check for GitHub workflow files (Shai-Hulud 2.0)
        if '.github' in root or 'workflows' in root:
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    workflow_path = os.path.join(root, file)
                    try:
                        with open(workflow_path, 'r', encoding='utf-8') as f:
                            workflow_content = f.read()
                            
                            # Check for discussion.yaml pattern
                            if re.search(SHAI_HULUD_IOCS['github_workflow_patterns']['discussion_yaml'], 
                                       workflow_path.replace('\\', '/')):
                                if re.search(SHAI_HULUD_IOCS['self_hosted_runner_pattern'], workflow_content):
                                    iocs_found.append({
                                        'type': 'malicious_github_workflow',
                                        'path': os.path.relpath(workflow_path, directory),
                                        'pattern': 'discussion.yaml with self-hosted runner',
                                        'severity': 'CRITICAL',
                                        'variant': '2.0'
                                    })
                            
                            # Check for formatter workflow pattern
                            if re.search(SHAI_HULUD_IOCS['github_workflow_patterns']['formatter_yml'],
                                       workflow_path.replace('\\', '/')):
                                iocs_found.append({
                                    'type': 'malicious_github_workflow',
                                    'path': os.path.relpath(workflow_path, directory),
                                    'pattern': 'formatter workflow for secret exfiltration',
                                    'severity': 'CRITICAL',
                                    'variant': '2.0'
                                })
                            
                            # Check for SHA1HULUD runner name
                            if re.search(SHAI_HULUD_IOCS['sha1hulud_runner_pattern'], workflow_content, re.IGNORECASE):
                                iocs_found.append({
                                    'type': 'sha1hulud_runner',
                                    'path': os.path.relpath(workflow_path, directory),
                                    'pattern': 'SHA1HULUD runner registration',
                                    'severity': 'CRITICAL',
                                    'variant': '2.0'
                                })
                            
                            # Check for RUNNER_TRACKING_ID: 0
                            if re.search(SHAI_HULUD_IOCS['runner_tracking_id_pattern'], workflow_content):
                                iocs_found.append({
                                    'type': 'suspicious_runner_config',
                                    'path': os.path.relpath(workflow_path, directory),
                                    'pattern': 'RUNNER_TRACKING_ID: 0',
                                    'severity': 'HIGH',
                                    'variant': '2.0'
                                })
                            
                            # Check for original shai-hulud-workflow.yml
                            if re.search(SHAI_HULUD_IOCS['github_workflow_patterns']['shai_hulud_workflow'],
                                       workflow_path.replace('\\', '/')):
                                iocs_found.append({
                                    'type': 'malicious_github_workflow',
                                    'path': os.path.relpath(workflow_path, directory),
                                    'pattern': 'shai-hulud-workflow.yml',
                                    'severity': 'CRITICAL',
                                    'variant': 'original'
                                })
                    except Exception:
                        continue

        # Check other JavaScript files for webhook references and Docker patterns
        for file in files:
            if file.endswith(('.js', '.ts', '.json', '.sh', '.bash')) and file != 'package.json':
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check for webhook.site URL references
                        if SHAI_HULUD_IOCS['webhook_url'] in content:
                            iocs_found.append({
                                'type': 'webhook_site_reference',
                                'path': os.path.relpath(file_path, directory),
                                'url': SHAI_HULUD_IOCS['webhook_url'],
                                'severity': 'HIGH'
                            })
                        
                        # Check for Docker privilege escalation pattern (Shai-Hulud 2.0)
                        if re.search(SHAI_HULUD_IOCS['docker_privilege_escalation_pattern'], content):
                            iocs_found.append({
                                'type': 'docker_privilege_escalation',
                                'path': os.path.relpath(file_path, directory),
                                'pattern': 'Docker privileged container with host mount',
                                'severity': 'CRITICAL',
                                'variant': '2.0'
                            })
                except Exception:
                    # Skip files that can't be read as text
                    continue

    return iocs_found


def scan_package_json(file_path: str) -> Tuple[List[Dict], List[Dict]]:
    """Scan a package.json or package-lock.json file for affected packages."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Error reading {file_path}: {e}")
        return [], []

    affected_db = load_affected_packages_from_yaml()

    # Determine file type and scan accordingly
    if file_path.endswith('package-lock.json'):
        return scan_package_lock_dependencies(package_data, affected_db)
    else:
        return scan_package_json_dependencies(package_data, affected_db)


def scan_package_json_dependencies(package_data: dict, affected_db: Dict[str, Set[str]]) -> Tuple[
    List[Dict], List[Dict]]:
    """Scan package.json dependency sections."""
    found_packages = []
    potential_matches = []

    # Check all dependency sections
    deps_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

    for section in deps_sections:
        if section not in package_data:
            continue

        for pkg_name, installed_version in package_data[section].items():
            # Clean version string (remove ^, ~, etc.)
            clean_version = re.sub(r'^[\^~>=<]', '', installed_version)

            if pkg_name in affected_db:
                # Check if installed version matches any affected version
                if clean_version in affected_db[pkg_name]:
                    found_packages.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': section,
                        'exact_match': True
                    })
                else:
                    # Package name matches but version might be different
                    potential_matches.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': section,
                        'exact_match': False
                    })

    return found_packages, potential_matches


def scan_package_lock_dependencies(package_data: dict, affected_db: Dict[str, Set[str]]) -> Tuple[
    List[Dict], List[Dict]]:
    """Scan package-lock.json dependencies (includes nested dependencies)."""
    found_packages = []
    potential_matches = []

    def scan_dependencies_recursive(deps: dict, section: str = 'lockfile', depth: int = 0):
        """Recursively scan dependencies in package-lock.json format."""
        if not deps:
            return

        for pkg_name, pkg_info in deps.items():
            if not isinstance(pkg_info, dict):
                continue

            # Get version from package-lock.json
            installed_version = pkg_info.get('version', '')

            if pkg_name in affected_db and installed_version:
                if installed_version in affected_db[pkg_name]:
                    found_packages.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': f'{section} (depth {depth})',
                        'exact_match': True
                    })
                else:
                    potential_matches.append({
                        'name': pkg_name,
                        'installed_version': installed_version,
                        'affected_versions': list(affected_db[pkg_name]),
                        'section': f'{section} (depth {depth})',
                        'exact_match': False
                    })

            # Recursively scan nested dependencies
            if 'dependencies' in pkg_info:
                scan_dependencies_recursive(pkg_info['dependencies'], section, depth + 1)

    # Scan top-level dependencies in package-lock.json
    if 'dependencies' in package_data:
        scan_dependencies_recursive(package_data['dependencies'], 'dependencies')

    # Also scan packages section if present (npm v7+ format)
    if 'packages' in package_data:
        for pkg_path, pkg_info in package_data['packages'].items():
            if pkg_path == '':  # Skip root package
                continue

            # Extract package name from node_modules path
            if pkg_path.startswith('node_modules/'):
                pkg_name = pkg_path[len('node_modules/'):]
                # Handle scoped packages
                if pkg_name.count('/') > 1:
                    parts = pkg_name.split('/')
                    if parts[0].startswith('@'):
                        pkg_name = f"{parts[0]}/{parts[1]}"
                    else:
                        pkg_name = parts[0]

                installed_version = pkg_info.get('version', '')

                if pkg_name in affected_db and installed_version:
                    if installed_version in affected_db[pkg_name]:
                        found_packages.append({
                            'name': pkg_name,
                            'installed_version': installed_version,
                            'affected_versions': list(affected_db[pkg_name]),
                            'section': 'packages',
                            'exact_match': True
                        })
                    else:
                        potential_matches.append({
                            'name': pkg_name,
                            'installed_version': installed_version,
                            'affected_versions': list(affected_db[pkg_name]),
                            'section': 'packages',
                            'exact_match': False
                        })

    return found_packages, potential_matches


def scan_directory(directory: str) -> None:
    """Recursively scan directory for package.json and package-lock.json files."""
    print(f"🔍 Scanning directory: {directory}")
    print("=" * 60)

    # First scan for IoCs
    print("\n🕵️  Scanning for Shai-Hulud IoCs...")
    iocs = scan_for_iocs(directory)

    if iocs:
        print(f"🚨 CRITICAL: Found {len(iocs)} Indicators of Compromise:")
        for ioc in iocs:
            severity_emoji = "🔴" if ioc['severity'] == 'CRITICAL' else "🟠"
            variant_info = f" [{ioc.get('variant', 'unknown')}]" if 'variant' in ioc else ""
            print(f"   {severity_emoji} {ioc['type'].upper()}{variant_info}: {ioc['path']}")

            if ioc['type'] == 'malicious_bundle_js':
                print(f"      SHA-256: {ioc['hash']}")
            elif ioc['type'] in ['malicious_postinstall', 'malicious_preinstall']:
                print(f"      Pattern: {ioc['pattern']}")
            elif ioc['type'] == 'webhook_site_reference':
                print(f"      URL: {ioc['url']}")
            elif ioc['type'] == 'malicious_payload_file':
                print(f"      Payload file: {ioc.get('filename', 'unknown')}")
            elif ioc['type'] == 'shai_hulud_data_file':
                print(f"      Data file: {ioc.get('filename', 'unknown')}")
            elif ioc['type'] in ['malicious_github_workflow', 'sha1hulud_runner', 'suspicious_runner_config']:
                print(f"      Pattern: {ioc.get('pattern', 'unknown')}")
            elif ioc['type'] == 'docker_privilege_escalation':
                print(f"      Pattern: {ioc.get('pattern', 'unknown')}")
    else:
        print("✅ No IoCs detected")

    print("\n📦 Scanning for compromised packages...")
    found_any = False

    for root, dirs, files in os.walk(directory):
        # Skip node_modules directories
        dirs[:] = [d for d in dirs if d != 'node_modules']

        # Check for both package.json and package-lock.json files
        files_to_scan = []
        if 'package.json' in files:
            files_to_scan.append(('package.json', '📦'))
        if 'package-lock.json' in files:
            files_to_scan.append(('package-lock.json', '🔒'))

        for filename, icon in files_to_scan:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, directory)

            print(f"\n{icon} Checking: {relative_path}")

            exact_matches, potential_matches = scan_package_json(file_path)

            if exact_matches:
                found_any = True
                print(f"🚨 CRITICAL: Found {len(exact_matches)} CONFIRMED compromised packages:")
                for pkg in exact_matches:
                    print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                    print(f"     Affected versions: {', '.join(pkg['affected_versions'])}")

            if potential_matches:
                print(f"⚠️  WARNING: Found {len(potential_matches)} packages with different versions:")
                for pkg in potential_matches:
                    print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                    print(f"     Known affected versions: {', '.join(pkg['affected_versions'])}")

            if not exact_matches and not potential_matches:
                print("✅ No affected packages found")

    print("\n" + "=" * 60)
    if found_any or iocs:
        print("🚨 IMMEDIATE ACTION REQUIRED!")
        print("1. Remove compromised packages immediately")
        print("2. Delete any malicious bundle.js files")
        print("3. Rotate ALL credentials (GitHub tokens, npm tokens, API keys)")
        print("4. Check for 'Shai-Hulud' repos in your GitHub account")
        print("5. Review GitHub audit logs")
        print("6. Scan network logs for webhook.site communications")
    else:
        print("✅ No confirmed compromised packages or IoCs found in scanned directories")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 shai_hulud_scanner.py <path_to_package.json|package-lock.json_or_directory>")
        print("Examples:")
        print("  python3 shai_hulud_scanner.py ./package.json")
        print("  python3 shai_hulud_scanner.py ./package-lock.json")
        print("  python3 shai_hulud_scanner.py ./my-project")
        print("  python3 shai_hulud_scanner.py .")
        sys.exit(1)

    target_path = sys.argv[1]

    if os.path.isfile(target_path) and (
            target_path.endswith('package.json') or target_path.endswith('package-lock.json')):
        print(f"🔍 Scanning file: {target_path}")
        print("=" * 60)

        # Scan for IoCs in the directory containing the file
        directory = os.path.dirname(target_path) if os.path.dirname(target_path) else '.'
        print("\n🕵️  Scanning for Shai-Hulud IoCs...")
        iocs = scan_for_iocs(directory)

        if iocs:
            print(f"🚨 CRITICAL: Found {len(iocs)} Indicators of Compromise:")
            for ioc in iocs:
                severity_emoji = "🔴" if ioc['severity'] == 'CRITICAL' else "🟠"
                variant_info = f" [{ioc.get('variant', 'unknown')}]" if 'variant' in ioc else ""
                print(f"   {severity_emoji} {ioc['type'].upper()}{variant_info}: {ioc['path']}")
                
                if ioc['type'] == 'malicious_bundle_js' and 'hash' in ioc:
                    print(f"      SHA-256: {ioc['hash']}")
                elif ioc['type'] in ['malicious_postinstall', 'malicious_preinstall'] and 'pattern' in ioc:
                    print(f"      Pattern: {ioc['pattern']}")
                elif ioc['type'] == 'webhook_site_reference' and 'url' in ioc:
                    print(f"      URL: {ioc['url']}")
                elif ioc['type'] == 'malicious_payload_file' and 'filename' in ioc:
                    print(f"      Payload file: {ioc['filename']}")
                elif ioc['type'] == 'shai_hulud_data_file' and 'filename' in ioc:
                    print(f"      Data file: {ioc['filename']}")
                elif ioc['type'] in ['malicious_github_workflow', 'sha1hulud_runner', 'suspicious_runner_config', 'docker_privilege_escalation'] and 'pattern' in ioc:
                    print(f"      Pattern: {ioc['pattern']}")
        else:
            print("✅ No IoCs detected")

        print(f"\n📦 Scanning package file: {target_path}")
        exact_matches, potential_matches = scan_package_json(target_path)

        if exact_matches:
            print(f"🚨 CRITICAL: Found {len(exact_matches)} CONFIRMED compromised packages:")
            for pkg in exact_matches:
                print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                print(f"     Affected versions: {', '.join(pkg['affected_versions'])}")

        if potential_matches:
            print(f"⚠️  WARNING: Found {len(potential_matches)} packages with different versions:")
            for pkg in potential_matches:
                print(f"   • {pkg['name']} v{pkg['installed_version']} in {pkg['section']}")
                print(f"     Known affected versions: {', '.join(pkg['affected_versions'])}")

        if not exact_matches and not potential_matches:
            print("✅ No affected packages found")

        if exact_matches or iocs:
            print("\n🚨 IMMEDIATE ACTION REQUIRED!")
            print("1. Remove compromised packages immediately")
            print("2. Delete any malicious bundle.js files")
            print("3. Rotate ALL credentials")

    elif os.path.isdir(target_path):
        scan_directory(target_path)
    else:
        print(f"❌ Error: {target_path} is not a valid file or directory")
        sys.exit(1)


if __name__ == "__main__":
    main()