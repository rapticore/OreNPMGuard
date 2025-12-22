#!/usr/bin/env python3
"""
IoC (Indicators of Compromise) Detection Module
Detects Shai-Hulud attack patterns and other malicious indicators
"""

import os
import re
import hashlib
from typing import List, Dict, Optional, Set


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


def calculate_file_hash(file_path: str) -> Optional[str]:
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SHA-256 hash as hex string, or None on error
    """
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
    """
    Scan directory for Shai-Hulud IoCs (Indicators of Compromise).
    
    Detects both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) indicators.
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        List of IoC dictionaries with type, path, severity, etc.
    """
    iocs_found = []
    
    # Skip directories that shouldn't be scanned
    skip_dirs = [
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        '.next', 'build', 'dist', '.build', 'target', 'out', '.cache',
        '.idea', '.vscode', '.vs', 'coverage', '.nyc_output', '.pytest_cache',
        'bin', 'obj', '.gradle', '.mvn', 'vendor', 'bower_components'
    ]
    
    for root, dirs, files in os.walk(directory):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]

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

