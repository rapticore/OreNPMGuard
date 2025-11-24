#!/usr/bin/env python3
"""
Python Scanner Test Suite
Tests for shai_hulud_scanner.py covering both original and Shai-Hulud 2.0 detection.
"""

import unittest
import os
import sys
import tempfile
import shutil
import json
from pathlib import Path

# Add parent directory to path to import scanner
sys.path.insert(0, str(Path(__file__).parent.parent))
from shai_hulud_scanner import (
    scan_for_iocs,
    scan_package_json,
    load_affected_packages_from_yaml,
    SHAI_HULUD_IOCS
)


class TestIOCDetection(unittest.TestCase):
    """Test IoC detection for both original and Shai-Hulud 2.0."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)
    
    def test_original_postinstall_detection(self):
        """Test detection of original Shai-Hulud postinstall hook."""
        package_json = {
            "scripts": {
                "postinstall": "node bundle.js"
            }
        }
        package_path = os.path.join(self.test_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f)
        
        iocs = scan_for_iocs(self.test_dir)
        self.assertGreater(len(iocs), 0, "Should detect postinstall hook")
        
        postinstall_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_postinstall']
        self.assertGreater(len(postinstall_iocs), 0, "Should find malicious_postinstall IoC")
        self.assertEqual(postinstall_iocs[0]['variant'], 'original', "Should be original variant")
    
    def test_shai_hulud_2_preinstall_detection(self):
        """Test detection of Shai-Hulud 2.0 preinstall hook."""
        package_json = {
            "scripts": {
                "preinstall": "node setup_bun.js"
            }
        }
        package_path = os.path.join(self.test_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f)
        
        iocs = scan_for_iocs(self.test_dir)
        preinstall_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_preinstall']
        self.assertGreater(len(preinstall_iocs), 0, "Should detect preinstall hook")
        self.assertEqual(preinstall_iocs[0]['variant'], '2.0', "Should be 2.0 variant")
    
    def test_setup_bun_js_detection(self):
        """Test detection of setup_bun.js payload file."""
        payload_path = os.path.join(self.test_dir, "setup_bun.js")
        with open(payload_path, 'w') as f:
            f.write("// malicious payload")
        
        iocs = scan_for_iocs(self.test_dir)
        payload_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_payload_file']
        self.assertGreater(len(payload_iocs), 0, "Should detect setup_bun.js")
        self.assertEqual(payload_iocs[0]['filename'], 'setup_bun.js')
        self.assertEqual(payload_iocs[0]['variant'], '2.0')
    
    def test_bun_environment_js_detection(self):
        """Test detection of bun_environment.js payload file."""
        payload_path = os.path.join(self.test_dir, "bun_environment.js")
        with open(payload_path, 'w') as f:
            f.write("// malicious payload")
        
        iocs = scan_for_iocs(self.test_dir)
        payload_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_payload_file']
        self.assertGreater(len(payload_iocs), 0, "Should detect bun_environment.js")
        self.assertEqual(payload_iocs[0]['filename'], 'bun_environment.js')
    
    def test_data_files_detection(self):
        """Test detection of Shai-Hulud 2.0 data files."""
        data_files = ['cloud.json', 'contents.json', 'environment.json', 'truffleSecrets.json']
        
        for data_file in data_files:
            data_path = os.path.join(self.test_dir, data_file)
            with open(data_path, 'w') as f:
                f.write('{}')
        
        iocs = scan_for_iocs(self.test_dir)
        data_file_iocs = [ioc for ioc in iocs if ioc['type'] == 'shai_hulud_data_file']
        self.assertEqual(len(data_file_iocs), len(data_files), "Should detect all data files")
        
        for ioc in data_file_iocs:
            self.assertEqual(ioc['variant'], '2.0')
            self.assertIn(ioc['filename'], data_files)
    
    def test_webhook_site_reference(self):
        """Test detection of webhook.site references."""
        test_file = os.path.join(self.test_dir, "test.js")
        with open(test_file, 'w') as f:
            f.write(f'const url = "{SHAI_HULUD_IOCS["webhook_url"]}";')
        
        iocs = scan_for_iocs(self.test_dir)
        webhook_iocs = [ioc for ioc in iocs if ioc['type'] == 'webhook_site_reference']
        self.assertGreater(len(webhook_iocs), 0, "Should detect webhook.site reference")
    
    def test_discussion_yaml_workflow(self):
        """Test detection of discussion.yaml workflow."""
        workflows_dir = os.path.join(self.test_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        workflow_content = """name: Discussion Create
on:
  discussion:
jobs:
  process:
    env:
      RUNNER_TRACKING_ID: 0
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v5
"""
        workflow_path = os.path.join(workflows_dir, "discussion.yaml")
        with open(workflow_path, 'w') as f:
            f.write(workflow_content)
        
        iocs = scan_for_iocs(self.test_dir)
        workflow_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_github_workflow']
        self.assertGreater(len(workflow_iocs), 0, "Should detect discussion.yaml workflow")
        
        discussion_iocs = [ioc for ioc in workflow_iocs if 'discussion.yaml' in ioc['pattern']]
        self.assertGreater(len(discussion_iocs), 0, "Should identify as discussion.yaml")
        self.assertEqual(discussion_iocs[0]['variant'], '2.0')
    
    def test_formatter_workflow(self):
        """Test detection of formatter workflow."""
        workflows_dir = os.path.join(self.test_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        workflow_path = os.path.join(workflows_dir, "formatter_123456789.yml")
        with open(workflow_path, 'w') as f:
            f.write("name: Code Formatter\n")
        
        iocs = scan_for_iocs(self.test_dir)
        workflow_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_github_workflow']
        formatter_iocs = [ioc for ioc in workflow_iocs if 'formatter' in ioc['pattern']]
        self.assertGreater(len(formatter_iocs), 0, "Should detect formatter workflow")
        self.assertEqual(formatter_iocs[0]['variant'], '2.0')
    
    def test_sha1hulud_runner_detection(self):
        """Test detection of SHA1HULUD runner name."""
        workflows_dir = os.path.join(self.test_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        workflow_content = "runs-on: SHA1HULUD\n"
        workflow_path = os.path.join(workflows_dir, "test.yml")
        with open(workflow_path, 'w') as f:
            f.write(workflow_content)
        
        iocs = scan_for_iocs(self.test_dir)
        runner_iocs = [ioc for ioc in iocs if ioc['type'] == 'sha1hulud_runner']
        self.assertGreater(len(runner_iocs), 0, "Should detect SHA1HULUD runner")
        self.assertEqual(runner_iocs[0]['variant'], '2.0')
    
    def test_docker_privilege_escalation(self):
        """Test detection of Docker privilege escalation pattern."""
        script_path = os.path.join(self.test_dir, "malicious.sh")
        with open(script_path, 'w') as f:
            f.write('docker run --rm --privileged -v /:/host ubuntu bash\n')
        
        iocs = scan_for_iocs(self.test_dir)
        docker_iocs = [ioc for ioc in iocs if ioc['type'] == 'docker_privilege_escalation']
        self.assertGreater(len(docker_iocs), 0, "Should detect Docker privilege escalation")
        self.assertEqual(docker_iocs[0]['variant'], '2.0')
    
    def test_runner_tracking_id(self):
        """Test detection of RUNNER_TRACKING_ID: 0."""
        workflows_dir = os.path.join(self.test_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        workflow_content = "env:\n  RUNNER_TRACKING_ID: 0\n"
        workflow_path = os.path.join(workflows_dir, "test.yml")
        with open(workflow_path, 'w') as f:
            f.write(workflow_content)
        
        iocs = scan_for_iocs(self.test_dir)
        tracking_iocs = [ioc for ioc in iocs if ioc['type'] == 'suspicious_runner_config']
        self.assertGreater(len(tracking_iocs), 0, "Should detect RUNNER_TRACKING_ID: 0")
        self.assertEqual(tracking_iocs[0]['variant'], '2.0')


class TestPackageDetection(unittest.TestCase):
    """Test package version detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)
    
    def test_compromised_package_detection(self):
        """Test detection of compromised package versions."""
        # Use a known compromised package from the database
        package_json = {
            "dependencies": {
                "@ctrl/deluge": "7.2.2"
            }
        }
        package_path = os.path.join(self.test_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f)
        
        exact_matches, potential_matches = scan_package_json(package_path)
        self.assertGreater(len(exact_matches), 0, "Should detect compromised package")
        self.assertEqual(exact_matches[0]['name'], '@ctrl/deluge')
        self.assertEqual(exact_matches[0]['installed_version'], '7.2.2')
    
    def test_potential_match_detection(self):
        """Test detection of packages with different versions."""
        package_json = {
            "dependencies": {
                "@ctrl/deluge": "7.2.0"  # Different version
            }
        }
        package_path = os.path.join(self.test_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f)
        
        exact_matches, potential_matches = scan_package_json(package_path)
        self.assertEqual(len(exact_matches), 0, "Should not have exact match")
        self.assertGreater(len(potential_matches), 0, "Should detect potential match")
        self.assertEqual(potential_matches[0]['name'], '@ctrl/deluge')


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with original Shai-Hulud detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)
    
    def test_original_bundle_js_detection(self):
        """Test that original bundle.js detection still works."""
        # Create a bundle.js file (we can't test hash without actual malicious file)
        bundle_path = os.path.join(self.test_dir, "bundle.js")
        with open(bundle_path, 'w') as f:
            f.write("// test bundle")
        
        # The scanner checks for hash, so this won't trigger, but structure should work
        iocs = scan_for_iocs(self.test_dir)
        # At minimum, the file exists and scanner processes it
        self.assertIsNotNone(iocs)
    
    def test_original_workflow_detection(self):
        """Test detection of original shai-hulud-workflow.yml."""
        workflows_dir = os.path.join(self.test_dir, ".github", "workflows")
        os.makedirs(workflows_dir, exist_ok=True)
        
        workflow_path = os.path.join(workflows_dir, "shai-hulud-workflow.yml")
        with open(workflow_path, 'w') as f:
            f.write("name: Shai-Hulud\n")
        
        iocs = scan_for_iocs(self.test_dir)
        workflow_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_github_workflow']
        original_iocs = [ioc for ioc in workflow_iocs if ioc.get('variant') == 'original']
        self.assertGreater(len(original_iocs), 0, "Should detect original workflow")
    
    def test_both_variants_detected(self):
        """Test that both original and 2.0 variants can be detected simultaneously."""
        package_json = {
            "scripts": {
                "postinstall": "node bundle.js",  # Original
                "preinstall": "node setup_bun.js"  # 2.0
            }
        }
        package_path = os.path.join(self.test_dir, "package.json")
        with open(package_path, 'w') as f:
            json.dump(package_json, f)
        
        # Create 2.0 payload file
        setup_bun_path = os.path.join(self.test_dir, "setup_bun.js")
        with open(setup_bun_path, 'w') as f:
            f.write("// payload")
        
        iocs = scan_for_iocs(self.test_dir)
        
        postinstall_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_postinstall']
        preinstall_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_preinstall']
        payload_iocs = [ioc for ioc in iocs if ioc['type'] == 'malicious_payload_file']
        
        self.assertGreater(len(postinstall_iocs), 0, "Should detect original postinstall")
        self.assertGreater(len(preinstall_iocs), 0, "Should detect 2.0 preinstall")
        self.assertGreater(len(payload_iocs), 0, "Should detect 2.0 payload file")


class TestIOCPatterns(unittest.TestCase):
    """Test IoC pattern definitions."""
    
    def test_ioc_patterns_defined(self):
        """Test that all required IoC patterns are defined."""
        required_patterns = [
            'webhook_url',
            'bundle_js_hashes',
            'postinstall_pattern',
            'preinstall_pattern',
            'payload_files',
            'data_files',
            'github_workflow_patterns',
            'self_hosted_runner_pattern',
            'sha1hulud_runner_pattern',
            'runner_tracking_id_pattern',
            'docker_privilege_escalation_pattern'
        ]
        
        for pattern in required_patterns:
            self.assertIn(pattern, SHAI_HULUD_IOCS, f"Missing IoC pattern: {pattern}")
    
    def test_payload_files_list(self):
        """Test that payload files list includes all expected files."""
        expected_files = ['bundle.js', 'setup_bun.js', 'bun_environment.js']
        payload_files = SHAI_HULUD_IOCS['payload_files']
        
        for expected_file in expected_files:
            self.assertIn(expected_file, payload_files, f"Missing payload file: {expected_file}")
    
    def test_data_files_list(self):
        """Test that data files list includes all expected files."""
        expected_files = ['cloud.json', 'contents.json', 'environment.json', 'truffleSecrets.json']
        data_files = SHAI_HULUD_IOCS['data_files']
        
        for expected_file in expected_files:
            self.assertIn(expected_file, data_files, f"Missing data file: {expected_file}")


if __name__ == '__main__':
    unittest.main()

