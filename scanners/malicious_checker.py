#!/usr/bin/env python3
"""
Malicious Package Checker Module
Checks packages against unified malicious package databases (SQLite)
"""

import os
import re
import sys
import urllib.request
import urllib.error
import yaml
from typing import List, Dict, Optional, Set
from pathlib import Path

# Add collectors directory to path for db module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'collectors'))
import db


class MaliciousPackageChecker:
    """Checks packages against malicious package databases."""
    
    def __init__(self, collectors_dir: Optional[str] = None):
        """
        Initialize the checker.

        Args:
            collectors_dir: Path to collectors directory (defaults to relative path)
        """
        if collectors_dir is None:
            # Default to collectors directory relative to this file
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            collectors_dir = os.path.join(script_dir, 'collectors')

        self.collectors_dir = collectors_dir
        self.final_data_dir = os.path.join(collectors_dir, 'final-data')
        self._db_cache = {}  # Cache database connections per ecosystem
        self._shai_hulud_cache = None  # Cache for Shai-Hulud affected packages
        self._shai_hulud_loaded = False
        self.github_yaml_url = "https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml"

    def _get_db_connection(self, ecosystem: str):
        """
        Get cached database connection for ecosystem.

        Args:
            ecosystem: Ecosystem name (npm, pypi, etc.)

        Returns:
            Database connection or None if not found
        """
        if ecosystem in self._db_cache:
            return self._db_cache[ecosystem]

        db_path = os.path.join(self.final_data_dir, f'unified_{ecosystem}.db')
        conn = db.open_database(db_path)

        if conn:
            self._db_cache[ecosystem] = conn

        return conn
    
    def _normalize_package_name(self, name: str) -> str:
        """
        Normalize package name for comparison (case-insensitive).
        
        Args:
            name: Package name
            
        Returns:
            Normalized package name
        """
        return name.lower().strip()
    
    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string for comparison.
        
        Args:
            version: Version string
            
        Returns:
            Normalized version
        """
        return version.strip()
    
    def _load_shai_hulud_packages(self) -> Dict[str, Set[str]]:
        """
        Load Shai-Hulud affected packages from GitHub or local YAML file.
        Uses caching to avoid reloading.
        
        Returns:
            Dict mapping package names to sets of affected versions
        """
        # Return cached data if already loaded
        if self._shai_hulud_loaded and self._shai_hulud_cache is not None:
            return self._shai_hulud_cache
        
        # First try to download from GitHub
        config = self._download_affected_packages_yaml()
        
        # If download failed, try local file
        if config is None:
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(script_dir, 'affected_packages.yaml')
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    print(f"✅ Loaded local Shai-Hulud configuration with {len(config.get('affected_packages', []))} packages")
            except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
                print(f"⚠️  Warning: Could not load Shai-Hulud configuration: {e}")
                self._shai_hulud_cache = {}
                self._shai_hulud_loaded = True
                return self._shai_hulud_cache
        
        # Parse the configuration and cache it
        packages = {}
        if config:
            for pkg in config.get('affected_packages', []):
                packages[pkg['name']] = set(pkg['versions'])
        
        self._shai_hulud_cache = packages
        self._shai_hulud_loaded = True
        return packages
    
    def _download_affected_packages_yaml(self) -> Optional[Dict]:
        """
        Download the latest affected packages YAML from GitHub.
        
        Returns:
            Parsed YAML config or None on error
        """
        try:
            req = urllib.request.Request(
                self.github_yaml_url,
                headers={'User-Agent': 'OreNPMGuard-Scanner/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                yaml_content = response.read().decode('utf-8')
                config = yaml.safe_load(yaml_content)
                return config
        except (urllib.error.URLError, urllib.error.HTTPError, yaml.YAMLError, KeyError) as e:
            # Silently fail - will fall back to local file
            return None
        except Exception:
            return None
    
    def _check_shai_hulud_packages(self, packages: List[Dict[str, str]]) -> List[Dict]:
        """
        Check packages against Shai-Hulud affected packages list.
        
        Args:
            packages: List of dicts with 'name' and optionally 'version'
            
        Returns:
            List of malicious packages found from Shai-Hulud list
        """
        malicious_found = []
        
        # Load Shai-Hulud affected packages
        affected_db = self._load_shai_hulud_packages()
        if not affected_db:
            return malicious_found
        
        # Check each package
        for pkg in packages:
            pkg_name = pkg.get('name', '')
            pkg_version = pkg.get('version', '')
            
            if not pkg_name:
                continue
            
            normalized_name = self._normalize_package_name(pkg_name)
            
            # Check if package is in Shai-Hulud affected list
            if normalized_name in affected_db:
                affected_versions = affected_db[normalized_name]
                
                # Check version match
                is_malicious = False
                matched_version = None
                
                if pkg_version:
                    # Clean version string (remove ^, ~, etc.)
                    clean_version = re.sub(r'^[\^~>=<]', '', pkg_version)
                    is_malicious = clean_version in affected_versions
                    if is_malicious:
                        matched_version = clean_version
                else:
                    # No version specified - if package has any affected versions, flag it
                    if affected_versions:
                        is_malicious = True
                        matched_version = list(affected_versions)[0] if affected_versions else None
                
                if is_malicious:
                    # Create result entry
                    result = {
                        'name': pkg_name,
                        'version': pkg_version or matched_version,
                        'matched_version': matched_version,
                        'severity': 'critical',
                        'sources': ['shai-hulud'],
                        'description': f'Shai-Hulud compromised package: {pkg_name}',
                        'detected_behaviors': ['supply_chain_attack', 'malicious_code'],
                        'affected_versions': list(affected_versions),
                        'source_details': {
                            'shai-hulud': {
                                'severity': 'critical',
                                'url': 'https://github.com/rapticore/OreNPMGuard',
                                'description': f'Shai-Hulud compromised package: {pkg_name}'
                            }
                        }
                    }
                    malicious_found.append(result)
        
        return malicious_found
    
    def _match_version(self, package_version: str, malicious_versions: List[str]) -> bool:
        """
        Check if a package version matches any malicious version.
        
        Args:
            package_version: Version to check
            malicious_versions: List of malicious versions
            
        Returns:
            True if version matches
        """
        normalized_pkg_version = self._normalize_version(package_version)
        
        for mal_version in malicious_versions:
            normalized_mal_version = self._normalize_version(mal_version)
            
            # Exact match
            if normalized_pkg_version == normalized_mal_version:
                return True
            
            # Handle version ranges (basic support)
            # If package version is empty, check if any version is malicious
            if not normalized_pkg_version and normalized_mal_version:
                # Empty version means any version - be conservative
                continue
        
        return False
    
    def check_packages(self, packages: List[Dict[str, str]], ecosystem: str,
                      include_shai_hulud: bool = True) -> List[Dict]:
        """
        Check a list of packages against the malicious database.

        Args:
            packages: List of dicts with 'name' and optionally 'version'
            ecosystem: Ecosystem name (npm, pypi, etc.)
            include_shai_hulud: Whether to also check against Shai-Hulud affected packages (npm only)

        Returns:
            List of malicious packages found with full metadata
        """
        malicious_found = []

        # Get database connection
        conn = self._get_db_connection(ecosystem)

        if conn:
            # Check each package using SQLite
            for pkg in packages:
                pkg_name = pkg.get('name', '')
                pkg_version = pkg.get('version', '')

                if not pkg_name:
                    continue

                # Use db.check_package for lookup
                result = db.check_package(conn, pkg_name, pkg_version)
                if result:
                    malicious_found.append(result)
        else:
            print(f"Warning: Database not found for ecosystem: {ecosystem}")

        # Also check against Shai-Hulud affected packages for npm ecosystem
        if include_shai_hulud and ecosystem == 'npm':
            shai_hulud_malicious = self._check_shai_hulud_packages(packages)

            # Merge results, avoiding duplicates
            existing_names = {(pkg['name'].lower(), pkg.get('version', '')) for pkg in malicious_found}
            for pkg in shai_hulud_malicious:
                key = (pkg['name'].lower(), pkg.get('version', ''))
                if key not in existing_names:
                    malicious_found.append(pkg)
                    existing_names.add(key)

        return malicious_found


def check_malicious_packages(packages: List[Dict[str, str]], ecosystem: str, 
                            collectors_dir: Optional[str] = None,
                            include_shai_hulud: bool = True) -> List[Dict]:
    """
    Convenience function to check packages.
    
    Args:
        packages: List of dicts with 'name' and optionally 'version'
        ecosystem: Ecosystem name (npm, pypi, etc.)
        collectors_dir: Optional path to collectors directory
        include_shai_hulud: Whether to also check against Shai-Hulud affected packages (npm only)
        
    Returns:
        List of malicious packages found
    """
    checker = MaliciousPackageChecker(collectors_dir)
    return checker.check_packages(packages, ecosystem, include_shai_hulud=include_shai_hulud)

