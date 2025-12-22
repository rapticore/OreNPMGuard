#!/usr/bin/env python3
"""
Dependency Parsers Module
Parses dependency files for various package ecosystems
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional
from pathlib import Path


def parse_npm_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse npm dependencies from package.json or package-lock.json.
    
    Args:
        file_path: Path to package.json or package-lock.json
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    packages = []
    
    if file_path.endswith('package-lock.json'):
        packages.extend(_parse_package_lock(package_data))
    else:
        packages.extend(_parse_package_json(package_data))
    
    return packages


def _parse_package_json(package_data: dict) -> List[Dict[str, str]]:
    """Parse package.json dependency sections."""
    packages = []
    deps_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
    
    for section in deps_sections:
        if section not in package_data:
            continue
        
        for pkg_name, version_spec in package_data[section].items():
            # Extract version from version spec (remove ^, ~, etc.)
            clean_version = re.sub(r'^[\^~>=<]', '', version_spec)
            packages.append({
                'name': pkg_name,
                'version': clean_version,
                'section': section
            })
    
    return packages


def _parse_package_lock(package_data: dict) -> List[Dict[str, str]]:
    """Parse package-lock.json dependencies."""
    packages = []
    
    def extract_from_deps(deps: dict):
        """Recursively extract packages from dependencies."""
        if not deps:
            return
        
        for pkg_name, pkg_info in deps.items():
            if isinstance(pkg_info, dict):
                version = pkg_info.get('version', '')
                if version:
                    packages.append({
                        'name': pkg_name,
                        'version': version,
                        'section': 'lockfile'
                    })
                
                if 'dependencies' in pkg_info:
                    extract_from_deps(pkg_info['dependencies'])
    
    # Parse dependencies section
    if 'dependencies' in package_data:
        extract_from_deps(package_data['dependencies'])
    
    # Parse packages section (npm v7+)
    if 'packages' in package_data:
        for pkg_path, pkg_info in package_data['packages'].items():
            if pkg_path == '':
                continue
            
            if isinstance(pkg_info, dict):
                version = pkg_info.get('version', '')
                if version:
                    # Extract package name from path
                    pkg_name = pkg_path
                    if pkg_path.startswith('node_modules/'):
                        pkg_name = pkg_path[len('node_modules/'):]
                        # Handle scoped packages
                        if '/' in pkg_name:
                            parts = pkg_name.split('/')
                            if parts[0].startswith('@'):
                                pkg_name = f"{parts[0]}/{parts[1]}"
                            else:
                                pkg_name = parts[0]
                    
                    packages.append({
                        'name': pkg_name,
                        'version': version,
                        'section': 'packages'
                    })
    
    return packages


def parse_pypi_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse PyPI dependencies from requirements.txt.
    
    Args:
        file_path: Path to requirements.txt
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages
    
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        
        # Skip -r includes (could be handled separately if needed)
        if line.startswith('-r') or line.startswith('--'):
            continue
        
        # Parse package specification
        # Format: package==version, package>=version, package, etc.
        # Extract package name and version
        match = re.match(r'^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)(.*)$', line)
        if match:
            pkg_name = match.group(1)
            version_spec = match.group(2).strip()
            
            # Extract version from spec
            version = ''
            if version_spec:
                # Match ==, >=, <=, >, <, ~=, !=
                version_match = re.match(r'^[=<>!~]+(.+)$', version_spec)
                if version_match:
                    version = version_match.group(1).strip()
            
            # Remove any extras from package name (e.g., package[extra])
            pkg_name = re.sub(r'\[.*\]', '', pkg_name)
            
            packages.append({
                'name': pkg_name,
                'version': version,
                'section': 'requirements'
            })
    
    return packages


def parse_maven_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Maven dependencies from pom.xml.
    
    Args:
        file_path: Path to pom.xml
        
    Returns:
        List of dicts with 'name' (groupId:artifactId) and 'version' keys
    """
    packages = []
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except (FileNotFoundError, ET.ParseError):
        return packages
    
    # Handle namespace
    ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
    if root.tag.startswith('{'):
        ns_uri = root.tag[1:].split('}')[0]
        ns = {'maven': ns_uri}
    
    # Find all dependencies
    dependencies = root.findall('.//maven:dependency', ns)
    if not dependencies:
        # Try without namespace
        dependencies = root.findall('.//dependency')
    
    for dep in dependencies:
        group_id_elem = dep.find('maven:groupId', ns) or dep.find('groupId')
        artifact_id_elem = dep.find('maven:artifactId', ns) or dep.find('artifactId')
        version_elem = dep.find('maven:version', ns) or dep.find('version')
        
        if group_id_elem is not None and artifact_id_elem is not None:
            group_id = group_id_elem.text.strip() if group_id_elem.text else ''
            artifact_id = artifact_id_elem.text.strip() if artifact_id_elem.text else ''
            version = version_elem.text.strip() if version_elem and version_elem.text else ''
            
            # Maven uses groupId:artifactId as package identifier
            pkg_name = f"{group_id}:{artifact_id}"
            
            packages.append({
                'name': pkg_name,
                'version': version,
                'section': 'dependencies'
            })
    
    return packages


def parse_rubygems_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse RubyGems dependencies from Gemfile.
    
    Args:
        file_path: Path to Gemfile
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        return packages
    
    # Simple regex-based parsing for Gemfile
    # Format: gem 'name', 'version' or gem "name", "version"
    gem_pattern = r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?"
    
    for match in re.finditer(gem_pattern, content):
        gem_name = match.group(1)
        gem_version = match.group(2) if match.group(2) else ''
        
        packages.append({
            'name': gem_name,
            'version': gem_version,
            'section': 'gems'
        })
    
    return packages


def parse_go_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Go dependencies from go.mod.
    
    Args:
        file_path: Path to go.mod
        
    Returns:
        List of dicts with 'name' (module path) and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return packages
    
    in_require_block = False
    
    for line in lines:
        line = line.strip()
        
        # Check for require block
        if line.startswith('require'):
            in_require_block = True
            # Check if it's a single-line require
            if '(' not in line:
                # Single-line format: require module/path v1.2.3
                parts = line.split()
                if len(parts) >= 3:
                    pkg_name = parts[1]
                    version = parts[2] if len(parts) > 2 else ''
                    packages.append({
                        'name': pkg_name,
                        'version': version,
                        'section': 'require'
                    })
                in_require_block = False
            continue
        
        # Check for end of require block
        if line == ')' and in_require_block:
            in_require_block = False
            continue
        
        # Parse require entries
        if in_require_block:
            # Format: module/path v1.2.3
            parts = line.split()
            if len(parts) >= 2:
                pkg_name = parts[0]
                version = parts[1] if len(parts) > 1 else ''
                packages.append({
                    'name': pkg_name,
                    'version': version,
                    'section': 'require'
                })
    
    return packages


def parse_cargo_dependencies(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Cargo dependencies from Cargo.toml.
    
    Args:
        file_path: Path to Cargo.toml
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        return packages
    
    # Simple TOML parsing for dependencies section
    # This is a basic implementation - for full TOML support, consider using toml library
    in_dependencies = False
    in_section = False
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Check for [dependencies] section
        if line.startswith('[dependencies]'):
            in_dependencies = True
            continue
        
        # Check for end of dependencies section
        if line.startswith('[') and in_dependencies:
            break
        
        if in_dependencies:
            # Parse dependency line
            # Format: name = "version" or name = { version = "1.0.0" }
            if '=' in line and not line.startswith('#'):
                # Extract package name and version
                parts = line.split('=', 1)
                if len(parts) == 2:
                    pkg_name = parts[0].strip()
                    version_part = parts[1].strip()
                    
                    # Extract version from string or table
                    version = ''
                    if version_part.startswith('"') or version_part.startswith("'"):
                        # String format: "1.0.0"
                        version_match = re.search(r'["\']([^"\']+)["\']', version_part)
                        if version_match:
                            version = version_match.group(1)
                    elif '{' in version_part:
                        # Table format: { version = "1.0.0" }
                        version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', version_part)
                        if version_match:
                            version = version_match.group(1)
                    
                    packages.append({
                        'name': pkg_name,
                        'version': version,
                        'section': 'dependencies'
                    })
    
    return packages


def parse_dependencies(file_path: str, ecosystem: str) -> List[Dict[str, str]]:
    """
    Parse dependencies from a file based on ecosystem.
    
    Args:
        file_path: Path to dependency file
        ecosystem: Ecosystem name (npm, pypi, maven, etc.)
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    parsers = {
        'npm': parse_npm_dependencies,
        'pypi': parse_pypi_dependencies,
        'maven': parse_maven_dependencies,
        'rubygems': parse_rubygems_dependencies,
        'go': parse_go_dependencies,
        'cargo': parse_cargo_dependencies,
    }
    
    parser = parsers.get(ecosystem)
    if parser:
        return parser(file_path)
    
    return []

