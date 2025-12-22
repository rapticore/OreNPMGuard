#!/usr/bin/env python3
"""
File Input Parser Module
Parses generic file inputs (text, JSON, YAML) to extract package lists
"""

import json
import os
import re
import yaml
from typing import List, Dict, Optional


def parse_file_input(file_path: str) -> List[Dict[str, str]]:
    """
    Parse a file input to extract packages.
    Supports text, JSON, and YAML formats.
    
    Args:
        file_path: Path to the input file
        
    Returns:
        List of dicts with 'name' and optionally 'version' keys
    """
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return []
    
    # Detect file format
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext in ['.json']:
        return parse_json_input(file_path)
    elif file_ext in ['.yaml', '.yml']:
        return parse_yaml_input(file_path)
    else:
        # Default to text format
        return parse_text_input(file_path)


def parse_text_input(file_path: str) -> List[Dict[str, str]]:
    """
    Parse text file with one package per line.
    Supports formats:
    - package-name
    - package-name@version
    - package-name==version
    
    Args:
        file_path: Path to text file
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading text file {file_path}: {e}")
        return packages
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Parse package@version or package==version
        if '@' in line:
            parts = line.split('@', 1)
            pkg_name = parts[0].strip()
            version = parts[1].strip()
        elif '==' in line:
            parts = line.split('==', 1)
            pkg_name = parts[0].strip()
            version = parts[1].strip()
        else:
            # Just package name
            pkg_name = line.strip()
            version = ''
        
        if pkg_name:
            packages.append({
                'name': pkg_name,
                'version': version,
                'line': line_num
            })
    
    return packages


def parse_json_input(file_path: str) -> List[Dict[str, str]]:
    """
    Parse JSON file with package list.
    Supports formats:
    - {"packages": ["pkg1", "pkg2"]}
    - {"packages": [{"name": "pkg1", "version": "1.0.0"}]}
    - [{"name": "pkg1", "version": "1.0.0"}]
    - ["pkg1", "pkg2"]
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file {file_path}: {e}")
        return packages
    except Exception as e:
        print(f"Error reading JSON file {file_path}: {e}")
        return packages
    
    # Handle different JSON structures
    if isinstance(data, dict):
        # Format: {"packages": [...]}
        if 'packages' in data:
            pkg_list = data['packages']
        else:
            # Try to find any list in the dict
            pkg_list = None
            for key, value in data.items():
                if isinstance(value, list):
                    pkg_list = value
                    break
            
            if pkg_list is None:
                print(f"Warning: Could not find package list in JSON file {file_path}")
                return packages
    elif isinstance(data, list):
        # Format: ["pkg1", "pkg2"] or [{"name": "pkg1", ...}]
        pkg_list = data
    else:
        print(f"Warning: Unexpected JSON structure in {file_path}")
        return packages
    
    # Parse package list
    for item in pkg_list:
        if isinstance(item, dict):
            # Format: {"name": "pkg1", "version": "1.0.0"}
            pkg_name = item.get('name', '')
            version = item.get('version', '')
            if pkg_name:
                packages.append({
                    'name': pkg_name,
                    'version': version
                })
        elif isinstance(item, str):
            # Format: "pkg1" or "pkg1@1.0.0"
            if '@' in item:
                parts = item.split('@', 1)
                pkg_name = parts[0].strip()
                version = parts[1].strip()
            else:
                pkg_name = item.strip()
                version = ''
            
            if pkg_name:
                packages.append({
                    'name': pkg_name,
                    'version': version
                })
    
    return packages


def parse_yaml_input(file_path: str) -> List[Dict[str, str]]:
    """
    Parse YAML file with package list.
    Supports same formats as JSON.
    
    Args:
        file_path: Path to YAML file
        
    Returns:
        List of dicts with 'name' and 'version' keys
    """
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file {file_path}: {e}")
        return packages
    except Exception as e:
        print(f"Error reading YAML file {file_path}: {e}")
        return packages
    
    if data is None:
        return packages
    
    # Handle different YAML structures (same as JSON)
    if isinstance(data, dict):
        if 'packages' in data:
            pkg_list = data['packages']
        else:
            pkg_list = None
            for key, value in data.items():
                if isinstance(value, list):
                    pkg_list = value
                    break
            
            if pkg_list is None:
                print(f"Warning: Could not find package list in YAML file {file_path}")
                return packages
    elif isinstance(data, list):
        pkg_list = data
    else:
        print(f"Warning: Unexpected YAML structure in {file_path}")
        return packages
    
    # Parse package list (same logic as JSON)
    for item in pkg_list:
        if isinstance(item, dict):
            pkg_name = item.get('name', '')
            version = item.get('version', '')
            if pkg_name:
                packages.append({
                    'name': pkg_name,
                    'version': version
                })
        elif isinstance(item, str):
            if '@' in item:
                parts = item.split('@', 1)
                pkg_name = parts[0].strip()
                version = parts[1].strip()
            else:
                pkg_name = item.strip()
                version = ''
            
            if pkg_name:
                packages.append({
                    'name': pkg_name,
                    'version': version
                })
    
    return packages

