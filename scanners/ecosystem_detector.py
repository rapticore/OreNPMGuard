#!/usr/bin/env python3
"""
Ecosystem Detection Module
Detects package ecosystems from directory structure or file names
"""

import os
from pathlib import Path
from typing import Optional, List, Set, Tuple


# Mapping of file names to ecosystems
FILENAME_TO_ECOSYSTEM = {
    # npm
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'npm',
    'pnpm-lock.yaml': 'npm',
    # pypi
    'requirements.txt': 'pypi',
    'setup.py': 'pypi',
    'pyproject.toml': 'pypi',
    'Pipfile': 'pypi',
    'poetry.lock': 'pypi',
    # maven
    'pom.xml': 'maven',
    'build.gradle': 'maven',
    # rubygems
    'Gemfile': 'rubygems',
    'Gemfile.lock': 'rubygems',
    # go
    'go.mod': 'go',
    'go.sum': 'go',
    # cargo
    'Cargo.toml': 'cargo',
    'Cargo.lock': 'cargo',
}


def detect_ecosystem_from_filename(filepath: str) -> Optional[str]:
    """
    Detect ecosystem from file name.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Ecosystem name (npm, pypi, maven, etc.) or None if not detected
    """
    filename = os.path.basename(filepath)
    return FILENAME_TO_ECOSYSTEM.get(filename)


def detect_ecosystem_from_directory(directory: str) -> Optional[str]:
    """
    Detect ecosystem by scanning directory for ecosystem-specific files.
    When multiple ecosystems are found, returns the first one found (prioritized order).
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        Ecosystem name (npm, pypi, maven, etc.) or None if none found
    """
    if not os.path.isdir(directory):
        return None
    
    found_ecosystems: Set[str] = set()
    
    # Skip common directories (build artifacts, caches, dependencies)
    skip_dirs = [
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        '.next', 'build', 'dist', '.build', 'target', 'out', '.cache',
        '.idea', '.vscode', '.vs', 'coverage', '.nyc_output', '.pytest_cache',
        'bin', 'obj', '.gradle', '.mvn', 'vendor', 'bower_components'
    ]
    
    # Scan for ecosystem-specific files
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for filename in files:
            ecosystem = FILENAME_TO_ECOSYSTEM.get(filename)
            if ecosystem:
                found_ecosystems.add(ecosystem)
    
    # Return ecosystem if found
    if found_ecosystems:
        # Priority order: npm, pypi, maven, rubygems, go, cargo
        priority_order = ['npm', 'pypi', 'maven', 'rubygems', 'go', 'cargo']
        for eco in priority_order:
            if eco in found_ecosystems:
                return eco
        # If not in priority list, return first one
        return list(found_ecosystems)[0]
    
    return None


def detect_all_ecosystems_from_directory(directory: str) -> List[str]:
    """
    Detect all ecosystems found in directory.
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        List of ecosystem names found
    """
    if not os.path.isdir(directory):
        return []
    
    found_ecosystems: Set[str] = set()
    
    # Skip common directories (build artifacts, caches, dependencies)
    skip_dirs = [
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        '.next', 'build', 'dist', '.build', 'target', 'out', '.cache',
        '.idea', '.vscode', '.vs', 'coverage', '.nyc_output', '.pytest_cache',
        'bin', 'obj', '.gradle', '.mvn', 'vendor', 'bower_components'
    ]
    
    # Scan for ecosystem-specific files
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for filename in files:
            ecosystem = FILENAME_TO_ECOSYSTEM.get(filename)
            if ecosystem:
                found_ecosystems.add(ecosystem)
    
    # Return in priority order
    priority_order = ['npm', 'pypi', 'maven', 'rubygems', 'go', 'cargo']
    result = []
    for eco in priority_order:
        if eco in found_ecosystems:
            result.append(eco)
    
    # Add any remaining ecosystems not in priority list
    for eco in found_ecosystems:
        if eco not in result:
            result.append(eco)
    
    return result


def find_dependency_files(directory: str, ecosystem: str) -> List[str]:
    """
    Find all dependency files for a given ecosystem in a directory.
    
    Args:
        directory: Path to directory to scan
        ecosystem: Ecosystem name (npm, pypi, maven, etc.)
        
    Returns:
        List of paths to dependency files
    """
    if not os.path.isdir(directory):
        return []
    
    # Map ecosystem to its dependency files
    ecosystem_files = {
        'npm': ['package.json', 'package-lock.json'],
        'pypi': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
        'maven': ['pom.xml', 'build.gradle'],
        'rubygems': ['Gemfile', 'Gemfile.lock'],
        'go': ['go.mod', 'go.sum'],
        'cargo': ['Cargo.toml', 'Cargo.lock'],
    }
    
    target_files = ecosystem_files.get(ecosystem, [])
    found_files = []
    
    for root, dirs, files in os.walk(directory):
        # Skip common directories (build artifacts, caches, dependencies)
        skip_dirs = [
            'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
            '.next', 'build', 'dist', '.build', 'target', 'out', '.cache',
            '.idea', '.vscode', '.vs', 'coverage', '.nyc_output', '.pytest_cache',
            'bin', 'obj', '.gradle', '.mvn', 'vendor', 'bower_components'
        ]
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for filename in files:
            if filename in target_files:
                found_files.append(os.path.join(root, filename))
    
    return found_files

