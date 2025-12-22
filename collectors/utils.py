#!/usr/bin/env python3
"""
Utility functions for package collectors
Simple, function-based helpers for HTTP requests, file I/O, and data processing
"""

import json
import os
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


def fetch_json(url, headers=None, timeout=30):
    """
    Fetch JSON from URL with error handling

    Args:
        url (str): URL to fetch
        headers (dict): Optional HTTP headers
        timeout (int): Request timeout in seconds

    Returns:
        dict/list: Parsed JSON data, or None on error
    """
    if headers is None:
        headers = {}

    # Add default user agent if not provided
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'OreNPMGuard-Collector/1.0'

    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=timeout) as response:
            data = response.read().decode('utf-8')
            return json.loads(data)
    except HTTPError as e:
        print(f"HTTP Error {e.code} fetching {url}: {e.reason}")
        return None
    except URLError as e:
        print(f"URL Error fetching {url}: {e.reason}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error for {url}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error fetching {url}: {e}")
        return None


def fetch_text(url, headers=None, timeout=30):
    """
    Fetch text content from URL with error handling

    Args:
        url (str): URL to fetch
        headers (dict): Optional HTTP headers
        timeout (int): Request timeout in seconds

    Returns:
        str: Text content, or None on error
    """
    if headers is None:
        headers = {}

    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'OreNPMGuard-Collector/1.0'

    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def save_json(data, filepath):
    """
    Save data as formatted JSON file with atomic write

    Args:
        data (dict/list): Data to save
        filepath (str): Target file path

    Returns:
        bool: True on success, False on error
    """
    try:
        # Create parent directories if needed
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Atomic write: write to temp file then rename
        temp_filepath = f"{filepath}.tmp"
        with open(temp_filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Rename temp file to target file (atomic on Unix)
        os.replace(temp_filepath, filepath)

        print(f"Saved: {filepath}")
        return True
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return False


def load_json(filepath):
    """
    Load JSON from file

    Args:
        filepath (str): Path to JSON file

    Returns:
        dict/list: Parsed JSON data, or None if file doesn't exist or error
    """
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"JSON decode error in {filepath}: {e}")
        return None
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None


def get_timestamp():
    """
    Get current UTC timestamp in ISO 8601 format

    Returns:
        str: Timestamp like "2025-12-12T10:30:00Z"
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def standardize_severity(severity_input):
    """
    Normalize severity levels from different sources to standard levels

    Args:
        severity_input (str/int): Severity from source (various formats)

    Returns:
        str: One of "critical", "high", "medium", "low", or "unknown"
    """
    if severity_input is None:
        return "unknown"

    # Convert to string and lowercase
    severity = str(severity_input).lower().strip()

    # Map various formats to standard levels
    if severity in ['critical', 'crit', 'severe']:
        return 'critical'
    elif severity in ['high', 'important']:
        return 'high'
    elif severity in ['medium', 'moderate', 'med']:
        return 'medium'
    elif severity in ['low', 'minor']:
        return 'low'

    # Handle numeric scores (0-100)
    try:
        score = float(severity_input)
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    except (ValueError, TypeError):
        pass

    return 'unknown'


def normalize_ecosystem(ecosystem_input):
    """
    Normalize ecosystem names to standard format

    Args:
        ecosystem_input (str): Ecosystem name from source

    Returns:
        str: One of "npm", "pypi", "rubygems", "go", or None
    """
    if ecosystem_input is None:
        return None

    ecosystem = str(ecosystem_input).lower().strip()

    # NPM variations
    if ecosystem in ['npm', 'node', 'nodejs', 'node.js', 'javascript', 'js']:
        return 'npm'

    # PyPI variations
    if ecosystem in ['pypi', 'python', 'pip', 'py']:
        return 'pypi'

    # RubyGems variations
    if ecosystem in ['rubygems', 'ruby', 'gem', 'gems']:
        return 'rubygems'

    # Go variations
    if ecosystem in ['go', 'golang']:
        return 'go'

    # Maven variations
    if ecosystem in ['maven', 'java', 'mvn']:
        return 'maven'

    # Rust variations
    if ecosystem in ['crates', 'cargo', 'rust', 'crates.io']:
        return 'cargo'

    return None


def retry_with_backoff(func, max_attempts=3, initial_delay=1):
    """
    Retry a function with exponential backoff

    Args:
        func (callable): Function to retry (should return None on failure)
        max_attempts (int): Maximum retry attempts
        initial_delay (int): Initial delay in seconds

    Returns:
        Result of func, or None if all attempts fail
    """
    delay = initial_delay

    for attempt in range(max_attempts):
        result = func()
        if result is not None:
            return result

        if attempt < max_attempts - 1:
            print(f"Attempt {attempt + 1} failed, retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2  # Exponential backoff

    print(f"All {max_attempts} attempts failed")
    return None


def ensure_directory(directory):
    """
    Ensure directory exists, create if needed

    Args:
        directory (str): Directory path

    Returns:
        bool: True if directory exists or was created
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False
