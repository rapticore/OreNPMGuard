#!/usr/bin/env python3
"""
Socket.dev Collector
Fetches package risk data from Socket.dev API
"""

import os
import sys
import yaml

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import utils


def load_config():
    """Load configuration from config.yaml"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None


def fetch_socketdev_packages():
    """
    Fetch high-risk packages from Socket.dev API

    Returns:
        dict: Standardized data structure with packages
    """
    config = load_config()
    if not config:
        return None

    socketdev_config = config.get('socketdev', {})
    api_url = socketdev_config.get('api_url')
    api_key = socketdev_config.get('api_key', '').strip()
    timeout = socketdev_config.get('timeout', 30)
    min_risk_score = socketdev_config.get('min_risk_score', 80)

    print("Fetching from Socket.dev...")

    # Check if API key is provided
    if not api_key:
        print("Warning: Socket.dev API key not configured in config.yaml")
        print("Skipping Socket.dev collection (API key required)")
        return {
            "source": "socketdev",
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "note": "API key not configured - skipped"
        }

    # Prepare headers with API key
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json'
    }

    packages = []

    # Socket.dev API structure - this is a simplified example
    # The actual API may have different endpoints
    # Note: Socket.dev may not have a public API for listing all malicious packages
    # This is a placeholder implementation

    print("Note: Socket.dev collector is a placeholder")
    print("Socket.dev does not provide a public API for bulk package queries")
    print("Consider using their npm package scanner or web interface")

    # For now, return empty result with note
    result = {
        "source": "socketdev",
        "collected_at": utils.get_timestamp(),
        "total_packages": len(packages),
        "ecosystems": [],
        "packages": packages,
        "note": "Socket.dev requires package-specific queries. Use their web interface or npm scanner for individual package analysis."
    }

    return result


def main():
    """Main entry point"""
    print("=" * 60)
    print("Socket.dev Collector")
    print("=" * 60)

    data = fetch_socketdev_packages()

    if data:
        # Save to raw-data
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'socketdev.json')
        if utils.save_json(data, output_path):
            print(f"\nCollected {data['total_packages']} packages")
            if data.get('note'):
                print(f"Note: {data['note']}")
            print(f"Saved to: {output_path}")
        else:
            print("Error: Failed to save data")
            sys.exit(1)
    else:
        print("Error: Failed to fetch Socket.dev data")
        # Create empty file
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'socketdev.json')
        utils.save_json({
            "source": "socketdev",
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": "Failed to fetch data from Socket.dev"
        }, output_path)
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
