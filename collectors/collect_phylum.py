#!/usr/bin/env python3
"""
Phylum.io Blog Collector
Scrapes malicious package reports from Phylum's research blog
"""

import os
import sys
import yaml
import re

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


def extract_packages_from_text(text):
    """
    Extract package names from blog post text using regex patterns

    Args:
        text (str): Blog post content

    Returns:
        list: List of package dictionaries
    """
    packages = []

    # Common patterns for package mentions in blog posts
    # npm: package-name, @scope/package-name
    npm_pattern = r'`(@?[a-z0-9-_]+(?:/[a-z0-9-_]+)?)`'

    # PyPI: package_name, package-name
    pypi_pattern = r'PyPI.*?`([a-z0-9-_]+)`'

    # Find npm packages
    npm_matches = re.findall(npm_pattern, text, re.IGNORECASE)
    for pkg in npm_matches:
        if pkg and len(pkg) > 2:  # Filter out single letters
            packages.append({
                "name": pkg,
                "ecosystem": "npm",
                "versions": [],
                "severity": "high",
                "detected_behaviors": ["reported_by_phylum"],
                "description": "Malicious package reported in Phylum blog"
            })

    # Find PyPI packages
    pypi_matches = re.findall(pypi_pattern, text, re.IGNORECASE)
    for pkg in pypi_matches:
        if pkg and len(pkg) > 2:
            packages.append({
                "name": pkg,
                "ecosystem": "pypi",
                "versions": [],
                "severity": "high",
                "detected_behaviors": ["reported_by_phylum"],
                "description": "Malicious package reported in Phylum blog"
            })

    return packages


def fetch_phylum_packages():
    """
    Scrape malicious packages from Phylum blog posts

    Returns:
        dict: Standardized data structure with packages
    """
    config = load_config()
    if not config:
        return None

    phylum_config = config.get('phylum', {})
    blog_url = phylum_config.get('blog_url')
    blog_feed = phylum_config.get('blog_feed')
    timeout = phylum_config.get('timeout', 30)

    print("Fetching from Phylum.io blog...")

    packages = []

    # Try to fetch blog feed (RSS)
    feed_content = utils.fetch_text(blog_feed, timeout=timeout)

    if feed_content:
        print(f"  Fetched blog feed ({len(feed_content)} bytes)")

        # Simple extraction of package names from feed
        # In production, you'd want to parse XML properly and visit each post
        extracted = extract_packages_from_text(feed_content)
        packages.extend(extracted)

        print(f"  Found {len(extracted)} package mentions in feed")
    else:
        print("  Warning: Could not fetch blog feed")

    # Deduplicate packages by name
    seen = {}
    for pkg in packages:
        key = f"{pkg['ecosystem']}:{pkg['name']}"
        if key not in seen:
            seen[key] = pkg

    packages = list(seen.values())

    # Build standardized structure
    result = {
        "source": "phylum",
        "collected_at": utils.get_timestamp(),
        "total_packages": len(packages),
        "ecosystems": list(set(p.get('ecosystem') for p in packages if p.get('ecosystem'))),
        "packages": packages,
        "note": "Extracted from Phylum blog feed using simple regex parsing. May include false positives."
    }

    return result


def main():
    """Main entry point"""
    print("=" * 60)
    print("Phylum.io Blog Collector")
    print("=" * 60)

    data = fetch_phylum_packages()

    if data:
        # Save to raw-data
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'phylum.json')
        if utils.save_json(data, output_path):
            print(f"\nCollected {data['total_packages']} packages")
            print(f"Ecosystems: {', '.join(data['ecosystems']) if data['ecosystems'] else 'none'}")
            if data.get('note'):
                print(f"Note: {data['note']}")
            print(f"Saved to: {output_path}")
        else:
            print("Error: Failed to save data")
            sys.exit(1)
    else:
        print("Error: Failed to fetch Phylum data")
        # Create empty file
        output_path = os.path.join(os.path.dirname(__file__), 'raw-data', 'phylum.json')
        utils.save_json({
            "source": "phylum",
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": "Failed to fetch data from Phylum blog"
        }, output_path)
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
