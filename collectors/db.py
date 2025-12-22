#!/usr/bin/env python3
"""
SQLite Database Module for Malicious Package Storage
Handles all database operations: create, insert, query
"""

import sqlite3
import json
import os
import re
from typing import Dict, List, Optional, Any, Tuple


# Schema SQL
SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    name_normalized TEXT NOT NULL,
    severity TEXT DEFAULT 'unknown',
    first_seen TEXT,
    modified TEXT,
    last_updated TEXT,
    description TEXT,
    full_details TEXT,
    detected_behaviors TEXT,
    source_details TEXT,
    aliases TEXT,
    cwes TEXT
);

CREATE TABLE IF NOT EXISTS package_versions (
    package_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    PRIMARY KEY (package_id, version)
);

CREATE TABLE IF NOT EXISTS package_sources (
    package_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (package_id, source)
);

CREATE TABLE IF NOT EXISTS package_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL,
    ref_type TEXT NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS package_origins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL,
    source_name TEXT NOT NULL,
    source_id TEXT,
    modified_time TEXT,
    ranges TEXT,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
);
'''

INDEX_SQL = '''
CREATE UNIQUE INDEX IF NOT EXISTS idx_packages_name_normalized
ON packages(name_normalized);

CREATE INDEX IF NOT EXISTS idx_references_package_id
ON package_references(package_id);

CREATE INDEX IF NOT EXISTS idx_origins_package_id
ON package_origins(package_id);

CREATE INDEX IF NOT EXISTS idx_origins_source_id
ON package_origins(source_id);
'''


def create_database(db_path: str) -> Tuple[sqlite3.Connection, str]:
    """
    Create a new SQLite database with schema.
    Uses temp file + atomic rename for safety.

    Args:
        db_path: Path for the database file

    Returns:
        Tuple of (connection, temp_path)
    """
    temp_path = f"{db_path}.tmp"

    # Clean up any existing temp file
    if os.path.exists(temp_path):
        os.remove(temp_path)

    conn = sqlite3.connect(temp_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    return conn, temp_path


def finalize_database(conn: sqlite3.Connection, temp_path: str, final_path: str):
    """
    Create indexes and atomically move database to final location.

    Args:
        conn: Database connection
        temp_path: Temporary file path
        final_path: Final destination path
    """
    conn.executescript(INDEX_SQL)
    conn.commit()
    conn.close()

    # Atomic rename
    os.replace(temp_path, final_path)


def insert_metadata(conn: sqlite3.Connection, ecosystem: str,
                   packages: List[Dict], timestamp: str):
    """
    Insert database metadata.

    Args:
        conn: Database connection
        ecosystem: Ecosystem name
        packages: List of packages (for counting)
        timestamp: Current timestamp
    """
    total_versions = sum(len(p.get('versions', [])) for p in packages)
    all_sources = set()
    for pkg in packages:
        all_sources.update(pkg.get('sources', []))

    metadata = [
        ('ecosystem', ecosystem),
        ('last_updated', timestamp),
        ('total_packages', str(len(packages))),
        ('total_versions', str(total_versions)),
        ('sources', json.dumps(sorted(list(all_sources))))
    ]

    conn.executemany('INSERT INTO metadata (key, value) VALUES (?, ?)', metadata)
    conn.commit()


def insert_package_references(conn: sqlite3.Connection, package_id: int, references: List[Dict]):
    """
    Insert package references (advisory URLs, etc.).

    Args:
        conn: Database connection
        package_id: ID of the package
        references: List of reference dicts with 'type' and 'url'
    """
    if not references:
        return

    cursor = conn.cursor()
    for ref in references:
        ref_type = ref.get('type', 'WEB')
        url = ref.get('url', '')
        if url:
            cursor.execute(
                'INSERT INTO package_references (package_id, ref_type, url) VALUES (?, ?, ?)',
                (package_id, ref_type, url)
            )


def insert_package_origins(conn: sqlite3.Connection, package_id: int, origins: List[Dict]):
    """
    Insert source origin details.

    Args:
        conn: Database connection
        package_id: ID of the package
        origins: List of origin dicts with source, id, modified_time, ranges
    """
    if not origins:
        return

    cursor = conn.cursor()
    for origin in origins:
        source_name = origin.get('source', '')
        source_id = origin.get('id', '')
        modified_time = origin.get('modified_time', '')
        ranges = origin.get('ranges')
        ranges_json = json.dumps(ranges) if ranges else None

        if source_name:
            cursor.execute(
                '''INSERT INTO package_origins
                   (package_id, source_name, source_id, modified_time, ranges)
                   VALUES (?, ?, ?, ?, ?)''',
                (package_id, source_name, source_id, modified_time, ranges_json)
            )


def insert_packages(conn: sqlite3.Connection, packages: List[Dict]):
    """
    Bulk insert packages with their versions, sources, references, and origins.

    Args:
        conn: Database connection
        packages: List of package dictionaries
    """
    cursor = conn.cursor()

    for pkg in packages:
        name = pkg.get('name', '')
        if not name:
            continue

        # Insert package with new fields
        cursor.execute('''
            INSERT INTO packages
            (name, name_normalized, severity, first_seen, modified, last_updated,
             description, full_details, detected_behaviors, source_details, aliases, cwes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            name,
            name.lower().strip(),
            pkg.get('severity', 'unknown'),
            pkg.get('first_seen', ''),
            pkg.get('modified', ''),
            pkg.get('last_updated', ''),
            pkg.get('description', ''),
            pkg.get('full_details', ''),
            json.dumps(pkg.get('detected_behaviors', [])),
            json.dumps(pkg.get('source_details', {})),
            json.dumps(pkg.get('aliases', [])),
            json.dumps(pkg.get('cwes', []))
        ))

        package_id = cursor.lastrowid

        # Insert versions
        versions = pkg.get('versions', [])
        if versions:
            cursor.executemany(
                'INSERT OR IGNORE INTO package_versions (package_id, version) VALUES (?, ?)',
                [(package_id, v) for v in versions]
            )

        # Insert sources
        sources = pkg.get('sources', [])
        if sources:
            cursor.executemany(
                'INSERT OR IGNORE INTO package_sources (package_id, source) VALUES (?, ?)',
                [(package_id, s) for s in sources]
            )

        # Insert references
        references = pkg.get('references', [])
        insert_package_references(conn, package_id, references)

        # Insert origins
        origins = pkg.get('origins', [])
        insert_package_origins(conn, package_id, origins)

    conn.commit()


def open_database(db_path: str) -> Optional[sqlite3.Connection]:
    """
    Open database for reading (read-only mode).

    Args:
        db_path: Path to database file

    Returns:
        Connection or None if file doesn't exist
    """
    if not os.path.exists(db_path):
        return None

    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error opening database {db_path}: {e}")
        return None


def get_package(conn: sqlite3.Connection, name: str) -> Optional[Dict]:
    """
    Get package by name (case-insensitive).

    Args:
        conn: Database connection
        name: Package name to lookup

    Returns:
        Package dict with versions and sources, or None
    """
    normalized_name = name.lower().strip()
    cursor = conn.cursor()

    # Lookup package with new fields
    cursor.execute('''
        SELECT id, name, severity, first_seen, modified, last_updated,
               description, full_details, detected_behaviors, source_details,
               aliases, cwes
        FROM packages WHERE name_normalized = ?
    ''', (normalized_name,))

    row = cursor.fetchone()
    if not row:
        return None

    package_id = row['id']

    # Get versions
    cursor.execute(
        'SELECT version FROM package_versions WHERE package_id = ?',
        (package_id,)
    )
    versions = [r[0] for r in cursor.fetchall()]

    # Get sources
    cursor.execute(
        'SELECT source FROM package_sources WHERE package_id = ?',
        (package_id,)
    )
    sources = [r[0] for r in cursor.fetchall()]

    return {
        'name': row['name'],
        'severity': row['severity'],
        'first_seen': row['first_seen'],
        'modified': row['modified'],
        'last_updated': row['last_updated'],
        'description': row['description'],
        'full_details': row['full_details'],
        'detected_behaviors': json.loads(row['detected_behaviors'] or '[]'),
        'source_details': json.loads(row['source_details'] or '{}'),
        'aliases': json.loads(row['aliases'] or '[]'),
        'cwes': json.loads(row['cwes'] or '[]'),
        'versions': versions,
        'sources': sources
    }


def get_package_full(conn: sqlite3.Connection, name: str) -> Optional[Dict]:
    """
    Get package with all related data including references and origins.

    Args:
        conn: Database connection
        name: Package name to lookup

    Returns:
        Package dict with all fields, versions, sources, references, origins
    """
    pkg = get_package(conn, name)
    if not pkg:
        return None

    normalized_name = name.lower().strip()
    cursor = conn.cursor()

    # Get package ID
    cursor.execute(
        'SELECT id FROM packages WHERE name_normalized = ?',
        (normalized_name,)
    )
    row = cursor.fetchone()
    package_id = row['id']

    # Get references
    cursor.execute(
        'SELECT ref_type, url FROM package_references WHERE package_id = ?',
        (package_id,)
    )
    references = [{'type': r['ref_type'], 'url': r['url']} for r in cursor.fetchall()]

    # Get origins
    cursor.execute(
        '''SELECT source_name, source_id, modified_time, ranges
           FROM package_origins WHERE package_id = ?''',
        (package_id,)
    )
    origins = []
    for r in cursor.fetchall():
        origin = {
            'source': r['source_name'],
            'id': r['source_id'],
            'modified_time': r['modified_time']
        }
        if r['ranges']:
            origin['ranges'] = json.loads(r['ranges'])
        origins.append(origin)

    pkg['references'] = references
    pkg['origins'] = origins

    return pkg


def check_package(conn: sqlite3.Connection, name: str, version: str = '') -> Optional[Dict]:
    """
    Check if a package (and optionally version) is malicious.

    Args:
        conn: Database connection
        name: Package name
        version: Optional version to check

    Returns:
        Match result dict or None if not malicious
    """
    # Use get_package_full() to include references and origins
    pkg = get_package_full(conn, name)
    if not pkg:
        return None

    versions = pkg.get('versions', [])

    # Check version match
    is_malicious = False
    matched_version = None

    if version:
        # Clean version (remove ^, ~, etc.)
        clean_version = re.sub(r'^[\^~>=<]', '', version).strip()
        is_malicious = clean_version in versions
        if is_malicious:
            matched_version = clean_version
    elif versions:
        # No version specified - any malicious version counts
        is_malicious = True
        matched_version = versions[0]

    if not is_malicious:
        return None

    return {
        'name': pkg['name'],
        'version': version or matched_version,
        'matched_version': matched_version,
        'severity': pkg['severity'],
        'sources': pkg['sources'],
        'description': pkg['description'],
        'full_details': pkg.get('full_details', ''),
        'detected_behaviors': pkg['detected_behaviors'],
        'first_seen': pkg['first_seen'],
        'modified': pkg.get('modified', ''),
        'last_updated': pkg['last_updated'],
        'source_details': pkg['source_details'],
        'aliases': pkg.get('aliases', []),
        'cwes': pkg.get('cwes', []),
        'references': pkg.get('references', []),
        'origins': pkg.get('origins', [])
    }


def get_metadata(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Get database metadata.

    Args:
        conn: Database connection

    Returns:
        Dict with ecosystem, last_updated, counts, etc.
    """
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM metadata')

    metadata = {}
    for row in cursor.fetchall():
        key, value = row[0], row[1]
        # Parse JSON for sources
        if key == 'sources':
            metadata[key] = json.loads(value)
        elif key in ('total_packages', 'total_versions'):
            metadata[key] = int(value)
        else:
            metadata[key] = value

    return metadata
