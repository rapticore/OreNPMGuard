#!/bin/bash
# Run all collectors and build unified indexes
# Usage: ./run_all.sh

set -e  # Exit on error

echo "================================================================"
echo "OreNPMGuard Dynamic Package Collector"
echo "================================================================"
echo ""

# Change to script directory
cd "$(dirname "$0")"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required but not found"
    exit 1
fi

# Check if PyYAML is installed
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "Warning: PyYAML not found. Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
fi

# Make collectors executable
chmod +x collect_openssf.py
chmod +x collect_socketdev.py
chmod +x collect_osv.py
chmod +x collect_phylum.py
chmod +x build_unified_index.py

echo "Starting package collection..."
echo "================================================================"
echo ""

# Track success/failure
FAILED_COLLECTORS=()

# Run individual collectors (continue even if some fail)
echo "[1/4] Collecting from OpenSSF Package Analysis..."
echo "----------------------------------------------------------------"
if python3 collect_openssf.py; then
    echo "✓ OpenSSF collection completed"
else
    echo "✗ OpenSSF collection failed (continuing...)"
    FAILED_COLLECTORS+=("openssf")
fi
echo ""

echo "[2/4] Collecting from Socket.dev..."
echo "----------------------------------------------------------------"
if python3 collect_socketdev.py; then
    echo "✓ Socket.dev collection completed"
else
    echo "✗ Socket.dev collection failed (continuing...)"
    FAILED_COLLECTORS+=("socketdev")
fi
echo ""

echo "[3/4] Collecting from OSV.dev..."
echo "----------------------------------------------------------------"
if python3 collect_osv.py; then
    echo "✓ OSV.dev collection completed"
else
    echo "✗ OSV.dev collection failed (continuing...)"
    FAILED_COLLECTORS+=("osv")
fi
echo ""

echo "[4/4] Collecting from Phylum.io..."
echo "----------------------------------------------------------------"
if python3 collect_phylum.py; then
    echo "✓ Phylum.io collection completed"
else
    echo "✗ Phylum.io collection failed (continuing...)"
    FAILED_COLLECTORS+=("phylum")
fi
echo ""

echo "================================================================"
echo "Building unified indexes..."
echo "================================================================"
echo ""

if python3 build_unified_index.py; then
    echo "✓ Unified indexes built successfully"
else
    echo "✗ Failed to build unified indexes"
    exit 1
fi

echo ""
echo "================================================================"
echo "Collection Summary"
echo "================================================================"

if [ ${#FAILED_COLLECTORS[@]} -eq 0 ]; then
    echo "✓ All collectors ran successfully!"
else
    echo "⚠ Some collectors failed:"
    for collector in "${FAILED_COLLECTORS[@]}"; do
        echo "  - $collector"
    done
fi

echo ""
echo "Raw data location:    collectors/raw-data/"
echo "Unified data location: collectors/final-data/"
echo ""
echo "You can now use the scanner with the unified data:"
echo "  node shai_hulud_scanner.js /path/to/project"
echo ""
echo "================================================================"
echo "Collection complete!"
echo "================================================================"
