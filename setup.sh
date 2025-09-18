#!/bin/bash

# OreNPMGuard Setup Script
# Installs dependencies for both Python and Node.js scanners

set -e

echo "🔧 Setting up OreNPMGuard - Shai-Hulud Package Scanner"
echo "=================================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed. Please install Python 3 first."
    exit 1
fi

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed. Please install Node.js first."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo "✅ Node.js found: $(node --version)"

# Install Node.js dependencies
echo ""
echo "📦 Installing Node.js dependencies..."
npm install

# Install Python dependencies
echo ""
echo "🐍 Installing Python dependencies..."
pip3 install -r requirements.txt

# Make scripts executable
echo ""
echo "🔑 Making scripts executable..."
chmod +x shai_hulud_scanner.py
chmod +x shai_hulud_scanner.js

# Validate installations
echo ""
echo "🧪 Validating installations..."
npm run validate
npm run validate:python

echo ""
echo "✅ Setup complete! You can now use:"
echo "   • npm run scan                    - Scan current directory with Node.js"
echo "   • npm run scan:python            - Scan current directory with Python"
echo "   • node shai_hulud_scanner.js <path>  - Direct Node.js usage"
echo "   • python3 shai_hulud_scanner.py <path>  - Direct Python usage"
echo ""
echo "📚 For more information, see README.md"