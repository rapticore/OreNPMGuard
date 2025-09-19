# Shai-Hulud Package Sync Tool

A comprehensive tool to synchronize the `affected_packages.yaml` file with the banned package files (`banned-packages.yaml`, `banned-packages.json`, and `bannedpackages.csv`) while preserving existing structure and metadata.

## 🎯 Purpose

This tool ensures that all compromised packages from the Shai-Hulud supply chain attack are consistently tracked across all banned package formats, making it easy to:

- Keep banned package lists up-to-date
- Maintain consistent data across YAML, JSON, and CSV formats
- Preserve existing file structures and metadata
- Add new packages with appropriate severity classifications

## 📁 Files

- **`shai_hulud_sync.py`** - Main Python script with full functionality
- **`sync-shai-hulud-packages.sh`** - Bash wrapper script (includes Python code inline)
- **`README.md`** - This documentation

## 🚀 Quick Start

### Option 1: Using the Bash Wrapper (Recommended)

```bash
# Make the script executable
chmod +x sync-shai-hulud-packages.sh

# Run the sync
./sync-shai-hulud-packages.sh
```

### Option 2: Using Python Directly

```bash
# Install dependencies
pip3 install pyyaml

# Run the script
python3 shai_hulud_sync.py
```

## 📋 Prerequisites

- Python 3.6 or higher
- PyYAML library (`pip3 install pyyaml`)
- Required input file: `affected_packages.yaml`

## 📂 Expected File Structure

```
project/
├── affected_packages.yaml        # Source of truth (required)
├── banned-packages.yaml          # Will be updated/created
├── banned-packages.json          # Will be updated/created
├── bannedpackages.csv            # Will be updated/created
└── sync-shai-hulud-packages.sh   # Sync script
```

## ⚙️ How It Works

1. **Loads Data**: Reads the affected packages and existing banned package files
2. **Analyzes Packages**: Determines severity levels based on package name patterns:
   - **Critical**: `@ctrl/deluge`, `@ctrl/tinycolor`, `ngx-bootstrap`, `rxnt-authentication`, `angulartics2`
   - **High**: Packages starting with `@ctrl/`, `@nativescript-community/`, `@crowdstrike/`, `ngx-`, `ember-`, `react-`
   - **Medium**: All other packages
3. **Estimates Impact**: Assigns weekly download estimates based on package popularity
4. **Preserves Structure**: Maintains existing metadata, remediation info, and file formatting
5. **Updates Files**: Adds missing packages and updates metadata counts
6. **Creates Backups**: Automatically backs up existing files before modification

## 🔧 Features

### Smart Package Classification
- Automatic severity assignment based on package patterns
- Download count estimation for impact assessment
- Patient zero identification (`rxnt-authentication`)

### Data Preservation
- Maintains existing file structures
- Preserves all metadata and remediation information
- Updates timestamps and package counts automatically

### Safety Features
- Creates timestamped backups before modification
- Validates file formats and handles missing files gracefully
- Detailed logging and error handling

### Multi-Format Support
- **YAML**: Human-readable with metadata and remediation steps
- **JSON**: Structured data for APIs and tools
- **CSV**: Compatible with spreadsheets and database imports

## 📊 Output Example

```
🚀 Shai-Hulud Package Sync Script Started
==================================================
📖 Loading affected packages from affected_packages.yaml
✅ Loaded 180 affected packages
📖 Loading banned YAML from banned-packages.yaml
✅ Loaded existing banned YAML with 15 packages

🔄 Starting package synchronization...
✅ Synchronization complete!
   📦 Total packages: 180
   🆕 New packages added: 165
   🔴 Critical: 5
   🟠 High: 65
   🟡 Medium: 110

💾 Saving updated files...
💾 Saving banned YAML to banned-packages.yaml
✅ YAML saved successfully
💾 Saving banned JSON to banned-packages.json
✅ JSON saved successfully
💾 Saving banned CSV to bannedpackages.csv
✅ CSV saved successfully

🎉 Package synchronization completed successfully!
```

## 🛡️ Security Features

The tool automatically includes remediation guidance and detection indicators:

- Immediate removal commands
- Credential rotation checklists
- CI/CD integration examples
- GitHub Actions workflows for blocking
- Investigation steps for compromise detection

## 🔍 File Format Details

### YAML Structure
```yaml
meta:
  name: "Shai-Hulud Attack - Banned npm Packages"
  total_packages: 180
  severity_distribution:
    critical: 5
    high: 65
    medium: 110

critical_packages: [...]
high_packages: [...]
banned_packages: [...]
remediation: [...]
```

### JSON Structure
```json
{
  "meta": { ... },
  "banned_packages": [
    {
      "name": "@ctrl/deluge",
      "banned_versions": ["7.2.2", "7.2.1"],
      "severity": "critical",
      "weekly_downloads": 2200000,
      "patient_zero": false,
      "attack_vector": "postinstall script"
    }
  ]
}
```

### CSV Columns
- `package_name`
- `banned_versions`
- `severity`
- `weekly_downloads`
- `first_detected`
- `patient_zero`
- `description`
- `attack_vector`
- `priority`

## 🚨 Troubleshooting

### Common Issues

**"File not found: affected_packages.yaml"**
- Ensure the affected packages file exists in the current directory
- Check the filename spelling and case sensitivity

**"Permission denied"**
- Make the script executable: `chmod +x sync-shai-hulud-packages.sh`
- Ensure write permissions for the target directory

**"Module 'yaml' not found"**
- Install PyYAML: `pip3 install pyyaml`
- Or use the bash wrapper which handles this automatically

### Recovery

If something goes wrong, the tool automatically creates timestamped backups:
```bash
# Restore from backup
cp banned-packages.yaml.backup.20250918_143022 banned-packages.yaml
```

## 🤝 Contributing

When adding new severity patterns or download estimates:

1. Edit the `severity_patterns` and `download_estimates` dictionaries in the script
2. Test with a sample of packages
3. Update the README with new patterns

## 📞 Support

For issues related to the Shai-Hulud attack or the OreNPMGuard scanner:
- GitHub: https://github.com/rapticore/orenpmpguard
- Email: contact@rapticore.com

---

**⚠️ Security Note**: Always review the synchronized files before deploying to production environments. This tool helps maintain consistency but human review of security-critical data is recommended.