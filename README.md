# OreNPMGuard - Shai-Hulud Package Scanner
## Version 1.2.0 - Enhanced Detection & Prevention System

A security tool to detect compromised npm packages from the Shai-Hulud supply chain attack. Scans both package.json and package-lock.json files to detect exact installed versions. Available in both Python and Node.js implementations with centralized YAML configuration for easy maintenance.

**Latest Update:** September 18, 2025 - **200 compromised packages** now tracked with comprehensive prevention suite.

## 🚨 About the Shai-Hulud Attack

**Shai-Hulud** is a self-replicating worm that began compromising npm packages on September 14-15, 2025, representing the first successful self-propagating attack in the npm ecosystem and one of the most severe JavaScript supply-chain attacks observed to date. Named after the giant sandworms from Frank Herbert's Dune series, this malware has infected **200 npm packages** (as tracked in this tool) with multiple versions affected per package.

### 🦠 How the Attack Works

**Patient Zero**: The attack started with the `rxnt-authentication` package published on September 14, 2025, at 17:58:50 UTC by the compromised "techsupportrxnt" npm account.

**Attack Chain**:
1. **Installation**: Malicious package runs `postinstall` script executing `bundle.js` (3MB+ JavaScript payload)
2. **Credential Harvesting**: Uses TruffleHog to scan for GitHub/npm tokens, AWS/GCP/Azure credentials, environment variables, and IMDS-exposed cloud keys
3. **Data Exfiltration**: Creates public "Shai-Hulud" repository under victim's GitHub account with stolen secrets in `data.json` (double base64-encoded)
4. **Persistence**: Injects malicious GitHub Actions workflow (`.github/workflows/shai-hulud-workflow.yml`) that exfiltrates repository secrets to `webhook[.]site`
5. **Repository Migration**: Forces private organizational repositories to become public personal repositories with "-migration" suffix and "Shai-Hulud Migration" description
6. **Worm Propagation**: Uses stolen npm tokens to inject malware into other packages maintained by the victim, incrementing version numbers and adding `postinstall` hooks

### 🎯 What Gets Stolen
- **Development Credentials**: GitHub PATs (`ghp_*`, `gho_*`), npm authentication tokens
- **Cloud Credentials**: AWS, GCP, Azure access keys and tokens
- **API Keys**: Atlassian, Datadog, and other service credentials
- **System Information**: Environment variables, host details, user accounts
- **Source Code**: Private repositories made public or cloned

### 📊 Impact Scale
- **200 packages** compromised in this tracking database (including popular packages like `@ctrl/tinycolor`, `ngx-bootstrap`)
- Multiple GitHub accounts compromised (exact count varies by reporting source)
- Public repositories created with "Shai-Hulud Migration" label
- Developers potentially affected through package dependencies

### 🔗 Connection to Previous Attacks
This attack is directly linked to the August 2025 **s1ngularity/Nx compromise**, where initial GitHub token theft enabled the broader supply chain attack. Many initial Shai-Hulud victims were known victims of the s1ngularity attack. Security researchers also note the integration of AI-generated content within the campaign, with moderate confidence that an LLM was used to generate the malicious bash script.

### 📅 Attack Timeline
- **August 26, 2025**: s1ngularity/Nx compromise occurs (precursor attack)
- **September 14, 2025 17:58 UTC**: First malicious package `rxnt-authentication` published ("Patient Zero")
- **September 15, 2025**: Attack detected and reported by security researchers
- **September 15-16, 2025**: Worm spreads rapidly across npm ecosystem
- **September 16, 2025**: Over 180 packages confirmed compromised
- **September 17, 2025**: Ongoing monitoring and cleanup efforts
- **September 18, 2025**: v1.2.0 release with 200 packages tracked and enhanced prevention tools

## Quick Start

### Prerequisites
- **Python scanner**: Requires `PyYAML` (`pip install pyyaml`)
- **Node.js scanner**: Requires `js-yaml` (`npm install js-yaml`)

### Python Version
```bash
# Make executable
chmod +x shai_hulud_scanner.py

# Scan single package.json
python3 shai_hulud_scanner.py ./package.json

# Scan package-lock.json for exact versions
python3 shai_hulud_scanner.py ./package-lock.json

# Scan entire project directory
python3 shai_hulud_scanner.py ./my-project

# Scan current directory
python3 shai_hulud_scanner.py .
```

### Node.js Version
```bash
# Install dependencies first
npm install

# Make executable
chmod +x shai_hulud_scanner.js

# Scan single package.json
node shai_hulud_scanner.js ./package.json

# Scan package-lock.json for exact versions
node shai_hulud_scanner.js ./package-lock.json

# Scan entire project directory
node shai_hulud_scanner.js ./my-project

# Scan current directory
node shai_hulud_scanner.js .
```

## What the Scanner Does

✅ **Exact Match Detection**: Identifies packages with exact version matches to known compromised versions

⚠️ **Potential Risk Detection**: Flags packages with the same name but different versions (may still be at risk)

🔍 **Dual File Support**: Scans both package.json (declared dependencies) and package-lock.json (exact installed versions)

📦 **Comprehensive Coverage**: package-lock.json scanning includes nested dependencies and transitive packages

🔄 **Recursive Scanning**: Automatically scans all subdirectories while skipping `node_modules`

📋 **Detailed Reporting**: Shows package names, versions, dependency sections, and affected versions

🔎 **IOC Detection**: Identifies Indicators of Compromise including:
   - `"postinstall": "node bundle.js"` hooks in package.json
   - Presence of `bundle.js` files (3MB+ malicious payload)
   - References to `webhook.site` exfiltration endpoints

## Output Examples

### 🚨 Critical (Compromised Packages Found)
```
🚨 CRITICAL: Found 2 CONFIRMED compromised packages:
   • @ctrl/deluge v7.2.2 in dependencies
     Affected versions: 7.2.2, 7.2.1
   • ngx-bootstrap v19.0.3 in devDependencies
     Affected versions: 18.1.4, 19.0.3, 20.0.4, 20.0.5, 20.0.6, 19.0.4, 20.0.3
```

### ⚠️ Warning (Version Mismatch)
```
⚠️ WARNING: Found 1 packages with different versions:
   • @ctrl/deluge v7.2.0 in dependencies
     Known affected versions: 7.2.2, 7.2.1
```

### ✅ Clean
```
✅ No affected packages found
```

## If Compromised Packages Are Found

### IMMEDIATE ACTIONS:
1. **Stop all development work** on affected projects
2. **Remove compromised packages**: `npm uninstall <package-name>`
3. **Clear npm cache**: `npm cache clean --force`
4. **Delete node_modules**: `rm -rf node_modules`

### CREDENTIAL ROTATION:
1. **GitHub Personal Access Tokens**
2. **npm Authentication Tokens**
3. **SSH Keys**
4. **API Keys** (AWS, Atlassian, Datadog, etc.)

### INVESTIGATION:
1. Check GitHub for public repos named **"Shai-Hulud"**
2. Look for repos with **"-migration"** suffix
3. Review GitHub audit logs
4. Check for branches named **shai-hulud**
5. **Scan for IOCs (Indicators of Compromise)**:
   - Search for `"postinstall": "node bundle.js"` in package.json files
   - Look for `bundle.js` files (3MB+ in size, contains malicious payload)
   - Check for `webhook.site` references in code or network logs
   - Examine `.github/workflows/shai-hulud-workflow.yml` files

## Configuration

Package data is centralized in `affected_packages.yaml`. To add new compromised packages:

1. Edit `affected_packages.yaml`
2. Add entries in the format:
   ```yaml
   - name: "package-name"
     versions: ["1.0.0", "1.0.1"]
   ```
3. Both Python and JavaScript scanners will automatically use the updated data

This centralized approach eliminates the need to update multiple files when new threats are discovered.

## Deployment Options

### For Security Teams
```bash
# Create central scanning script
curl -O https://your-domain.com/shai_hulud_scanner.py
chmod +x shai_hulud_scanner.py

# Mass scan multiple projects
for dir in /projects/*/; do
    echo "Scanning $dir"
    python3 shai_hulud_scanner.py "$dir"
done
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Scan for Shai-Hulud packages
  run: |
    curl -O https://your-domain.com/shai_hulud_scanner.js
    npm install js-yaml
    node shai_hulud_scanner.js .
    if [ $? -ne 0 ]; then
      echo "SECURITY ALERT: Compromised packages detected!"
      exit 1
    fi
```

### Enterprise Deployment
```bash
# Add to security toolkit
cp shai_hulud_scanner.py /usr/local/bin/
cp shai_hulud_scanner.js /usr/local/bin/
cp affected_packages.yaml /usr/local/bin/

# Create alias for easy access
echo 'alias scan-shai="python3 /usr/local/bin/shai_hulud_scanner.py"' >> ~/.bashrc
```

## Technical Notes

- **Target Platforms**: Linux and macOS only (deliberately skips Windows systems)
- **Payload Size**: 3MB+ minified JavaScript bundle
- **Self-Propagation**: First successful self-replicating worm in npm ecosystem
- **Dependencies**: Python requires PyYAML, Node.js requires js-yaml
- **Safe**: Read-only operations, no modifications to your files
- **Fast**: Optimized for quick scanning of large codebases
- **Accurate**: Based on official IoC list from security researchers
- **AI-Generated Components**: Security researchers assess with moderate confidence that an LLM was used to generate parts of the malicious bash script
- **Persistence Mechanisms**: GitHub Actions workflows, malicious branches, and repository migrations
- **Cloud Integration**: Specifically targets AWS and GCP environments using SDK libraries and IMDS endpoints

### **Indicators of Compromise (IOCs)**
- **Malicious postinstall hook**: `"postinstall": "node bundle.js"` in package.json
- **Payload file**: `bundle.js` (typically 3MB+ minified JavaScript)
- **Exfiltration endpoint**: References to `webhook.site` domains
- **GitHub workflow**: `.github/workflows/shai-hulud-workflow.yml` for persistence
- **Repository naming**: Repos with "Shai-Hulud" or "-migration" suffixes
- **Branch indicators**: Branches named `shai-hulud` containing malicious commits

## 📚 Documentation

- **[Release Notes v1.2.0](docs/RELEASE_NOTES_v1.2.0.md)** - Complete changelog and new features
- **[Security Assessment](docs/SECURITY_ASSESSMENT.md)** - Comprehensive security analysis
- **[Prevention Guide](prevention/README.md)** - 490+ lines of integration instructions
- **[GitHub Actions Workflow](prevention/github-actions/shai-hulud-blocking.yml)** - Automated CI/CD protection

## 🛡️ New in v1.2.0

### **Enhanced Prevention Suite**
- **Multi-format configs**: JSON, YAML, CSV for different use cases
- **GitHub Actions integration**: Automated CI/CD blocking workflow
- **Standalone blocker script**: `prevention/block-shai-hulud.sh`
- **Package sync tools**: Automated threat intelligence updates

### **Expanded Detection**
- **200 compromised packages** tracked in database
- **IoC scanning** for webhook.site references
- **Severity categorization** (Critical/High/Medium)
- **Enhanced threat intelligence** with download counts and attack vectors

## Support

For issues or questions:
- **Security Team**: contact@rapticore.com
- **Development**: contact@rapticore.com