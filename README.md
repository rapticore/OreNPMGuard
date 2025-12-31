# OreNPMGuard - Shai-Hulud Package Scanner
## Version 2.0.0 - Shai-Hulud 2.0 Detection & Enhanced Prevention System

A security tool to detect compromised npm packages from the Shai-Hulud supply chain attacks (original September 2025 and Shai-Hulud 2.0 November 2025). Scans both package.json and package-lock.json files to detect exact installed versions and Indicators of Compromise (IoCs). Available in both Python and Node.js implementations with centralized YAML configuration for easy maintenance.

**Latest Update:** November 24, 2025 - **738+ compromised packages** tracked with **1,291 unique package@version combinations**. Now detects both original Shai-Hulud and Shai-Hulud 2.0 attack variants.

**For multi-ecosystem scanning**, see [ore-mal-pkg-inspector](https://github.com/rapticore/ore-mal-pkg-inspector).

## 🔗 Related Projects

For **multi-ecosystem malicious package scanning** (npm, PyPI, Maven, RubyGems, Go, Cargo), see:
**[ore-mal-pkg-inspector](https://github.com/rapticore/ore-mal-pkg-inspector)** - Comprehensive malicious package scanner with dynamic threat intelligence.

OreNPMGuard focuses specifically on **Shai-Hulud attack defense** for npm packages.

## 🚨 About the Shai-Hulud Attacks

**Shai-Hulud** is a self-replicating worm that began compromising npm packages on September 14-15, 2025, representing the first successful self-propagating attack in the npm ecosystem and one of the most severe JavaScript supply-chain attacks observed to date. Named after the giant sandworms from Frank Herbert's Dune series, this malware has evolved into multiple variants.

### Original Shai-Hulud (September 2025)
The original attack infected **200+ npm packages** (as tracked in this tool) with multiple versions affected per package.

### Shai-Hulud 2.0 (November 2025) - NEW
A new variant emerged in November 2025 with significant changes:
- **738+ compromised packages** with **1,291 unique package@version combinations**
- **25,000+ affected repositories** across **~350 unique users**
- **New execution phase**: Uses `preinstall` scripts (not just `postinstall`)
- **New payload files**: `setup_bun.js` and `bun_environment.js` (in addition to `bundle.js`)
- **Enhanced persistence**: Creates self-hosted runners named 'SHA1HULUD' and new GitHub workflow patterns
- **Multi-cloud targeting**: AWS, Azure, and GCP credential harvesting
- **Docker privilege escalation**: Attempts to gain root access via privileged containers
- Packages uploaded between **November 21-23, 2025**

**Reference**: [Wiz Research - Shai-Hulud 2.0 Blog Post](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

### 🦠 How the Attack Works

**Patient Zero**: The attack started with the `rxnt-authentication` package published on September 14, 2025, at 17:58:50 UTC by the compromised "techsupportrxnt" npm account.

**Attack Chain (Original Shai-Hulud)**:
1. **Installation**: Malicious package runs `postinstall` script executing `bundle.js` (3MB+ JavaScript payload)
2. **Credential Harvesting**: Uses TruffleHog to scan for GitHub/npm tokens, AWS/GCP/Azure credentials, environment variables, and IMDS-exposed cloud keys
3. **Data Exfiltration**: Creates public "Shai-Hulud" repository under victim's GitHub account with stolen secrets in `data.json` (double base64-encoded)
4. **Persistence**: Injects malicious GitHub Actions workflow (`.github/workflows/shai-hulud-workflow.yml`) that exfiltrates repository secrets to `webhook[.]site`
5. **Repository Migration**: Forces private organizational repositories to become public personal repositories with "-migration" suffix and "Shai-Hulud Migration" description
6. **Worm Propagation**: Uses stolen npm tokens to inject malware into other packages maintained by the victim, incrementing version numbers and adding `postinstall` hooks

**Attack Chain (Shai-Hulud 2.0 - November 2025)**:
1. **Installation**: Malicious package runs `preinstall` script executing `setup_bun.js` or `bun_environment.js` (new payload files)
2. **Data File Creation**: Creates `cloud.json`, `contents.json`, `environment.json`, and `truffleSecrets.json` files
3. **Credential Harvesting**: Multi-cloud targeting (AWS, Azure, GCP) using official SDKs, scraping credentials from config files, environment variables, and IMDS
4. **Self-Hosted Runner Registration**: Registers infected machine as self-hosted runner named 'SHA1HULUD'
5. **GitHub Workflow Injection**: 
   - Creates `.github/workflows/discussion.yaml` with self-hosted runner for backdoor access
   - Creates `.github/workflows/formatter_*.yml` for secret exfiltration (then deletes workflow to hide activity)
6. **Docker Privilege Escalation**: Attempts to gain root access via `docker run --rm --privileged -v /:/host`
7. **Cloud Secret Dumping**: Uses authenticated sessions to dump secrets from AWS Secrets Manager, Google Secret Manager, and Azure Key Vault
8. **Repository Creation**: Creates repositories with "Shai-Hulud" in description for exfiltration

### 🎯 What Gets Stolen
- **Development Credentials**: GitHub PATs (`ghp_*`, `gho_*`), npm authentication tokens
- **Cloud Credentials**: AWS, GCP, Azure access keys and tokens
- **API Keys**: Atlassian, Datadog, and other service credentials
- **System Information**: Environment variables, host details, user accounts
- **Source Code**: Private repositories made public or cloned

### 📊 Impact Scale

**Original Shai-Hulud (September 2025)**:
- **200+ packages** compromised in this tracking database (including popular packages like `@ctrl/tinycolor`, `ngx-bootstrap`)
- Multiple GitHub accounts compromised (exact count varies by reporting source)
- Public repositories created with "Shai-Hulud Migration" label
- Developers potentially affected through package dependencies

**Shai-Hulud 2.0 (November 2025)**:
- **738+ compromised packages** with **1,291 unique package@version combinations**
- **25,000+ affected repositories** created across **~350 unique users**
- **1,000+ new repositories** added every 30 minutes during initial campaign hours
- Affects packages from major ecosystems: Zapier, ENS Domains, PostHog, Postman, AsyncAPI, and more
- Multi-cloud credential theft (AWS, Azure, GCP)
- Docker privilege escalation attempts

**Verified Credential Theft (from ~20,000 analyzed repos):**
- 775 compromised GitHub access tokens
- 373 AWS credentials exposed
- 300 GCP credentials exposed
- 115 Azure credentials exposed

### ⚠️ Cross-Victim Exfiltration Warning

**CRITICAL**: Wiz Research has confirmed **cross-victim exfiltration** is occurring. This means:
- One victim's stolen secrets may be published to repositories owned by a **different, unrelated victim**
- If you find suspicious data in your GitHub repositories, it may belong to another compromised user
- Your data may have been exfiltrated to repositories you don't own
- This complicates attribution and incident response

**Investigation Implication**: When reviewing exfiltrated data in your repositories, verify whether the data actually belongs to your organization or another victim.

### 🔗 Connection to Previous Attacks
This attack is directly linked to the August 2025 **s1ngularity/Nx compromise**, where initial GitHub token theft enabled the broader supply chain attack. Many initial Shai-Hulud victims were known victims of the s1ngularity attack. Security researchers also note the integration of AI-generated content within the campaign, with moderate confidence that an LLM was used to generate the malicious bash script.

### 📅 Attack Timeline

**Original Shai-Hulud Campaign**:
- **August 26, 2025**: s1ngularity/Nx compromise occurs (precursor attack)
- **September 14, 2025 17:58 UTC**: First malicious package `rxnt-authentication` published ("Patient Zero")
- **September 15, 2025**: Attack detected and reported by security researchers
- **September 15-16, 2025**: Worm spreads rapidly across npm ecosystem
- **September 16, 2025**: Over 180 packages confirmed compromised
- **September 17, 2025**: Ongoing monitoring and cleanup efforts
- **September 18, 2025**: v1.2.0 release with 200 packages tracked and enhanced prevention tools

**Shai-Hulud 2.0 Campaign**:
- **November 21-23, 2025**: Malicious packages uploaded to npm registry
- **November 24, 2025**: Attack detected and reported by Wiz Research and Aikido
- **November 24, 2025**: v2.0.0 release with 738+ packages tracked and Shai-Hulud 2.0 detection capabilities
- **Ongoing**: GitHub continues removing attacker-created repositories; attacker continues creating new repositories

## Quick Start

### Prerequisites
- **Python scanner**: Requires `PyYAML` (`pip install pyyaml`)
- **Node.js scanner**: Requires `js-yaml` (`npm install js-yaml`)

### Python Scanner
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

### Node.js Scanner
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

🔎 **IOC Detection**: Identifies Indicators of Compromise for both original Shai-Hulud and Shai-Hulud 2.0:
   - **Original Shai-Hulud**: `"postinstall": "node bundle.js"` hooks, `bundle.js` files, `shai-hulud-workflow.yml`
   - **Shai-Hulud 2.0**: `"preinstall"` hooks, `setup_bun.js`, `bun_environment.js`, `discussion.yaml`, `formatter_*.yml` workflows
   - **Common**: References to `webhook.site` exfiltration endpoints, SHA1HULUD runner patterns, Docker privilege escalation

## Output Examples

**🚨 Critical (Compromised Packages Found):**
```
🚨 CRITICAL: Found 2 CONFIRMED compromised packages:
   • @ctrl/deluge v7.2.2 in dependencies
     Affected versions: 7.2.2, 7.2.1
   • ngx-bootstrap v19.0.3 in devDependencies
     Affected versions: 18.1.4, 19.0.3, 20.0.4, 20.0.5, 20.0.6, 19.0.4, 20.0.3
```

**⚠️ Warning (Version Mismatch):**
```
⚠️ WARNING: Found 1 packages with different versions:
   • @ctrl/deluge v7.2.0 in dependencies
     Known affected versions: 7.2.2, 7.2.1
```

**✅ Clean:**
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
1. Check GitHub for public repos named **"Shai-Hulud"** or with "Shai-Hulud" in description
2. Look for repos with **"-migration"** suffix (original Shai-Hulud)
3. Review GitHub audit logs for unauthorized repository creation
4. Check for branches named **shai-hulud**
5. **Scan for IOCs (Indicators of Compromise)**:
   - **Original Shai-Hulud**: 
     - Search for `"postinstall": "node bundle.js"` in package.json files
     - Look for `bundle.js` files (3MB+ in size, contains malicious payload)
     - Examine `.github/workflows/shai-hulud-workflow.yml` files
   - **Shai-Hulud 2.0**:
     - Search for `"preinstall"` hooks in package.json files
     - Look for `setup_bun.js` and `bun_environment.js` payload files
     - Check for data files: `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`
     - Examine `.github/workflows/discussion.yaml` (with self-hosted runner)
     - Examine `.github/workflows/formatter_*.yml` files
     - Check for 'SHA1HULUD' runner name in workflows
     - Look for Docker privilege escalation commands (`docker run --rm --privileged -v /:/host`)
   - **Common**:
     - Check for `webhook.site` references in code or network logs
     - Review self-hosted runner registrations
     - Check cloud provider credentials and secret manager access

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

- **Target Platforms**: Linux, macOS, and Windows (Shai-Hulud 2.0 adds Windows support)
- **Payload Size**: 3MB+ minified JavaScript bundle (original), new payloads in Shai-Hulud 2.0
- **Self-Propagation**: First successful self-replicating worm in npm ecosystem
- **Execution Phases**: Original uses `postinstall`, Shai-Hulud 2.0 uses `preinstall` (increases exposure in build environments)
- **Dependencies**: Python requires PyYAML, Node.js requires js-yaml
- **Safe**: Read-only operations, no modifications to your files
- **Fast**: Optimized for quick scanning of large codebases
- **Accurate**: Based on official IoC lists from security researchers (Wiz Research, Aikido)
- **AI-Generated Components**: Security researchers assess with moderate confidence that an LLM was used to generate parts of the malicious bash script
- **Persistence Mechanisms**: 
  - Original: GitHub Actions workflows, malicious branches, and repository migrations
  - Shai-Hulud 2.0: Self-hosted runners, discussion-based workflows, formatter workflows
- **Cloud Integration**: 
  - Original: Targets AWS and GCP environments using SDK libraries and IMDS endpoints
  - Shai-Hulud 2.0: Multi-cloud targeting (AWS, Azure, GCP) with official SDKs, secret manager dumping

### **Indicators of Compromise (IOCs)**

**Original Shai-Hulud (September 2025)**:
- **Malicious postinstall hook**: `"postinstall": "node bundle.js"` in package.json
- **Payload file**: `bundle.js` (typically 3MB+ minified JavaScript)
- **Exfiltration endpoint**: References to `webhook.site` domains
- **GitHub workflow**: `.github/workflows/shai-hulud-workflow.yml` for persistence
- **Repository naming**: Repos with "Shai-Hulud" or "-migration" suffixes
- **Branch indicators**: Branches named `shai-hulud` containing malicious commits

**Shai-Hulud 2.0 (November 2025)**:
- **Malicious preinstall hook**: `"preinstall": "node setup_bun.js"` or `"preinstall": "node bun_environment.js"` in package.json
- **New payload files**: `setup_bun.js`, `bun_environment.js` (in addition to `bundle.js`)
- **Data files**: `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`
- **GitHub workflows**: 
  - `.github/workflows/discussion.yaml` (with `runs-on: self-hosted` and `RUNNER_TRACKING_ID: 0`)
  - `.github/workflows/formatter_*.yml` (pattern matching, used for secret exfiltration)
- **Self-hosted runner**: Runner named 'SHA1HULUD' registered on infected machines
- **Docker privilege escalation**: Commands like `docker run --rm --privileged -v /:/host`
- **Repository descriptions**: Repos with "Shai-Hulud" in description
- **Multi-cloud targeting**: AWS Secrets Manager, Google Secret Manager, Azure Key Vault access attempts
- **Exfiltration endpoint**: References to `webhook.site` domains (same as original)

**Common to Both Variants**:
- **Exfiltration endpoint**: References to `webhook.site` domains
- **Repository naming**: Repos with "Shai-Hulud" in name or description

## 📚 Documentation

- **[Release Notes v1.2.0](docs/RELEASE_NOTES_v1.2.0.md)** - Complete changelog and new features
- **[Security Assessment](docs/SECURITY_ASSESSMENT.md)** - Comprehensive security analysis
- **[Prevention Guide](prevention/README.md)** - 490+ lines of integration instructions
- **[GitHub Actions Workflow](prevention/github-actions/shai-hulud-blocking.yml)** - Automated CI/CD protection

## 🛡️ New in v2.0.0

### **Shai-Hulud 2.0 Detection**
- **Preinstall hook detection**: Detects `preinstall` scripts (Shai-Hulud 2.0 execution phase)
- **New payload file detection**: Scans for `setup_bun.js` and `bun_environment.js`
- **Data file detection**: Identifies `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`
- **GitHub workflow scanning**: Detects `discussion.yaml` and `formatter_*.yml` workflow patterns
- **Self-hosted runner detection**: Identifies 'SHA1HULUD' runner registrations
- **Docker privilege escalation detection**: Scans for privileged container execution patterns
- **Backward compatibility**: Continues to detect original Shai-Hulud (September 2025) indicators

### **Expanded Package Database**
- **738+ compromised packages** tracked (up from 200)
- **1,291 unique package@version combinations** in database
- **25,000+ affected repositories** identified
- **~350 unique users** compromised

### **Enhanced Prevention Suite** (from v1.2.0)
- **Multi-format configs**: JSON, YAML, CSV for different use cases
- **GitHub Actions integration**: Automated CI/CD blocking workflow
- **Standalone blocker script**: `prevention/block-shai-hulud.sh`
- **Package sync tools**: Automated threat intelligence updates

### **Improved Detection Capabilities**
- **IoC scanning** for both original and Shai-Hulud 2.0 variants
- **Severity categorization** (Critical/High/Medium) with variant identification
- **Enhanced threat intelligence** with download counts and attack vectors
- **Multi-cloud credential detection**: AWS, Azure, GCP targeting patterns

## Support

For issues or questions:
- **Security Team**: contact@rapticore.com
- **Development**: contact@rapticore.com