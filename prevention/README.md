# 🛡️ Shai-Hulud Prevention & Blocking Guide

This directory contains comprehensive prevention tools and configurations to protect your organization from the Shai-Hulud supply chain attack. Use these tools to automatically detect, block, and prevent compromised npm packages from entering your development pipeline.

## 📁 **Available Formats & Tools**

| File | Format | Use Case | Integration |
|------|--------|----------|-------------|
| `banned-packages.json` | JSON | Security tools, APIs, automation | ✅ Programmatic access |
| `banned-packages.yaml` | YAML | CI/CD, configuration files | ✅ Human-readable config |
| `banned-packages.csv` | CSV | Reporting, spreadsheets, analysis | ✅ Data analysis |
| `github-actions/shai-hulud-blocking.yml` | GitHub Actions | Automated CI/CD blocking | ✅ Pull request protection |
| `block-shai-hulud.sh` | Shell Script | Standalone security scanner | ✅ Any Unix environment |

---

## 🚀 **Quick Start Integration**

### 1. **🔄 GitHub Actions (Recommended)**

Automatically block compromised packages in your CI/CD pipeline:

```bash
# Copy the workflow to your repository
mkdir -p .github/workflows
cp prevention/github-actions/shai-hulud-blocking.yml .github/workflows/

# Commit and push
git add .github/workflows/shai-hulud-blocking.yml
git commit -m "Add Shai-Hulud security blocking workflow"
git push
```

**Features:**
- ✅ Automatic scanning on every push and PR
- ✅ Blocks deployment of compromised packages
- ✅ Posts detailed security reports on PRs
- ✅ Fails builds immediately on critical packages
- ✅ Sends notifications to security teams

### 2. **🖥️ Command Line Scanner**

Use the standalone shell script for immediate protection:

```bash
# Download and run
curl -sSL https://raw.githubusercontent.com/rapticore/orenpmpguard/main/prevention/block-shai-hulud.sh -o block-shai-hulud.sh
chmod +x block-shai-hulud.sh

# Scan current directory
./block-shai-hulud.sh

# Scan specific file
./block-shai-hulud.sh -f package.json

# Quiet mode for automation
./block-shai-hulud.sh -q /path/to/project
```

### 3. **📦 npm Scripts Integration**

Add security scanning to your package.json:

```json
{
  "scripts": {
    "security:scan": "npx orenpmpguard .",
    "security:block": "curl -sSL https://raw.githubusercontent.com/rapticore/orenpmpguard/main/prevention/block-shai-hulud.sh | bash -s -- .",
    "preinstall": "npx orenpmpguard package.json",
    "postinstall": "npx orenpmpguard package-lock.json"
  }
}
```

---

## 🔧 **Detailed Integration Instructions**

### **A. Package Manager Integration**

#### **npm Configuration**
```bash
# Add audit script to package.json
npm pkg set scripts.audit="npm audit --audit-level critical && npx orenpmpguard ."

# Run security scan before every install
npm pkg set scripts.preinstall="npx orenpmpguard package.json"
```

#### **Yarn Configuration**
```bash
# Add to package.json
yarn set scripts.audit "yarn audit --level critical && npx orenpmpguard ."
```

### **B. Pre-commit Hooks**

#### **Using Husky**
```bash
# Install husky
npm install --save-dev husky

# Add pre-commit hook
npx husky add .husky/pre-commit "npx orenpmpguard ."
```

#### **Manual Git Hook**
```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "🔍 Scanning for Shai-Hulud compromised packages..."
npx orenpmpguard . || exit 1
echo "✅ Security scan passed"
EOF

chmod +x .git/hooks/pre-commit
```

### **C. Docker Integration**

#### **Multi-stage Dockerfile**
```dockerfile
# Security scanning stage
FROM node:18-alpine AS security
WORKDIR /app
COPY package*.json ./
RUN npm install -g orenpmpguard
RUN orenpmpguard .

# Main application stage
FROM node:18-alpine AS app
WORKDIR /app
COPY --from=security /app/package*.json ./
RUN npm ci --only=production
COPY . .
CMD ["npm", "start"]
```

#### **Docker Compose**
```yaml
version: '3.8'
services:
  security-scan:
    image: node:18-alpine
    volumes:
      - .:/app
    working_dir: /app
    command: >
      sh -c "npm install -g orenpmpguard && orenpmpguard ."

  app:
    build: .
    depends_on:
      - security-scan
```

### **D. CI/CD Platform Integration**

#### **GitLab CI**
```yaml
# .gitlab-ci.yml
security_scan:
  stage: security
  image: node:18-alpine
  script:
    - npm install -g orenpmpguard
    - orenpmpguard .
  allow_failure: false
  only:
    - merge_requests
    - main
```

#### **Jenkins Pipeline**
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g orenpmpguard'
                sh 'orenpmpguard .'
            }
        }
    }
    post {
        failure {
            emailext (
                subject: "🚨 Security Alert: Shai-Hulud packages detected",
                body: "Compromised packages found in ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                to: "security@yourcompany.com"
            )
        }
    }
}
```

#### **Azure DevOps**
```yaml
# azure-pipelines.yml
trigger:
  - main

stages:
- stage: SecurityScan
  jobs:
  - job: ScanPackages
    steps:
    - task: NodeTool@0
      inputs:
        versionSpec: '18.x'
    - script: |
        npm install -g orenpmpguard
        orenpmpguard .
      displayName: 'Scan for Shai-Hulud packages'
      failOnStderr: true
```

### **E. IDE Integration**

#### **VS Code Workspace Settings**
```json
{
  "settings": {
    "files.watcherExclude": {
      "**/node_modules/**": true
    }
  },
  "tasks": {
    "version": "2.0.0",
    "tasks": [
      {
        "label": "Security Scan",
        "type": "shell",
        "command": "npx orenpmpguard .",
        "group": "build",
        "presentation": {
          "echo": true,
          "reveal": "always",
          "focus": false,
          "panel": "shared"
        },
        "problemMatcher": []
      }
    ]
  }
}
```

---

## 📊 **Programmatic Usage**

### **JavaScript/Node.js**
```javascript
const fs = require('fs');
const bannedPackages = JSON.parse(fs.readFileSync('banned-packages.json', 'utf8'));

function checkPackage(packageName, version) {
  const pkg = bannedPackages.banned_packages.find(p => p.name === packageName);
  if (pkg && pkg.banned_versions.includes(version)) {
    console.error(`🚨 CRITICAL: ${packageName}@${version} is compromised!`);
    return false;
  }
  return true;
}

// Example usage
if (!checkPackage('@ctrl/deluge', '7.2.2')) {
  process.exit(1);
}
```

### **Python**
```python
import json
import yaml

# Load banned packages
with open('banned-packages.json', 'r') as f:
    banned_data = json.load(f)

def check_package(package_name, version):
    for pkg in banned_data['banned_packages']:
        if pkg['name'] == package_name and version in pkg['banned_versions']:
            print(f"🚨 CRITICAL: {package_name}@{version} is compromised!")
            return False
    return True

# Example usage
if not check_package('@ctrl/deluge', '7.2.2'):
    exit(1)
```

### **Bash/Shell**
```bash
#!/bin/bash

check_package() {
    local package_name="$1"
    local version="$2"

    if grep -q "\"$package_name\"" banned-packages.json; then
        if grep -A 5 "\"$package_name\"" banned-packages.json | grep -q "\"$version\""; then
            echo "🚨 CRITICAL: $package_name@$version is compromised!"
            return 1
        fi
    fi
    return 0
}

# Example usage
if ! check_package "@ctrl/deluge" "7.2.2"; then
    exit 1
fi
```

---

## 🔒 **Security Tool Integration**

### **Snyk Integration**
```bash
# Custom Snyk policy
cat > .snyk << 'EOF'
# Snyk policy file for Shai-Hulud protection
ignore:
  # Add specific CVEs if needed

exclude:
  # Exclude compromised packages from scanning
  - "@ctrl/deluge"
  - "ngx-bootstrap"
  - "rxnt-authentication"
EOF
```

### **OWASP Dependency Check**
```xml
<!-- Add to dependency-check configuration -->
<suppressions>
  <suppress>
    <packageUrl regex="true">^pkg:npm/@ctrl/deluge@.*$</packageUrl>
    <cve>CVE-SHAI-HULUD-2025</cve>
  </suppress>
</suppressions>
```

### **WhiteSource/Mend Integration**
```json
{
  "configType": "globalSettings",
  "productName": "YourProduct",
  "projectName": "YourProject",
  "ignoreSourceFiles": [
    "**/@ctrl/deluge/**",
    "**/ngx-bootstrap/**",
    "**/rxnt-authentication/**"
  ]
}
```

---

## 📋 **Monitoring & Alerting**

### **Slack Notifications**
```bash
# Add to your security scan script
send_slack_alert() {
    local message="$1"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 Security Alert: $message\"}" \
        "$SLACK_WEBHOOK_URL"
}

# Usage
if orenpmpguard . | grep -q "CRITICAL"; then
    send_slack_alert "Shai-Hulud packages detected in $(pwd)"
fi
```

### **Email Notifications**
```bash
# Email alert function
send_email_alert() {
    local subject="$1"
    local body="$2"

    mail -s "$subject" security@yourcompany.com << EOF
$body

Repository: $(git remote get-url origin)
Branch: $(git branch --show-current)
Commit: $(git rev-parse HEAD)

Scan performed at: $(date)
EOF
}
```

### **Logging Integration**
```bash
# Structured logging
log_security_event() {
    local event_type="$1"
    local package_name="$2"
    local version="$3"

    echo "{
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"event_type\": \"$event_type\",
        \"package_name\": \"$package_name\",
        \"version\": \"$version\",
        \"scanner\": \"orenpmpguard\",
        \"repository\": \"$(git remote get-url origin)\",
        \"branch\": \"$(git branch --show-current)\"
    }" >> security-events.log
}
```

---

## 🆘 **Emergency Response Procedures**

### **If Compromised Packages Are Detected:**

#### **Immediate Actions (Within 15 minutes):**
1. **🛑 STOP** all development work on affected projects
2. **📦 Remove** compromised packages: `npm uninstall <package-name>`
3. **🧹 Clear** npm cache: `npm cache clean --force`
4. **🗂️ Delete** node_modules: `rm -rf node_modules && npm install`

#### **Credential Rotation (Within 1 hour):**
1. **🔑 GitHub Personal Access Tokens** (`ghp_*`, `gho_*`)
2. **📦 npm Authentication Tokens**
3. **🔐 SSH Keys**
4. **☁️ Cloud credentials** (AWS, GCP, Azure)
5. **🔗 API Keys** (Atlassian, Datadog, etc.)

#### **Investigation (Within 24 hours):**
1. **🔍 Check GitHub** for public repos named "Shai-Hulud"
2. **📁 Look for repos** with "-migration" suffix
3. **📊 Review GitHub audit logs**
4. **🌿 Check for branches** named "shai-hulud"
5. **⚙️ Scan for malicious** GitHub Actions workflows
6. **🔎 Look for Shai-Hulud 2.0 files**: `setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`
7. **🏃 Check self-hosted runners** for 'SHA1HULUD' named runners

#### **⚠️ Cross-Victim Exfiltration Warning:**
Wiz Research has confirmed that **cross-victim exfiltration** occurs in Shai-Hulud 2.0:
- One victim's secrets may be published to repos owned by **another unrelated victim**
- If you find suspicious data in your repos, verify if it actually belongs to your organization
- Your data may exist in repositories you don't own
- **Action**: When reviewing exfiltrated data, check if it belongs to you or another victim

#### **Communication:**
- **📧 Security Team**: security@yourcompany.com
- **🚨 Emergency Contact**: contact@rapticore.com
- **📖 Documentation**: https://github.com/rapticore/orenpmpguard

---

## 📞 **Support & Resources**

### **Getting Help**
- **🐛 Issues**: https://github.com/rapticore/orenpmpguard/issues
- **📧 Email**: contact@rapticore.com
- **📖 Documentation**: https://github.com/rapticore/orenpmpguard
- **🔒 Security Advisories**: https://github.com/rapticore/orenpmpguard/security

### **Customization**
All configuration files can be customized for your organization's specific needs:

1. **Edit `banned-packages.json`** to add internal package restrictions
2. **Modify `shai-hulud-blocking.yml`** for custom notification channels
3. **Update `block-shai-hulud.sh`** for custom logging and reporting
4. **Extend `banned-packages.yaml`** with additional security policies

### **Updates**
Check for updates regularly:
```bash
# Check for latest scanner version
npm info orenpmpguard version

# Update configurations
curl -sSL https://api.github.com/repos/rapticore/orenpmpguard/releases/latest
```

---

## ⚖️ **License & Legal**

This prevention toolkit is provided by **Rapticore Security** under the MIT License.

**Disclaimer**: These tools are provided as-is for security protection. Organizations should review and customize configurations according to their specific security policies and compliance requirements.

**Copyright** © 2025 Rapticore Security. All rights reserved.