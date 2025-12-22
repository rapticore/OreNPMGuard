Here is a **curated, high-quality list** of open-source and community sources that track **malicious open-source packages (NPM, PyPI, RubyGems, etc.), compromised GitHub repos, malicious CDNs, and malicious domains**.
These are the best inputs you can feed into ORE Hammer, supply-chain scanners, or your SurrealDB mesh.

---

# ✅ **1. Malicious Open-Source Package Feeds**

### **Open Source / Community Intelligence Sources**

These track **malicious packages, typosquats, dependency hijacks, and supply-chain attacks**:

### **🟦 Open Source Security Foundation (OpenSSF) / Package Analysis**

* Analyzes new packages uploaded to NPM, PyPI, RubyGems, etc.
* Detects malicious behavior using dynamic sandboxing.
  🔗 [https://github.com/ossf/package-analysis](https://github.com/ossf/package-analysis)

---

### **🟦 Socket.dev Open Source Dataset**

* Tracks malware, install scripts, network calls, telemetry, obfuscation.
* Has a **risk score** for 140M+ packages.
  🔗 [https://socket.dev](https://socket.dev)

---

### **🟦 Open Source Vulnerability Database (OSV)**

* Not malware-specific but identifies **compromised package versions** and malicious commits.
  🔗 [https://osv.dev](https://osv.dev)

---

### **🟦 PackageURL (purl) datasets**

* Used by scanners like Syft/Grype/Dependency Track.
* Many malware rules ship via community contributions.
  🔗 [https://github.com/package-url](https://github.com/package-url)

---

### **🟦 Dependency Comb / Malware DB for Packages**

* Specialized for catching **typosquats** and suspicious package names.
  🔗 [https://github.com/oclaussen/dependencycomb](https://github.com/oclaussen/dependencycomb)

---

### **🟦 Phylum.io – Open Malicious Package Reports**

Their research team publishes ongoing dumps of:

* malicious npm packages
* compromised PyPI maintainers
* dependency confusion drops
* malware families in JavaScript & Python ecosystems
  🔗 [https://blog.phylum.io](https://blog.phylum.io)

---

# ✅ **2. GitHub / Code Repository Threat Intel**

### **🟦 GitHub Advisory Database (GHSA)**

Includes:

* compromised packages
* malicious maintainers
* backdoored commits
* CVEs
  🔗 [https://github.com/advisories](https://github.com/advisories)

---

### **🟦 GitHub Secret Scanning + Exposed Token Feeds**

Community scanners like:

* TruffleHog
* Gitleaks
* GitLeaks.io (aggregated database)
  help detect repos that push malware or secret-stealing payloads.

🔗 [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
🔗 [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)

---

### **🟦 HuggingFace Security / Model Malware Tracking**

Tracks malicious ML repos, poisoned datasets, supply-chain tampering.
🔗 [https://huggingface.co/docs/security](https://huggingface.co/docs/security)

---

# ✅ **3. Malicious Domain / CDN / Infrastructure Feeds**

Useful for **typosquat package callbacks**, exfil servers, command-and-control, package post-install scripts.

### **🟦 Abuse.ch Feeds**

The world's most respected open platform for malware infrastructure:

* URLhaus (malicious URLs)
* MalwareBazaar (samples)
* ThreatFox (IOCs & malicious domains)
* SSLBL (malicious TLS certificates)

🔗 [https://abuse.ch](https://abuse.ch)

---

### **🟦 OpenPhish Community Feed**

Malicious URLs/domains.
🔗 [https://openphish.com](https://openphish.com)

---

### **🟦 PhishTank**

Crowdsourced malicious domain database.
🔗 [https://phishtank.org](https://phishtank.org)

---

### **🟦 Cert Spotter / CT Logs**

Detect malicious certificates often used for:

* domain typosquatting
* exfiltration servers
* phishing infrastructure

🔗 [https://github.com/SSLMate/certspotter](https://github.com/SSLMate/certspotter)

---

### **🟦 MalwareDomains.com / URLBlacklists**

Legacy but still useful.
🔗 [http://www.malwaredomains.com/](http://www.malwaredomains.com/)

---

### **🟦 Cloudflare Radar (Domains + Malware Trends)**

Provides free threat intelligence data for DNS-based threats.
🔗 [https://radar.cloudflare.com](https://radar.cloudflare.com)

---

# ✅ **4. Container / Supply-Chain Threat Sources**

### **🟦 Docker Hub Malicious Image Feeds**

Aggregated research from:

* Sysdig
* Aqua Nautilus
* Wiz Labs
* Unit 42 Palo Alto

---

### **🟦 Artifact Hub Security Reports**

For Helm charts, OPA policies, Falco rules, containers.
🔗 [https://artifacthub.io](https://artifacthub.io)

---

# ✅ **5. Public Malware / Behavioral Analysis**

### **🟦 VirusTotal Public API + Community Rules**

With your own account you can query:

* URLs
* IPs
* binaries
* package tarballs
* callback domains from NPM scripts

🔗 [https://www.virustotal.com](https://www.virustotal.com)

---

### **🟦 YARA Rules Public Repos**

Thousands of rules for:

* JS malware
* Python malware
* supply chain IOC patterns

🔗 [https://github.com/Yara-Rules](https://github.com/Yara-Rules)

---

# ✅ **6. Runtime Telemetry Intelligence**

Not directly package-stamped intel, but reveals malicious infrastructure.

### **🟦 Censys.io**

Historical hosting of malicious IPs/domains.
🔗 [https://search.censys.io](https://search.censys.io)

---

### **🟦 Shodan**

Critical for linking malicious domains → hosting → ports → malware families.
🔗 [https://shodan.io](https://shodan.io)

---

# 📌 **What Rapticore Could Do With These Feeds**

Using your Attack Surface Mesh + SurrealDB:

### **1. Map package malware → callback domains → malicious infrastructure**

* NPM postinstall callbacks to:
  `abc-download[.]xyz`
  → domain in Abuse.ch → C2 cluster

### **2. Detect malicious maintainers in your dependency tree**

* Phylum + OpenSSF + GHSA

### **3. Identify poisoned GitHub repos or commits**

* GHSA
* TruffleHog patterns
* Gitleaks datasets

### **4. Connect malicious packages with typosquat domains**

* OSINT + CT logs + URLHaus

### **5. Real-time breach probability if a malicious package exists**

* SurrealDB graph sees:

  * dev → staging → prod
  * build pipeline permissions
  * NPM install → network callback

→ Computes lateral movement & impact.

---

# 📦 If you want, I can also generate:

✔ A combined "Threat Intel ETL" pipeline for SurrealDB
✔ A unified schema for ingesting all feeds
✔ A daily enrichment process (Python or Go)
✔ Auto-matching MITRE ATT&CK techniques to malicious package families
✔ Visual dashboard queries
✔ A scoring model for package risk

Just tell me the direction you'd like to take next.


# List of more resources from where we can collect data

  * https://github.com/ossf/malicious-packages?referrer=grok.com //Repo contains list of malicious packages
  * https://api.osv.dev/v1/query //OSV malicious packages
  * https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0 //for shai-hulude
  * https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack //list of packages
  * https://api.osv.dev/v1/vulns?ecosystem=npm&published_after=2025-12-01T00:00:00Z.
  * https://api.github.com/repos/github/advisory-database/contents/advisories
