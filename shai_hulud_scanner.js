#!/usr/bin/env node

/**
 * Shai-Hulud npm Package Scanner (Node.js) - Enhanced Version
 * Scans package.json and package-lock.json files for compromised packages from the Shai-Hulud attack
 * Includes IoC detection and downloads latest package data from GitHub
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const yaml = require('js-yaml');

// Shai-Hulud IoCs (Indicators of Compromise)
// Includes both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) patterns
const SHAI_HULUD_IOCS = {
    // Original Shai-Hulud IoCs
    webhookUrl: 'https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
    bundleJsHashes: new Set([
        '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09',
        '81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3',
        'dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c'
    ]),
    postinstallPattern: /"postinstall":\s*"node\s+bundle\.js"/,
    
    // Shai-Hulud 2.0 IoCs (November 2025)
    preinstallPattern: /"preinstall":\s*"node\s+(bundle|setup_bun|bun_environment)\.js"/,
    payloadFiles: ['bundle.js', 'setup_bun.js', 'bun_environment.js'],
    dataFiles: ['cloud.json', 'contents.json', 'environment.json', 'truffleSecrets.json'],
    githubWorkflowPatterns: {
        discussionYaml: /\.github\/workflows\/discussion\.yaml/,
        formatterYml: /\.github\/workflows\/formatter_\d+\.yml/,
        shaiHuludWorkflow: /\.github\/workflows\/shai-hulud-workflow\.yml/  // Original
    },
    selfHostedRunnerPattern: /runs-on:\s*self-hosted/,
    sha1huludRunnerPattern: /SHA1HULUD/i,
    runnerTrackingIdPattern: /RUNNER_TRACKING_ID:\s*0/,
    dockerPrivilegeEscalationPattern: /docker\s+run\s+--rm\s+--privileged\s+-v\s+\/:\/host/
};

const GITHUB_YAML_URL = "https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml";

// Global cache for affected packages data
let _affectedPackagesCache = null;
let _cacheLoaded = false;

/**
 * Download the latest affected packages YAML from GitHub
 */
function downloadAffectedPackagesYaml() {
    return new Promise((resolve, reject) => {
        console.log('Downloading latest package data from GitHub...');

        const options = {
            headers: {
                'User-Agent': 'Shai-Hulud-Scanner/1.0'
            },
            timeout: 10000
        };

        const req = https.get(GITHUB_YAML_URL, options, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
                return;
            }

            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const config = yaml.load(data);
                    console.log(`✅ Successfully downloaded data for ${config.affected_packages?.length || 0} packages`);
                    resolve(config);
                } catch (error) {
                    reject(new Error(`YAML parse error: ${error.message}`));
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

/**
 * Load affected packages from GitHub or local YAML configuration file (with caching)
 */
async function loadAffectedPackagesFromYaml() {
    // Return cached data if already loaded
    if (_cacheLoaded && _affectedPackagesCache !== null) {
        return _affectedPackagesCache;
    }

    // First try to download from GitHub
    try {
        const config = await downloadAffectedPackagesYaml();
        const packages = new Map();
        for (const pkg of config.affected_packages || []) {
            packages.set(pkg.name, new Set(pkg.versions));
        }
        _affectedPackagesCache = packages;
        _cacheLoaded = true;
        return packages;
    } catch (error) {
        console.error(`❌ Error downloading from GitHub: ${error.message}`);
        console.error('Falling back to local file...');
    }

    // Try local file
    const configPath = path.join(__dirname, 'affected_packages.yaml');
    try {
        const yamlContent = fs.readFileSync(configPath, 'utf8');
        const config = yaml.load(yamlContent);
        console.log(`✅ Loaded local configuration with ${config.affected_packages?.length || 0} packages`);

        const packages = new Map();
        for (const pkg of config.affected_packages || []) {
            packages.set(pkg.name, new Set(pkg.versions));
        }
        _affectedPackagesCache = packages;
        _cacheLoaded = true;
        return packages;
    } catch (error) {
        console.error(`❌ Error loading local configuration from ${configPath}: ${error.message}`);
        console.error('Using minimal fallback data...');
        _affectedPackagesCache = parseAffectedPackagesFallback();
        _cacheLoaded = true;
        return _affectedPackagesCache;
    }
}

/**
 * Fallback hardcoded package data in case both GitHub and local files are unavailable
 */
function parseAffectedPackagesFallback() {
    console.log('⚠️  Using minimal fallback package data');
    const packages = new Map();
    packages.set('@ctrl/deluge', new Set(['7.2.2', '7.2.1']));
    packages.set('ngx-bootstrap', new Set(['18.1.4', '19.0.3', '20.0.4', '20.0.5', '20.0.6', '19.0.4', '20.0.3']));
    packages.set('@ctrl/tinycolor', new Set(['4.1.1', '4.1.2']));
    packages.set('rxnt-authentication', new Set(['0.0.5', '0.0.6', '0.0.3', '0.0.4']));
    packages.set('angulartics2', new Set(['14.1.2', '14.1.1']));
    return packages;
}

/**
 * Calculate SHA-256 hash of a file
 */
function calculateFileHash(filePath) {
    try {
        const fileContent = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(fileContent).digest('hex');
    } catch (error) {
        console.error(`❌ Error calculating hash for ${filePath}: ${error.message}`);
        return null;
    }
}

/**
 * Scan directory for Shai-Hulud IoCs (Indicators of Compromise)
 * Detects both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) indicators.
 */
function scanForIocs(directory) {
    const iocsFound = [];

    function walkDir(dir) {
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);

                if (entry.isDirectory() && entry.name !== 'node_modules') {
                    walkDir(fullPath);
                } else if (entry.isFile()) {
                    const relativePath = path.relative(directory, fullPath);

                    // Check for malicious payload files (original and Shai-Hulud 2.0)
                    for (const payloadFile of SHAI_HULUD_IOCS.payloadFiles) {
                        if (entry.name === payloadFile) {
                            // For bundle.js, check hash against known malicious hashes
                            if (payloadFile === 'bundle.js') {
                                const fileHash = calculateFileHash(fullPath);
                                if (fileHash && SHAI_HULUD_IOCS.bundleJsHashes.has(fileHash)) {
                                    iocsFound.push({
                                        type: 'malicious_bundle_js',
                                        path: relativePath,
                                        hash: fileHash,
                                        severity: 'CRITICAL',
                                        variant: 'original'
                                    });
                                }
                            } else {
                                // For Shai-Hulud 2.0 payload files, presence is suspicious
                                iocsFound.push({
                                    type: 'malicious_payload_file',
                                    path: relativePath,
                                    filename: payloadFile,
                                    severity: 'CRITICAL',
                                    variant: '2.0'
                                });
                            }
                        }
                    }

                    // Check for Shai-Hulud 2.0 data files
                    for (const dataFile of SHAI_HULUD_IOCS.dataFiles) {
                        if (entry.name === dataFile) {
                            iocsFound.push({
                                type: 'shai_hulud_data_file',
                                path: relativePath,
                                filename: dataFile,
                                severity: 'HIGH',
                                variant: '2.0'
                            });
                        }
                    }

                    // Check package.json files for malicious hooks
                    if (entry.name === 'package.json') {
                        try {
                            const content = fs.readFileSync(fullPath, 'utf8');

                            // Check for malicious postinstall pattern (original Shai-Hulud)
                            if (SHAI_HULUD_IOCS.postinstallPattern.test(content)) {
                                iocsFound.push({
                                    type: 'malicious_postinstall',
                                    path: relativePath,
                                    pattern: 'node bundle.js',
                                    severity: 'CRITICAL',
                                    variant: 'original'
                                });
                            }

                            // Check for malicious preinstall pattern (Shai-Hulud 2.0)
                            if (SHAI_HULUD_IOCS.preinstallPattern.test(content)) {
                                iocsFound.push({
                                    type: 'malicious_preinstall',
                                    path: relativePath,
                                    pattern: 'preinstall hook with suspicious payload',
                                    severity: 'CRITICAL',
                                    variant: '2.0'
                                });
                            }

                            // Check for webhook.site URL references
                            if (content.includes(SHAI_HULUD_IOCS.webhookUrl)) {
                                iocsFound.push({
                                    type: 'webhook_site_reference',
                                    path: relativePath,
                                    url: SHAI_HULUD_IOCS.webhookUrl,
                                    severity: 'HIGH'
                                });
                            }
                        } catch (error) {
                            console.error(`❌ Error reading ${fullPath}: ${error.message}`);
                        }
                    }

                    // Check for GitHub workflow files (Shai-Hulud 2.0)
                    if (fullPath.includes('.github') || fullPath.includes('workflows')) {
                        if (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml')) {
                            try {
                                const workflowContent = fs.readFileSync(fullPath, 'utf8');
                                const normalizedPath = fullPath.replace(/\\/g, '/');
                                
                                // Check for discussion.yaml pattern
                                if (SHAI_HULUD_IOCS.githubWorkflowPatterns.discussionYaml.test(normalizedPath)) {
                                    if (SHAI_HULUD_IOCS.selfHostedRunnerPattern.test(workflowContent)) {
                                        iocsFound.push({
                                            type: 'malicious_github_workflow',
                                            path: relativePath,
                                            pattern: 'discussion.yaml with self-hosted runner',
                                            severity: 'CRITICAL',
                                            variant: '2.0'
                                        });
                                    }
                                }
                                
                                // Check for formatter workflow pattern
                                if (SHAI_HULUD_IOCS.githubWorkflowPatterns.formatterYml.test(normalizedPath)) {
                                    iocsFound.push({
                                        type: 'malicious_github_workflow',
                                        path: relativePath,
                                        pattern: 'formatter workflow for secret exfiltration',
                                        severity: 'CRITICAL',
                                        variant: '2.0'
                                    });
                                }
                                
                                // Check for SHA1HULUD runner name
                                if (SHAI_HULUD_IOCS.sha1huludRunnerPattern.test(workflowContent)) {
                                    iocsFound.push({
                                        type: 'sha1hulud_runner',
                                        path: relativePath,
                                        pattern: 'SHA1HULUD runner registration',
                                        severity: 'CRITICAL',
                                        variant: '2.0'
                                    });
                                }
                                
                                // Check for RUNNER_TRACKING_ID: 0
                                if (SHAI_HULUD_IOCS.runnerTrackingIdPattern.test(workflowContent)) {
                                    iocsFound.push({
                                        type: 'suspicious_runner_config',
                                        path: relativePath,
                                        pattern: 'RUNNER_TRACKING_ID: 0',
                                        severity: 'HIGH',
                                        variant: '2.0'
                                    });
                                }
                                
                                // Check for original shai-hulud-workflow.yml
                                if (SHAI_HULUD_IOCS.githubWorkflowPatterns.shaiHuludWorkflow.test(normalizedPath)) {
                                    iocsFound.push({
                                        type: 'malicious_github_workflow',
                                        path: relativePath,
                                        pattern: 'shai-hulud-workflow.yml',
                                        severity: 'CRITICAL',
                                        variant: 'original'
                                    });
                                }
                            } catch (error) {
                                // Skip files that can't be read
                                continue;
                            }
                        }
                    }

                    // Check other files for webhook references and Docker patterns
                    if ((entry.name.endsWith('.js') || entry.name.endsWith('.ts') || 
                         entry.name.endsWith('.json') || entry.name.endsWith('.sh') || 
                         entry.name.endsWith('.bash')) && entry.name !== 'package.json') {
                        try {
                            const content = fs.readFileSync(fullPath, 'utf8');
                            
                            // Check for webhook.site URL references
                            if (content.includes(SHAI_HULUD_IOCS.webhookUrl)) {
                                iocsFound.push({
                                    type: 'webhook_site_reference',
                                    path: relativePath,
                                    url: SHAI_HULUD_IOCS.webhookUrl,
                                    severity: 'HIGH'
                                });
                            }
                            
                            // Check for Docker privilege escalation pattern (Shai-Hulud 2.0)
                            if (SHAI_HULUD_IOCS.dockerPrivilegeEscalationPattern.test(content)) {
                                iocsFound.push({
                                    type: 'docker_privilege_escalation',
                                    path: relativePath,
                                    pattern: 'Docker privileged container with host mount',
                                    severity: 'CRITICAL',
                                    variant: '2.0'
                                });
                            }
                        } catch (error) {
                            // Skip files that can't be read as text
                            continue;
                        }
                    }
                }
            }
        } catch (error) {
            console.error(`❌ Error scanning directory ${dir}: ${error.message}`);
        }
    }

    walkDir(directory);
    return iocsFound;
}

/**
 * Scan a package.json or package-lock.json file for affected packages
 */
async function scanPackageJson(filePath) {
    try {
        const packageData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const affectedDb = await loadAffectedPackagesFromYaml();

        // Determine file type and scan accordingly
        if (filePath.endsWith('package-lock.json')) {
            return scanPackageLockDependencies(packageData, affectedDb);
        } else {
            return scanPackageJsonDependencies(packageData, affectedDb);
        }
    } catch (error) {
        console.error(`❌ Error reading ${filePath}: ${error.message}`);
        return { foundPackages: [], potentialMatches: [] };
    }
}

/**
 * Scan package.json dependency sections
 */
function scanPackageJsonDependencies(packageData, affectedDb) {
    const foundPackages = [];
    const potentialMatches = [];

    // Check all dependency sections
    const depsSections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

    for (const section of depsSections) {
        if (!packageData[section]) continue;

        for (const [pkgName, installedVersion] of Object.entries(packageData[section])) {
            // Clean version string (remove ^, ~, etc.)
            const cleanVersion = installedVersion.replace(/^[\^~>=<]/, '');

            if (affectedDb.has(pkgName)) {
                const affectedVersions = affectedDb.get(pkgName);

                if (affectedVersions.has(cleanVersion)) {
                    // Exact match - confirmed compromise
                    foundPackages.push({
                        name: pkgName,
                        installedVersion,
                        affectedVersions: Array.from(affectedVersions),
                        section,
                        exactMatch: true
                    });
                } else {
                    // Package name matches but version might be different
                    potentialMatches.push({
                        name: pkgName,
                        installedVersion,
                        affectedVersions: Array.from(affectedVersions),
                        section,
                        exactMatch: false
                    });
                }
            }
        }
    }

    return { foundPackages, potentialMatches };
}

/**
 * Scan package-lock.json dependencies (includes nested dependencies)
 */
function scanPackageLockDependencies(packageData, affectedDb) {
    const foundPackages = [];
    const potentialMatches = [];

    function scanDependenciesRecursive(deps, section = 'lockfile', depth = 0) {
        if (!deps) return;

        for (const [pkgName, pkgInfo] of Object.entries(deps)) {
            if (typeof pkgInfo !== 'object') continue;

            // Get version from package-lock.json
            const installedVersion = pkgInfo.version || '';

            if (affectedDb.has(pkgName) && installedVersion) {
                const affectedVersions = affectedDb.get(pkgName);

                if (affectedVersions.has(installedVersion)) {
                    foundPackages.push({
                        name: pkgName,
                        installedVersion,
                        affectedVersions: Array.from(affectedVersions),
                        section: `${section} (depth ${depth})`,
                        exactMatch: true
                    });
                } else {
                    potentialMatches.push({
                        name: pkgName,
                        installedVersion,
                        affectedVersions: Array.from(affectedVersions),
                        section: `${section} (depth ${depth})`,
                        exactMatch: false
                    });
                }
            }

            // Recursively scan nested dependencies
            if (pkgInfo.dependencies) {
                scanDependenciesRecursive(pkgInfo.dependencies, section, depth + 1);
            }
        }
    }

    // Scan top-level dependencies in package-lock.json
    if (packageData.dependencies) {
        scanDependenciesRecursive(packageData.dependencies, 'dependencies');
    }

    // Also scan packages section if present (npm v7+ format)
    if (packageData.packages) {
        for (const [pkgPath, pkgInfo] of Object.entries(packageData.packages)) {
            if (pkgPath === '') continue; // Skip root package

            // Extract package name from node_modules path
            if (pkgPath.startsWith('node_modules/')) {
                let pkgName = pkgPath.substring('node_modules/'.length);

                // Handle scoped packages
                if (pkgName.includes('/')) {
                    const parts = pkgName.split('/');
                    if (parts[0].startsWith('@')) {
                        pkgName = `${parts[0]}/${parts[1]}`;
                    } else {
                        pkgName = parts[0];
                    }
                }

                const installedVersion = pkgInfo.version || '';

                if (affectedDb.has(pkgName) && installedVersion) {
                    const affectedVersions = affectedDb.get(pkgName);

                    if (affectedVersions.has(installedVersion)) {
                        foundPackages.push({
                            name: pkgName,
                            installedVersion,
                            affectedVersions: Array.from(affectedVersions),
                            section: 'packages',
                            exactMatch: true
                        });
                    } else {
                        potentialMatches.push({
                            name: pkgName,
                            installedVersion,
                            affectedVersions: Array.from(affectedVersions),
                            section: 'packages',
                            exactMatch: false
                        });
                    }
                }
            }
        }
    }

    return { foundPackages, potentialMatches };
}

/**
 * Recursively scan directory for package.json and package-lock.json files
 */
async function scanDirectory(directory) {
    console.log(`🔍 Scanning directory: ${directory}`);
    console.log('='.repeat(60));

    // First scan for IoCs
    console.log('\n🕵️  Scanning for Shai-Hulud IoCs...');
    const iocs = scanForIocs(directory);

    if (iocs.length > 0) {
        console.log(`🚨 CRITICAL: Found ${iocs.length} Indicators of Compromise:`);
        for (const ioc of iocs) {
            const severityEmoji = ioc.severity === 'CRITICAL' ? '🔴' : '🟠';
            const variantInfo = ioc.variant ? ` [${ioc.variant}]` : '';
            console.log(`   ${severityEmoji} ${ioc.type.toUpperCase()}${variantInfo}: ${ioc.path}`);

            if (ioc.type === 'malicious_bundle_js' && ioc.hash) {
                console.log(`      SHA-256: ${ioc.hash}`);
            } else if ((ioc.type === 'malicious_postinstall' || ioc.type === 'malicious_preinstall') && ioc.pattern) {
                console.log(`      Pattern: ${ioc.pattern}`);
            } else if (ioc.type === 'webhook_site_reference' && ioc.url) {
                console.log(`      URL: ${ioc.url}`);
            } else if (ioc.type === 'malicious_payload_file' && ioc.filename) {
                console.log(`      Payload file: ${ioc.filename}`);
            } else if (ioc.type === 'shai_hulud_data_file' && ioc.filename) {
                console.log(`      Data file: ${ioc.filename}`);
            } else if ((ioc.type === 'malicious_github_workflow' || ioc.type === 'sha1hulud_runner' || 
                       ioc.type === 'suspicious_runner_config' || ioc.type === 'docker_privilege_escalation') && ioc.pattern) {
                console.log(`      Pattern: ${ioc.pattern}`);
            }
        }
    } else {
        console.log('✅ No IoCs detected');
    }

    console.log('\n📦 Scanning for compromised packages...');
    let foundAny = false;

    function walkDir(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        // Collect files to scan in this directory
        const filesToScan = [];
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory() && entry.name !== 'node_modules') {
                walkDir(fullPath);
            } else if (entry.isFile()) {
                if (entry.name === 'package.json') {
                    filesToScan.push({ name: entry.name, icon: '📦', path: fullPath });
                } else if (entry.name === 'package-lock.json') {
                    filesToScan.push({ name: entry.name, icon: '🔒', path: fullPath });
                }
            }
        }

        // Process all files to scan
        filesToScan.forEach(async (file) => {
            const relativePath = path.relative(directory, file.path);
            console.log(`\n${file.icon} Checking: ${relativePath}`);

            const { foundPackages, potentialMatches } = await scanPackageJson(file.path);

            if (foundPackages.length > 0) {
                foundAny = true;
                console.log(`🚨 CRITICAL: Found ${foundPackages.length} CONFIRMED compromised packages:`);
                for (const pkg of foundPackages) {
                    console.log(`   • ${pkg.name} v${pkg.installedVersion} in ${pkg.section}`);
                    console.log(`     Affected versions: ${pkg.affectedVersions.join(', ')}`);
                }
            }

            if (potentialMatches.length > 0) {
                console.log(`⚠️  WARNING: Found ${potentialMatches.length} packages with different versions:`);
                for (const pkg of potentialMatches) {
                    console.log(`   • ${pkg.name} v${pkg.installedVersion} in ${pkg.section}`);
                    console.log(`     Known affected versions: ${pkg.affectedVersions.join(', ')}`);
                }
            }

            if (foundPackages.length === 0 && potentialMatches.length === 0) {
                console.log('✅ No affected packages found');
            }
        });
    }

    try {
        walkDir(directory);
    } catch (error) {
        console.error(`❌ Error scanning directory: ${error.message}`);
        return;
    }

    console.log('\n' + '='.repeat(60));
    if (foundAny || iocs.length > 0) {
        console.log('🚨 IMMEDIATE ACTION REQUIRED!');
        console.log('1. Remove compromised packages immediately');
        console.log('2. Delete any malicious bundle.js files');
        console.log('3. Rotate ALL credentials (GitHub tokens, npm tokens, API keys)');
        console.log('4. Check for \'Shai-Hulud\' repos in your GitHub account');
        console.log('5. Review GitHub audit logs');
        console.log('6. Scan network logs for webhook.site communications');
    } else {
        console.log('✅ No confirmed compromised packages or IoCs found in scanned directories');
    }
}

/**
 * Main function
 */
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log('Usage: node shai_hulud_scanner.js <path_to_package.json|package-lock.json_or_directory>');
        console.log('Examples:');
        console.log('  node shai_hulud_scanner.js ./package.json');
        console.log('  node shai_hulud_scanner.js ./package-lock.json');
        console.log('  node shai_hulud_scanner.js ./my-project');
        console.log('  node shai_hulud_scanner.js .');
        process.exit(1);
    }

    const targetPath = args[0];

    try {
        const stats = fs.statSync(targetPath);

        if (stats.isFile() && (targetPath.endsWith('package.json') || targetPath.endsWith('package-lock.json'))) {
            console.log(`🔍 Scanning file: ${targetPath}`);
            console.log('='.repeat(60));

            // Scan for IoCs in the directory containing the file
            const directory = path.dirname(targetPath) || '.';
            console.log('\n🕵️  Scanning for Shai-Hulud IoCs...');
            const iocs = scanForIocs(directory);

            if (iocs.length > 0) {
                console.log(`🚨 CRITICAL: Found ${iocs.length} Indicators of Compromise:`);
                for (const ioc of iocs) {
                    const severityEmoji = ioc.severity === 'CRITICAL' ? '🔴' : '🟠';
                    const variantInfo = ioc.variant ? ` [${ioc.variant}]` : '';
                    console.log(`   ${severityEmoji} ${ioc.type.toUpperCase()}${variantInfo}: ${ioc.path}`);
                    
                    if (ioc.type === 'malicious_bundle_js' && ioc.hash) {
                        console.log(`      SHA-256: ${ioc.hash}`);
                    } else if ((ioc.type === 'malicious_postinstall' || ioc.type === 'malicious_preinstall') && ioc.pattern) {
                        console.log(`      Pattern: ${ioc.pattern}`);
                    } else if (ioc.type === 'webhook_site_reference' && ioc.url) {
                        console.log(`      URL: ${ioc.url}`);
                    } else if (ioc.type === 'malicious_payload_file' && ioc.filename) {
                        console.log(`      Payload file: ${ioc.filename}`);
                    } else if (ioc.type === 'shai_hulud_data_file' && ioc.filename) {
                        console.log(`      Data file: ${ioc.filename}`);
                    } else if ((ioc.type === 'malicious_github_workflow' || ioc.type === 'sha1hulud_runner' || 
                               ioc.type === 'suspicious_runner_config' || ioc.type === 'docker_privilege_escalation') && ioc.pattern) {
                        console.log(`      Pattern: ${ioc.pattern}`);
                    }
                }
            } else {
                console.log('✅ No IoCs detected');
            }

            console.log(`\n📦 Scanning package file: ${targetPath}`);
            const { foundPackages, potentialMatches } = await scanPackageJson(targetPath);

            if (foundPackages.length > 0) {
                console.log(`🚨 CRITICAL: Found ${foundPackages.length} CONFIRMED compromised packages:`);
                for (const pkg of foundPackages) {
                    console.log(`   • ${pkg.name} v${pkg.installedVersion} in ${pkg.section}`);
                    console.log(`     Affected versions: ${pkg.affectedVersions.join(', ')}`);
                }
            }

            if (potentialMatches.length > 0) {
                console.log(`⚠️  WARNING: Found ${potentialMatches.length} packages with different versions:`);
                for (const pkg of potentialMatches) {
                    console.log(`   • ${pkg.name} v${pkg.installedVersion} in ${pkg.section}`);
                    console.log(`     Known affected versions: ${pkg.affectedVersions.join(', ')}`);
                }
            }

            if (foundPackages.length === 0 && potentialMatches.length === 0) {
                console.log('✅ No affected packages found');
            }

            if (foundPackages.length > 0 || iocs.length > 0) {
                console.log('\n🚨 IMMEDIATE ACTION REQUIRED!');
                console.log('1. Remove compromised packages immediately');
                console.log('2. Delete any malicious bundle.js files');
                console.log('3. Rotate ALL credentials');
            }

        } else if (stats.isDirectory()) {
            await scanDirectory(targetPath);
        } else {
            console.error(`❌ Error: ${targetPath} is not a valid package.json file or directory`);
            process.exit(1);
        }
    } catch (error) {
        console.error(`❌ Error: ${targetPath} does not exist or is not accessible`);
        process.exit(1);
    }
}

// Run the scanner
if (require.main === module) {
    main().catch(error => {
        console.error('❌ Fatal error:', error.message);
        process.exit(1);
    });
}

module.exports = { loadAffectedPackagesFromYaml, scanPackageJson, scanDirectory, scanForIocs };