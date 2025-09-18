#!/usr/bin/env node

/**
 * Shai-Hulud npm Package Scanner (Node.js)
 * Scans package.json files for compromised packages from the Shai-Hulud attack
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Load affected packages from YAML configuration file
 */
function loadAffectedPackagesFromYaml() {
    const configPath = path.join(__dirname, 'affected_packages.yaml');

    try {
        const yamlContent = fs.readFileSync(configPath, 'utf8');
        const config = yaml.load(yamlContent);

        const packages = new Map();
        for (const pkg of config.affected_packages) {
            packages.set(pkg.name, new Set(pkg.versions));
        }

        return packages;
    } catch (error) {
        console.error(`❌ Error loading configuration from ${configPath}: ${error.message}`);
        console.error('Using fallback hardcoded data...');
        return parseAffectedPackagesFallback();
    }
}

/**
 * Fallback hardcoded package data in case YAML file is unavailable
 */
function parseAffectedPackagesFallback() {
    // Minimal fallback data - in production, the YAML file should always be available
    const packages = new Map();
    packages.set('@ctrl/deluge', new Set(['7.2.2', '7.2.1']));
    packages.set('ngx-bootstrap', new Set(['18.1.4', '19.0.3', '20.0.4', '20.0.5', '20.0.6', '19.0.4', '20.0.3']));
    // Add more critical packages as needed
    return packages;
}

/**
 * Scan a package.json file for affected packages
 */
function scanPackageJson(filePath) {
    try {
        const packageData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const affectedDb = loadAffectedPackagesFromYaml();
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
    } catch (error) {
        console.error(`❌ Error reading ${filePath}: ${error.message}`);
        return { foundPackages: [], potentialMatches: [] };
    }
}

/**
 * Recursively scan directory for package.json files
 */
function scanDirectory(directory) {
    console.log(`🔍 Scanning directory: ${directory}`);
    console.log('='.repeat(60));

    let foundAny = false;

    function walkDir(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory() && entry.name !== 'node_modules') {
                walkDir(fullPath);
            } else if (entry.isFile() && entry.name === 'package.json') {
                const relativePath = path.relative(directory, fullPath);
                console.log(`\n📦 Checking: ${relativePath}`);

                const { foundPackages, potentialMatches } = scanPackageJson(fullPath);

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
            }
        }
    }

    try {
        walkDir(directory);
    } catch (error) {
        console.error(`❌ Error scanning directory: ${error.message}`);
        return;
    }

    console.log('\n' + '='.repeat(60));
    if (foundAny) {
        console.log('🚨 IMMEDIATE ACTION REQUIRED!');
        console.log('1. Remove compromised packages immediately');
        console.log('2. Rotate ALL credentials (GitHub tokens, npm tokens, API keys)');
        console.log('3. Check for \'Shai-Hulud\' repos in your GitHub account');
        console.log('4. Review GitHub audit logs');
    } else {
        console.log('✅ No confirmed compromised packages found in scanned directories');
    }
}

/**
 * Main function
 */
function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log('Usage: node shai_hulud_scanner.js <path_to_package.json_or_directory>');
        console.log('Examples:');
        console.log('  node shai_hulud_scanner.js ./package.json');
        console.log('  node shai_hulud_scanner.js ./my-project');
        console.log('  node shai_hulud_scanner.js .');
        process.exit(1);
    }

    const targetPath = args[0];

    try {
        const stats = fs.statSync(targetPath);

        if (stats.isFile() && targetPath.endsWith('package.json')) {
            console.log(`🔍 Scanning file: ${targetPath}`);
            console.log('='.repeat(60));

            const { foundPackages, potentialMatches } = scanPackageJson(targetPath);

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

        } else if (stats.isDirectory()) {
            scanDirectory(targetPath);
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
    main();
}

module.exports = { loadAffectedPackagesFromYaml, scanPackageJson, scanDirectory };