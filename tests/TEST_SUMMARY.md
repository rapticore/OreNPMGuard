# Test Suite Summary

## Overview

Comprehensive test suite created for OreNPMGuard covering both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) detection capabilities.

## Test Results

### Python Tests
- **Total Tests**: 21
- **Status**: ✅ All Passing (1 skipped - awaiting GitHub sync)
- **Coverage**: IoC detection, package detection, backward compatibility, pattern definitions

### Node.js Tests
- **Total Tests**: 15
- **Status**: ✅ All Passing (1 skipped - awaiting GitHub sync)
- **Coverage**: IoC detection, backward compatibility, variant detection, package detection

## Test Files Created

1. **tests/test_python_scanner.py** - Python unittest suite
2. **tests/test_nodejs_scanner.js** - Node.js test suite
3. **tests/run_tests.sh** - Unified test runner script
4. **tests/fixtures/** - Test fixtures directory
   - `package_original_shai_hulud.json`
   - `package_shai_hulud_2.json`
   - `package_both_variants.json`
   - `discussion.yaml`
   - `formatter_123456789.yml`
5. **tests/README.md** - Test documentation

## Test Coverage

### IoC Detection
- ✅ Original postinstall hook (`"postinstall": "node bundle.js"`)
- ✅ Shai-Hulud 2.0 preinstall hook (`"preinstall": "node setup_bun.js"`)
- ✅ Payload files (`setup_bun.js`, `bun_environment.js`)
- ✅ Data files (`cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`)
- ✅ **NEW**: `actionsSecrets.json` detection (GitHub Actions secrets exfiltration file)
- ✅ Webhook.site references
- ✅ GitHub workflows (`discussion.yaml`, `formatter_*.yml`)
- ✅ Self-hosted runner detection (SHA1HULUD)
- ✅ Docker privilege escalation patterns
- ✅ RUNNER_TRACKING_ID detection

### Package Detection
- ✅ Compromised package version matching
- ✅ Potential match detection (same package, different version)
- ✅ **NEW**: `zapier-platform-legacy-scripting-runner` detection (skipped until GitHub sync)

### Backward Compatibility
- ✅ Original Shai-Hulud patterns still detected
- ✅ Both variants detected simultaneously
- ✅ Original workflow detection

## Running Tests

```bash
# Run all tests
./tests/run_tests.sh

# Or using npm
npm test

# Run Python tests only
npm run test:python

# Run Node.js tests only
npm run test:nodejs
```

## Test Execution

All tests use temporary directories that are automatically cleaned up after execution. Tests are isolated and can be run independently.

## Next Steps

- Add integration tests for full scan workflows
- Add performance tests for large codebases
- Add tests for package-lock.json scanning
- Add tests for edge cases and error handling

