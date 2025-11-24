# OreNPMGuard Test Suite

Comprehensive test suite for the Shai-Hulud package scanner, covering both original Shai-Hulud (September 2025) and Shai-Hulud 2.0 (November 2025) detection capabilities.

## Test Structure

```
tests/
├── __init__.py                    # Python package init
├── test_python_scanner.py         # Python scanner tests
├── test_nodejs_scanner.js         # Node.js scanner tests
├── run_tests.sh                   # Unified test runner
├── fixtures/                      # Test fixtures
│   ├── package_original_shai_hulud.json
│   ├── package_shai_hulud_2.json
│   ├── package_both_variants.json
│   ├── discussion.yaml
│   └── formatter_123456789.yml
└── README.md                      # This file
```

## Running Tests

### Run All Tests

```bash
# Using the test runner script
./tests/run_tests.sh

# Or using npm scripts
npm test
```

### Run Python Tests Only

```bash
# Using unittest
python3 -m unittest discover -s tests -p "test_*.py" -v

# Or directly
python3 -m unittest tests.test_python_scanner -v
```

### Run Node.js Tests Only

```bash
node tests/test_nodejs_scanner.js
```

## Test Coverage

### IoC Detection Tests

- ✅ Original Shai-Hulud postinstall hook detection
- ✅ Shai-Hulud 2.0 preinstall hook detection
- ✅ Payload file detection (`setup_bun.js`, `bun_environment.js`)
- ✅ Data file detection (`cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`)
- ✅ Webhook.site reference detection
- ✅ GitHub workflow detection (`discussion.yaml`, `formatter_*.yml`)
- ✅ Self-hosted runner detection (SHA1HULUD)
- ✅ Docker privilege escalation pattern detection
- ✅ RUNNER_TRACKING_ID detection

### Package Detection Tests

- ✅ Compromised package version detection
- ✅ Potential match detection (same package, different version)

### Backward Compatibility Tests

- ✅ Original Shai-Hulud patterns still detected
- ✅ Both variants detected simultaneously
- ✅ Original workflow detection

### Pattern Definition Tests

- ✅ All required IoC patterns defined
- ✅ Payload files list complete
- ✅ Data files list complete

## Test Fixtures

The `fixtures/` directory contains sample files for testing:

- `package_original_shai_hulud.json` - Package with original Shai-Hulud postinstall hook
- `package_shai_hulud_2.json` - Package with Shai-Hulud 2.0 preinstall hook
- `package_both_variants.json` - Package with both variants
- `discussion.yaml` - Shai-Hulud 2.0 discussion workflow
- `formatter_123456789.yml` - Shai-Hulud 2.0 formatter workflow

## Writing New Tests

### Python Tests

Add new test methods to `test_python_scanner.py`:

```python
def test_new_feature(self):
    """Test description."""
    # Setup
    test_dir = tempfile.mkdtemp()
    # ... create test files ...
    
    # Execute
    iocs = scan_for_iocs(test_dir)
    
    # Assert
    self.assertGreater(len(iocs), 0)
```

### Node.js Tests

Add new test cases to `test_nodejs_scanner.js`:

```javascript
test('New feature test', () => {
    const testDir = createTempDir();
    try {
        // Setup
        writeFile(testDir, 'test.json', '{}');
        
        // Execute
        const iocs = scanForIocs(testDir);
        
        // Assert
        assertGreaterThan(iocs.length, 0, 'Should detect...');
    } finally {
        cleanupTempDir(testDir);
    }
});
```

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Tests
  run: |
    ./tests/run_tests.sh
```

## Test Requirements

- **Python**: Python 3.6+ with `unittest` (built-in)
- **Node.js**: Node.js 14+ (no external dependencies required for tests)

## Troubleshooting

### Python Tests Fail

- Ensure Python 3 is installed: `python3 --version`
- Check that `shai_hulud_scanner.py` is in the parent directory
- Verify PyYAML is installed: `pip3 install pyyaml`

### Node.js Tests Fail

- Ensure Node.js is installed: `node --version`
- Check that `shai_hulud_scanner.js` is in the parent directory
- Verify js-yaml is installed: `npm install`

### Tests Time Out

- Some tests download package data from GitHub
- Ensure internet connection is available
- Tests will fall back to local files if download fails

## Contributing

When adding new detection capabilities:

1. Add corresponding tests for both Python and Node.js scanners
2. Test backward compatibility (ensure original patterns still work)
3. Update this README with new test coverage
4. Run all tests before submitting: `./tests/run_tests.sh`

