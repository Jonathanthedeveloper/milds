# MLIDS Test Suite

This directory contains comprehensive tests for the Multi-Level Intrusion Detection System (MLIDS).

## Test Structure

```
tests/
├── test_config.py      # Configuration loading and validation tests
├── test_logger.py      # Logger setup and functionality tests
├── test_events.py      # Event dispatching and action tests
├── test_host.py        # File monitoring tests
├── test_net.py         # Network monitoring tests
├── test_app.py         # Application log monitoring tests
├── __init__.py         # Test package initialization
└── conftest.py         # Pytest configuration and fixtures
```

## Running Tests

### Quick Start
```bash
# Run all tests
python run_tests.py

# Run specific test file
python run_tests.py test_config.py

# Run with verbose output
python run_tests.py test_app.py -v

# Run tests matching a pattern
python run_tests.py -k "test_sql"
```

### Using pytest directly
```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest

# Run specific test file
pytest tests/test_config.py

# Run with coverage
pytest --cov=mlids --cov-report=html
```

## Test Categories

### Unit Tests
- **Configuration Tests** (`test_config.py`): Test config loading from JSON/YAML, validation, and rule loading
- **Logger Tests** (`test_logger.py`): Test structured logging, file rotation, and console formatting
- **Event Tests** (`test_events.py`): Test event dispatching, TCP/WebSocket sinks, and action execution
- **Host Tests** (`test_host.py`): Test file monitoring, baseline creation, and change detection
- **Network Tests** (`test_net.py`): Test packet analysis, port scanning, and anomaly detection
- **App Tests** (`test_app.py`): Test log parsing, pattern matching, and brute force detection

### Integration Tests
- End-to-end monitoring scenarios
- Cross-module event propagation
- Configuration-driven behavior

## Test Coverage

The test suite covers:

### Core Functionality
- ✅ Configuration loading and validation
- ✅ Structured logging with JSON output
- ✅ Event dispatching and action execution
- ✅ File integrity monitoring
- ✅ Network packet analysis
- ✅ Application log parsing

### Security Features
- ✅ SQL injection detection
- ✅ XSS attempt detection
- ✅ Path traversal detection
- ✅ Command injection detection
- ✅ Brute force attack detection
- ✅ Port scanning detection
- ✅ DoS attack detection
- ✅ File change anomaly detection

### Advanced Features
- ✅ TCP alert streaming
- ✅ WebSocket real-time alerts
- ✅ Firewall automation (simulated)
- ✅ Command execution (guarded)
- ✅ External rule loading
- ✅ Threat intelligence tagging

## Mocking Strategy

Tests use comprehensive mocking to:
- Avoid filesystem dependencies
- Simulate network interfaces
- Mock external libraries (scapy, watchdog, tailer)
- Test error conditions safely
- Enable fast, reliable test execution

## Test Data

Tests include realistic test data:
- Sample log entries with various attack patterns
- Mock packet captures
- Simulated file system events
- Configuration files in JSON and YAML formats

## Continuous Integration

The test suite is designed to run in CI environments:
- No external network dependencies
- Fast execution (< 30 seconds)
- Deterministic results
- Clear pass/fail criteria

## Adding New Tests

When adding new functionality:

1. Create corresponding test file in `tests/` directory
2. Follow naming convention: `test_<module>.py`
3. Use descriptive test function names: `test_<feature>_<scenario>`
4. Include docstrings explaining test purpose
5. Mock external dependencies appropriately
6. Test both success and failure scenarios

Example:
```python
def test_new_feature_success_case():
    """Test that new feature works correctly under normal conditions."""
    # Arrange
    cfg = Config()
    # Act
    result = new_feature_function(cfg)
    # Assert
    assert result == expected_value

def test_new_feature_error_handling():
    """Test that new feature handles errors gracefully."""
    # Arrange
    cfg = Config()
    # Act & Assert
    with pytest.raises(ExpectedException):
        new_feature_function(cfg, invalid_param)
```

## Dependencies

Test dependencies (automatically installed by `run_tests.py`):
- `pytest` - Test framework
- `pytest-cov` - Coverage reporting (optional)

The test suite is designed to work with the existing MLIDS dependencies and doesn't require additional libraries beyond what's already needed for the main application.