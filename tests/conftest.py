"""
Pytest configuration and shared fixtures for MLIDS tests.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock
from milds.config import Config
from milds.logger import get_logger


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def config():
    """Create a default configuration for testing."""
    return Config()


@pytest.fixture
def custom_config():
    """Create a custom configuration for testing."""
    return Config(
        port_scan_threshold=5,
        brute_force_threshold=3,
        enable_network=True,
        tcp_sink_enabled=True,
        tcp_sink_host="127.0.0.1",
        tcp_sink_port=9999
    )


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    return MagicMock()


@pytest.fixture
def mock_dispatcher():
    """Create a mock event dispatcher for testing."""
    return MagicMock()


@pytest.fixture
def temp_log_file(temp_dir):
    """Create a temporary log file for testing."""
    log_file = os.path.join(temp_dir, "test.log")
    with open(log_file, 'w') as f:
        f.write("Test log entry\n")
    return log_file


@pytest.fixture
def sample_log_entries():
    """Provide sample log entries for testing."""
    return [
        "192.168.1.100 - - [01/Jan/2023:12:00:00 +0000] \"GET /index.php?id=1' OR 1=1 -- HTTP/1.1\" 200 1234",
        "192.168.1.101 - - [01/Jan/2023:12:01:00 +0000] \"POST /login.php HTTP/1.1\" 401 234",
        "Failed login from 10.0.0.5",
        "Failed login from 10.0.0.5",
        "Failed login from 10.0.0.5",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "; rm -rf /",
        "Normal log entry with no issues"
    ]


@pytest.fixture
def attack_patterns():
    """Provide various attack patterns for testing."""
    return {
        'sql_injection': [
            "SELECT * FROM users WHERE id=1' OR '1'='1",
            "UNION SELECT username FROM admin",
            "1' OR 1=1 --",
            "admin' --"
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=javascript:alert('XSS')>",
            "javascript:alert(document.cookie)",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>"
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "....//....//....//etc/passwd"
        ],
        'command_injection': [
            "; cat /etc/passwd",
            "&& whoami",
            "| dir",
            "`id`"
        ],
        'brute_force': [
            "Failed login from 192.168.1.100",
            "Authentication failed for user admin from 192.168.1.100",
            "Login attempt failed from IP 10.0.0.5"
        ]
    }


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Clean up any test files created during tests."""
    yield
    # Cleanup code would go here if needed
    # This fixture runs automatically before and after each test


@pytest.fixture
def mock_scapy():
    """Mock scapy module for network tests."""
    mock_scapy = MagicMock()
    mock_scapy.sniff = MagicMock()
    mock_scapy.get_working_ifaces = MagicMock(return_value=[])
    mock_scapy.IP = MagicMock()
    mock_scapy.TCP = MagicMock()
    mock_scapy.Dot11Beacon = MagicMock()
    return mock_scapy


@pytest.fixture
def mock_watchdog():
    """Mock watchdog module for host tests."""
    mock_watchdog = MagicMock()
    mock_observer = MagicMock()
    mock_watchdog.Observer = MagicMock(return_value=mock_observer)
    return mock_watchdog


@pytest.fixture
def mock_tailer():
    """Mock tailer module for app tests."""
    mock_tailer = MagicMock()
    mock_tailer.follow = MagicMock(return_value=[])
    return mock_tailer


# Test markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "unit: mark test as unit test")


# Test collection modifications
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Mark tests based on their file location
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)

        # Mark slow tests
        if "slow" in item.name or "performance" in item.name:
            item.add_marker(pytest.mark.slow)