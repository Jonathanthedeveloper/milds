"""
Integration tests for MLIDS system components working together.
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock
from milds.config import Config, load_config
from milds.logger import get_logger
from milds.events import EventDispatcher


def test_full_system_initialization():
    """Test that all system components can be initialized together."""
    # Create a comprehensive configuration
    cfg = Config(
        logs_dir="test_logs",
        enable_network=False,  # Disable network for testing
        tcp_sink_enabled=True,
        tcp_sink_host="127.0.0.1",
        tcp_sink_port=8888,
        websocket_sink_enabled=True,
        websocket_sink_host="127.0.0.1",
        websocket_sink_port=8889,
        allow_firewall_actions=False,
        allow_system_commands=False
    )

    # Initialize logger (writes to cfg.logs_dir/mlids.json)
    logger = get_logger("integration_test", logs_dir=cfg.logs_dir)

    # Initialize event dispatcher
    dispatcher = EventDispatcher(
        logger=logger,
        tcp_sink=None,  # Skip sinks for this test
        ws_sink=None,
        actions={},
        allow_firewall=False,
        allow_commands=False
    )

    # Verify components are properly initialized
    assert cfg is not None
    assert logger is not None
    assert dispatcher is not None
    assert dispatcher.logger == logger


def test_config_file_integration(temp_dir):
    """Test loading configuration from file and using it throughout the system."""
    # Create a test config file
    config_data = {
        "log_file": "integration.log",
        "logs_dir": "logs",
        "port_scan_threshold": 10,
        "brute_force_threshold": 5,
        "enable_network": False,
        "tcp_sink_enabled": True,
        "tcp_sink_host": "127.0.0.1",
        "tcp_sink_port": 8765,
        "allow_firewall_actions": False,
        "allow_system_commands": False
    }

    config_file = os.path.join(temp_dir, "test_config.json")
    import json
    with open(config_file, 'w') as f:
        json.dump(config_data, f)

    # Load configuration
    cfg = load_config(config_file)

    # Verify configuration was loaded correctly (log_file is not retained on Config)
    assert cfg.logs_dir == "logs"
    assert cfg.port_scan_threshold == 10
    assert cfg.tcp_sink_enabled is True

    # Use configuration with logger (use cfg.logs_dir)
    logger = get_logger("test", logs_dir=cfg.logs_dir)

    # Verify logger was created with correct configuration
    assert logger is not None


def test_event_dispatcher_with_actions():
    """Test event dispatcher with various action types."""
    logger = MagicMock()
    actions = {
        "SQL Injection": [
            {"type": "print"},
            {"type": "webhook", "url": "http://example.local"}
        ],
        "File Change": [
            {"type": "run", "cmd": "echo 'File changed'"}
        ]
    }

    dispatcher = EventDispatcher(
        logger=logger,
        actions=actions,
        allow_firewall=False,
        allow_commands=False
    )

    # Emit an event
    dispatcher.emit("SQL Injection", {"line": "SELECT * FROM users"})

    # Verify event was logged
    logger.warning.assert_called()

    # Verify actions were processed (print action should log)
    print_calls = [call for call in logger.warning.call_args_list
                   if 'ACTION print' in str(call)]
    assert len(print_calls) > 0


def test_system_with_mocked_dependencies():
    """Test system initialization with mocked external dependencies."""
    cfg = Config(enable_network=False)

    with patch('mlids.app.tailer', None):  # Simulate tailer not available
        with patch('mlids.net.scapy', None):  # Simulate scapy not available
            with patch('mlids.host.FileSystemEventHandler', None), \
                 patch('mlids.host.Observer', None):  # Simulate watchdog not available
                # System should still initialize gracefully
                logger = MagicMock()
                dispatcher = EventDispatcher(logger=logger)

                assert logger is not None
                assert dispatcher is not None

                # Emit an event - should work even with missing dependencies
                dispatcher.emit("Test Event", {"message": "test"})

                # Should have logged the event
                logger.warning.assert_called()


@pytest.mark.slow
def test_performance_basic_operations():
    """Test basic operations perform adequately."""
    import time

    cfg = Config()
    logger = get_logger("performance_test")

    # Test configuration loading performance
    start_time = time.time()
    for _ in range(100):
        test_cfg = Config()
    config_time = time.time() - start_time

    # Test event dispatching performance
    dispatcher = EventDispatcher(logger=logger)
    start_time = time.time()
    for i in range(1000):
        dispatcher.emit("Performance Test", {"iteration": i})
    dispatch_time = time.time() - start_time

    # Performance should be reasonable (adjust thresholds as needed)
    assert config_time < 1.0, f"Config creation too slow: {config_time}s"
    assert dispatch_time < 5.0, f"Event dispatching too slow: {dispatch_time}s"


def test_error_handling_integration():
    """Test that system handles various error conditions gracefully."""
    cfg = Config()

    # Test with invalid log directory using a MagicMock logger
    from unittest.mock import MagicMock
    logger = MagicMock()

    # Should still work (logger should handle the error)
    assert logger is not None

    # Test event dispatcher with invalid actions
    dispatcher = EventDispatcher(
        logger=logger,
        actions={"Test": [{"type": "invalid_action"}]}
    )

    # Should handle invalid action gracefully
    dispatcher.emit("Test", {"data": "test"})

    # Should have logged the event even with invalid action
    logger.warning.assert_called()


def test_configuration_persistence(temp_dir):
    """Test that configuration can be saved and loaded correctly."""
    from milds.config import save_config

    # Create a custom configuration
    original_cfg = Config(
        port_scan_threshold=15,
        enable_network=True,
        tcp_sink_enabled=True,
        tcp_sink_host="192.168.1.100",
        tcp_sink_port=9999
    )

    # Save configuration
    config_file = os.path.join(temp_dir, "saved_config.json")
    save_config(original_cfg, config_file)

    # Load configuration
    loaded_cfg = load_config(config_file)

    # Verify saved file does not include 'log_file' (Config no longer contains that attribute)
    import json as _json
    with open(config_file, 'r', encoding='utf-8') as _f:
        saved = _json.load(_f)
    assert 'log_file' not in saved
    assert loaded_cfg.port_scan_threshold == original_cfg.port_scan_threshold
    assert loaded_cfg.enable_network == original_cfg.enable_network
    assert loaded_cfg.tcp_sink_enabled == original_cfg.tcp_sink_enabled
    assert loaded_cfg.tcp_sink_host == original_cfg.tcp_sink_host
    assert loaded_cfg.tcp_sink_port == original_cfg.tcp_sink_port