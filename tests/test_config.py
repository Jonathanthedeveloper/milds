import pytest
import json
import tempfile
import os
from pathlib import Path
from milds.config import Config, load_config, save_config, YAML_AVAILABLE


class TestConfig:
    def test_default_config(self):
        """Test default configuration values."""
        cfg = Config()
        assert cfg.logs_dir == "logs"
        assert cfg.port_scan_threshold == 10
        assert cfg.brute_force_threshold == 5
        assert cfg.enable_network is False
        assert cfg.console_color is True
        assert cfg.tcp_sink_enabled is False
        assert cfg.allow_firewall_actions is False
        assert cfg.allow_system_commands is False

    def test_config_with_custom_values(self):
        """Test configuration with custom values."""
        cfg = Config(
            port_scan_threshold=20,
            enable_network=True,
            tcp_sink_enabled=True,
            tcp_sink_host="192.168.1.100",
            tcp_sink_port=9999
        )
        assert cfg.port_scan_threshold == 20
        assert cfg.enable_network is True
        assert cfg.tcp_sink_enabled is True
        assert cfg.tcp_sink_host == "192.168.1.100"
        assert cfg.tcp_sink_port == 9999

    def test_load_config_json(self):
        """Test loading configuration from JSON file."""
        config_data = {
            "log_file": "test_logs.json",
            "port_scan_threshold": 15,
            "enable_network": True,
            "tcp_sink_enabled": True,
            "tcp_sink_host": "127.0.0.1",
            "tcp_sink_port": 8080,
            "allow_firewall_actions": True
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            cfg = load_config(config_path)
            assert cfg.port_scan_threshold == 15
            assert cfg.enable_network is True
            assert cfg.tcp_sink_enabled is True
            assert cfg.tcp_sink_host == "127.0.0.1"
            assert cfg.tcp_sink_port == 8080
            assert cfg.allow_firewall_actions is True
        finally:
            os.unlink(config_path)

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not available")
    def test_load_config_yaml(self):
        """Test loading configuration from YAML file."""
        import yaml

        config_data = {
            "log_file": "test_logs.yaml",
            "brute_force_threshold": 3,
            "websocket_sink_enabled": True,
            "websocket_sink_host": "localhost",
            "websocket_sink_port": 8766
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.safe_dump(config_data, f)
            config_path = f.name

        try:
            cfg = load_config(config_path)
            assert cfg.brute_force_threshold == 3
            assert cfg.websocket_sink_enabled is True
            assert cfg.websocket_sink_host == "localhost"
            assert cfg.websocket_sink_port == 8766
        finally:
            os.unlink(config_path)

    def test_load_config_nonexistent_file(self):
        """Test loading configuration from non-existent file returns defaults."""
        cfg = load_config("nonexistent_file.json")
        assert cfg.enable_network is False

    def test_load_config_invalid_json(self):
        """Test loading configuration from invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content {")
            config_path = f.name

        try:
            cfg = load_config(config_path)
            # Should return defaults when JSON is invalid
            # log_file is no longer part of Config; just ensure defaults applied
            assert cfg.enable_network is False
        finally:
            os.unlink(config_path)

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not available")
    def test_load_config_with_rules_file(self):
        """Test loading configuration with external rules file."""
        import yaml

        # Create rules file
        rules_data = {
            "rules": [
                {
                    "name": "Test SQL Injection",
                    "pattern": "SELECT.*FROM.*WHERE",
                    "category": "sql",
                    "severity": "high",
                    "enabled": True
                },
                {
                    "name": "Test XSS",
                    "pattern": "<script>.*</script>",
                    "category": "xss",
                    "severity": "medium",
                    "enabled": False  # disabled rule
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.safe_dump(rules_data, f)
            rules_path = f.name

        # Create config file that references the rules file
        config_data = {
            "rules_file": rules_path
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            cfg = load_config(config_path)
            # Should have loaded the enabled rule
            assert "Test SQL Injection" in cfg.app_rules
            assert cfg.app_rules["Test SQL Injection"] == "SELECT.*FROM.*WHERE"
            assert cfg.rule_meta["Test SQL Injection"]["category"] == "sql"
            assert cfg.rule_meta["Test SQL Injection"]["severity"] == "high"
            # Disabled rule should not be loaded
            assert "Test XSS" not in cfg.app_rules
        finally:
            os.unlink(rules_path)
            os.unlink(config_path)

    def test_save_config_json(self):
        """Test saving configuration to JSON file."""
        cfg = Config(
            port_scan_threshold=25,
            enable_network=True
        )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = f.name

        try:
            save_config(cfg, config_path)

            # Load it back and verify
            with open(config_path, 'r') as f:
                saved_data = json.load(f)

            assert saved_data["port_scan_threshold"] == 25
            assert saved_data["enable_network"] is True
        finally:
            os.unlink(config_path)

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not available")
    def test_save_config_yaml(self):
        """Test saving configuration to YAML file."""
        import yaml

        cfg = Config(
            brute_force_threshold=8,
            console_color=False
        )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_path = f.name

        try:
            save_config(cfg, config_path)

            # Load it back and verify
            with open(config_path, 'r') as f:
                saved_data = yaml.safe_load(f)

            assert saved_data["brute_force_threshold"] == 8
            assert saved_data["console_color"] is False
        finally:
            os.unlink(config_path)