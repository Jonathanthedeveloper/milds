from typing import TypedDict, Any
from dataclasses import dataclass, field
from pathlib import Path
import json

# Optional YAML support
try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False


class ConfigDict(TypedDict, total=False):
    logs_dir: str
    app_log_file: str
    monitor_dir: str
    port_scan_threshold: int
    brute_force_threshold: int
    packet_rate_threshold: int
    anomaly_window: int
    sleep_idle: float
    log_window: int
    enable_network: bool
    console_color: bool
    actions: dict
    tcp_sink_enabled: bool
    tcp_sink_host: str
    tcp_sink_port: int
    app_rules: dict
    allow_firewall_actions: bool
    allow_system_commands: bool
    rules_file: str
    rule_meta: dict
    mfa_totp_enabled: bool
    mfa_totp_secret: str
    intel_ip_file: str
    websocket_sink_enabled: bool
    websocket_sink_host: str
    websocket_sink_port: int


@dataclass
class Config:
    logs_dir: str = "logs"
    app_log_file: str = "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log"
    monitor_dir: str = str(Path.home())
    port_scan_threshold: int = 10
    brute_force_threshold: int = 5
    packet_rate_threshold: int = 100
    anomaly_window: int = 60
    sleep_idle: float = 0.1
    log_window: int = 1000
    enable_network: bool = False
    console_color: bool = True
    actions: dict = field(default_factory=dict)  # mapping event_type -> list of action dicts
    tcp_sink_enabled: bool = False
    tcp_sink_host: str = "127.0.0.1"
    tcp_sink_port: int = 8765
    app_rules: dict = field(default_factory=dict)
    allow_firewall_actions: bool = False
    allow_system_commands: bool = False
    rules_file: str = "rules/default_rules.yaml"
    rule_meta: dict = field(default_factory=dict)
    mfa_totp_enabled: bool = False
    # Do NOT store secrets in source-controlled config files. Prefer environment variables
    # or a secret manager. This default is intentionally empty.
    mfa_totp_secret: str = ""
    intel_ip_file: str = ""
    websocket_sink_enabled: bool = False
    websocket_sink_host: str = "127.0.0.1"
    websocket_sink_port: int = 8766


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        return Config()
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    # choose parser based on availability or extension
    data = {}
    if str(path).lower().endswith(('.yaml', '.yml')):
        try:
            if YAML_AVAILABLE:
                loaded = yaml.safe_load(text)  # type: ignore[union-attr]
                data = loaded if isinstance(loaded, dict) else {}
            else:
                data = {}
        except Exception:
            data = {}
    else:
        try:
            data = json.loads(text)
        except Exception:
            try:
                if YAML_AVAILABLE:
                    loaded = yaml.safe_load(text)  # type: ignore[union-attr]
                    data = loaded if isinstance(loaded, dict) else {}
                else:
                    data = {}
            except Exception:
                data = {}
            
    cfg = Config()
    if isinstance(data, dict):
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    # Load external rules file (YAML) into app_rules and rule_meta if available
    try:
        rules_path = Path(getattr(cfg, 'rules_file', ''))
        if rules_path and rules_path.exists():
            if YAML_AVAILABLE:
                loaded = yaml.safe_load(rules_path.read_text(encoding='utf-8'))  # type: ignore[union-attr]
                rules_doc = loaded if isinstance(loaded, dict) else {}
            else:
                rules_doc = {}
            rules = rules_doc.get('rules', []) if isinstance(rules_doc, dict) else []
            for r in rules:
                if not r.get('enabled', True):
                    continue
                name = r.get('name')
                pattern = r.get('pattern')
                if name and pattern:
                    cfg.app_rules[name] = pattern
                    cfg.rule_meta[name] = {
                        'category': r.get('category', 'app'),
                        'severity': r.get('severity', 'medium')
                    }
    except Exception:
        pass
    return cfg


def save_config(cfg: Config, path: str | Path) -> None:
    path = Path(path)
    data = {k: getattr(cfg, k) for k in cfg.__dict__.keys()}
    with open(path, 'w', encoding='utf-8') as f:
        # Prefer JSON for .json files. Use YAML only for yaml/yml paths when available.
        suffix = str(path).lower()
        if suffix.endswith(('.yaml', '.yml')) and YAML_AVAILABLE:
            try:
                yaml.safe_dump(data, f)  # type: ignore[union-attr]
                return
            except Exception:
                pass
        # default to JSON
        json.dump(data, f, indent=2)
