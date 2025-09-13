#!/usr/bin/env python
"""
MLIDS - Multi-Level Intrusion Detection System
Main CLI application
"""

import json
import time
import threading
import argparse
import platform
import os
import sys
import getpass
import pandas as pd  # type: ignore
import numpy as np  # type: ignore
import matplotlib
import matplotlib.pyplot as plt

def main():
    """Main entry point for MLIDS CLI"""
    # Import here to avoid circular imports
    from milds.config import load_config, Config
    from milds.logger import get_logger
    from milds.host import host_monitor as ml_host_monitor
    from milds.net import network_monitor as ml_network_monitor
    from milds.app import app_monitor as ml_app_monitor
    from milds.events import EventDispatcher, TcpSinkServer
    from milds.events import WebSocketSinkServer

    # Config defaults
    CONFIG = {
        'logs_dir': 'logs',
        'app_log_file': 'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log' if platform.system() == 'Windows' else '/var/log/apache2/access.log',
        'monitor_dir': os.path.expanduser('~'),  # User home for default
        'port_scan_threshold': 10,
        'brute_force_threshold': 5,
        'packet_rate_threshold': 100,
        'anomaly_window': 60,
        'sleep_idle': 0.1,
        'log_window': 1000,  # Max log entries for analysis
        'enable_network': False,
        'console_color': True,
        'tcp_sink_enabled': False,
        'tcp_sink_host': '127.0.0.1',
        'tcp_sink_port': 8765,
    }

    # Try to load project config.yaml (optional)
    DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        cfg_obj = load_config(DEFAULT_CONFIG_PATH)
        # overlay values into CONFIG dict (only keys that exist)
        for k, v in cfg_obj.__dict__.items():
            if k in CONFIG and v is not None:
                CONFIG[k] = v
    except Exception:
        pass

    # CLI Parser
    parser = argparse.ArgumentParser(description="Multi-Level IDS CLI Tool")
    subparsers = parser.add_subparsers(dest='command')

    # Start monitoring
    start_parser = subparsers.add_parser('start', help='Start monitoring')
    start_parser.add_argument('--interface', default=None, help='Network interface (default: auto)')
    start_parser.add_argument('--app-log', help='Application log file')
    start_parser.add_argument('--dir', help='Directory to monitor')
    start_parser.add_argument('--enable-net', action='store_true', help='Enable network sniffing (requires pcap/Npcap and privileges)')
    start_parser.add_argument('--tcp-sink', action='store_true', help='Enable TCP JSON-line sink for alerts (for external GUIs)')
    start_parser.add_argument('--tcp-host', default=None, help='TCP sink host (default from config)')
    start_parser.add_argument('--tcp-port', type=int, default=None, help='TCP sink port (default from config)')
    start_parser.add_argument('--ws-sink', action='store_true', help='Enable WebSocket sink for alerts')
    start_parser.add_argument('--ws-host', default=None, help='WebSocket sink host (default from config)')
    start_parser.add_argument('--ws-port', type=int, default=None, help='WebSocket sink port (default from config)')

    # Analyze logs
    analyze_parser = subparsers.add_parser('analyze', help='Analyze logs')
    analyze_parser.add_argument('--search', help='Search term in logs')
    analyze_parser.add_argument('--report', choices=['compliance'], help='Generate a report to logs directory')
    analyze_parser.add_argument('--plot', action='store_true', help='Generate a summary plot of event types')
    analyze_parser.add_argument('--plot-path', help='Path to save the plot image (default: logs/summary.png)')

    # Config
    config_parser = subparsers.add_parser('config', help='Set config')
    config_parser.add_argument('--key', help='Config key')
    config_parser.add_argument('--value', help='Config value')

    args = parser.parse_args()

    if args.command == 'start':
        if args.app_log:
            CONFIG['app_log_file'] = args.app_log
        if args.dir:
            CONFIG['monitor_dir'] = args.dir
        if args.enable_net:
            CONFIG['enable_network'] = True
        if args.tcp_sink:
            CONFIG['tcp_sink_enabled'] = True
        if args.tcp_host:
            CONFIG['tcp_sink_host'] = args.tcp_host
        if args.tcp_port:
            CONFIG['tcp_sink_port'] = args.tcp_port
        if args.ws_sink:
            CONFIG['websocket_sink_enabled'] = True
        if args.ws_host:
            CONFIG['websocket_sink_host'] = args.ws_host
        if args.ws_port:
            CONFIG['websocket_sink_port'] = args.ws_port

        # Initialize structured logger
        # Initialize structured logger (defaults to log unless logs_dir overridden)
        logger = get_logger('mlids', logs_dir=CONFIG.get('logs_dir'), console_color=CONFIG.get('console_color', True))

        # Optional MFA TOTP gate
        if CONFIG.get('mfa_totp_enabled'):
            try:
                import pyotp  # type: ignore
                secret = CONFIG.get('mfa_totp_secret')
                if not secret:
                    logger.error('MFA enabled but no secret configured')
                    sys.exit(1)
                code = getpass.getpass('Enter MFA code: ')
                if not pyotp.TOTP(secret).verify(code):
                    logger.error('Invalid MFA code')
                    sys.exit(1)
            except Exception as e:
                logger.error(f'MFA error: {e}')
                sys.exit(1)

        # Start TCP sink if enabled and create dispatcher
        tcp_sink = None
        ws_sink = None
        if CONFIG.get('tcp_sink_enabled'):
            tcp_sink = TcpSinkServer(CONFIG.get('tcp_sink_host', '127.0.0.1'), int(CONFIG.get('tcp_sink_port', 8765)), logger)
            tcp_sink.start()
        if CONFIG.get('websocket_sink_enabled'):
            ws_sink = WebSocketSinkServer(CONFIG.get('websocket_sink_host', '127.0.0.1'), int(CONFIG.get('websocket_sink_port', 8766)), logger)
            ws_sink.start()
        actions_cfg = CONFIG.get('actions', {}) if isinstance(CONFIG.get('actions', {}), dict) else {}
        intel_ips = set()
        try:
            intel_file = CONFIG.get('intel_ip_file')
            if intel_file and os.path.exists(intel_file):
                with open(intel_file, 'r', encoding='utf-8') as f:
                    intel_ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        except Exception:
            pass
        dispatcher = EventDispatcher(
            logger,
            tcp_sink=tcp_sink,
            ws_sink=ws_sink,
            actions=actions_cfg,
            allow_firewall=bool(CONFIG.get('allow_firewall_actions', False)),
            allow_commands=bool(CONFIG.get('allow_system_commands', False)),
            intel_ips=intel_ips
        )

        # Start modular monitors
        cfg = Config(**CONFIG)
        threading.Thread(target=lambda: ml_network_monitor(cfg, logger, args.interface, dispatcher), daemon=True).start()
        threading.Thread(target=lambda: ml_host_monitor(cfg, logger, dispatcher), daemon=True).start()
        threading.Thread(target=lambda: ml_app_monitor(cfg, logger, None, dispatcher), daemon=True).start()
        logger.info('Monitoring started. Press Ctrl+C to stop.')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info('Stopping monitoring.')

    elif args.command == 'analyze':
        # Read all JSON log files in the configured logs directory (recursively).
        logs_dir = CONFIG.get('logs_dir', 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        pattern = os.path.join(logs_dir, '**', '*.json')
        files = sorted([f for f in __import__('glob').glob(pattern, recursive=True) if os.path.isfile(f)])
        if not files:
            print("No logs found in", logs_dir)
            sys.exit(0)


        # Aggregate JSON lines from found files (most recent files last)
        logs = []
        for fname in files:
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            logs.append(json.loads(line))
                        except Exception:
                            continue
            except Exception:
                continue

        if not logs:
            print("No valid log entries found in", logs_dir)
            sys.exit(0)

        # Limit to the configured window if needed
        recent_logs = logs[-CONFIG.get('log_window', 1000):]


        # Build DataFrame from aggregated logs (if available)
        df = pd.DataFrame(recent_logs)
        if args.search:
            filtered = df[df.apply(lambda x: args.search.lower() in str(x).lower(), axis=1)]
            print(filtered.to_json(orient='records', lines=True, indent=2))
        else:
            print("Log Summary:")
            print(df['type'].value_counts())
            if args.report == 'compliance':
                outdir = CONFIG.get('logs_dir', '.')
                os.makedirs(outdir, exist_ok=True)
                outfile = os.path.join(outdir, 'compliance_report.csv')
                df[['timestamp', 'type']].to_csv(outfile, index=False)
                print(f"Compliance report written to {outfile}")
            if args.plot:
                matplotlib.use('Agg')
                counts = df['type'].value_counts()
                fig, ax = plt.subplots(figsize=(8, 4.5))
                counts.plot(kind='bar', ax=ax, color='#4C78A8')
                ax.set_title('MLIDS Event Types Summary')
                ax.set_xlabel('Event Type')
                ax.set_ylabel('Count')
                plt.tight_layout()
                outdir = CONFIG.get('logs_dir', '.')
                os.makedirs(outdir, exist_ok=True)
                outpath = args.plot_path or os.path.join(outdir, 'summary.png')
                plt.savefig(outpath)
                print(f"Summary plot written to {outpath}")
                    
            # Anomaly: High event rate
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            recent = df[df['timestamp'] > df['timestamp'].max() - pd.Timedelta(seconds=CONFIG['anomaly_window'])]
            counts = recent.groupby('type').size()
            if not counts.empty:
                median = counts.median()
                mad = np.median(np.abs(counts - median))
                if mad > 0:
                    outliers = counts[abs(counts - median) / mad > 3]
                    if not outliers.empty:
                        print("Anomalous event rates:", outliers.to_dict())

    elif args.command == 'config':
        if args.key in CONFIG:
            CONFIG[args.key] = type(CONFIG[args.key])(args.value)
            print(f"Set {args.key} to {CONFIG[args.key]}")
        else:
            print("Invalid key.")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()