"""Application log monitoring helpers.

Exposes `app_monitor(cfg, logger)` that tails the configured application log file
and emits structured events. If `tailer` is missing, the function returns early.
"""
from .config import Config
import os
import re
from collections import defaultdict
import logging
from typing import Optional, IO
from .events import EventDispatcher

try:
    import tailer
except Exception:
    tailer = None

SQL_INJECTION_PATTERNS = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\bOR\b\s+1=1)|(\bAND\b\s+1=1)", re.IGNORECASE)
XSS_PATTERNS = re.compile(r"(<script>)|(alert\()|(<img src=javascript:)", re.IGNORECASE)
PATH_TRAVERSAL = re.compile(r"\.\./|\..\\", re.IGNORECASE)
CMD_INJECTION = re.compile(r"(;|&&|\|\|)\s*(cat|type|whoami|id|dir|ls)\b", re.IGNORECASE)


def detect_log_line(line: str, cfg: Config) -> list[tuple[str, dict]]:
    """Return list of (event_type, details) detected in the log line.

    This pure function is easy to unit test with synthetic lines.
    """
    events: list[tuple[str, dict]] = []

    # Get custom rule names to avoid duplicates
    custom_rule_names = set(cfg.app_rules.keys()) if cfg.app_rules else set()

    # Check built-in patterns only if not overridden by custom rules
    if 'SQL Injection' not in custom_rule_names and SQL_INJECTION_PATTERNS.search(line):
        events.append(('SQL Injection', {'line': line}))
    if 'XSS Attempt' not in custom_rule_names and XSS_PATTERNS.search(line):
        events.append(('XSS Attempt', {'line': line}))
    if 'Path Traversal' not in custom_rule_names and PATH_TRAVERSAL.search(line):
        events.append(('Path Traversal', {'line': line}))
    if 'Command Injection' not in custom_rule_names and CMD_INJECTION.search(line):
        events.append(('Command Injection', {'line': line}))

    # Config-driven rules (regex): cfg.app_rules can contain { name: pattern }
    for name, pattern in (cfg.app_rules or {}).items():
        try:
            rx = re.compile(pattern, re.IGNORECASE)
            if rx.search(line):
                events.append((name, {'line': line}))
        except Exception:
            pass

    match = re.search(r'(?:failed|Failed).*?(?:from|From)(?:\s+IP)?\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
    if match:
        src_ip = match.group(1)
        events.append(('Failed Login', {'ip': src_ip}))
    return events


def app_monitor(cfg: Config, logger: logging.Logger, fileobj: Optional[IO[str]] = None, dispatcher: Optional[EventDispatcher] = None):
    """Tail `cfg.app_log_file` (or supplied fileobj) and emit structured events.

    The `fileobj` parameter is for testing: pass an open text file or StringIO to avoid
    relying on the filesystem tailer in unit tests.
    """
    if fileobj is None and not tailer:
        logger.info('App monitoring skipped: tailer not available')
        return

    path = cfg.app_log_file
    if fileobj is None and not os.path.exists(path):
        logger.info('App log not found', extra={'extra': {'path': path}})
        return

    failed_logins: dict[str, int] = defaultdict(int)

    def emit(event_type: str, details: dict):
        # convert Failed Login into Brute Force if threshold exceeded
        if event_type == 'Failed Login':
            ip = details.get('ip')
            if not ip:
                return
            failed_logins[ip] += 1
            # Always emit the individual failed login event
            logger.warning(event_type, extra={'extra': details})
            if dispatcher:
                dispatcher.emit(event_type, details)
            # Also emit brute force if threshold exceeded
            if failed_logins[ip] > cfg.brute_force_threshold:
                logger.warning('Brute Force', extra={'extra': {'ip': ip}})
                if dispatcher:
                    dispatcher.emit('Brute Force', {'ip': ip})
                failed_logins[ip] = 0
            return
        logger.warning(event_type, extra={'extra': details})
        if dispatcher:
            dispatcher.emit(event_type, details)

    # Use supplied fileobj for tests, otherwise follow file on disk
    if fileobj is not None:
        for raw in fileobj:
            line = raw.strip()
            for ev_type, details in detect_log_line(line, cfg):
                emit(ev_type, details)
        return

    # Real runtime: use tailer.follow and reopen on rotation gracefully
    if tailer is None:
        logger.info('App monitoring skipped: tailer not available')
        return
    try:
        fh = open(path, 'r', encoding='utf-8')
    except Exception as e:
        logger.info('Failed to open app log', extra={'extra': {'path': path, 'error': str(e)}})
        return

    try:
        for line in tailer.follow(fh, delay=cfg.sleep_idle):
            line = line.strip()
            for ev_type, details in detect_log_line(line, cfg):
                emit(ev_type, details)
            # handle log rotation: if file was truncated, reopen
            if fh.tell() > 10_000_000:  # very large file protection
                fh.close()
                fh = open(path, 'r', encoding='utf-8')
    except Exception as e:
        logger.info('App monitor stopped', extra={'extra': {'error': str(e)}})
    finally:
        try:
            fh.close()
        except Exception:
            pass
