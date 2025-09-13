import io
import logging
import pytest
from unittest.mock import patch, MagicMock
from milds.config import Config
from milds.app import detect_log_line, app_monitor


def test_detect_sql_xss_and_failed_login():
    cfg = Config()
    line_sql = "GET /index.php?id=1' OR 1=1 --"
    events = detect_log_line(line_sql, cfg)
    assert any(e[0] == 'SQL Injection' for e in events)

    line_xss = '<script>alert(1)</script>'
    events = detect_log_line(line_xss, cfg)
    assert any(e[0] == 'XSS Attempt' for e in events)

    line_failed = 'Failed login from 192.168.0.5'
    events = detect_log_line(line_failed, cfg)
    assert any(e[0] == 'Failed Login' for e in events)


def test_detect_path_traversal():
    """Test path traversal detection."""
    cfg = Config()
    line = "../../../etc/passwd"
    events = detect_log_line(line, cfg)
    assert any(e[0] == 'Path Traversal' for e in events)


def test_detect_command_injection():
    """Test command injection detection."""
    cfg = Config()
    line = "; cat /etc/passwd"
    events = detect_log_line(line, cfg)
    assert any(e[0] == 'Command Injection' for e in events)

    line2 = "&& whoami"
    events2 = detect_log_line(line2, cfg)
    assert any(e[0] == 'Command Injection' for e in events2)


def test_detect_configured_rules():
    """Test detection using configured regex rules."""
    cfg = Config()
    cfg.app_rules = {
        'Custom Attack': r'MALICIOUS_PAYLOAD',
        'Another Rule': r'select.*from.*users'
    }

    line = "Found MALICIOUS_PAYLOAD in request"
    events = detect_log_line(line, cfg)
    assert any(e[0] == 'Custom Attack' for e in events)

    line2 = "select name from users where id=1"
    events2 = detect_log_line(line2, cfg)
    assert any(e[0] == 'Another Rule' for e in events2)


def test_detect_multiple_events_in_line():
    """Test detection of multiple event types in a single line."""
    cfg = Config()
    line = "GET /../../../etc/passwd?id=1' OR 1=1 -- <script>alert(1)</script>"
    events = detect_log_line(line, cfg)

    event_types = [e[0] for e in events]
    assert 'SQL Injection' in event_types
    assert 'XSS Attempt' in event_types
    assert 'Path Traversal' in event_types


def test_detect_no_events():
    """Test line with no detectable events."""
    cfg = Config()
    line = "Normal log entry with no suspicious content"
    events = detect_log_line(line, cfg)
    assert events == []


def test_detect_case_insensitive():
    """Test that detection is case insensitive."""
    cfg = Config()
    line = "get /index.php?ID=1' or 1=1 --"
    events = detect_log_line(line, cfg)
    assert any(e[0] == 'SQL Injection' for e in events)


def test_detect_ip_extraction():
    """Test IP address extraction from failed login lines."""
    cfg = Config()
    line = 'Failed login from 10.0.0.5'
    events = detect_log_line(line, cfg)

    failed_login_events = [e for e in events if e[0] == 'Failed Login']
    assert len(failed_login_events) == 1
    assert failed_login_events[0][1]['ip'] == '10.0.0.5'


def test_detect_ip_extraction_various_formats():
    """Test IP extraction with different log formats."""
    cfg = Config()

    test_cases = [
        'Authentication failed for user admin from 192.168.1.100',
        'Login attempt failed from IP 172.16.0.50',
        'Failed authentication from 10.10.10.10: invalid credentials'
    ]

    for line in test_cases:
        events = detect_log_line(line, cfg)
        failed_login_events = [e for e in events if e[0] == 'Failed Login']
        assert len(failed_login_events) == 1, f"Failed to extract IP from: {line}"


def test_app_monitor_emits_bruteforce(caplog):
    cfg = Config(brute_force_threshold=2)
    # supply a fake file-like object with three failed login lines
    fake = io.StringIO('\n'.join([
        'Failed login from 10.0.0.1',
        'Failed login from 10.0.0.1',
        'Failed login from 10.0.0.1',
    ]))
    # Create a logger that will be captured by caplog
    logger = logging.getLogger('test_bruteforce')
    logger.setLevel(logging.WARNING)
    app_monitor(cfg, logger=logger, fileobj=fake)
    # caplog records warnings; check that brute force was logged
    msgs = [r.getMessage() for r in caplog.records]
    assert any('Brute Force' in m or 'Brute force' in m for m in msgs)


def test_app_monitor_with_dispatcher():
    """Test app monitor with event dispatcher."""
    cfg = Config(brute_force_threshold=2)
    logger = MagicMock()
    dispatcher = MagicMock()

    fake = io.StringIO('\n'.join([
        'Failed login from 10.0.0.1',
        'Failed login from 10.0.0.1',
        'Failed login from 10.0.0.1',
    ]))

    app_monitor(cfg, logger, fileobj=fake, dispatcher=dispatcher)

    # Should emit events via dispatcher
    assert dispatcher.emit.call_count >= 3  # At least 3 failed logins

    # Should emit brute force event
    brute_force_calls = [call for call in dispatcher.emit.call_args_list
                        if call[0][0] == 'Brute Force']
    assert len(brute_force_calls) >= 1


def test_app_monitor_file_not_found():
    """Test app monitor when log file doesn't exist."""
    cfg = Config(app_log_file="/nonexistent/logfile.log")
    logger = MagicMock()

    app_monitor(cfg, logger)

    # Should log that app log is not found
    logger.info.assert_called_with('App log not found', extra={'extra': {'path': '/nonexistent/logfile.log'}})


def test_app_monitor_tailer_unavailable():
    """Test app monitor when tailer is not available."""
    cfg = Config(app_log_file="/tmp/test.log")
    logger = MagicMock()

    # Mock tailer as None
    with patch('mlids.app.tailer', None):
        app_monitor(cfg, logger)

        # Should log that app monitoring is skipped
        logger.info.assert_called_with('App monitoring skipped: tailer not available')


def test_app_monitor_with_real_file():
    """Test app monitor with a real temporary file."""
    import tempfile
    import os

    cfg = Config(brute_force_threshold=2)
    logger = MagicMock()
    dispatcher = MagicMock()

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('Failed login from 10.0.0.1\n')
        f.write('Failed login from 10.0.0.1\n')
        f.write('Failed login from 10.0.0.1\n')
        temp_file = f.name

    try:
        cfg.app_log_file = temp_file
        # Use a short monitoring session to avoid hanging
        with patch('mlids.app.tailer.follow') as mock_follow:
            mock_follow.return_value = [
                'Failed login from 10.0.0.1',
                'Failed login from 10.0.0.1',
                'Failed login from 10.0.0.1'
            ]
            app_monitor(cfg, logger, dispatcher=dispatcher)

        # Should have processed the lines
        assert dispatcher.emit.call_count > 0

    finally:
        os.unlink(temp_file)


def test_app_monitor_handles_exceptions():
    """Test app monitor handles file opening exceptions."""
    # Use a directory path that exists but can't be opened as a file
    cfg = Config(app_log_file="/")
    logger = MagicMock()

    app_monitor(cfg, logger)

    # Should log the failure
    logger.info.assert_called_with('Failed to open app log',
                                  extra={'extra': {'path': '/',
                                                 'error': "[Errno 13] Permission denied: '/'"}})
def test_detect_log_line_with_config_rules():
    """Test detect_log_line with various configured rules."""
    cfg = Config()
    cfg.app_rules = {
        'SQL Injection': r'union.*select',
        'File Inclusion': r'\.\./\.\./',
        'Code Execution': r'eval\(|exec\('
    }

    test_cases = [
    ('SELECT * FROM users UNION SELECT username FROM admin', 'SQL Injection'),
        ('../../../etc/passwd', 'File Inclusion'),
        ('eval($_GET["cmd"])', 'Code Execution')
    ]

    for line, expected_event in test_cases:
        events = detect_log_line(line, cfg)
        assert any(e[0] == expected_event for e in events), f"Failed to detect {expected_event} in: {line}"


def test_detect_log_line_rule_precedence():
    """Test that configured rules take precedence over built-in patterns."""
    cfg = Config()
    # Override built-in SQL pattern with a custom one
    cfg.app_rules = {
        'SQL Injection': r'custom_sql_pattern'
    }

    # This would match built-in pattern but not custom
    line = "SELECT * FROM users WHERE id=1' OR '1'='1"
    events = detect_log_line(line, cfg)

    # Should not match built-in SQL pattern since we overrode it
    sql_events = [e for e in events if e[0] == 'SQL Injection']
    assert len(sql_events) == 0

    # This should match custom pattern
    line2 = "Found custom_sql_pattern in log"
    events2 = detect_log_line(line2, cfg)
    sql_events2 = [e for e in events2 if e[0] == 'SQL Injection']
    assert len(sql_events2) == 1


def test_app_monitor_brute_force_threshold():
    """Test brute force detection with different thresholds."""
    test_cases = [
        (1, 2, True),   # threshold=1, 2 attempts -> should trigger
        (3, 2, False),  # threshold=3, 2 attempts -> should not trigger
        (2, 3, True),   # threshold=2, 3 attempts -> should trigger
    ]

    for threshold, attempts, should_trigger in test_cases:
        cfg = Config(brute_force_threshold=threshold)
        logger = MagicMock()
        dispatcher = MagicMock()

        lines = ['Failed login from 192.168.1.1'] * attempts
        fake = io.StringIO('\n'.join(lines))

        app_monitor(cfg, logger, fileobj=fake, dispatcher=dispatcher)

        brute_force_calls = [call for call in dispatcher.emit.call_args_list
                           if call[0][0] == 'Brute Force']

        if should_trigger:
            assert len(brute_force_calls) >= 1, f"Should trigger brute force with threshold={threshold}, attempts={attempts}"
        else:
            assert len(brute_force_calls) == 0, f"Should not trigger brute force with threshold={threshold}, attempts={attempts}"
