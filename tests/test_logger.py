import pytest
import tempfile
import datetime
import os
import json
from unittest.mock import patch, MagicMock
from milds.logger import get_logger, JsonFormatter, RICH_AVAILABLE


class TestJsonFormatter:
    def test_format_basic_record(self):
        """Test JSON formatter with basic log record."""
        formatter = JsonFormatter()
        record = MagicMock()
        record.levelname = "INFO"
        record.getMessage.return_value = "Test message"
        record.name = "test_logger"
        record.extra = None

        # Mock formatTime to return a fixed timestamp
        with patch.object(formatter, 'formatTime', return_value='2023-01-01 12:00:00'):
            result = formatter.format(record)
            data = json.loads(result)

            assert data['timestamp'] == '2023-01-01 12:00:00'
            assert data['level'] == 'INFO'
            assert data['message'] == 'Test message'
            assert data['name'] == 'test_logger'

    def test_format_with_extra_data(self):
        """Test JSON formatter with extra data in log record."""
        formatter = JsonFormatter()
        record = MagicMock()
        record.levelname = "WARNING"
        record.getMessage.return_value = "Alert detected"
        record.name = "mlids"
        record.extra = {'extra': {'type': 'SQL Injection', 'details': {'ip': '192.168.1.1'}}}

        with patch.object(formatter, 'formatTime', return_value='2023-01-01 12:30:00'):
            result = formatter.format(record)
            data = json.loads(result)

            assert data['extra']['type'] == 'SQL Injection'
            assert data['extra']['details']['ip'] == '192.168.1.1'
            assert data['level'] == 'WARNING'
            assert data['message'] == 'Alert detected'

    def test_format_with_exception_in_extra(self):
        """Test JSON formatter handles exceptions when accessing extra data."""
        formatter = JsonFormatter()
        record = MagicMock()
        record.levelname = "ERROR"
        record.getMessage.return_value = "Error occurred"
        record.name = "test"

        # Make getattr raise an exception
        with patch('mlids.logger.getattr', side_effect=Exception("Test error")):
            record.extra = {'extra': {'some': 'data'}}

            with patch.object(formatter, 'formatTime', return_value='2023-01-01 13:00:00'):
                result = formatter.format(record)
                data = json.loads(result)

                # Should still format correctly even with exception
                assert data['level'] == 'ERROR'
                assert data['message'] == 'Error occurred'


class TestGetLogger:
    def test_get_logger_creates_logger_with_defaults(self):
        """Test get_logger creates logger with default parameters."""
        logger = get_logger()

        assert logger.name == 'mlids'
        assert len(logger.handlers) >= 2  # Should have file and console handlers

        # Check that handlers are properly configured
        file_handler = None
        console_handler = None
        for handler in logger.handlers:
            if hasattr(handler, 'baseFilename'):
                file_handler = handler
            else:
                console_handler = handler

        assert file_handler is not None
        assert console_handler is not None
        # Verify file handler has the expected attribute
        assert hasattr(file_handler, 'baseFilename')

    def test_get_logger_with_custom_name_and_file(self):
        """Test get_logger with custom name and log file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Pass logs_dir so the logger writes to the temp directory
            logger = get_logger(name='custom_logger', logs_dir=temp_dir)

            assert logger.name == 'custom_logger'

            # Check file handler points to correct file
            file_handler = None
            for handler in logger.handlers:
                if hasattr(handler, 'baseFilename'):
                    file_handler = handler
                    break

            assert file_handler is not None
            assert hasattr(file_handler, 'baseFilename')
            if hasattr(file_handler, 'baseFilename'):
                assert os.path.dirname(getattr(file_handler, 'baseFilename')) == temp_dir

            # Clean up handlers to avoid Windows file lock issues
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def test_get_logger_creates_logs_directory(self):
        """Test get_logger creates logs directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = os.path.join(temp_dir, 'custom_logs')
            # Ensure directory doesn't exist initially
            assert not os.path.exists(logs_dir)

            # Use unique logger name to ensure fresh logger creation
            logger = get_logger(name='test_logs_dir_logger', logs_dir=logs_dir)

            # Directory should now exist
            assert os.path.exists(logs_dir)

            # File should be in the logs directory
            expected_file = os.path.join(logs_dir, datetime.date.today().isoformat() + '.json')
            file_handler = None
            for handler in logger.handlers:
                if hasattr(handler, 'baseFilename'):
                    file_handler = handler
                    break

            assert file_handler is not None
            assert getattr(file_handler, 'baseFilename') == expected_file

            # Clean up handlers to avoid Windows file lock issues
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def test_get_logger_returns_same_instance(self):
        """Test get_logger returns the same logger instance for same name."""
        logger1 = get_logger(name='test_logger')
        logger2 = get_logger(name='test_logger')

        assert logger1 is logger2

    @pytest.mark.skipif(RICH_AVAILABLE, reason="Rich is available, testing fallback")
    def test_get_logger_console_fallback_without_rich(self):
        """Test console handler fallback when Rich is not available."""
        logger = get_logger(console_color=True)

        # Should have console handler
        console_handler = None
        for handler in logger.handlers:
            if not hasattr(handler, 'baseFilename'):
                console_handler = handler
                break

        assert console_handler is not None
        # Should use JsonFormatter for console when Rich not available
        assert isinstance(console_handler.formatter, JsonFormatter)

    @pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich not available, skipping Rich test")
    def test_get_logger_console_with_rich(self):
        """Test console handler uses Rich when available."""
        logger = get_logger(console_color=True)

        # Should have console handler
        console_handler = None
        for handler in logger.handlers:
            if not hasattr(handler, 'baseFilename'):
                console_handler = handler
                break

        assert console_handler is not None
        # Should use simple formatter for Rich (not JsonFormatter)
        assert not isinstance(console_handler.formatter, JsonFormatter)

    def test_get_logger_no_color_console(self):
        """Test console handler when color is disabled."""
        logger = get_logger(console_color=False)

        # Should have console handler
        console_handler = None
        for handler in logger.handlers:
            if not hasattr(handler, 'baseFilename'):
                console_handler = handler
                break

        assert console_handler is not None
        # Should use JsonFormatter when color is disabled
        assert isinstance(console_handler.formatter, JsonFormatter)