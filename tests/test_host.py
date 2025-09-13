import pytest
import tempfile
import datetime
import os
import time
from unittest.mock import patch, MagicMock
from milds.config import Config
from milds.host import HostEventHandler, host_monitor


class TestHostEventHandler:
    def test_host_event_handler_initialization(self):
        """Test HostEventHandler initialization."""
        cfg = Config(monitor_dir="/tmp")
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk, \
             patch('builtins.open', MagicMock()) as mock_open:
            mock_walk.return_value = [
                ("/tmp", [], ["file1.txt", "file2.txt"])
            ]

            # Mock file reading
            mock_file = MagicMock()
            mock_file.read.return_value = b"content"
            mock_open.return_value.__enter__.return_value = mock_file

            handler = HostEventHandler(cfg, logger, dispatcher)

            assert handler.cfg == cfg
            assert handler.logger == logger
            assert handler.dispatcher == dispatcher
            assert len(handler.baseline) == 2  # Two files
            assert os.path.join("/tmp", "file1.txt") in handler.baseline
            assert os.path.join("/tmp", "file2.txt") in handler.baseline

    def test_update_baseline_skips_log_file(self):
        """Test that baseline creation skips the log file."""
        cfg = Config(monitor_dir="/tmp")
        logger = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk, \
             patch('builtins.open', MagicMock()) as mock_open:
            mock_walk.return_value = [
                ("/tmp", [], ["file1.txt", datetime.date.today().isoformat() + ".json", "file2.txt"])
            ]

            # Mock file reading
            mock_file = MagicMock()
            mock_file.read.return_value = b"content"
            mock_open.return_value.__enter__.return_value = mock_file

            # instruct handler to skip the mlids log filename
            handler = HostEventHandler(cfg, logger, skip_filenames={datetime.date.today().isoformat() + ".json"})

            # Should not include the log file in baseline
            assert (datetime.date.today().isoformat() + ".json") not in handler.baseline
            assert len(handler.baseline) == 2

    def test_update_baseline_skips_logs_dir(self):
        """Test that baseline creation skips files in logs directory."""
        cfg = Config(monitor_dir="/tmp", logs_dir="logs")
        logger = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk, \
             patch('builtins.open', MagicMock()) as mock_open:
            mock_walk.return_value = [
                ("/tmp", ["logs"], ["file1.txt"]),
                ("/tmp/logs", [], ["log1.json", "log2.json"])
            ]

            # Mock file reading
            mock_file = MagicMock()
            mock_file.read.return_value = b"content"
            mock_open.return_value.__enter__.return_value = mock_file

            handler = HostEventHandler(cfg, logger)

            # Should not include files from logs directory
            assert os.path.join("/tmp", "logs", "log1.json") not in handler.baseline
            assert os.path.join("/tmp", "logs", "log2.json") not in handler.baseline
            assert len(handler.baseline) == 1
            assert os.path.join("/tmp", "file1.txt") in handler.baseline

    def test_on_created_adds_to_baseline(self):
        """Test file creation event adds file to baseline."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk', return_value=[("/tmp", [], [])]):
            handler = HostEventHandler(cfg, logger, dispatcher)

        # Simulate file creation
        with patch('builtins.open', MagicMock()) as mock_open:
            mock_file = MagicMock()
            mock_file.read.return_value = b"test content"
            mock_open.return_value.__enter__.return_value = mock_file

            event = MagicMock()
            event.is_directory = False
            event.src_path = "/tmp/newfile.txt"

            handler.on_created(event)

            # Should add to baseline
            assert "/tmp/newfile.txt" in handler.baseline
            # Should log and emit event
            logger.info.assert_called()
            dispatcher.emit.assert_called_with('File Created', {'path': '/tmp/newfile.txt'})

    def test_on_created_skips_directories(self):
        """Test file creation event skips directories."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk', return_value=[("/tmp", [], [])]), \
             patch('builtins.open', MagicMock()) as mock_open:
            # Mock file reading for baseline
            mock_file = MagicMock()
            mock_file.read.return_value = b"content"
            mock_open.return_value.__enter__.return_value = mock_file

            handler = HostEventHandler(cfg, logger, dispatcher)

        # Reset mock to ignore baseline creation calls
        logger.reset_mock()
        dispatcher.reset_mock()

        event = MagicMock()
        event.is_directory = True
        event.src_path = "/tmp/newdir"

        handler.on_created(event)

        # Should not log or emit for directory creation
        logger.info.assert_not_called()
        dispatcher.emit.assert_not_called()

    def test_on_deleted_removes_from_baseline(self):
        """Test file deletion event removes file from baseline."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk:
            mock_walk.return_value = [("/tmp", [], ["test.txt"])]

            with patch('builtins.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"content"
                mock_open.return_value.__enter__.return_value = mock_file

                handler = HostEventHandler(cfg, logger, dispatcher)

        # Verify file is in baseline
        expected_path = os.path.join("/tmp", "test.txt")
        assert expected_path in handler.baseline

        # Simulate file deletion
        event = MagicMock()
        event.is_directory = False
        event.src_path = expected_path

        handler.on_deleted(event)

        # Should remove from baseline
        assert expected_path not in handler.baseline
        # Should log and emit
        logger.info.assert_called()
        dispatcher.emit.assert_called_with('File Deletion', {'path': expected_path})

    def test_on_modified_detects_changes(self):
        """Test file modification detection."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk:
            mock_walk.return_value = [("/tmp", [], ["test.txt"])]

            with patch('builtins.open', MagicMock()) as mock_open:
                # Initial content
                mock_file = MagicMock()
                mock_file.read.return_value = b"original content"
                mock_open.return_value.__enter__.return_value = mock_file

                handler = HostEventHandler(cfg, logger, dispatcher)

        # Reset mock to ignore baseline creation calls
        logger.reset_mock()
        dispatcher.reset_mock()

        # Simulate file modification with different content
        with patch('builtins.open', MagicMock()) as mock_open:
            mock_file = MagicMock()
            mock_file.read.return_value = b"modified content"
            mock_open.return_value.__enter__.return_value = mock_file

            expected_path = os.path.join("/tmp", "test.txt")
            event = MagicMock()
            event.is_directory = False
            event.src_path = expected_path

            handler.on_modified(event)

            # Should detect change and emit
            logger.warning.assert_called()
            dispatcher.emit.assert_called_with('File Change', {'path': expected_path})

    def test_on_modified_no_change(self):
        """Test file modification with no actual change."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk') as mock_walk:
            mock_walk.return_value = [("/tmp", [], ["test.txt"])]

            with patch('builtins.open', MagicMock()) as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = b"same content"
                mock_open.return_value.__enter__.return_value = mock_file

                handler = HostEventHandler(cfg, logger, dispatcher)

        # Simulate file modification with same content
        with patch('builtins.open', MagicMock()) as mock_open:
            mock_file = MagicMock()
            mock_file.read.return_value = b"same content"
            mock_open.return_value.__enter__.return_value = mock_file

            event = MagicMock()
            event.is_directory = False
            event.src_path = "/tmp/test.txt"

            handler.on_modified(event)

            # Should not detect change
            logger.warning.assert_not_called()
            dispatcher.emit.assert_not_called()

    def test_events_skip_log_file(self):
        """Test that all events skip the log file."""
        cfg = Config()
        logger = MagicMock()
        dispatcher = MagicMock()

        with patch('mlids.host.os.walk', return_value=[("/tmp", [], [])]), \
             patch('builtins.open', MagicMock()) as mock_open:
            # Mock file reading for baseline
            mock_file = MagicMock()
            mock_file.read.return_value = b"content"
            mock_open.return_value.__enter__.return_value = mock_file

            handler = HostEventHandler(cfg, logger, dispatcher, skip_filenames={datetime.date.today().isoformat() + ".json"})

        # Reset mock to ignore baseline creation calls
        logger.reset_mock()
        dispatcher.reset_mock()

        # Test all event types
        events_to_test = [
            ('on_created', f'/tmp/{datetime.date.today().isoformat()}.json'),
            ('on_deleted', f'/tmp/{datetime.date.today().isoformat()}.json'),
            ('on_modified', f'/tmp/{datetime.date.today().isoformat()}.json')
        ]

        for event_method, file_path in events_to_test:
            event = MagicMock()
            event.is_directory = False
            event.src_path = file_path

            getattr(handler, event_method)(event)

            # Should not log or emit for log file
            logger.info.assert_not_called()
            logger.warning.assert_not_called()
            dispatcher.emit.assert_not_called()


class TestHostMonitor:
    def test_host_monitor_directory_not_found(self):
        """Test host_monitor when directory doesn't exist."""
        cfg = Config(monitor_dir="/nonexistent")
        logger = MagicMock()

        host_monitor(cfg, logger)

        # Should log error
        logger.error.assert_called_with(
            'Monitor directory not found',
            extra={'extra': {'path': '/nonexistent'}}
        )

    def test_host_monitor_success(self):
        """Test successful host monitor setup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg = Config(monitor_dir=temp_dir)
            logger = MagicMock()

            # Mock Observer to avoid actually starting monitoring
            with patch('mlids.host.Observer') as mock_observer_class:
                mock_observer = MagicMock()
                mock_observer_class.return_value = mock_observer

                # Call host_monitor with block=False to avoid infinite loop
                host_monitor(cfg, logger, block=False)

                # Verify observer was created and configured
                mock_observer_class.assert_called_once()
                mock_observer.schedule.assert_called_once()
                mock_observer.start.assert_called_once()

                # Should log start message
                logger.info.assert_called_with(
                    'Host monitoring started',
                    extra={'extra': {'path': temp_dir}}
                )

    def test_host_monitor_keyboard_interrupt(self):
        """Test host monitor handles keyboard interrupt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg = Config(monitor_dir=temp_dir)
            logger = MagicMock()

            with patch('mlids.host.Observer') as mock_observer_class:
                mock_observer = MagicMock()
                mock_observer_class.return_value = mock_observer

                # Mock time.sleep to raise KeyboardInterrupt
                with patch('mlids.host.time.sleep', side_effect=KeyboardInterrupt):
                    host_monitor(cfg, logger, block=True)

                # Should stop observer
                mock_observer.stop.assert_called_once()
                mock_observer.join.assert_called_once()

                # Should log stopping message
                logger.info.assert_called_with('Stopping host monitor')