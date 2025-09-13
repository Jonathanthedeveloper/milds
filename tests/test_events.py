import pytest
import json
import socket
import threading
import time
from unittest.mock import patch, MagicMock, AsyncMock
from milds.events import EventDispatcher, TcpSinkServer, WebSocketSinkServer, WEBSOCKETS_AVAILABLE


class TestTcpSinkServer:
    def test_tcp_sink_initialization(self):
        """Test TCP sink server initialization."""
        logger = MagicMock()
        server = TcpSinkServer("127.0.0.1", 8765, logger)

        assert server.host == "127.0.0.1"
        assert server.port == 8765
        assert server.logger == logger
        assert server._clients == []
        assert server._srv is None
        assert server._thread is None

    def test_tcp_sink_broadcast_no_clients(self):
        """Test broadcasting to TCP sink with no clients."""
        logger = MagicMock()
        server = TcpSinkServer("127.0.0.1", 8765, logger)

        payload = {"type": "test", "details": {"ip": "192.168.1.1"}}
        server.broadcast(payload)

        # Should not raise any exceptions
        assert True

    def test_tcp_sink_broadcast_with_mock_client(self):
        """Test broadcasting to TCP sink with a mock client."""
        logger = MagicMock()
        server = TcpSinkServer("127.0.0.1", 8765, logger)

        # Mock client socket
        mock_client = MagicMock()
        server._clients = [mock_client]

        payload = {"type": "SQL Injection", "details": {"line": "SELECT * FROM users"}}
        server.broadcast(payload)

        # Verify sendall was called with correct data
        expected_data = (json.dumps(payload) + '\n').encode('utf-8')
        mock_client.sendall.assert_called_once_with(expected_data)

    def test_tcp_sink_broadcast_client_error(self):
        """Test broadcasting handles client errors gracefully."""
        logger = MagicMock()
        server = TcpSinkServer("127.0.0.1", 8765, logger)

        # Mock client that raises exception
        mock_client = MagicMock()
        mock_client.sendall.side_effect = Exception("Connection error")
        mock_client.close = MagicMock()
        server._clients = [mock_client]

        payload = {"type": "test"}
        server.broadcast(payload)

        # Should have tried to close the dead client
        mock_client.close.assert_called_once()
        # Client should be removed from list
        assert mock_client not in server._clients


class TestWebSocketSinkServer:
    def test_websocket_sink_initialization(self):
        """Test WebSocket sink server initialization."""
        logger = MagicMock()
        server = WebSocketSinkServer("127.0.0.1", 8766, logger)

        assert server.host == "127.0.0.1"
        assert server.port == 8766
        assert server.logger == logger
        assert server.clients == set()

    @pytest.mark.skipif(WEBSOCKETS_AVAILABLE, reason="WebSockets available, testing unavailable case")
    def test_websocket_sink_start_unavailable(self):
        """Test WebSocket sink start when websockets library is not available."""
        logger = MagicMock()
        server = WebSocketSinkServer("127.0.0.1", 8766, logger)

        server.start()

        # Should log that WebSocket sink is unavailable
        logger.info.assert_called_with('WebSocket sink unavailable (dependency missing)')

    @pytest.mark.skipif(not WEBSOCKETS_AVAILABLE, reason="WebSockets not available")
    def test_websocket_sink_broadcast_no_loop(self):
        """Test WebSocket broadcast when event loop is not available."""
        logger = MagicMock()
        server = WebSocketSinkServer("127.0.0.1", 8766, logger)
        server.loop = None

        payload = {"type": "test"}
        server.broadcast(payload)

        # Should return early without error
        assert True

    @pytest.mark.skipif(not WEBSOCKETS_AVAILABLE, reason="WebSockets not available")
    def test_websocket_sink_broadcast_with_mock_clients(self):
        """Test WebSocket broadcast with mock clients."""
        logger = MagicMock()
        server = WebSocketSinkServer("127.0.0.1", 8766, logger)

        # Mock event loop and clients
        mock_loop = MagicMock()
        server.loop = mock_loop

        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        server.clients = {mock_ws1, mock_ws2}

        payload = {"type": "File Change", "details": {"path": "/tmp/test.txt"}}

        with patch('asyncio.create_task') as mock_create_task:
            server.broadcast(payload)

            # Should have called call_soon_threadsafe
            mock_loop.call_soon_threadsafe.assert_called_once()


class TestEventDispatcher:
    def test_event_dispatcher_initialization(self):
        """Test EventDispatcher initialization."""
        logger = MagicMock()
        tcp_sink = MagicMock()
        ws_sink = MagicMock()
        actions = {"SQL Injection": [{"type": "print"}]}
        intel_ips = {"192.168.1.1", "10.0.0.1"}

        dispatcher = EventDispatcher(
            logger=logger,
            tcp_sink=tcp_sink,
            ws_sink=ws_sink,
            actions=actions,
            allow_firewall=True,
            allow_commands=False,
            intel_ips=intel_ips
        )

        assert dispatcher.logger == logger
        assert dispatcher.tcp_sink == tcp_sink
        assert dispatcher.ws_sink == ws_sink
        assert dispatcher.actions == actions
        assert dispatcher.allow_firewall is True
        assert dispatcher.allow_commands is False
        assert dispatcher.intel_ips == intel_ips

    def test_emit_basic_event(self):
        """Test emitting a basic event."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger)

        event_type = "File Created"
        details = {"path": "/tmp/newfile.txt"}

        dispatcher.emit(event_type, details)

        # Should log the event
        logger.warning.assert_called_once()
        call_args = logger.warning.call_args
        assert call_args[0][0] == event_type
        assert "extra" in call_args[1]
        assert call_args[1]["extra"]["extra"]["type"] == event_type
        assert call_args[1]["extra"]["extra"]["details"] == details

    def test_emit_with_intel_match(self):
        """Test emitting event with IP that matches intel list."""
        logger = MagicMock()
        intel_ips = {"192.168.1.100"}
        dispatcher = EventDispatcher(logger=logger, intel_ips=intel_ips)

        details = {"ip": "192.168.1.100"}
        dispatcher.emit("Failed Login", details)

        # Should mark as intel match
        call_args = logger.warning.call_args
        assert call_args[1]["extra"]["extra"]["intel_match"] is True

    def test_emit_with_tcp_sink(self):
        """Test emitting event with TCP sink."""
        logger = MagicMock()
        tcp_sink = MagicMock()
        dispatcher = EventDispatcher(logger=logger, tcp_sink=tcp_sink)

        payload = {"type": "SQL Injection", "details": {"line": "SELECT * FROM users"}}
        dispatcher.emit("SQL Injection", payload["details"])

        # Should broadcast to TCP sink
        tcp_sink.broadcast.assert_called_once()

    def test_emit_with_ws_sink(self):
        """Test emitting event with WebSocket sink."""
        logger = MagicMock()
        ws_sink = MagicMock()
        dispatcher = EventDispatcher(logger=logger, ws_sink=ws_sink)

        payload = {"type": "File Change", "details": {"path": "/tmp/test.txt"}}
        dispatcher.emit("File Change", payload["details"])

        # Should broadcast to WebSocket sink
        ws_sink.broadcast.assert_called_once()

    def test_emit_with_actions(self):
        """Test emitting event triggers configured actions."""
        logger = MagicMock()
        actions = {
            "SQL Injection": [
                {"type": "print"},
                {"type": "webhook", "url": "http://example.local/webhook"}
            ]
        }
        dispatcher = EventDispatcher(logger=logger, actions=actions)

        dispatcher.emit("SQL Injection", {"line": "SELECT * FROM users"})

        # Should have called logger.warning twice (once for event, once for print action)
        assert logger.warning.call_count == 2

    def test_run_action_print(self):
        """Test print action execution."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger)

        action = {"type": "print"}
        payload = {"type": "test", "details": {"ip": "192.168.1.1"}}

        dispatcher._run_action(action, payload)

        # Should log the action
        logger.warning.assert_called_once_with('ACTION print', extra={'extra': {'payload': payload}})

    def test_run_action_webhook(self):
        """Test webhook action (currently just logs)."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger)
        action = {"type": "webhook", "url": "http://example.local"}
        payload = {"type": "test"}

        dispatcher._run_action(action, payload)

        # Should log that webhook is deferred
        logger.info.assert_called_once_with('Webhook action deferred (no external calls)')

    @patch('platform.system')
    @patch('subprocess.run')
    def test_run_action_block_ip_windows(self, mock_subprocess, mock_platform):
        """Test block_ip action on Windows."""
        mock_platform.return_value = "Windows"
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger, allow_firewall=True)

        action = {"type": "block_ip"}
        payload = {"details": {"ip": "192.168.1.100"}}

        dispatcher._run_action(action, payload)

        # Should call subprocess.run with netsh command
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args
        assert call_args[0][0][0] == "netsh"  # First element of command list
        assert "action=block" in call_args[0][0]  # Check if 'action=block' is in the command list
        assert "remoteip=192.168.1.100" in call_args[0][0]  # Check if IP is in the command list

    @patch('platform.system')
    @patch('subprocess.run')
    def test_run_action_block_ip_linux(self, mock_subprocess, mock_platform):
        """Test block_ip action on Linux."""
        mock_platform.return_value = "Linux"
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger, allow_firewall=True)

        action = {"type": "block_ip"}
        payload = {"details": {"ip": "192.168.1.100"}}

        dispatcher._run_action(action, payload)

        # Should call subprocess.run with iptables command
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args
        assert "iptables" in call_args[0][0]
        assert "DROP" in call_args[0][0]
        assert "192.168.1.100" in call_args[0][0]

    def test_run_action_block_ip_disabled(self):
        """Test block_ip action when firewall actions are disabled."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger, allow_firewall=False)

        action = {"type": "block_ip"}
        payload = {"details": {"ip": "192.168.1.100"}}

        dispatcher._run_action(action, payload)

        # Should log that it would block but is disabled
        logger.warning.assert_called_once()
        assert "Would block IP" in logger.warning.call_args[0][0]

    @patch('subprocess.run')
    def test_run_action_run_command(self, mock_subprocess):
        """Test run command action."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger, allow_commands=True)

        action = {"type": "run", "cmd": "echo 'test'"}
        payload = {"type": "test"}

        dispatcher._run_action(action, payload)

        # Should call subprocess.run with the command
        mock_subprocess.assert_called_once_with("echo 'test'", shell=True, check=False, timeout=5)

    def test_run_action_run_command_disabled(self):
        """Test run command action when commands are disabled."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger, allow_commands=False)

        action = {"type": "run", "cmd": "echo 'test'"}
        payload = {"type": "test"}

        dispatcher._run_action(action, payload)

        # Should log that it would run but is disabled
        logger.warning.assert_called_once()
        assert "Would run command" in logger.warning.call_args[0][0]

    def test_run_action_unknown_type(self):
        """Test unknown action type is ignored."""
        logger = MagicMock()
        dispatcher = EventDispatcher(logger=logger)

        action = {"type": "unknown"}
        payload = {"type": "test"}

        # Should not raise exception
        dispatcher._run_action(action, payload)

        # Should not log anything
        logger.warning.assert_not_called()
        logger.info.assert_not_called()