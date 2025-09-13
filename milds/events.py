import json
import logging
import socket
import threading
import subprocess
import platform
from typing import Any, Dict, List, Set
import asyncio
try:
    import websockets  # type: ignore
    WEBSOCKETS_AVAILABLE = True
except Exception:
    websockets = None  # type: ignore
    WEBSOCKETS_AVAILABLE = False


class TcpSinkServer:
    def __init__(self, host: str, port: int, logger: logging.Logger):
        self.host = host
        self.port = port
        self.logger = logger
        self._clients: List[socket.socket] = []
        self._lock = threading.Lock()
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        def run():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.listen(5)
                self._srv = srv
                self.logger.info('TCP sink listening', extra={'extra': {'host': self.host, 'port': self.port}})
                while True:
                    try:
                        conn, addr = srv.accept()
                        with self._lock:
                            self._clients.append(conn)
                        self.logger.info('TCP sink client connected', extra={'extra': {'addr': addr[0], 'port': addr[1]}})
                    except Exception as e:
                        self.logger.debug('TCP sink accept error', extra={'extra': {'error': str(e)}})
                        break

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def broadcast(self, obj: Dict[str, Any]) -> None:
        data = (json.dumps(obj) + '\n').encode('utf-8')
        dead: List[socket.socket] = []
        with self._lock:
            for c in list(self._clients):
                try:
                    c.sendall(data)
                except Exception:
                    dead.append(c)
            for d in dead:
                try:
                    d.close()
                except Exception:
                    pass
                try:
                    self._clients.remove(d)
                except ValueError:
                    pass
                
                
class WebSocketSinkServer:
    def __init__(self, host: str, port: int, logger: logging.Logger):
        self.host = host
        self.port = port
        self.logger = logger
        self.clients: Set[Any] = set()
        self.loop: Any = None
        self.server: Any = None

    async def _handler(self, websocket, path):  # type: ignore[no-redef]
        self.clients.add(websocket)
        try:
            async for _ in websocket:
                pass
        finally:
            self.clients.discard(websocket)

    def start(self):
        if not WEBSOCKETS_AVAILABLE:
            # Dependency missing; log and return
            try:
                self.logger.info('WebSocket sink unavailable (dependency missing)')
            except Exception:
                pass
            return

        def run():
            self.loop = asyncio.new_event_loop()  # type: ignore[union-attr]
            asyncio.set_event_loop(self.loop)  # type: ignore[union-attr]
            self.server = self.loop.run_until_complete(websockets.serve(self._handler, self.host, self.port))  # type: ignore[union-attr]
            self.logger.info('WebSocket sink listening', extra={'extra': {'host': self.host, 'port': self.port}})
            self.loop.run_forever()
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def broadcast(self, obj: Dict[str, Any]):
        if not self.loop:
            return
        data = json.dumps(obj)
        async def _send():
            dead = []
            for ws in list(self.clients):
                try:
                    await ws.send(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                try:
                    await ws.close()
                except Exception:
                    pass
                self.clients.discard(ws)
        # Guard asyncio usage
        try:
            # Ensure the coroutine is created inside the event loop thread.
            # Pass a callable to call_soon_threadsafe which will call create_task(_send())
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(_send()))  # type: ignore[union-attr]
        except Exception:
            pass


class EventDispatcher:
    """Central event dispatcher that can execute actions and pipe alerts."""

    def __init__(self, logger: logging.Logger, tcp_sink: TcpSinkServer | None = None, ws_sink: WebSocketSinkServer | None = None, actions: Dict[str, List[Dict[str, Any]]] | None = None, allow_firewall: bool = False, allow_commands: bool = False, intel_ips: Set[str] | None = None):
        self.logger = logger
        self.tcp_sink = tcp_sink
        self.ws_sink = ws_sink
        self.actions = actions or {}
        self.allow_firewall = allow_firewall
        self.allow_commands = allow_commands
        self.intel_ips = intel_ips or set()

    def emit(self, event_type: str, details: Dict[str, Any]) -> None:
        payload: Dict[str, Any] = {'timestamp': None, 'type': event_type, 'details': details}
        # tag with intel if applicable
        ip = details.get('ip') or details.get('src')
        if ip and ip in self.intel_ips:
            payload['intel_match'] = True
        # Log the event via logger first
        self.logger.warning(event_type, extra={'extra': payload})
        # Pipe to TCP sink if enabled
        if self.tcp_sink is not None:
            try:
                self.tcp_sink.broadcast(payload)
            except Exception as e:
                self.logger.debug('TCP sink broadcast error', extra={'extra': {'error': str(e)}})
        if self.ws_sink is not None:
            try:
                self.ws_sink.broadcast(payload)
            except Exception as e:
                self.logger.debug('WS sink broadcast error', extra={'extra': {'error': str(e)}})
        # Run configured actions
        for action in self.actions.get(event_type, []):
            try:
                self._run_action(action, payload)
            except Exception as e:
                self.logger.debug('Action error', extra={'extra': {'error': str(e), 'action': action}})

    def _run_action(self, action: Dict[str, Any], payload: Dict[str, Any]) -> None:
        kind = action.get('type')
        if kind == 'print':
            self.logger.warning('ACTION print', extra={'extra': {'payload': payload}})
        elif kind == 'webhook':
            # Deferred: avoid network calls; show how it would be done
            self.logger.info('Webhook action deferred (no external calls)')
        elif kind == 'block_ip':
            ip = payload.get('details', {}).get('ip')
            if not ip:
                return
            if not self.allow_firewall:
                self.logger.warning('Would block IP (disabled)', extra={'extra': {'ip': ip}})
                return
            try:
                if platform.system() == 'Windows':
                    # netsh advfirewall firewall add rule name="MLIDS_Block_{ip}" dir=in action=block remoteip={ip}
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=MLIDS_Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'
                    ]
                else:
                    # iptables -A INPUT -s {ip} -j DROP
                    cmd = ['sudo', '-n', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                self.logger.warning('Blocked IP', extra={'extra': {'ip': ip}})
            except Exception as e:
                self.logger.warning('Block IP failed', extra={'extra': {'ip': ip, 'error': str(e)}})
        elif kind == 'run':
            # cmd may be a string or list of strings; treat as Any to allow flexible inputs
            from typing import Any as _Any
            _cmd: _Any = action.get('cmd')
            if not _cmd:
                return
            if not self.allow_commands:
                self.logger.warning('Would run command (disabled)', extra={'extra': {'cmd': _cmd}})
                return
            try:
                # subprocess.run accepts both str and sequence; pass through
                subprocess.run(_cmd, shell=True, check=False, timeout=5)
                self.logger.warning('Ran command', extra={'extra': {'cmd': _cmd}})
            except Exception as e:
                self.logger.warning('Run command failed', extra={'extra': {'cmd': _cmd, 'error': str(e)}})