import os
import hashlib
import time
from typing import Optional
from .events import EventDispatcher
from .config import Config
import logging
from watchdog.events import FileSystemEventHandler  # type: ignore
from watchdog.observers import Observer  # type: ignore


class HostEventHandler(FileSystemEventHandler):
    def __init__(self, cfg: Config, logger: logging.Logger, dispatcher: Optional[EventDispatcher] = None, skip_filenames: Optional[set] = None):
        super().__init__()
        self.cfg = cfg
        self.logger = logger
        self.dispatcher = dispatcher
        # filenames (basenames) to always ignore (e.g., main log file)
        self._skip_filenames = set(skip_filenames) if skip_filenames else set()
        self.baseline: dict[str, str] = {}
        # Precompute absolute logs directory path for consistent comparisons
        self._logs_dir_abs: Optional[str] = None
        try:
            if getattr(self.cfg, 'logs_dir', None):
                self._logs_dir_abs = os.path.abspath(os.path.join(self.cfg.monitor_dir, self.cfg.logs_dir))
        except Exception:
            self._logs_dir_abs = None
        self.logger.info('Creating file baseline', extra={'extra': {'action': 'baseline_start'}})
        self.update_baseline()
        self.logger.info('Baseline created', extra={'extra': {'count': len(self.baseline)}})

    def update_baseline(self) -> None:
        for root, _, files in os.walk(self.cfg.monitor_dir):
            for file in files:
                filepath = os.path.join(root, file)
                # coerce to str to avoid bytes/str typing issues from external libs
                filepath = str(filepath)
                # skip anything inside logs_dir or matching configured skip_filenames
                if self._logs_dir_abs and os.path.abspath(filepath).startswith(self._logs_dir_abs):
                    continue
                if os.path.basename(filepath) in self._skip_filenames:
                    continue
                try:
                    with open(filepath, 'rb') as f:
                        self.baseline[filepath] = hashlib.sha256(f.read()).hexdigest()
                except Exception as e:
                    self.logger.debug(f'Could not hash {filepath}: {e}')

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = str(event.src_path)

        # skip anything inside the configured logs directory
        if self._logs_dir_abs and os.path.abspath(filepath).startswith(self._logs_dir_abs):
            return
        if os.path.basename(filepath) in self._skip_filenames:
            return
        try:
            with open(filepath, 'rb') as f:
                self.baseline[filepath] = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass
        self.logger.info('File created', extra={'extra': {'path': filepath}})
        if self.dispatcher:
            self.dispatcher.emit('File Created', {'path': filepath})

    def on_deleted(self, event):
        if event.is_directory:
            return
        filepath = str(event.src_path)
        if self._logs_dir_abs and os.path.abspath(filepath).startswith(self._logs_dir_abs):
            return
        if os.path.basename(filepath) in self._skip_filenames:
            return
        if filepath in self.baseline:
            del self.baseline[filepath]
        self.logger.info('File deleted', extra={'extra': {'path': filepath}})
        if self.dispatcher:
            self.dispatcher.emit('File Deletion', {'path': filepath})

    def on_modified(self, event):
        if event.is_directory:
            return
        filepath = str(event.src_path)
        if self._logs_dir_abs and os.path.abspath(filepath).startswith(self._logs_dir_abs):
            return
        try:
            with open(filepath, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            if filepath in self.baseline and self.baseline[filepath] != current_hash:
                self.logger.warning('File modified', extra={'extra': {'path': filepath}})
                if self.dispatcher:
                    self.dispatcher.emit('File Change', {'path': filepath})
            self.baseline[filepath] = current_hash
        except Exception:
            pass


def host_monitor(cfg: Config, logger: logging.Logger, dispatcher: Optional[EventDispatcher] = None, block: Optional[bool] = True) -> None:
    if Observer is None:
        logger.info('Host monitoring disabled: watchdog not available')
        return
    if not os.path.exists(cfg.monitor_dir):
        logger.error('Monitor directory not found', extra={'extra': {'path': cfg.monitor_dir}})
        return
    event_handler = HostEventHandler(cfg, logger, dispatcher)
    observer = Observer()
    observer.schedule(event_handler, cfg.monitor_dir, recursive=True)  # type: ignore
    observer.start()
    logger.info('Host monitoring started', extra={'extra': {'path': cfg.monitor_dir}})
    try:
        if block:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info('Stopping host monitor')
    observer.stop()
    observer.join()
