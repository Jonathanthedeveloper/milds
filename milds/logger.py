import logging
import logging.handlers
import json
import os
import datetime
import threading
from typing import Optional

# Optional import for rich (console pretty printing). Expose RICH_AVAILABLE for tests.
try:
    from rich.logging import RichHandler  # type: ignore
    RICH_AVAILABLE = True
except Exception:
    RichHandler = None  # type: ignore
    RICH_AVAILABLE = False



class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'message': record.getMessage(),
            'name': record.name,
        }
        # record may include an 'extra' dict passed via logger.*(..., extra={'extra': {...}})
        try:
            extra = getattr(record, 'extra', None)
            if isinstance(extra, dict):
                payload.update(extra)
        except Exception:
            pass
        return json.dumps(payload)


def get_logger(name: str = 'mlids', logs_dir: Optional[str] = None, console_color: bool = True) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        # Already configured; ensure console handler formatter matches console_color
        # If console_color is False, replace any RichHandler with a StreamHandler using JsonFormatter
        if not console_color:
            for h in list(logger.handlers):
                if h.__class__.__name__.lower().startswith('rich'):
                    logger.removeHandler(h)
            # add a plain stream handler if none exists
            if not any(not getattr(h, 'baseFilename', None) for h in logger.handlers):
                ch = logging.StreamHandler()
                ch.setFormatter(JsonFormatter())
                logger.addHandler(ch)
        return logger

    logger.setLevel(logging.INFO)
    # ensure logs directory exists (if provided)
    if logs_dir:
        os.makedirs(logs_dir, exist_ok=True)

    # Decide where to place log files. Default directory is 'logs' under
    # the project root or the provided `logs_dir` argument. Use a stable
    # filename so handler.baseFilename remains predictable across platforms.
    # Use current date as filename (YYYY-MM-DD.json). This avoids invalid
    # characters on Windows and aligns with daily rotation semantics.
    base_name = datetime.date.today().isoformat() + '.json'
    target_logs_dir = logs_dir or 'logs'
    # ensure we have an explicit directory path (empty string means cwd)
    full_path = os.path.join(target_logs_dir, base_name) if target_logs_dir else base_name
    handler = logging.handlers.TimedRotatingFileHandler(
        filename=full_path,
        when='midnight',
        interval=1,
        backupCount=30,
        encoding='utf-8',
        utc=False
    )
    formatter = JsonFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Console handler: pretty/colored if possible, else JSON
    if console_color and RichHandler is not None:
        console_handler: logging.Handler = RichHandler(show_time=True, rich_tracebacks=False, markup=False)  # type: ignore[operator]
        # Use a simple message-only formatter for Rich
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(console_handler)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
