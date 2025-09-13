# Compatibility shim: tests and older code import 'mlids' package. Re-export from 'milds'.
from importlib import import_module

__all__ = []
# re-export commonly used submodules
for _mod in ('app', 'config', 'events', 'host', 'logger', 'net'):
    try:
        globals()[_mod] = import_module('milds.' + _mod)
        __all__.append(_mod)
    except Exception:
        globals()[_mod] = None
