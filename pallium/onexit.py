# Atexit wrapper supporting custom signals and keeping track of registered functions, so they can be cleared at once.

import atexit
import logging
import os
import signal
import traceback

from . import sysutil

_exitstack = []
_done = False
_registered = False


class Atomic:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def register(func, *args, **kwargs):
    global _registered
    with Atomic(custom_handler=run):
        if not _registered:
            atexit.register(run, None, None)
            signal.signal(signal.SIGTERM, run)
        _registered = True
        _exitstack.append((func, os.getpid(), args, kwargs))
        return func


def clear():
    global _exitstack
    logging.getLogger(__name__).debug('Clear exit stack, pid=%d' % os.getpid())
    _exitstack.clear()


def unregister(f):
    global _exitstack
    with Atomic(custom_handler=run):
        new_exitstack = []
        for entry in _exitstack:
            if entry[0] != f:
                new_exitstack.append(entry)
        _exitstack = new_exitstack


def run(_, __):
    global _done
    with Atomic(custom_handler=run, suppress=True):
        if _done:
            return
        logging.getLogger(__name__).debug('Run exit functions, pid=%d' % os.getpid())
        _done = True
        for (func, pid, args, kwargs) in reversed(_exitstack):
            if os.getpid() == pid:
                try:
                    func(*args, **kwargs)
                except:
                    traceback.print_exc()
