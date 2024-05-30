import logging
import os.path
import random
import signal
import subprocess
import time

from . import sysutil
from . import xlib


def kill_preexec():
    sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)


def wait_for_file_exists(path, raise_function=None):
    while not os.path.exists(path):
        if raise_function:
            raise_function()
        time.sleep(0.1)


def find_unused_display():
    for i in range(100):
        no = random.randint(21, 999)
        try:
            xlib.Display(no)
        except IOError:
            return no
    raise "Unable to find unused display number"


def start_xpra(quiet=True):
    kwargs = {}
    if quiet and logging.getLogger().level != logging.DEBUG:
        kwargs = {
            'stdout': subprocess.DEVNULL,
            'stderr': subprocess.DEVNULL,
        }
    display_no = find_unused_display()
    p = subprocess.Popen([
        'xpra',
        'start',
        ':%d' % display_no,
        '--attach=yes',
        '--daemon=no',
        # The dbus proxy option has been deprecated since version 6:
        # https://github.com/Xpra-org/xpra/blob/6b1b939f4dd7155778c2b32079849c54d2dcfb2b/xpra/scripts/config.py#L755
        # '--dbus-proxy=no',
        '--dbus-launch=no',
        '--dbus-control=no',
        '--mdns=no',
        '--splash=no',
        '--title=@title@ (pallium)'
        ],
        preexec_fn=kill_preexec,
        **kwargs,
        start_new_session=True)

    def raise_process_error():
        if p.poll() is not None:
            raise ChildProcessError('xpra exited with error code %d' % p.returncode)

    wait_for_file_exists('/tmp/.X11-unix/X%d' % display_no, raise_process_error)
    display = xlib.Display(display_no)
    display.disable_access_control()
    return display_no
