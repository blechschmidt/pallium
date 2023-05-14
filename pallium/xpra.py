import os.path
import random
import signal
import subprocess
import time

from . import sysutil
from . import xlib


def kill_preexec():
    sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)


def wait_for_file_exists(path):
    while not os.path.exists(path):
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
    if quiet:
        kwargs = {
            'stdout': subprocess.DEVNULL,
            'stderr': subprocess.DEVNULL,
        }
    display_no = find_unused_display()
    subprocess.Popen([
        'xpra',
        'start',
        ':%d' % display_no,
        '--attach=yes',
        '--daemon=no',
        '--dbus-proxy=no',
        '--dbus-launch=no',
        '--dbus-control=no',
        '--mdns=no',
        '--splash=no',
        '--title=@title@ (pallium)'
        ],
        preexec_fn=kill_preexec,
        **kwargs,
        start_new_session=True)
    wait_for_file_exists('/tmp/.X11-unix/X%d' % display_no)
    display = xlib.Display(display_no)
    display.disable_access_control()
    return display_no
