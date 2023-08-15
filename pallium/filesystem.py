import errno
import shutil
import subprocess
import tempfile

from . import onexit
from . import sysutil
from . import util
from .runtime import *

"""Unfortunately, bind mounts do not persist when the underlying file is deleted. Programs like the network manager
may modify /etc/resolv.conf (by deleting and writing anew) causing a simple bind mount to fail.
For this reason, an overlay mount is used instead."""


class OverlayMount:
    def __init__(self, root, overlay, workdir=None):
        self.root = root
        self.overlay = overlay
        self.tmp = workdir
        self.stopped = False

    def mount(self):
        if self.tmp is None:
            self.tmp = tempfile.mkdtemp(dir=APP_RUN_DIR)

        encoded = map(util.addslashes, [self.root, self.overlay, self.tmp])
        options = 'index=off,lowerdir=%s,upperdir=%s,workdir=%s' % tuple(encoded)
        sysutil.mount(b'overlay', self.root.encode(), b'overlay', 0, options.encode())

    def start(self):
        self.mount()
        onexit.register(self.stop)

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        """try:
            sysutil.umount2(self.root.encode(), 0)
        except OSError as e:
            if e.errno != errno.EBUSY:
                raise"""
        try:
            shutil.rmtree(self.tmp)
        except FileNotFoundError:
            pass
