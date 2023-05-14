import logging
import os
import re
import shutil

from . import runtime


DEFAULT_HOME_DIR_MOUNT = '/pallium/home'
DEFAULT_SKELETON_DIR = '/etc/skel'


class VirtualUser:
    """
    A virtual user is mainly the identifier of a custom home folder. It is mounted over the original home.
    """

    def __init__(self, name, skeleton=DEFAULT_SKELETON_DIR):
        self.temporary = name == '$tmp'
        if self.temporary:
            name = 'tmp'
        assert isinstance(name, str) and re.match(r'^[a-z_][a-z0-9_-]{0,31}$', name)
        self.name = name
        self.skeleton = skeleton

    def _copy_skeleton(self):
        if self.skeleton is None or os.path.exists(self.home):
            return
        if os.path.exists(self.skeleton):
            shutil.copytree(self.skeleton, self.home)
            os.chmod(self.home, 0o700)
        else:
            logging.getLogger().error('Skeleton not copied because skeleton folder does not exist')

    def prepare(self):
        """
        Set up the user's home directory.
        """
        if not self.temporary:
            try:
                os.mkdir(runtime.BASE_DIR, 0o700)
            except FileExistsError:
                pass

            try:
                os.mkdir(runtime.VIRTUSER_DIR, 0o700)
            except FileExistsError:
                pass

            try:
                os.mkdir(os.path.join(runtime.VIRTUSER_DIR, self.name), 0o700)
            except FileExistsError:
                pass

            self._copy_skeleton()

            try:
                os.mkdir(self.home, 0o700)
            except FileExistsError:
                pass

        # TODO: Copy skeleton for temporary users.

    @property
    def home_mount(self):
        return os.path.join('/home', self.name)

    @property
    def home(self):
        if self.temporary:
            return None
        return os.path.join(runtime.VIRTUSER_DIR, self.name, 'home')

    @classmethod
    def from_json(cls, data):
        if isinstance(data, str):
            name = data
            skel = DEFAULT_SKELETON_DIR
        else:
            name = data['name']
            skel = data.get('skeleton', DEFAULT_SKELETON_DIR)
        return cls(name, skel)
