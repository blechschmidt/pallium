import sys
import os
import stat
from typing import Optional

_is_sudo_or_root: Optional[bool] = None


def is_suid() -> bool:
    if not getattr(sys, 'frozen', False):
        return False
    info = os.stat(sys.executable)
    return info.st_uid == 0 and (info.st_mode & stat.S_ISUID) != 0


def is_sudo_or_root() -> bool:
    global _is_sudo_or_root
    if _is_sudo_or_root is not None:
        return _is_sudo_or_root
    ruid, euid, suid = os.getresuid()
    # rgid, egid, sgid = os.getresgid()
    _is_sudo_or_root = ruid == 0 or euid == 0
    return _is_sudo_or_root


def real_user() -> int:
    ruid, euid, suid = os.getresuid()
    if ruid == 0:
        if 'SUDO_UID' not in os.environ:
            return 0
        return int(os.environ['SUDO_UID'])
    return ruid


def real_group() -> int:
    ruid, euid, suid = os.getresgid()
    if ruid == 0:
        if 'SUDO_GID' not in os.environ:
            return 0
        return int(os.environ['SUDO_GID'])
    return ruid


is_sudo_or_root()

RUID, EUID, SUID = os.getresuid()
RGID, EGID, SGID = os.getresgid()
