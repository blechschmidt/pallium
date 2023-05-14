import grp
import os

from . import sysutil
from . import xlib


def has_display_access(user, display=None):
    if display is None:
        display = xlib.Display()
    try:
        user = sysutil.get_pw_entry(user)
        username = user.pw_name
    except KeyError:
        # The username was not found
        if not isinstance(user, int):
            raise

        # man 7 xsecurity:
        # "For POSIX & UNIX platforms, if the value starts with the character '#', the rest of the string is treated as
        # a decimal uid or gid, otherwise the string is defined as a username or group name."
        username = '#%d' % user
    mode, hosts = display.list_hosts()
    try:
        if mode == xlib.DisableAccess:
            return True  # Everyone has access
        elif mode == xlib.EnableAccess:
            for h in hosts:
                if h.family != xlib.FamilyServerInterpreted or not all(True for x in h.name if x < 0x7F):
                    continue
                values = ''.join(map(chr, h.name)).split('\0')
                if len(values) < 2:
                    continue
                tp = values[0]

                if tp == 'localuser' and values[1] == username:
                    return True
                elif tp == 'localgroup':
                    if isinstance(user, int):
                        continue
                    try:
                        group = grp.getgrnam(values[1])
                        if username in group.gr_mem or user.pw_gid == group.gr_gid:
                            return True
                    except KeyError:
                        continue
            return False
    finally:
        display.close()


def add_user_access(user):
    try:
        user = sysutil.get_pw_entry(user)
        username = user.pw_name
    except KeyError:
        # The username was not found
        if not isinstance(user, int):
            raise
        username = '#%d' % user
    display = xlib.Display()
    display.add_host(xlib.Host(family=xlib.FamilyServerInterpreted, name=b'localuser\0' + username.encode()))


def relax_socket_permissions(user):
    username = None
    try:
        user = sysutil.get_pw_entry(user)
        username = user.pw_name
    except KeyError:
        # The username was not found
        if not isinstance(user, int):
            raise
    display = os.environ['DISPLAY']
    if not display.startswith(':'):
        raise ValueError('Unexpected format of display environment variable')
    display = int(display[1:])
    path = '/tmp/.X11-unix/X%d' % display
    stat = os.stat(path)
    wbit = 2  # write bit for others
    if not isinstance(user, int):  # The user has no /etc/passwd entry
        try:
            group = grp.getgrgid(stat.st_gid)
            if stat.st_gid == user.pw_gid or username in group.gr_mem:
                wbit = wbit << 3  # move from others to group
        except KeyError:
            pass
        if stat.st_uid == user.pw_uid:
            wbit = wbit << 3  # move from group to owner

    if stat.st_mode & wbit == 0:
        os.chmod(path, stat.st_mode | wbit)
    return stat.st_mode


def enable_gui_access(user):
    if not has_display_access(user):
        add_user_access(user)
    relax_socket_permissions(user)
