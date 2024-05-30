import ctypes
import ctypes.util
import grp
import os
import pwd
import select
import signal
import socket
import struct
import typing
from typing import Optional, Union, List
from . import onexit
from . import security
import fcntl

CLONE_NEWNET = 0x40000000
MNT_DETACH = 0x00000002
MS_BIND = 4096
MS_SLAVE = 0x80000
MS_REC = 0x4000
MS_SHARED = 0x100000
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_NOSYMFOLLOW = 256
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUTS = 0x04000000
PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_CHILD_SUBREAPER = 36
PR_SET_NO_NEW_PRIVS = 38

CAP_CHOWN = 1 << 0
CAP_DAC_OVERRIDE = 1 << 1
CAP_DAC_READ_SEARCH = 1 << 2
CAP_FOWNER = 1 << 3
CAP_FSETID = 1 << 4
CAP_KILL = 1 << 5
CAP_SETGID = 1 << 6
CAP_SETUID = 1 << 7
CAP_SETPCAP = 1 << 8
CAP_LINUX_IMMUTABLE = 1 << 9
CAP_NET_BIND_SERVICE = 1 << 10
CAP_NET_BROADCAST = 1 << 11
CAP_NET_ADMIN = 1 << 12
CAP_NET_RAW = 1 << 13
CAP_IPC_LOCK = 1 << 14
CAP_IPC_OWNER = 1 << 15
CAP_SYS_MODULE = 1 << 16
CAP_SYS_RAWIO = 1 << 17
CAP_SYS_CHROOT = 1 << 18
CAP_SYS_PTRACE = 1 << 19
CAP_SYS_PACCT = 1 << 20
CAP_SYS_ADMIN = 1 << 21
CAP_SYS_BOOT = 1 << 22
CAP_SYS_NICE = 1 << 23
CAP_SYS_RESOURCE = 1 << 24
CAP_SYS_TIME = 1 << 25
CAP_SYS_TTY_CONFIG = 1 << 26
CAP_MKNOD = 1 << 27
CAP_LEASE = 1 << 28
CAP_AUDIT_WRITE = 1 << 29
CAP_AUDIT_CONTROL = 1 << 30
CAP_SETFCAP = 1 << 31
CAP_MAC_OVERRIDE = 1 << 32
CAP_MAC_ADMIN = 1 << 33
CAP_SYSLOG = 1 << 34
CAP_WAKE_ALARM = 1 << 35
CAP_BLOCK_SUSPEND = 1 << 36
CAP_AUDIT_READ = 1 << 37
CAP_PERFMON = 1 << 38
CAP_BPF = 1 << 39
CAP_CHECKPOINT_RESTORE = 1 << 40

LINUX_CAPABILITY_VERSION_3 = 0x20080522

IFNAMSIZ = 16

SIOCSIFNAME = 0x8923

SYSCALL_CAPGET = 125
SYSCALL_CAPSET = 126

class UserCapHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int)
    ]


class UserCapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


_libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
_libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
_libc.unshare.argtypes = (ctypes.c_int,)
_libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
_libc.setns.argtypes = (ctypes.c_int, ctypes.c_int)
_libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
_pivot_root = ctypes.CDLL(None).syscall
_pivot_root.restype = ctypes.c_int
_pivot_root.argtypes = ctypes.c_char_p, ctypes.c_char_p

# Reference: https://elixir.bootlin.com/linux/latest/A/ident/capset
_capset = ctypes.CDLL(None).syscall
_capset.restype = ctypes.c_int
_capset.argtypes = ctypes.c_long, ctypes.POINTER(UserCapHeader), ctypes.POINTER(UserCapData * 2)

# Reference: https://elixir.bootlin.com/linux/latest/A/ident/capget
_capget = ctypes.CDLL(None).syscall
_capget.restype = ctypes.c_int
_capget.argtypes = ctypes.c_long, ctypes.POINTER(UserCapHeader), ctypes.POINTER(UserCapData * 2)


def capset(effective=0, permitted=0, inheritable=0, pid=0):
    header = UserCapHeader(version=LINUX_CAPABILITY_VERSION_3, pid=pid)

    data = (UserCapData * 2)()

    # First struct contains low bits (irrespective of endianness)
    data[0].effective = effective & 0xffffffff
    data[0].permitted = permitted & 0xffffffff
    data[0].inheritable = inheritable & 0xffffffff

    # Second struct contains high bits (irrespective of endianness)
    data[1].effective = (effective >> 32) & 0xffffffff
    data[1].permitted = (permitted >> 32) & 0xffffffff
    data[1].inheritable = (inheritable >> 32) & 0xffffffff

    ret = _capset(SYSCALL_CAPSET, header, data)
    if ret < 0:
        errno = -ret
        raise OSError(errno, 'Capset error: {}'.format(os.strerror(errno)))


def bitmask_to_str_capset(mask) -> typing.Set[str]:
    caps = set()
    cap_var_names = [x for x in globals().keys() if x.startswith('CAP_')]
    for var in cap_var_names:
        if mask & globals()[var] != 0:
            caps.add(var)
    return caps


def capget(pid=0):
    header = UserCapHeader(version=LINUX_CAPABILITY_VERSION_3, pid=pid)
    data = (UserCapData * 2)()

    ret = _capget(SYSCALL_CAPGET, ctypes.byref(header), ctypes.byref(data))

    if ret != 0:
        errno = -ret
        raise OSError(errno, os.strerror(errno))

    effective = (data[0].effective | (data[1].effective << 32))
    permitted = (data[0].permitted | (data[1].permitted << 32))
    inheritable = (data[0].inheritable | (data[1].inheritable << 32))

    return effective, permitted, inheritable


class ReadWriteError(Exception):
    pass


class UnexpectedEOF(ReadWriteError):
    pass


class WriteError(ReadWriteError):
    pass


def fork_exit(code):
    onexit.run(None, None)
    # noinspection PyProtectedMember,PyUnresolvedReferences
    os._exit(code)


def mount_info():
    with open('/proc/self/mounts') as f:
        return [tuple(line.strip().split()[0:2]) for line in f.readlines()]


def is_mount(path):
    path = path.rstrip('/')
    return any([entry[1].rstrip('/') == path for entry in mount_info()])


def wait_for_mount(path):
    fd = os.open('/proc/self/mounts', os.O_RDONLY)
    while not is_mount(path):
        _, _, _ = select.select([], [], [fd], 1)
    os.close(fd)


def prctl(option, arg2, arg3=0, arg4=0, arg5=0):
    return _libc.prctl(option, arg2, arg3, arg4, arg5)


def pivot_root():
    _libc.pivot_root()


def mount(source, target, fstype, flags, options=None):
    ret = _libc.mount(source, target, fstype, flags, options)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'Error mounting {} ({}) on {} with options "{}": {}'.
                      format(source, fstype, target, options, os.strerror(errno)))


def umount2(target, flags):
    ret = _libc.umount2(target, flags)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'Error unmounting: {}'.format(os.strerror(errno)))


def unshare(flags):
    ret = _libc.unshare(flags)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'Error unsharing: {}'.format(os.strerror(errno)))


def setns(fd, nstype):
    ret = _libc.setns(fd, nstype)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'Error setting namespace: {}'.format(os.strerror(errno)))


def sysctl(setting: str, *args):
    if len(args) == 0:
        with open(setting, 'rb') as f:
            return f.read()
    else:
        with open(setting, 'wb') as f:
            f.write(args[0])
            f.flush()


def enable_ping():
    try:
        with open('/proc/sys/net/ipv4/ping_group_range', 'w') as f:
            f.write('0 0')
    except FileNotFoundError:
        return


def ip_forward(ip_version: int, enable: Optional[bool] = None):
    assert(ip_version in {4, 6})
    if ip_version == 4:
        path = '/proc/sys/net/ipv4/ip_forward'
    else:
        path = '/proc/sys/net/ipv6/conf/all/forwarding'
    if enable is None:
        return bool(int(sysctl(path).strip()))
    else:
        value = int(enable)
        sysctl(path, bytes(str(value), encoding='ascii') + b'\n')


def disable_duplicate_address_detection(iface):
    path = '/proc/sys/net/ipv6/conf/%s/accept_dad' % iface
    sysctl(path, bytes(str(0), encoding='ascii') + b'\n')
    assert int(sysctl(path).decode()) == 0


def write_blocking(fd: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        chunk = os.write(fd, data[written:])
        if chunk <= 0:
            raise WriteError('Failed to write')
        written += chunk


def read_blocking(fd: int, n: int) -> bytes:
    read = b''
    while n > 0:
        chunk = os.read(fd, n)
        if len(chunk) <= 0:
            raise UnexpectedEOF('Failed to read')
        read += chunk
        n -= len(chunk)
    return read


def user_to_uid(user: Union[int, str]):
    if isinstance(user, int):
        return user
    user = pwd.getpwnam(user)
    return user.pw_uid


def get_pw_entry(user: Union[int, str]):
    return pwd.getpwnam(user) if isinstance(user, str) else pwd.getpwuid(user)


def get_grp_entry(user: Union[int, str]):
    return grp.getgrnam(user) if isinstance(user, str) else grp.getgrgid(user)


def drop_privileges(user: Union[int, str], change_home: bool = False, group: Union[int, str, None] = None,
                    temporary: bool = False) -> None:
    pw_entry = get_pw_entry(user)

    if not temporary:
        os.setgroups(os.getgrouplist(pw_entry.pw_name, pw_entry.pw_gid))

    group_function = os.setgid if not temporary else os.setegid
    user_function = os.setuid if not temporary else os.seteuid

    group_function(pw_entry.pw_gid if group is None else get_grp_entry(group).gr_gid)
    user_function(pw_entry.pw_uid)

    if change_home:
        os.environ['HOME'] = pw_entry.pw_dir


def get_real_user():
    if os.geteuid() == 0:
        return int(os.environ.get('SUDO_UID', 0))
    return os.geteuid()


def privilege_drop_preexec(user: Union[int, str], change_home: bool = False, group: Union[int, str, None] = None,
                           temporary: bool = False, no_new_privs: bool = False):
    def f():
        try:
            drop_privileges(user, change_home, group, temporary)
            if no_new_privs:
                prctl(PR_SET_NO_NEW_PRIVS, 1)
        except:
            import traceback
            traceback.print_exc()
    env = dict(os.environ)
    if change_home:
        pw_entry = get_pw_entry(user)
        env['HOME'] = pw_entry.pw_dir
    return {'preexec_fn': f, 'env': env}


def create_folder_structure(structure, base: Union[str, None] = None, throw: bool = False) -> None:
    for entry in structure:
        name = entry[0]
        mode = entry[1]
        filename = name if base is None else os.path.join(base, name)
        if throw or not os.path.exists(filename):
            os.mkdir(filename, mode)
        if len(entry) >= 3 and isinstance(entry[2], list):
            create_folder_structure(entry[2], filename)


def change_owner(path, user):
    pw_entry = get_pw_entry(user)
    uid = pw_entry.pw_uid
    os.chown(path, uid, os.stat(path).st_gid)


class PeerCredentials:
    def __init__(self, pid, uid, gid):
        self.pid = pid
        self.uid = uid
        self.gid = gid

    @classmethod
    def from_binary(cls, data):
        return cls(*struct.unpack('3i', data))

    def __repr__(self):
        return 'pid=%d, uid=%d, gid=%d' % (self.pid, self.uid, self.gid)

    __str__ = __repr__


def get_peer_credentials(sock: socket.socket) -> PeerCredentials:
    return PeerCredentials.from_binary(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def rename_interface(old_name: str, new_name: str) -> None:
    class RenameIfreq(ctypes.Structure):
        # Practically, correct alignment is ensured by IFNAMSIZ being 16,
        # which is a multiple of the alignment required for the ifr_ifru union,
        # which ifr_newname is part of.
        # https://elixir.bootlin.com/linux/v5.18/source/include/uapi/linux/if.h#L255
        _fields_ = [
            ('ifr_name', ctypes.c_char * IFNAMSIZ),
            ('ifr_newname', ctypes.c_char * IFNAMSIZ),
        ]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    ifr = RenameIfreq()
    ifr.ifr_name = struct.pack('16s', old_name.encode())
    ifr.ifr_newname = struct.pack('16s', new_name.encode())
    fcntl.ioctl(s, SIOCSIFNAME, ifr, True)
    s.close()


def get_pids_in_ns(pid: int, nstype: str) -> List[int]:
    result = []
    all_pids = os.listdir('/proc/')
    netns_path = '/proc/%d/ns/%s' % (pid, nstype)
    cmp_stat = os.stat(netns_path)
    for pid in all_pids:
        try:
            pid = int(pid)
        except ValueError:  # not a process folder
            continue
        netns_path = '/proc/%d/ns/%s' % (pid, nstype)
        stat = os.stat(netns_path)
        if stat.st_dev == cmp_stat.st_dev and stat.st_ino == cmp_stat.st_ino:
            result.append(pid)
    return sorted(result)


def ps():
    for file in os.listdir('/proc'):
        try:
            pid = int(file)
        except ValueError:
            continue
        try:
            with open('/proc/%d/comm' % pid) as f:
                yield pid, f.read().strip()
        except:
            pass


def killall(comm, sig=signal.SIGTERM):
    for pid, pro_comm in ps():
        if pro_comm == comm:
            os.kill(pid, sig)
