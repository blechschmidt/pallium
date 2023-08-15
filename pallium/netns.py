import logging
import os
import pickle
import signal
import struct
import traceback
from typing import List, Optional

from . import sandbox
from . import sysutil, security, onexit
from .filesystem import OverlayMount

ETC_MOUNT_BIND = 0
ETC_MOUNT_OVERLAYFS = 1
ETC_MOUNT_AUTO = 2


class MountInstruction:
    def __init__(self, src: Optional[str], target: Optional[str], fstype='bind', options: Optional[dict] = None,
                 preexec_fn=None,
                 postexec_fn=None):
        self.src = src
        self.target = target
        self.fstype = fstype
        self.preexec_fn = preexec_fn
        self.postexec_fn = postexec_fn
        self.options = options

    def mount(self):
        if self.preexec_fn is not None:
            preexec_result = self.preexec_fn(self)
            if isinstance(preexec_result, bool) and not preexec_result:
                return
        flags = 0
        if self.fstype == 'bind':
            flags = sysutil.MS_BIND | sysutil.MS_REC
        src_arg = self.src.encode() if self.src is not None else None
        options = self.options
        if options is not None:
            options = ''
            for key, value in self.options.items():
                options += str(key)
                if value is not None and not (isinstance(value, bool) and value):
                    options += '=' + str(value)
                options += ','
            if len(options) > 0 and options[-1] == ',':
                options = options[:-1]
            options = options.encode()
        if self.fstype is not None:
            logging.debug('Mount %s on %s (%s)' % (self.src, self.target, self.fstype))
            sysutil.mount(src_arg, self.target.encode(), self.fstype.encode(), flags, options)

        if self.postexec_fn is not None:
            self.postexec_fn(self)

    def umount(self):
        if self.fstype is not None:
            sysutil.umount2(self.target.encode(), sysutil.MNT_DETACH)

    @classmethod
    def from_json(cls, obj):
        return cls(**obj)

    def to_json(self):
        return {'src': self.src, 'target': self.target}


# noinspection PyPep8Naming
class classproperty(object):
    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


class InvalidOperation(Exception):
    pass


class UnsupportedError(Exception):
    pass


def join_namespace(tp, pid):
    ns_map = {
        sysutil.CLONE_NEWUSER: 'user',
        sysutil.CLONE_NEWNET: 'net',
        sysutil.CLONE_NEWPID: 'pid',
        sysutil.CLONE_NEWNS: 'mnt',
        sysutil.CLONE_NEWIPC: 'ipc',
        sysutil.CLONE_NEWUTS: 'uts',
    }
    proc_path = '/proc/%d/ns/' % pid

    fd = os.open(os.path.join(proc_path, ns_map[tp]), os.O_RDONLY)
    sysutil.setns(fd, tp)
    os.close(fd)


class NetworkNamespace:
    _RUN_DIR = '/var/run/netns'
    _ETC_DIR = '/etc/netns'

    def __init__(self, name, etc_path=None, mounts=None, pid_path=None):
        self.custom_etc_path = etc_path

        # A network namespace can either be created through a name (as is done by the ip netns utility) or a file path.
        self.fd_path = name if name is None or '/' not in name else os.path.abspath(name)
        self.mounts = mounts if mounts else []
        self.fs = None
        self.fd_stack = []
        self.pid = None
        self.pid_path = pid_path

    @classmethod
    def identify(cls, pid=None):
        if pid is None:
            pid = os.getpid()
        program_stat = os.stat('/proc/%d/ns/net' % pid)
        if os.path.isdir(cls._RUN_DIR):
            for nsname in os.listdir(cls._RUN_DIR):
                netns_stat = os.stat(os.path.join(cls._RUN_DIR, nsname))
                if program_stat.st_dev == netns_stat.st_dev and program_stat.st_ino == netns_stat.st_ino:
                    return NetworkNamespace(nsname)
        return NetworkNamespace(None)

    def run(self, func, args=(), kwargs=None, wait=True, isolated=False, new_session=True, exclude_ns=0):
        logging.getLogger(__name__).debug('netns.run')
        if kwargs is None:
            kwargs = {}
        if self.is_default:
            return func(*args, **kwargs)
        if security.is_sudo_or_root():
            with self:
                return func(*args, **kwargs)
        else:
            rfchild, w2parent = os.pipe()
            rfparent, w2child = os.pipe()
            pid = os.fork()
            if pid == 0:
                if new_session:
                    os.setpgid(0, 0)
                sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)
                onexit.clear()
                os.close(rfchild)
                os.close(w2child)
                self.enter(exclude_ns=exclude_ns)

                # A second fork is performed because privileges may be dropped inside func which would prevent exit
                # handlers from releasing the resources acquired by the overlay filesystem due to a lack of permissions.
                pid2 = os.fork()
                if pid2 == 0:
                    if new_session:
                        os.setpgid(0, 0)
                    sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)
                    onexit.clear()
                    raised = False
                    try:
                        result = func(*args, **kwargs)
                    except BaseException as e:
                        traceback.print_exc()
                        result = e
                        raised = True
                    serialized = pickle.dumps(result)
                    header = struct.pack('=?Q', raised, len(serialized))
                    try:
                        sysutil.write_blocking(w2parent, header)
                        sysutil.write_blocking(w2parent, serialized)
                        sysutil.read_blocking(rfparent, 1)
                    except (sysutil.UnexpectedEOF, BrokenPipeError):
                        # Probably exception in parent. The parent will display the error.
                        sysutil.fork_exit(1)
                    os.close(w2parent)
                    os.close(rfparent)
                else:
                    logging.getLogger(__name__).debug(
                        'Inner fork: %s, child=%d, parent=%d' % (repr(self), pid2, os.getpid()))
                    os.waitpid(pid2, 0)
                sysutil.fork_exit(0)
            else:
                logging.getLogger(__name__).debug('Fork: %s, child=%d, parent=%d' % (repr(self), pid, os.getpid()))

                # Initialize variables for static analysis
                serialized = None
                raised = False

                os.close(w2parent)
                os.close(rfparent)
                if not wait:
                    os.close(w2child)
                    os.close(rfchild)
                    return
                try:
                    header = sysutil.read_blocking(rfchild, struct.calcsize('=?Q'))
                    raised, expected_length = struct.unpack('=?Q', header)
                    serialized = sysutil.read_blocking(rfchild, expected_length)
                    sysutil.write_blocking(w2child, b'\0')
                except (sysutil.UnexpectedEOF, BrokenPipeError):
                    # Probably exception in child. The child will display the error.
                    sysutil.fork_exit(1)
                os.close(w2child)
                os.close(rfchild)
                try:
                    os.waitpid(pid, 0)
                except OSError:
                    pass
                if not isolated:
                    # Unpickling should be safe even in the case of a privilege drop because it causes the dumpable
                    # attribute of a process to be set to 0. This ensures the integrity of the function code that is
                    # executed inside the child. In particular, an unprivileged process cannot tamper with its
                    # integrity and modify the pickled object sent to the parent. See `man 2 prctl`
                    # (PR_SET_DUMPABLE). See also `man 2 ptrace` (Ptrace access mode checking). Also see `man 5 proc`.

                    result = pickle.loads(serialized)
                    if raised:
                        raise result
                    return result

    def mount_etc(self):
        if not os.path.isdir(self.etc_path):
            return
        for filename in os.listdir(self.etc_path):
            source = os.path.join(self.etc_path, filename).encode()
            target = os.path.join('/etc', filename).encode()
            try:
                sysutil.mount(source, target, b'none', sysutil.MS_BIND, None)
            except FileNotFoundError:
                pass

    def umount_etc(self):
        for filename in os.listdir(self.etc_path):
            target = os.path.join('/etc', filename).encode()
            try:
                sysutil.umount2(target, sysutil.MNT_DETACH)
            except FileNotFoundError:
                pass

    def _join_ns(self, tp):
        ns_map = {
            sysutil.CLONE_NEWUSER: 'user',
            sysutil.CLONE_NEWNET: 'net',
            sysutil.CLONE_NEWPID: 'pid',
            sysutil.CLONE_NEWNS: 'mnt',
            sysutil.CLONE_NEWIPC: 'ipc',
            sysutil.CLONE_NEWUTS: 'uts',
        }
        if self.pid is not None:
            proc_path = '/proc/%d/ns/' % self.pid
        else:
            proc_path = self.fd_path

        fd = os.open(os.path.join(proc_path, ns_map[tp]), os.O_RDONLY)
        sysutil.setns(fd, tp)
        os.close(fd)
        pass

    def enter(self, overlay_fs=True, exclude_ns=0):
        self.fd_stack.append((
            os.open('/proc/self/ns/net', os.O_RDONLY),
            os.open('/proc/self/ns/mnt', os.O_RDONLY),
            *([] if security.is_sudo_or_root() else (os.open('/proc/self/ns/user', os.O_RDONLY),)),
        ))

        if security.is_sudo_or_root():
            fd = os.open(os.path.join(self._run_path, 'net'), os.O_RDONLY)
            sysutil.setns(fd, sysutil.CLONE_NEWNET)
            os.close(fd)
            sysutil.mount(b'', b'/', b'none', sysutil.MS_SLAVE | sysutil.MS_REC, None)

            sysutil.unshare(sysutil.CLONE_NEWNS)
            sysutil.umount2(b'/sys', sysutil.MNT_DETACH)
            sysutil.mount(self.fd_path.encode(), b'/sys', b'sysfs', 0, None)

            for mount in self.mounts:
                mount.mount()

            if overlay_fs:
                self.fs = OverlayMount('/etc', self.etc_path)
                self.fs.start()
            else:
                self.mount_etc()
        else:
            old_cwd = os.getcwd()

            if (exclude_ns & sysutil.CLONE_NEWUSER) == 0:
                self._join_ns(sysutil.CLONE_NEWUSER)
            if (exclude_ns & sysutil.CLONE_NEWNET) == 0:
                self._join_ns(sysutil.CLONE_NEWNET)
            if (exclude_ns & sysutil.CLONE_NEWPID) == 0:
                self._join_ns(sysutil.CLONE_NEWPID)
            if (exclude_ns & sysutil.CLONE_NEWIPC) == 0:
                self._join_ns(sysutil.CLONE_NEWIPC)
            if (exclude_ns & sysutil.CLONE_NEWUTS) == 0:
                self._join_ns(sysutil.CLONE_NEWUTS)

            # Mount namespace must be last
            if (exclude_ns & sysutil.CLONE_NEWNS) == 0:
                self._join_ns(sysutil.CLONE_NEWNS)

            try:
                os.chdir(old_cwd)
            except FileNotFoundError:
                pass

    def exit(self):
        cwd = os.getcwd()
        fds = self.fd_stack.pop()
        netns_fd, mnt_fd = fds[0:2]

        if not security.is_sudo_or_root():
            sysutil.setns(fds[2], sysutil.CLONE_NEWUSER)
            os.close(fds[2])

        sysutil.setns(netns_fd, sysutil.CLONE_NEWNET)
        os.close(netns_fd)

        sysutil.setns(mnt_fd, sysutil.CLONE_NEWNS)
        os.close(mnt_fd)

        os.chdir(cwd)

    def __enter__(self):
        self.enter()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exit()

    def _nodefault(self):
        if self.fd_path is None:
            raise InvalidOperation('Invalid operation for the default namespace')

    @property
    def _run_path(self):
        self._nodefault()
        if '/' in self.name:
            return self.name
        return os.path.join(self._RUN_DIR, self.fd_path)

    @property
    def etc_path(self):
        if self.name is None:
            return '/etc'
        if self.custom_etc_path is not None:
            return self.custom_etc_path
        return os.path.join(self._ETC_DIR, self.fd_path)

    def create(self):
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.setpgid(0, 0)
            os.close(read)
            self._nodefault()

            if not security.is_sudo_or_root():
                real_user = security.real_user()
                real_group = security.real_group()

                sandbox.map_user(real_user, real_group)
                sysutil.unshare(sysutil.CLONE_NEWNS)
                self.fs = OverlayMount('/etc', self.etc_path)
                self.fs.start()

            sysutil.unshare(sysutil.CLONE_NEWNET)
            sysutil.unshare(sysutil.CLONE_NEWPID)
            sysutil.unshare(sysutil.CLONE_NEWIPC)
            sysutil.unshare(sysutil.CLONE_NEWUTS)

            # We need to fork here because unshare(CLONE_NEWPID) is only effective when a process is created
            pid = os.fork()
            if pid == 0:
                os.setpgid(0, 0)
                # This is the init process inside our PID namespace (PID 1).
                # When it is killed, all other processes inside the namespace are killed as well.
                if not security.is_sudo_or_root():
                    sysutil.mount(b'proc', b'/proc', b'proc', 0, None)

                    # Prevent zombie processes
                    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
                    sysutil.prctl(sysutil.PR_SET_CHILD_SUBREAPER, 1)

                # This is a dirty hack. Mounts at / do not become effective unless rejoining the mount namespace.
                # Therefore, we signal changed root mounts through SIGUSR1.
                signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1, signal.SIGINT, signal.SIGTERM])
                while signal.sigwait([signal.SIGINT, signal.SIGTERM, signal.SIGUSR1]) == signal.SIGUSR1:
                    join_namespace(sysutil.CLONE_NEWNS, os.getpid())
                sysutil.fork_exit(0)

            os.write(write, struct.pack('I', pid))
            os.close(write)

            sysutil.fork_exit(0)
        else:
            os.close(write)
            ns_pid = struct.unpack('I', sysutil.read_blocking(read, 4))[0]
            os.close(read)
            os.symlink('/proc/%d/ns/' % ns_pid, self.fd_path)
            self.fd_path = '/proc/%d/ns' % ns_pid
            self.pid = ns_pid
            with open(self.pid_path, 'w') as f:
                f.write(str(ns_pid))
            os.waitpid(pid, 0)  # Do not let the process become a zombie.
            return ns_pid

    def delete(self, suppress_errors=False):
        pid = os.fork()
        if pid == 0:
            os.setpgid(0, 0)
            self._nodefault()
            try:
                sysutil.umount2(self._run_path.encode(), sysutil.MNT_DETACH)
            except OSError as e:
                if not suppress_errors:
                    raise e
            finally:
                try:
                    os.unlink(self._run_path)
                except Exception as e:
                    if not suppress_errors:
                        raise e

            # noinspection PyProtectedMember,PyUnresolvedReferences
            os._exit(0)
        else:
            os.waitpid(pid, 0)

    @classproperty
    def default(self):
        return NetworkNamespace('/proc/1/ns/net')

    @property
    def is_default(self):
        return self.fd_path is None or self.fd_path == '/proc/1/ns/net'

    @property
    def name(self):
        return self.fd_path
