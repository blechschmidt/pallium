import copy
import ctypes
import dataclasses
import errno
import glob
import json
import logging
import os.path
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import traceback
from typing import Optional

from . import onexit
from . import sysutil, security, netns, exceptions, util, virtuser
from . import xpra
from .exceptions import DependencyNotFoundException
from .virtuser import VirtualUser

try:
    import seccomp
except ImportError:
    import pyseccomp as seccomp

INACCESSIBLE_FILES = [
    '/run/systemd/inaccessible/reg',
]

INACCESSIBLE_DIRS = [
    '/run/systemd/inaccessible/dir',
]


@dataclasses.dataclass
class GvisorConfig:
    pass


ENV_INHERIT_DEFAULT = {'SHELL', 'DISPLAY', 'PATH'}


class PathEntry:
    from_glob = False

    def __init__(self, dst):
        self.dst = dst

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.dst)


class Blacklist(PathEntry):
    id = "blacklist"

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, str):
            raise exceptions.ConfigurationError("Invalid blacklist instruction: %s" % obj)
        return cls(obj)


class Mount(PathEntry):
    pass


class BindMountExternal(Mount):
    id = "bind"

    def __init__(self, dst, src=None):
        super().__init__(dst)
        if src is None:
            src = dst
        self.src = src
        self.fd: int
        self.is_dir = None

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, list) or len(obj) != 2:
            raise exceptions.ConfigurationError("Invalid bind mount: %s" % obj)
        return cls(*obj)


class Whitelist(BindMountExternal):
    id = "whitelist"

    def __init__(self, path):
        super().__init__(path, path)

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, str):
            raise exceptions.ConfigurationError("Invalid whitelist instruction: %s" % obj)
        return cls(obj)


class FileSystemMount(Mount):
    id = "fsmount"

    def __init__(self, dst, fs_type):
        super().__init__(dst)
        self.fs_type = fs_type

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, list) or len(obj) != 2:
            raise exceptions.ConfigurationError("Invalid file system mount: %s" % obj)
        return cls(*obj)


class ContentMount(Mount):
    def __init__(self, dst, content):
        super().__init__(dst)
        self.content = content


# If you touch this, do not forget to update the README.
VIRTUSER_DEFAULT_FILE_CONFIG = [
    Blacklist('/'),
    Whitelist('/usr'),
    Whitelist('/bin'),
    Whitelist('/usr/lib'),
    Whitelist('/lib'),
    Whitelist('/usr/lib64'),
    Whitelist('/lib64'),
    Whitelist('/dev/null'),
    Whitelist('/dev/zero'),
    Whitelist('/dev/random'),
    Whitelist('/dev/urandom'),
    Whitelist('/usr/share'),
    Whitelist('/etc/'),
    FileSystemMount('/tmp', 'tmpfs'),
    FileSystemMount('/run', 'tmpfs'),
    FileSystemMount('/sys', 'sysfs'),
    FileSystemMount('/var/tmp', 'tmpfs'),
    FileSystemMount('/dev/shm', 'tmpfs'),
    FileSystemMount('/dev/mqueue', 'mqueue'),
    FileSystemMount('/dev/pts', 'devpts'),
]


class _FileSystemTreeNode:
    def __init__(self):
        self.entry: Optional[PathEntry] = None
        self.parent: Optional[_FileSystemTreeNode] = None
        self.children = {}
        self.path = None
        self.has_non_blacklisted_children = False
        self.from_glob = False

    def __repr__(self):
        return str({
            'path': self.path,
            'entry': repr(self.entry),
            'children': {
                k: repr(self.children[k]) for k in self.children
            },
            'has_non_blacklisted_children': self.has_non_blacklisted_children,
        })


class _DenyPaths:
    denied_file: int
    denied_dir: int


def _path_components(path):
    return [x for x in path.split('/') if x != '']


def _clone_dir(path):
    pass


def _create_path(path, is_dir):
    """
    Create a path such that a mount at an arbitrary location can succeed.
    As an example, when you want to mount a file at /my/file and the path does not exist on the host, a temporary file
    system will be mounted at / with all directories and files of / path-mounted inside.

    @param path: The path.
    @param is_dir: Whether the destination is to be mounted as a directory or as a file.
    @return: None.
    """
    components = _path_components(path)
    assert len(components) > 0
    recreated_path = ''
    for j, component in enumerate(components):
        is_last_component = j == len(components) - 1
        if is_last_component and not is_dir:
            break
        recreated_path += '/' + component
        if not os.path.exists(recreated_path) and not os.path.islink(recreated_path):
            os.mkdir(recreated_path, 0o700)
    if not is_dir:
        os.close(os.open(path, os.O_CREAT))


def _add_to_tree(root: _FileSystemTreeNode, entry: PathEntry, overwrite_on_conflict: bool = False):
    assert os.path.isabs(entry.dst)
    path = _path_components(entry.dst)
    assert '.' not in path and '..' not in path
    node = root
    processed_path = ''
    for component in path:
        processed_path += '/' + component
        next_node = node.children.get(component, None)
        if next_node is None:
            next_node = _FileSystemTreeNode()
            node.children[component] = next_node
            next_node.parent = node
            next_node.path = processed_path
        node = next_node

    if node.entry is None:
        node.entry = entry
    elif node.entry.from_glob and not entry.from_glob:
        # The old node was from a glob, so it is less specific. The new node takes precedence.
        node.entry = entry
    elif not node.entry.from_glob and entry.from_glob:
        # The new node was from a glob, so it is less specific. The old node takes precedence.
        # The old node is already in the tree, so nothing to do.
        return
    elif node.entry is not None and node.entry.__class__ != entry.__class__ and not overwrite_on_conflict:
        raise Exception("Conflicting path entries")
    else:
        node.entry = entry

    if isinstance(entry, Blacklist):
        return

    node = node.parent
    while node is not None:
        node.has_non_blacklisted_children = True
        node = node.parent


def _add_list_to_tree(root, lst):
    for item in lst:
        if isinstance(item, Whitelist) or isinstance(item, Blacklist):
            globbed = glob.glob(item.dst, recursive=True)
            for name in globbed:
                # It was a glob expression if it returned more than one file
                # or if the first result does not match the input pattern.
                item.from_glob = len(globbed) > 1 or item.dst != globbed[0]
                item = copy.deepcopy(item)
                item.dst = name
                item.src = name
                _add_to_tree(root, item)
        else:
            _add_to_tree(root, item)


def build_mounts(paths, tmpdir=None):
    root = _FileSystemTreeNode()
    root.path = '/'
    _add_list_to_tree(root, paths)
    deny = _DenyPaths()
    disallowed_file = [f for f in INACCESSIBLE_FILES if os.path.exists(f)]
    if len(disallowed_file) == 0:
        disallowed_file = tempfile.mktemp(prefix='disallow', dir=tmpdir)
        os.close(os.open(disallowed_file, os.O_CREAT, 0o000))
        onexit.register(lambda: os.unlink(disallowed_file))
    else:
        disallowed_file = disallowed_file[0]

    disallowed_dir = [f for f in INACCESSIBLE_DIRS if os.path.exists(f)]
    if len(disallowed_dir) == 0:
        disallowed_dir = tempfile.mktemp(prefix='disallow', dir=tmpdir)
        os.mkdir(disallowed_dir, 0o000)
        onexit.register(lambda: os.rmdir(disallowed_dir))
    else:
        disallowed_dir = disallowed_dir[0]

    mounts = []

    def preexec_fn(_):
        deny.denied_file = os.open(disallowed_file, os.O_PATH)
        deny.denied_dir = os.open(disallowed_dir, os.O_PATH)

    mounts.append(netns.MountInstruction(None, None, None, preexec_fn=preexec_fn))

    to_traverse = [root]
    traversal = []
    while len(to_traverse) > 0:
        node = to_traverse.pop()
        traversal.append(node)
        to_traverse.extend(node.children.values())

    # We first traverse all the bind mounts to obtain path file descriptors and assign them to the nodes.
    for node in traversal:
        if not isinstance(node.entry, BindMountExternal):
            continue

        def keep_closure(node):
            def preexec_fn(_):
                fd = os.open(node.entry.src, os.O_PATH)
                node.entry.fd = fd
                node.entry.is_dir = os.path.isdir(node.entry.src)
                logging.getLogger(__name__).debug('Path %s at FD %d' % (node.entry.src, fd))

            return preexec_fn

        mounts.append(netns.MountInstruction(None, None, None, preexec_fn=keep_closure(node)))

    for node in traversal:
        if isinstance(node.entry, Blacklist):
            if node.has_non_blacklisted_children:
                def postexec_closure(node):
                    def postexec_fn(_):
                        if node.path == '/':
                            # Mounting a tmpfs at root only becomes effective by rejoining the mount namespace.
                            netns.join_namespace(sysutil.CLONE_NEWNS, os.getpid())
                            os.mkdir('/proc')
                            netns.MountInstruction('proc', '/proc', 'proc').mount()

                    return postexec_fn

                mounts.append(netns.MountInstruction(None, node.path, 'tmpfs', postexec_fn=postexec_closure(node)))
            else:
                if os.path.isdir(node.path):
                    def preexec_closure(node):
                        def preexec_fn(m):
                            if not os.path.exists(node.entry.dst):
                                return False
                            m.src = '/proc/self/fd/%d' % deny.denied_dir

                        return preexec_fn
                    preexec_fn = preexec_closure(node)
                elif os.path.exists(node.path):
                    def preexec_closure(node):
                        def preexec_fn(m):
                            if not node.path.exists(node.dst):
                                return False
                            m.src = '/proc/self/fd/%d' % deny.denied_file

                        return preexec_fn

                    preexec_fn = preexec_closure(node)
                else:
                    def preexec_fn(_):
                        return False
                mounts.append(netns.MountInstruction(None, node.path, preexec_fn=preexec_fn))

        # for node in traversal:
        if isinstance(node.entry, (BindMountExternal, FileSystemMount)):
            def pre_closure(node):
                def preexec(m):
                    if isinstance(node.entry, BindMountExternal):
                        m.src = '/proc/self/fd/%d' % node.entry.fd
                    is_dir = node.entry.is_dir if isinstance(node.entry, BindMountExternal) else True
                    _create_path(node.path, is_dir)

                return preexec

            fstype = 'bind' if isinstance(node.entry, BindMountExternal) else node.entry.fs_type
            mounts.append(netns.MountInstruction(None, node.entry.dst, fstype, preexec_fn=pre_closure(node)))

    # This it the final traversal where we close the path file descriptors that we have opened.
    for node in traversal:
        if not isinstance(node.entry, BindMountExternal):
            continue

        def capture(node):
            def preexec_fn(_):
                os.close(node.entry.fd)

            return preexec_fn

        mounts.append(netns.MountInstruction(None, None, None, preexec_fn=capture(node)))

    def preexec_fn(_):
        os.close(deny.denied_file)
        os.close(deny.denied_dir)

    mounts.append(netns.MountInstruction(None, None, None, preexec_fn=preexec_fn))

    return mounts


def gvisor_init_path():
    gvisor_init_exe = shutil.which(util.get_tool_path('gvisor-init'))
    if gvisor_init_exe is not None:
        return gvisor_init_exe
    return os.path.join(os.path.dirname(__file__), 'gvisor-init', 'gvisor-init')


class Sandbox:
    def __init__(self, paths=None, env=None, inherit_env=True, unpriv_user_ns=True, virtual_user=None,
                 audio=False, gui=False, tmpdir=None, hostname='pallium', workdir=None, gvisor=False):
        if inherit_env is None:
            inherit_env = ENV_INHERIT_DEFAULT
        if paths is None:
            # Effectively create a tmpfs for the root file system and path-mount all files and subdirectories.
            paths = [
                Blacklist('/'),
                Whitelist('/*'),
                # Also include hidden files.
                Whitelist('/.*')
            ]
        if inherit_env is True:
            new_env = os.environ.copy()
            if env is not None:
                for key in env:
                    new_env[key] = env[key]
            env = new_env
        elif isinstance(inherit_env, (list, set)):
            if env is None:
                env = {}
            for key in inherit_env:
                if key in os.environ:
                    env[key] = os.environ[key]
        if env is None:
            env = {}
        self.workdir = workdir
        self.unpriv_user_ns = unpriv_user_ns
        self.env = env
        self.paths = paths.copy()
        self.gvisor = gvisor

        self.tmpdir = tmpdir
        self.virtual_user = None
        self.hostname = hostname
        if virtual_user is not None:
            self._setup_virtual_user(virtual_user)
        if audio:
            self._setup_audio()
        if gui:
            self._setup_gui(gui)

    def _setup_audio(self):
        self.paths.append(BindMountExternal('/run/user/%d/pulse/' % security.EUID))

    def _setup_gui(self, method):
        original_display = os.environ.get('DISPLAY', None)
        if original_display is not None and original_display.startswith(':'):
            original_display = int(original_display[1:])

        if method == 'xpra' or method is True:
            display_no = xpra.start_xpra()
            display = ':%d' % display_no
        elif method != 'expose':
            raise exceptions.ConfigurationError('Invalid GUI forwarding method')
        else:
            display = os.environ.get('DISPLAY', None)
        if display is not None and display.startswith(':'):
            display = int(display[1:])
            self.paths.append(BindMountExternal('/tmp/.X11-unix/X%s' % original_display, '/tmp/.X11-unix/X%d' % display))

    def _etc_virtuser_mounts(self, virtual_user):
        pwd_struct = pwd.getpwuid(security.RUID)
        etc_passwd = '%s:x:%d:%d::%s:%s\n' % (
            virtual_user.name,
            pwd_struct.pw_uid,
            pwd_struct.pw_gid,
            virtual_user.home_mount,
            pwd_struct.pw_shell
        )

        passwd_file = util.mktemp()
        with open(passwd_file, 'w') as f:
            f.write(etc_passwd)

        group_file = '%s:x:%d:\n' % (
            virtual_user.name,
            pwd_struct.pw_gid
        )
        filename2 = util.mktemp()
        with open(filename2, 'w') as f:
            f.write(group_file)

        hostname_file = util.mktemp()
        with open(hostname_file, 'w') as f:
            f.write(self.hostname.strip() + '\n')

        return [
            BindMountExternal('/etc/passwd', passwd_file),
            BindMountExternal('/etc/group', filename2),
            BindMountExternal('/etc/hostname', hostname_file)
        ]

    def _setup_virtual_user(self, virtual_user):
        if isinstance(virtual_user, str):
            virtual_user = virtuser.VirtualUser(virtual_user)

        if isinstance(virtual_user, virtuser.VirtualUser):

            if virtual_user.temporary:
                self.paths.append(FileSystemMount(virtual_user.home_mount, 'tmpfs'))
            else:
                self.paths.append(BindMountExternal(virtual_user.home_mount, virtual_user.home))

            self.paths.extend(self._etc_virtuser_mounts(virtual_user))

            self.env['HOME'] = virtual_user.home_mount
        else:
            raise ValueError
        self.virtual_user = virtual_user

    def prepare(self):
        if self.virtual_user is not None:
            self.virtual_user.prepare()

    def get_mounts(self):
        return build_mounts(self.paths, self.tmpdir)

    def setup(self):
        socket.sethostname(self.hostname)

    def setup_and_enter(self, root=False):
        self.setup()
        self.enter(root)

    @property
    def working_dir(self):
        if self.workdir is not None:
            if self.workdir != "":
                return self.workdir
        elif self.virtual_user:
            return self.virtual_user.home_mount
        return os.getcwd()

    def enter(self, root=False):
        if self.gvisor is False:
            if os.path.isdir(self.working_dir):
                os.chdir(self.working_dir)
            else:
                logging.error('Working directory "%s" is not a directory' % self.working_dir)

        if self.gvisor is False and not root:
            map_back_real()

        # We support disabling user namespaces to reduce the attack surface of the kernel inside the sandbox.
        if not self.unpriv_user_ns:
            if self.gvisor is not False:
                raise Exception("Currently unsupported for gvisor")
            # See section "C library/kernel differences" on https://man7.org/linux/man-pages/man2/clone.2.html.
            # Other architectures are currently not supported because the `flags` argument may not be the first one,
            # rendering the seccomp rules useless.
            if ctypes.c_uint32(seccomp.system_arch()).value not in set(map(lambda x: ctypes.c_uint32(x).value, [
                seccomp.Arch.X86_64, seccomp.Arch.X86, seccomp.Arch.ARM, seccomp.Arch.AARCH64
            ])):
                raise Exception('Unsupported architecture')

            # Decrease attack surface by disallowing child namespaces
            f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
            f.add_rule(seccomp.ERRNO(errno.EPERM), "setns")
            f.add_rule(seccomp.ERRNO(errno.EPERM), "unshare")

            # Architecture check is performed by the seccomp library automatically.
            f.add_rule(seccomp.ERRNO(errno.EPERM), "clone",
                       seccomp.Arg(0, seccomp.MASKED_EQ, sysutil.CLONE_NEWUSER, sysutil.CLONE_NEWUSER))

            # Lack of seccomp deep argument inspection does not allow for targeting of CLONE_NEWUSER calls with clone3.
            # Simulate "not implemented" to suggest that the kernel is too old and hope that implementations fall back
            # to a clone version that we can inspect.
            f.add_rule(seccomp.ERRNO(errno.ENOSYS), "clone3")
            f.load()

    @classmethod
    def from_json(cls, obj):
        # Check for correct format. Maybe switch to JSON schema in the future.
        if not isinstance(obj, dict):
            raise exceptions.ConfigurationError('Sandbox must be an object.')
        paths = obj.get('paths', {})
        if not isinstance(paths, dict):
            raise exceptions.ConfigurationError('Sandbox paths property must be an object.')

        virtual_user = obj.get('virtuser')
        if virtual_user is not None:
            virtual_user = VirtualUser.from_json(virtual_user)

        gvisor = obj.get('gvisor')
        if gvisor:
            gvisor = GvisorConfig()
        else:
            gvisor = False

        # The mode handles how mount instructions are dealt with.
        # In case of 'append', the instructions are added to the default hierarchy.
        # In case of 'base', the hierarchy is created from an empty tmpfs. In this case, the user is responsible for
        # the creation of a minimally functional hierarchy.
        mode = paths.get('mode', 'append')
        if mode not in {'append', 'base'}:
            raise exceptions.ConfigurationError('Invalid mode.')
        paths_arg = None
        if 'virtuser' in obj or 'paths' in obj:
            paths_arg = VIRTUSER_DEFAULT_FILE_CONFIG.copy() if mode == 'append' else [Blacklist('/')]

        # Create the mount instructions as specified by the user.
        # The object keys are identifiers of the respective mount instruction class.
        # To additionally whitelist /opt, a user would provide the following object.
        # {
        #     "whitelist": ["/opt"]
        # }
        file_instruction_classes = {c.id: c for c in util.get_subclasses(PathEntry) if hasattr(c, 'id')}
        for tp in paths:
            if tp in {'mode'}:
                continue
            if tp not in file_instruction_classes:
                raise exceptions.ConfigurationError('Invalid path instruction type: %s' % tp)
            if not isinstance(paths[tp], list):
                raise exceptions.ConfigurationError('File instructions must be supplied as list')
            for entry in paths[tp]:
                if paths_arg is None:
                    paths_arg = []
                paths_arg.append(file_instruction_classes[tp].from_json(entry))

        return cls(paths=paths_arg,
                   virtual_user=virtual_user,
                   audio=obj.get('audio', False),
                   gui=obj.get('gui', False),
                   unpriv_user_ns=obj.get('unpriv_user_ns', True),
                   workdir=obj.get('workdir'),
                   hostname=obj.get('hostname', 'pallium'),
                   gvisor=gvisor)

    def run(self, session, argv, ns_index=-1, root=False, call_args=None, terminal=False):
        # TODO: Make this a parameter
        execute = False
        if isinstance(argv, str):
            argv = [argv]
        if call_args is None:
            call_args = {}

        # Only use gvisor if the sandbox specification requires it.
        # Since we run it in the last namespace only, we only enable it when the ns_index is -1.
        # The ns_index is for debugging only.
        use_gvisor = self.gvisor is not False and ns_index == -1

        profile = session.profile
        if security.is_sudo_or_root():
            call_args.update(sysutil.privilege_drop_preexec(profile.user, True))
        else:
            def preexec_fn():
                try:
                    profile.sandbox.setup_and_enter(root=root)
                except:
                    traceback.print_exc()
                    raise

            call_args.update(dict(
                preexec_fn=preexec_fn,
                env=profile.sandbox.env))
            if use_gvisor:
                argv_orig = argv
                runsc_path = shutil.which(util.get_tool_path('runsc'))
                if runsc_path is None:
                    raise DependencyNotFoundException('Unable to find the runsc binary. Gvisor needs to be installed.')

                # The gvisor bundle dir and root dir point to the gvisor folder inside
                # our session folder. We pass this as a path FD to gvisor. Since the FD
                # is not passed on to the sandbox, the guest has no access to the folder.
                # (Provided that the file system is not shared.)
                gvisor_config_dir = os.path.join(session.session_folder, 'gvisor')
                if os.path.exists(gvisor_config_dir):
                    execute = True
                else:
                    os.mkdir(gvisor_config_dir)
                gvisor_config_dir_fd = os.open(gvisor_config_dir, os.O_PATH)
                gvisor_config_fd_path = '/proc/self/fd/%d' % gvisor_config_dir_fd
                gvisor_init_fd = os.open(gvisor_init_path(), os.O_RDONLY)

                # This way, gvisor does not need to be in our path and can be excluded from the sandbox.
                # Thanks to static linking of Go binaries, this will work fine.
                runsc_fd = os.open(runsc_path, os.O_PATH)
                call_args['executable'] = '/proc/self/fd/%d' % runsc_fd
                call_args['pass_fds'] = [runsc_fd, gvisor_config_dir_fd, gvisor_init_fd]
                call_args['shell'] = False

                map_user_args = [
                    '--uid-map', '%d 0 1' % security.RUID,
                    '--gid-map', '%d 0 1' % security.RGID
                ] if not root else []

                controlling_terminal = [
                    '--controlling-terminal'
                ]

                init = [
                    'pallium-gvisor-init',
                    *map_user_args,
                    *controlling_terminal,
                    '--'
                ]

                argv_run = init
                if call_args.get('shell'):
                    unix_shell = '/system/bin/sh' if hasattr(sys, 'getandroidapilevel') else '/bin/sh'
                    argv_run += [unix_shell, '-c']
                assert len(argv_orig) > 0
                argv_orig[0] = shutil.which(argv_orig[0])
                argv_run += argv_orig

                spec = {
                    "root": {
                        "path": "/"
                    },
                    "process": {
                        "env": [k + '=' + v for k, v in profile.sandbox.env.items()],
                        "cwd": self.working_dir,
                        "args": argv_run,
                        "terminal": terminal,
                    },
                    "hostname": self.hostname
                }

                with open(os.path.join(gvisor_config_dir, 'config.json'), 'w') as f:
                    f.write(json.dumps(spec))

                def preexec():
                    try:
                        sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL)
                        profile.sandbox.setup_and_enter(root=root)
                    except:
                        traceback.print_exc()
                        sys.exit(1)

                call_args.update(dict(
                    preexec_fn=preexec))

                if terminal:
                    # Ignore all signals that we can ignore
                    signals = [getattr(signal, s) for s in dir(signal) if re.match(r'SIG[A-Z0-9]+', s)]
                    for s in signals:
                        if s == signal.SIGCHLD or s == signal.SIGPIPE:
                            continue
                        try:
                            signal.signal(s, signal.SIG_IGN)
                        except OSError as e:
                            # Error that is thrown when the signal cannot be ignored
                            if e.errno != errno.EINVAL:
                                raise

                if not execute:
                    argv = [
                        runsc_path,
                        '--ignore-cgroups',
                        '--network=host',
                        # '--debug', '--debug-log', '/tmp/gvisor-debug.txt',
                        '--file-access=shared',
                        '--rootless',
                        '--host-uds=all',
                        '--root=' + gvisor_config_dir,
                        '--overlay2=none',
                        'run',
                        '--exec-fd', '%d' % gvisor_init_fd,
                        '--bundle',
                        gvisor_config_fd_path,
                        session.long_id
                    ]
                else:
                    argv = [
                        runsc_path,
                        '--root=' + gvisor_config_dir,
                        'exec',
                        '--exec-fd', '%d' % gvisor_init_fd,
                        session.long_id
                    ] + argv_run

        ns = session.network_namespaces[ns_index]

        def run():
            try:
                subprocess.call(argv, **call_args)
            except:
                traceback.print_exc()
                sys.exit(1)
        os.kill(session.sandbox_pid, signal.SIGUSR1)
        ns.run(run, new_session=False)


def map_user(real_uid, real_gid, to_user=0, to_group=0):
    sysutil.unshare(sysutil.CLONE_NEWUSER)
    with open("/proc/self/uid_map", "w") as f:
        f.write('%d %d 1' % (to_user, real_uid))
    with open("/proc/self/setgroups", "w") as f:
        f.write('deny')
    with open("/proc/self/gid_map", "w") as f:
        f.write('%d %d 1' % (to_group, real_gid))


def map_back_real():
    map_user(0, 0, security.RUID, security.RGID)
