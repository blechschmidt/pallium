import logging
import os
import pwd
import select
import shutil
import signal
import socket
import sys

from . import sysutil, onexit
from . import util

"""We sometimes want to allow audio to be exposed to other users. Since pulseaudio is complex and we do not want to
fiddle with its configuration files, we override the pulseaudio config in the user's home directory by bind mounting a
custom configuration. This configuration instructs pulseaudio to connect to a Unix socket that acts as a proxy between
the pulseaudio daemon of the user that called pallium and the clients inside the application namespace.

We do not want to cover all configuration possibilities here. It is sufficient if this works for the majority of users.
In case it does not, the audio option cannot be used and it is up to the pallium user to configure audio accessibility
for other users manually."""


class ProxyState:
    def __init__(self, counterpart, connected=True):
        self.counterpart = counterpart
        self.to_be_sent = b''
        self.connected = connected

    def add_data(self, data):
        self.to_be_sent += data


class SocketProxy:
    def __init__(self, srv_path, dst_path):
        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.bind(srv_path)
        self.srv_sock = srv_sock
        self.dst_path = dst_path
        self.srv_sock.setblocking(False)
        self.sockmap = {}
        self._process = None

    def server_readable(self):
        client_sock, _ = self.srv_sock.accept()
        client_counterpart = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.setblocking(False)
        client_counterpart.setblocking(False)
        client_counterpart.connect(self.dst_path)
        self.sockmap[client_sock] = ProxyState(client_counterpart)
        self.sockmap[client_counterpart] = ProxyState(client_sock, False)

    def client_readable(self, sock):
        if sock not in self.sockmap:
            return
        try:
            data = sock.recv(4096)
        except (ConnectionError, OSError):
            self.remove_pair(sock)
            return
        counterpart = self.sockmap[sock].counterpart
        self.sockmap[counterpart].to_be_sent += data

    def client_writable(self, sock):
        if sock not in self.sockmap:
            return
        state = self.sockmap[sock]
        if not state.connected:
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                self.remove_pair(sock)
                return
            state.connected = True
            return
        try:
            sent = sock.send(state.to_be_sent)
            state.to_be_sent = state.to_be_sent[sent:]
        except (ConnectionError, OSError):
            self.remove_pair(sock)

    def remove_pair(self, sock):
        counterpart = self.sockmap[sock].counterpart
        del self.sockmap[sock]
        del self.sockmap[counterpart]
        sock.close()
        counterpart.close()

    def run(self):
        self.srv_sock.listen(16)
        while True:
            readsocks = [self.srv_sock] + list(self.sockmap.keys())
            writesocks = [sock for sock, st in self.sockmap.items() if len(st.to_be_sent) > 0 or not st.connected]
            read, write, ex = select.select(readsocks, writesocks, readsocks, 0.3)
            for r in read:
                if r is self.srv_sock:
                    self.server_readable()
                else:
                    self.client_readable(r)

            for w in write:
                self.client_writable(w)

    def start(self):
        self._process = os.fork()
        if self._process == 0:
            logging.getLogger().debug('Audio fork: %d' % self._process)
            sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL)
            onexit.clear()
            self.run()

    def stop(self):
        os.kill(self._process, signal.SIGTERM)


def mount_pulse_file(tmpdir, user_home, filename):
    src = os.path.join(tmpdir, filename).encode()
    target = os.path.join(user_home, '.config', 'pulse', filename).encode()
    sysutil.mount(src, target, b'none', sysutil.MS_BIND, None)


def proxy_pulseaudio(daemon_user, proxy_for_user):
    if sysutil.user_to_uid(proxy_for_user) == sysutil.user_to_uid(daemon_user):
        return

    # Detect if the target user has a pulseaudio daemon running. See `man pulseaudio` for details.
    proc = util.popen(['pulseaudio', '--check'], **sysutil.privilege_drop_preexec(proxy_for_user, True))
    proc.wait()
    daemon_running = proc.returncode == 0

    # We do not (need to) proxy audio in this case.
    if daemon_running:
        return

    proxy_for_user_pwd = pwd.getpwnam(proxy_for_user)
    daemon_user_pwd = pwd.getpwnam(daemon_user)

    daemon_user_home = daemon_user_pwd.pw_dir
    daemon_user_pulse_dir = os.path.join(daemon_user_home, '.config', 'pulse')
    cookie_file = os.path.join(daemon_user_pulse_dir, 'cookie')

    if not os.path.isfile(cookie_file):
        return

    daemon_srv_path = '/run/user/%d/pulse/native' % daemon_user_pwd.pw_uid
    if not os.path.exists(daemon_srv_path):
        return

    tmpdir = util.mkdtemp(prefix="pulse_")
    os.chown(tmpdir, proxy_for_user_pwd.pw_uid, proxy_for_user_pwd.pw_gid)

    shutil.copyfile(cookie_file, os.path.join(tmpdir, 'cookie'))
    os.chown(os.path.join(tmpdir, 'cookie'), proxy_for_user_pwd.pw_uid, proxy_for_user_pwd.pw_gid)

    client_srv_path = os.path.join(tmpdir, 'pulse.sock')
    with open(os.path.join(tmpdir, 'client.conf'), 'w') as f:
        f.write('default-server=%s\ndisable-shm=yes\n' % client_srv_path)
    os.chown(os.path.join(tmpdir, 'client.conf'), proxy_for_user_pwd.pw_uid, proxy_for_user_pwd.pw_gid)

    # mount_pulse_file(tmpdir, proxy_for_user_pwd.pw_dir, '')
    mi = (tmpdir, os.path.join(proxy_for_user_pwd.pw_dir, '.config', 'pulse',))

    proxy = SocketProxy(client_srv_path, daemon_srv_path)

    # Access to the proxy is guarded by file permissions of the proxy server socket
    os.chmod(client_srv_path, 0o700)
    os.chown(client_srv_path, proxy_for_user_pwd.pw_uid, proxy_for_user_pwd.pw_gid)

    proxy.start()

    def cleanup():
        proxy.stop()

    return cleanup, mi


if __name__ == '__main__':
    proxy_pulseaudio(sys.argv[1], sys.argv[2])
