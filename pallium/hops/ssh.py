from typing import List, Optional
from .socksapp import SocksAppHop
from .. import sandbox
from .. import security


class SshHop(SocksAppHop):
    def __init__(self,
                 destination: str,
                 user: Optional[str] = None,
                 ssh_args: Optional[List[str]] = None,
                 timeout: float = 30,
                 **kwargs):
        """


        @param destination: The destination as supplied to the ssh binary. [username@]host
        @param user: The user which to run the ssh process as.
        @param ssh_args: Additional arguments passed to the SSH daemon.
        @param timeout: Connection timeout in seconds.
        """
        super().__init__(user, None, timeout, **kwargs)
        self._destination = destination
        self._args = ssh_args if ssh_args is not None else []

    def update_cmd(self, hop_info):
        if not security.is_sudo_or_root():
            sandbox.map_back_real()
        self.cmd = ['ssh', '-N', '-D', '%s:%d' % self._socks_endpoint]
        if self._args is not None:
            self.cmd += self._args  # Append custom user-provided arguments
        self.cmd += [self._destination]

        # For now, we rely on SOCKS5 remote DNS as we want minimal configuration without relying on third-parties.
        # We could also set up a TCP proxy for the DNS servers inside the remote /etc/resolv.conf file.
        # Problem: We would have to remap special IPs, such as 127.0.0.1 (e.g. when systemd-resolve is used).
        # For example, 10.0.0.1 at the tun interface would be mapped to 127.0.0.1 at the SOCKS level.
        # But tun2socks does not support that (yet).
        """if not self.dns_overridden:
            fd = os.open('/tmp', os.O_RDWR | os.O_TMPFILE)
            subprocess.call(['scp', self._destination + ':/etc/resolv.conf', '/proc/self/fd/%d' % fd], pass_fds=[fd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open('/proc/self/fd/%d' % fd) as f:
                resolv_conf = f.read()
            os.close(fd)"""
