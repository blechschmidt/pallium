import binascii
import ipaddress
import os
import signal
import struct
import subprocess
import time
from typing import Optional

from pyroute2.iproute import IPRoute

from . import hop, socks
from .. import sysutil, security, netns


def decode_addr(addr):
    addr, port = addr.split(':')
    port = int(port, 16)
    return ipaddress.IPv4Address(struct.unpack('=I', binascii.unhexlify(addr))[0]), port


def get_tcp_connections():
    with open('/proc/net/tcp') as f:
        for i, line in enumerate(f):
            if i == 0 or line.strip() == '':
                continue
            local, remote = line.split()[1:3]
            local, remote = decode_addr(local), decode_addr(remote)
            yield local, remote


def wait_for_listener(addr, timeout: float = 30, exception_function=None):
    start_time = time.perf_counter()
    end_time = start_time + timeout if timeout is not None else None
    addr = ipaddress.ip_address(addr[0]), addr[1]

    while True:
        for conn in get_tcp_connections():
            local, remote = conn
            if addr == local and remote == (ipaddress.IPv4Address('0.0.0.0'), 0):
                return True

        if end_time is not None and time.perf_counter() >= end_time:
            return False
        time.sleep(0.1)

        if exception_function is not None:
            exception_function()


class SocksAppHop(hop.Hop):
    def __init__(self, user: str, cmd=None, timeout: float = 30, **kwargs):
        super().__init__(**kwargs)
        self._tun2socks = None
        self._socks_endpoint = None
        self._user = user
        self._timeout = timeout
        self.cmd = cmd
        self._proc_pid = None
        self.dns_servers = []

    @property
    def required_routes(self):
        return [ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')]

    def update_cmd(self, hop_info):
        pass

    def before_connect(self) -> None:
        hop_info = self.info
        address = hop_info.netinfo[0].network_address + 2
        self._socks_endpoint = address, 1080

    def connect(self):
        super(SocksAppHop, self).connect()
        hop_info = self.info

        # The user should be specified explicitly in order to prevent accidental SSH identity leaks
        """if self._user is None:
            raise Exception('User required')"""

        self.update_cmd(hop_info)
        # sysutil.prctl(sysutil.PR_SET_DUMPABLE, 1)
        # kwargs = {'preexec_fn': netns.map_back_real}
        kwargs = {}

        if security.is_sudo_or_root() and self._user is not None:
            kwargs = sysutil.privilege_drop_preexec(self._user, True)

        process = self.popen(self.cmd, **kwargs)
        self._proc_pid = process.pid
        # Wait for the SOCKS listener to appear
        self.log_debug('Waiting for SOCKS endpoint to appear at %s.' % str(self._socks_endpoint))

        def ssh_error():
            returncode = process.poll()
            if returncode is not None and returncode != 0:
                # TODO: Include command output in exception.
                raise ConnectionError('SOCKS app command exited with code %d' % returncode)

        if not wait_for_listener(self._socks_endpoint, exception_function=ssh_error):
            raise TimeoutError

    def next_hop(self) -> Optional[hop.Hop]:
        tun2socks = socks.SocksHop(self._socks_endpoint)
        tun2socks.quiet = self.quiet
        tun2socks.dns_servers = self.dns_servers
        tun2socks.dns_overridden = self.dns_overridden
        self._tun2socks = tun2socks
        return tun2socks

    def next_connect(self, hop_info: hop.HopInfo):
        """Same as for Tor. TODO: Remove code duplication."""
        with IPRoute() as ip:
            indev = ip.link_lookup(ifname=hop_info.indev)[0]

            for netinfo in self.info.netinfo:
                route = ipaddress.ip_network(netinfo.network_address + 2)
                gateway = list(filter(lambda x: x.version == route.version, hop_info.netinfo))[0].network_address + 1
                ip.route('add', dst=str(route), oif=indev, gateway=str(gateway), table=hop.POLICY_ROUTING_TABLE)

    def free(self):
        super(SocksAppHop, self).free()

        if self._tun2socks is not None:
            self._tun2socks.free()

        if self._proc_pid is not None:
            os.kill(self._proc_pid, signal.SIGTERM)

    @property
    def kill_switch_device(self) -> Optional[str]:
        return None  # Kill switching happens in the SocksHop
