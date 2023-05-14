import ipaddress
import os
import signal
import socket
import urllib.parse
from typing import Optional

from pyroute2.iproute import IPRoute

from . import hop
from .. import util


class Tun2socksHop(hop.Hop):
    app_requirements = ['tun2socks']
    default_port = 0

    def __init__(self, protocol, address, username=None, password=None, **kwargs):
        super().__init__(**kwargs)
        self._pid = None
        self._address, self._port = util.convert2addr(address, self.default_port)
        self._username, self._password = username, password
        self.required_routes = [ipaddress.ip_network(self._address)]
        self.protocol = protocol

    def free(self):
        super().free()
        if self._pid is not None:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def before_next_connect(self, hop_info: hop.HopInfo):
        def run_in_my_netns():
            with IPRoute() as ip:
                for netinfo in hop_info.netinfo:
                    family = socket.AF_INET if netinfo.version == 4 else socket.AF_INET6
                    # This fails on WSL2 for IPv6 and is likely a WSL bug.
                    # See: https://github.com/tailscale/tailscale/issues/831
                    ip.rule('add', src=str(netinfo.network_address + 2), table=hop.POLICY_ROUTING_TABLE, family=family)
        self.info.netns.run(run_in_my_netns)

    def connect(self):
        super().connect()

        with IPRoute() as ip:
            ip.link('add', ifname='tun0', kind='tuntap', mode='tun')
            tun = ip.link_lookup(ifname='tun0')[0]
            ip.link('set', index=tun, state='up')

            # Traffic from the next namespace should use this routing table
            for dst in self.providing_routes:
                ip.route('add', dst=str(dst), oif=tun, table=hop.POLICY_ROUTING_TABLE)

        # https://github.com/xjasonlyu/tun2socks
        url_credentials = ''
        if self._username is not None:
            url_credentials += urllib.parse.quote(self._username)
            if self._password is not None:
                url_credentials += ':' + urllib.parse.quote(self._password)
            url_credentials += '@'

        cmd = [self.get_tool_path('tun2socks'), '-device', 'tun0',
               '-proxy', self.protocol + '://%s%s:%d' % (url_credentials, str(self._address), self._port)]

        proc = self.popen(cmd)
        self._pid = proc.pid
        self.register_process(self._pid)

    @property
    def kill_switch_device(self) -> Optional[str]:
        return 'tun0'


class SocksHop(Tun2socksHop):
    default_port = 1080

    def __init__(self, address, username=None, password=None, version=5, **kwargs):
        super().__init__('socks%d' % version, address, username, password, **kwargs)


class HttpHop(Tun2socksHop):
    default_port = 3128

    def __init__(self, address, username=None, password=None, **kwargs):
        super().__init__('http', address, username, password, **kwargs)
