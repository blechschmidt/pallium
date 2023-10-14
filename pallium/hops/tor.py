import ipaddress
import os
import shutil
import time
from typing import Optional, List

from .hop import PortForward
from .. import nftables, security
from pyroute2.iproute import IPRoute

from . import hop, socks
from .. import sysutil
from .. import util
from ..nftables import NFTables
from ..tor import TorController


def get_tor_user():
    users = [
        'debian-tor',  # Debian
        'toranon',     # Fedora
        'tor'          # Arch Linux
    ]

    for name in users:
        try:
            sysutil.user_to_uid(name)
            return name
        except KeyError:
            pass


class TorHop(hop.Hop):
    app_requirements = ['tor'] + socks.SocksHop.app_requirements

    def __init__(self, *, timeout=300, circuit_build_timeout=60, builtin_dns=True, user=None, onion_support=True,
                 tor_args=None, **kwargs):
        """
        Tor hop using the `tor` binary of the machine. Requires Tor to be installed.

        @param timeout: Total timeout for setting up a Tor connection.
        @param circuit_build_timeout: Timeout for setting up a single circuit.
        @param builtin_dns: Whether to use and expose the builtin DNS server of Tor.
        @param user: The user to run Tor as. This is supplied to tor via the `--User` command line argument.
        @param onion_support: Whether to enable onion support through DNS by IP address to .onion name mapping.
        @param tor_args: Additional command line arguments to pass to Tor.
        @param kwargs: Additional arguments passed to the super class constructor.
        """
        super().__init__(**kwargs)
        if tor_args is None:
            tor_args = []
        self._tor_args = tor_args
        self._mgmt_path = None
        self._cookie_path = None
        self._socks_endpoint = None
        self._timeout = timeout
        self._circuit_build_timeout = circuit_build_timeout
        self._builtin_dns = builtin_dns
        if user is None:
            user = security.real_user()
        self._user = user
        self._onion_support = onion_support
        self.required_routes = [ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')]
        self._port_forwards = []

    def before_connect(self) -> None:
        bind_ip = self.info.netinfo[0].network_address + 2
        self.dns_servers = [str(bind_ip)]
        self._socks_endpoint = str(bind_ip), 9050

    def connect(self):
        self.log_info('Setting up Tor connection')
        super(TorHop, self).connect()
        hop_info = self.info
        bind_ip = hop_info.netinfo[0].network_address + 2
        mgmt_temp = util.mkdtemp()
        data_temp = util.mkdtemp()
        if security.is_sudo_or_root():
            sysutil.change_owner(mgmt_temp, self._user)
            sysutil.change_owner(data_temp, self._user)
        self._cookie_path = os.path.join(data_temp, 'control_auth_cookie')
        self._mgmt_path = os.path.join(mgmt_temp, 'management.sock')
        command = [self.get_tool_path('tor'),
                   '--DataDirectory', data_temp,
                   '--ControlSocket', 'unix:' + self._mgmt_path + ' WorldWritable',
                   '--CookieAuthentication', '1',
                   '--CookieAuthFile', self._cookie_path,
                   '--SocksPort', '%s:9050' % bind_ip,
                   '--ignore-missing-torrc',
                   '-f', '/proc/self/doesnotexist']
        if self._builtin_dns:
            command += ['--DNSPort', '%s:1053' % bind_ip]
        if self._onion_support:  # TODO: Parameterize virtual address network
            network = '10.123.0.0/16'
            command += ['--AutomapHostsOnResolve', '1', '--VirtualAddrNetworkIPv4', network]
        command += self._tor_args
        command += ['--Log', 'notice stderr']
        kwargs = {'env': os.environ.copy()}

        if security.is_sudo_or_root():
            kwargs = sysutil.privilege_drop_preexec(self._user)

        tor_env = self.get_tool_env('tor')
        if tor_env:
            kwargs['env'].update(tor_env)

        self.popen(command, **kwargs)

        self.log_info('Waiting for Tor control socket to be created')

        start_time = time.perf_counter()
        while not os.path.exists(self._mgmt_path) or not os.path.exists(self._cookie_path):
            time.sleep(0.01)
            if time.perf_counter() - start_time > self._timeout:
                raise TimeoutError('Timed out waiting for tor control socket')

        self.log_info('Waiting for Tor circuit to be established.')
        self.log_info('Management path: %s' % self._mgmt_path)

        with TorController(self._mgmt_path) as controller:
            controller.authenticate(cookie_path=self._cookie_path)

            start_time = time.perf_counter()
            circuit_time = start_time
            while True:
                time.sleep(0.1)
                conn_status = controller.get_info('status/circuit-established')
                if int(conn_status) == 1:
                    break
                now = time.perf_counter()
                if now - start_time > self._timeout:
                    raise TimeoutError('Timed out establishing Tor circuit')
                if now - circuit_time > self._circuit_build_timeout:
                    self.log_info('Circuit build timeout.')
                    controller.signal('HUP')
                    circuit_time = now

        self.log_info('Tor circuit established.')

        if self._builtin_dns:
            with NFTables() as nft:
                nft.table('add', name='pallium')
                nft.chain('add', table='pallium', name='PREROUTING', type='nat', hook='prerouting',
                          priority=-100, policy=1)
                nft.rule('add', table='pallium', chain='PREROUTING', expressions=(
                    nftables.udp(dport=53),
                    nftables.dnat(to=(bind_ip, 1053)),
                ))
            fw = [
                PortForward((nftables.ip(daddr=bind_ip), nftables.udp(dport=53), nftables.accept())),
                PortForward((nftables.ip(saddr=bind_ip), nftables.udp(sport=53), nftables.accept()))
            ]
            self._port_forwards.extend(fw)
        return self._port_forwards

    def handle_connect_results(self, results):
        self._port_forwards = results

    def next_hop(self):
        tun2socks = socks.SocksHop(self._socks_endpoint)
        tun2socks.quiet = self.quiet
        tun2socks.dns_servers = self.dns_servers
        tun2socks.dns_overridden = self.dns_overridden
        return tun2socks

    def next_connect(self, hop_info: hop.HopInfo):
        with IPRoute() as ip:
            indev = ip.link_lookup(ifname=hop_info.indev)[0]

            for netinfo in self.info.netinfo:
                route = ipaddress.ip_network(netinfo.network_address + 2)
                gateway = list(filter(lambda x: x.version == route.version, hop_info.netinfo))[0].network_address + 1
                ip.route('add', dst=str(route), oif=indev, gateway=str(gateway), table=hop.POLICY_ROUTING_TABLE)

    def free(self):
        super(TorHop, self).free()
        if os.getpid() != self._owner_process:
            return

        if self._mgmt_path is not None:
            try:
                with TorController(self._mgmt_path) as controller:
                    controller.authenticate(cookie_path=self._cookie_path)
                    controller.signal('TERM')
            except (FileNotFoundError, ConnectionError, sysutil.UnexpectedEOF):
                pass
            shutil.rmtree(os.path.dirname(self._mgmt_path), ignore_errors=True)
        if self._cookie_path is not None:
            shutil.rmtree(os.path.dirname(self._cookie_path), ignore_errors=True)

    @property
    def kill_switch_device(self) -> Optional[str]:
        return None  # Kill switching happens in the SocksHop

    @property
    def port_forwards(self) -> List[PortForward]:
        return self._port_forwards
