import configparser
import ipaddress
from typing import Optional

from pyroute2.iproute.linux import IPRoute
from pyroute2.netlink.generic.wireguard import WireGuard

from . import hop
from .. import util


class WireGuardHop(hop.Hop):
    app_requirements = []

    def __init__(self, config, **kwargs):
        """
        Wireguard hop.

        @param config: Path to the Wireguard configuration file, e.g. as produced by
                       https://github.com/angristan/wireguard-install.
        """
        super().__init__(**kwargs)
        self.config_path = config
        self.endpoint = None

    def connect(self):
        config = configparser.ConfigParser()
        config.read(self.config_path)
        assert 'Interface' in config
        assert 'Peer' in config
        private_key = config['Interface']['PrivateKey']
        addresses = [x.strip() for x in config['Interface']['Address'].split(',')]
        dns_servers = [x.strip() for x in config['Interface']['DNS'].split(',')]
        if self.dns_overridden is None:
            self.dns_overridden = dns_servers

        self.endpoint = util.convert2addr(config['Peer']['Endpoint'], 51820)
        allowed_ips = [x.strip() for x in config['Peer']['AllowedIPs'].split(',')]

        peer = {
            'public_key': config['Peer']['PublicKey'],
            'preshared_key': config['Peer']['PresharedKey'],
            'endpoint_addr': str(self.endpoint[0]),
            'endpoint_port': self.endpoint[1],
            'allowed_ips': allowed_ips,
        }

        self.required_routes = [self.endpoint[0]]

        super().connect()

        with IPRoute() as ip:
            ip.link('add', ifname='wg0', kind='wireguard')
            ifindex = ip.link_lookup(ifname='wg0')[0]
            ip.link('set', index=ifindex, state='up')
            for addr in addresses:
                net = ipaddress.ip_network(addr)
                ip.addr('add', index=ifindex, address=str(net.network_address), prefixlen=net.prefixlen)
            wg = WireGuard()
            wg.set('wg0', private_key=private_key, peer=peer)
            for net in allowed_ips:
                net = ipaddress.ip_network(net)
                ip.route('add', dst=str(net), oif=ifindex)

    @property
    def kill_switch_device(self) -> Optional[str]:
        return 'wg0'
