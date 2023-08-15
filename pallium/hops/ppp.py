"""
A hop for making use of PPPoE connections.

Some ISPs do not prevent the use of multiple PPP sessions in parallel. In this case, this hop can be used to obtain
additional IP addresses from the ISP via DHCP.

Under the hood, ppp is used (https://github.com/ppp-project/ppp). To use this hop, a provider file for use with ppp must
be created manually such that `pppd call provider` (which is equivalent to `pon`) successfully builds a connection.

For example, this profile would start a new Chromium instance (with a temporary browser profile) and a fresh IP address:
{
        "chain": [{
                "type": "ppp",
                "device": "eth0"
        }],
        "run": {
                "command": "chromium --user-data-dir=\"$(mktemp -d)\""
        }
}

This hop cannot be used in unprivileged mode, and it needs to be the first hop inside a chain.
"""
import os.path
from typing import Optional
import re

from pyroute2.iproute import IPRoute

from . import hop
from .. import sysutil
from .. import util
from ..exceptions import ConfigurationError


class PppHop(hop.Hop):
    app_requirements = ['pppd']

    def __init__(self, provider='provider', *, device=None, **kwargs):
        """
        Initialize the PPP hop.

        @param device: The device through which the connection is built (as specified in the provider config).
        @param provider: The name of the provider to be used by pppd. See e.g. https://wiki.archlinux.org/title/Ppp.
        @param kwargs: Additional arguments that are passed to the super constructor (generic hop arguments).
        """
        assert '/' not in provider
        assert provider is not None
        super().__init__(**kwargs)
        peer_file = '/etc/ppp/peers/%s' % provider
        if device is None and os.path.exists(peer_file):
            with open(peer_file) as f:
                match = re.match(r'(?:^|\s+)plugin\s+rp-pppoe.so\s+(\S+)(?:$|\s)', f.read())
                if match:
                    device = match[1]
        if device is None:
            raise ConfigurationError('The device used for the PPP connection could not be determined automatically. '
                                     'Thus, manual specification of the device is required.')
        self.device = device
        self.provider = provider
        self.dns_servers = hop.DnsOverlay()
        self._tmp_dev = 'pm' + util.random_string(10)

    def before_connect(self) -> None:
        if self.info.previous.hop is not None:
            raise ConfigurationError('A PPP hop must be the first hop of a chain.')
        with IPRoute() as ip:
            ifindex = ip.link_lookup(ifname=self.device)[0]
            ip.link('add', ifname=self._tmp_dev, kind='macvlan', link=ifindex)
            ip.link('set', ifname=self._tmp_dev, net_ns_fd=self.info.netns.name + '/net')

    def connect(self):
        sysutil.rename_interface(self._tmp_dev, self.device)
        with IPRoute() as ip:
            ip.link('set', ifname=self.device, state='up')

        self.popen(['pppd', 'call', self.provider, 'nodetach'])

    @property
    def kill_switch_device(self) -> Optional[str]:
        return 'ppp0'
