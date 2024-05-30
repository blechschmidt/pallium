import ipaddress
import signal
import subprocess
from typing import List, Union, Optional

from . import sysutil
from . import util

"""A DHCP server (manager) that provides leases to clients.

Supply clients connected to ethernet bridges with IP address leases.
"""

DNSMASQ_CONF = """interface=%s
listen-address=0.0.0.0
listen-address=::
"""

DHCP_RANGE_CONF_V4 = "dhcp-range=subnet%d,%s,%s,%s,12h\n"
DHCP_RANGE_CONF_V6 = "dhcp-range=::,constructor:%s,slaac\n"
DHCP_ROUTER_CONF = {
    4: "dhcp-option=subnet%d,3,%s\n",
}
DHCP_DNS_CONF = "dhcp-option=6,%s\n"


class DHCPServer:
    def __init__(self, ip_ranges: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                 interface: str,
                 dns: Optional[List[str]] = None,
                 debug: bool = False):
        self.ranges = ip_ranges
        self.interface = interface
        self.dhcp_server = None
        self.debug = debug
        self.cmd_args = []
        if dns is None:
            dns = []
        self.dns = dns

    @property
    def supported(self):
        return True

    def _get_conf(self):
        conf = DNSMASQ_CONF % self.interface
        for i, r in enumerate(self.ranges):
            if r.version == 4:
                conf += DHCP_RANGE_CONF_V4 % (i, r.network_address + 2, r.broadcast_address - 1, r.netmask)
                conf += DHCP_ROUTER_CONF[r.version] % (i, r.network_address + 1)
            else:
                conf += DHCP_RANGE_CONF_V6 % self.interface
        if len(self.dns) > 0:
            conf += DHCP_DNS_CONF % (','.join(map(str, self.dns)), )
        return conf

    def _run_server(self):

        self.cmd_args += ['-d' if self.debug else '-k']
        self.dhcp_server = util.popen(['dnsmasq', '--conf-file=-', '--pid-file'] + self.cmd_args,
                                      stdin=subprocess.PIPE)
        sysutil.write_blocking(self.dhcp_server.stdin.fileno(), self._get_conf().encode('ascii'))
        self.dhcp_server.stdin.close()

    def start(self):
        self._run_server()

    def stop(self):
        self.dhcp_server.terminate()
        del self.dhcp_server  # Prevent zombie process
