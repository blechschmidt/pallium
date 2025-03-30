import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import typing
from typing import Optional, Union, List

from pyroute2.iproute import IPRoute

from .. import resolvconf, security, runtime, typeinfo
from .. import sysutil
from .. import util
from ..netns import NetworkNamespace
from .. import dnsproxy

POLICY_ROUTING_TABLE = 123  # In our network namespaces, this routing table is guaranteed to not contain any rules
DEFAULT_ROUTE_IPV4, DEFAULT_ROUTE_IPV6 = ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')
DEFAULT_ROUTES = [DEFAULT_ROUTE_IPV4, DEFAULT_ROUTE_IPV6]


class AuthenticationError(Exception):
    pass


class ProtocolError(Exception):
    pass


def policy_ip_network(address, strict=True):
    try:
        return ipaddress.IPv4Network(address, strict)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        pass

    try:
        return ipaddress.IPv6Network(address, strict)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        pass

    raise ValueError('%r does not appear to be an IPv4 or IPv6 network' % address)


class HopInfo:
    """
    Holds runtime information for a hop, such as network namespace, IP networks and veth devices.
    """
    def __init__(self, netinfo: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                 network_namespace: Optional[NetworkNamespace], indev, outdev,
                 hop, previous=None, use_slirp=False):
        self.netinfo: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = netinfo
        self.netns: Optional[NetworkNamespace] = network_namespace
        self.indev: str = indev
        self.outdev: str = outdev
        self.previous: HopInfo = previous
        self.hop: Hop = hop
        self.use_slirp: bool = use_slirp

    @property
    def index(self) -> int:
        previous = self.previous
        i = 0
        while previous is not None:
            previous = previous.previous
            i += 1
        return i


class DnsOverlay:
    """
    When a hop exposes a DnsOverlay as its DNS servers, the DNS servers from /etc/resolv.conf are propagated to the next
    network namespace.
    """
    pass


class DnsTcpProxy:
    def __init__(self, nameservers):
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        self.nameservers = nameservers


class InternalPortForwarding:
    def __init__(self, nft_rule, ttl=1):
        self.nft_rule = nft_rule
        self.ttl = ttl


class Hop:
    app_requirements = []
    debug = False

    def __init__(self, quiet=None, dns=None, **kwargs):
        self._owner_process = os.getpid()
        self.info: Optional[HopInfo] = None
        self._connected_functions = []
        self._free_functions = []
        self.dns_servers = None
        self.paths = {}
        self.args = kwargs
        self.quiet = quiet
        if 'providing_routes' not in kwargs:
            self.providing_routes = [ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')]
        self.dns_overridden = dns
        self.started_pids = set()
        self.term_subprocesses_on_exit = False

        # Hops may want to override the required routes immediately, e.g. by implementing a getter
        if 'required_routes' not in dir(self):
            self.required_routes = []

    @classmethod
    def from_json(cls, obj: typing.Dict[str, typing.Any]) -> 'Hop':
        # Do not modify the passed dict.
        obj = dict(obj)

        if 'dns' in obj:
            proxied_addrs = []
            non_proxied_addrs = []
            for addr in obj['dns']:
                if addr.startswith('tcp://'):
                    proxied_addrs.append(addr[6:])
                else:
                    non_proxied_addrs.append(addr)
            dns = non_proxied_addrs
            if len(proxied_addrs) > 0:
                dns.append(DnsTcpProxy(proxied_addrs))
            obj['dns'] = dns

        type2class = dict()
        for hop_class in util.get_subclasses(cls):
            class_name = hop_class.__name__
            if hop_class.__name__.endswith('Hop'):
                class_name = class_name[:-len('Hop')]
            type2class[class_name.lower()] = hop_class

        hop_type = obj.pop('type')
        hop_class = type2class.get(hop_type.lower())
        if hop_class is None:
            raise ""

        return hop_class(**obj)

    def popen(self, *args, **kwargs):
        """Popen wrapper that keeps track of the started processes and handles command output.

        @param args: Positional arguments for `subprocess.Popen`.
        @param kwargs: Keyword arguments for `subprocess.Popen`.
        @return: The process returned by `subprocess.Popen`.
        """
        self.set_preexec_fn(kwargs)
        if self.quiet:
            kwargs.setdefault('stdout', subprocess.DEVNULL)
            kwargs.setdefault('stderr', subprocess.DEVNULL)
        if len(args) > 0:
            self.log_debug('Popen, pid=%d: %s' % (os.getpid(), ' '.join(args[0])))
        p = util.popen(*args, **kwargs)
        self.started_pids.add(p.pid)
        return p

    def set_preexec_fn(self, kwargs):
        if not self.term_subprocesses_on_exit:
            return
        if kwargs.get('preexec_fn', None) is not None:
            old_preexec_fn = kwargs['preexec_fn']
            assert callable(old_preexec_fn)

            def new_preexec_fn():
                sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)
                old_preexec_fn()
            kwargs['preexec_fn'] = new_preexec_fn
        else:
            def new_preexec_fn():
                sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)
            kwargs['preexec_fn'] = new_preexec_fn

    def pcall(self, *args, **kwargs):
        self.set_preexec_fn(kwargs)
        return util.proc_call(*args, **kwargs)

    def get_tool_path(self, name):
        return self.args.get(name + '_path', util.get_tool_execution_info(name)[0])

    @staticmethod
    def get_tool_env(name):
        return util.get_tool_execution_info(name)[1]

    def register_process(self, p):
        self.started_pids.add(p)

    def before_connect(self) -> None:
        """Method is run inside the default namespace before connecting.

        @return: None
        """
        pass

    def before_next_connect(self, hop_info: HopInfo):
        """Method is run inside the default namespace before the connect method of the next hop is called.

        @param hop_info: Hop information of the next hop.
        @return: None
        """
        pass

    def connect(self):
        """Connection method that is run inside the hop namespace. This method is used to set up the routes and DNS
        servers that are required for connection establishment.

        Example:
        In case of a proxy (1.2.3.4), this method would set up a route to 1.2.3.4.

        @return: None
        """
        self.add_required_routes(self.info)
        self.setup_dns_servers(self.info)

        if self.info.previous.hop is not None:
            self.info.previous.hop.next_connect(self.info)

    def free(self):
        self.log_debug('Free hop %s' % repr(self))
        for pid in self.started_pids:
            # TODO: Why do we have this check again?
            if not security.is_sudo_or_root():
                continue
            self.log_debug('Kill process %d' % pid)
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:  # happens when Ctrl+C is passed to subprocesses
                self.log_debug('Failed to kill process %d: Not found/already terminated' % pid)
        self._run_functions(self._free_functions)

    def log_info(self, *args, **kwargs):
        if not self.quiet:
            logging.getLogger(__name__).debug(*args, **kwargs)

    def log_debug(self, *args, **kwargs):
        if not self.quiet:
            logging.getLogger(__name__).debug(*args, **kwargs)

    def missing_apps(self):
        failed_apps = []
        for app in self.app_requirements:
            if shutil.which(app) is None and (self.paths.get(app) is None or shutil.which(self.paths.get(app)) is None):
                failed_apps.append(app)
        return failed_apps

    def next_hop(self) -> Optional['Hop']:
        """Some hops require an additional hop. Take Tor as an example. We do not know in advance, which destination
        (entry node) Tor will connect to. Therefore, a default route is required in the Tor namespace. But we also want
        to route all other traffic through Tor. To do that, we leverage a second namespace to not have a routing loop.

        @return: The next hop.
        """
        pass

    def next_connect(self, hop_info: HopInfo) -> None:
        """This function is to be run inside the connect function of the next hop.

        @param hop_info: The runtime information of the next hop at time of execution.
        @return: None
        """
        pass

    @property
    def kill_switch_device(self) -> Optional[str]:
        """Ensure that traffic does not bypass a hop.

        As an example, consider a VPN hop. If the VPN goes down, the tunnel interface will go down, too. Suddenly, the
        traffic will no longer be routed through the tunnel interface but via the device of the old default route.
        This must be prevented. Therefore, all traffic coming from the output device that does not go to the tunnel must
        be dropped.

        This function defines how the device through which routing is expected to happen is called.

        @return: The name of the interface through which traffic is expected to be routed.
        """
        raise NotImplementedError('This method must be implemented by subclasses for security reasons.')

    def handle_connect_results(self, results):
        pass

    @staticmethod
    def _add_functions(target, function, wait=False):
        if util.is_iterable(function):
            for f in function:
                if isinstance(f, tuple):
                    target.append(f)
                elif callable(f):
                    target.append((f, wait,))
                else:
                    raise ValueError
        else:
            target.append((function, wait,))

    def _run_functions(self, arr):
        for function, wait in arr:
            self.info.netns.run(function)

    def on_connected(self, function, wait=False):
        self._add_functions(self._connected_functions, function, wait)

    def on_free(self, function, wait=False):
        self._add_functions(self._free_functions, function, wait)

    def connected(self):
        self._run_functions(self._connected_functions)

    def setup_dns_servers(self, hop_info: HopInfo):
        """This method is called in the connect method of a hop. It sets up the DNS servers by modifying
        /etc/resolv.conf and starting a DNS proxy if necessary.

        @param hop_info: The hop info.
        @return: None.
        """
        prev = hop_info.previous
        self.log_debug('Setting up DNS servers for hop %s (%s)', hop_info.index, hop_info.hop)

        if prev is not None and prev.hop is not None and prev.hop.dns_overridden is not None:
            non_proxied_addrs = []
            proxied_addrs = []
            for dns_entry in prev.hop.dns_overridden:
                if isinstance(dns_entry, DnsTcpProxy):
                    for ns in dns_entry.nameservers:
                        proxied_addrs.append(util.convert2addr(ns, 53))
                else:
                    non_proxied_addrs.append(util.convert2addr(dns_entry, 53)[0])
            if len(proxied_addrs) > 0:
                dns_proxy = dnsproxy.setup_dns_tcp_proxy(proxied_addrs, non_proxied_addrs, forked=True)()
                self.register_process(dns_proxy)
            else:
                resolvconf.write_resolv_conf(non_proxied_addrs)
            return

        if prev is not None and prev.hop is not None and not isinstance(prev.hop.dns_servers, DnsOverlay):
            resolvconf.write_resolv_conf(prev.hop.dns_servers)
        else:
            self.log_debug('Previous hop did not expose DNS servers.')

    @property
    def port_forwards(self) -> List[InternalPortForwarding]:
        return []

    @staticmethod
    def add_required_routes(hop_info: HopInfo):
        """This method is run inside the connect function and adds the required routes.

        @param hop_info: Runtime information of the hop.
        @return: None.
        """
        # Slirp4netns adds the IPv4 default route automatically. It does not add an IPv6 route though.
        if hop_info.use_slirp and hop_info.previous.previous is None:
            if runtime.ip_proto_supported_default(6):
                with IPRoute() as ip:
                    infd = ip.link_lookup(ifname=hop_info.indev)[0]
                    # See https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md
                    ip6_net = ipaddress.ip_network('fd00::/64')
                    ip.addr('add', index=infd, address=str(ip6_net.network_address + 1), prefixlen=ip6_net.prefixlen)
                    ip.route('add', dst=str('::/0'), oif=infd, gateway=str(ip6_net.network_address + 2))
            return

        # Otherwise add those routes that are required by the hop.
        # Get intersection between routes required by this hop and routes exposed by the previous hop.
        # For example, if the previous hop, such as a slirp4netns hop, does not expose IPv6 routes (because the
        # default network namespace does not support IPv6), do not create an IPv6 route inside this namespace.
        with IPRoute() as ip:
            infd = ip.link_lookup(ifname=hop_info.indev)[0]
            for netinfo in hop_info.netinfo:
                destinations = [r for r in hop_info.hop.required_routes if r.version == netinfo.version]
                if hop_info.previous.previous is not None:
                    providing = [r for r in hop_info.previous.hop.providing_routes if r.version == netinfo.version]
                    destinations = util.get_intersection(providing, destinations)
                for route in destinations:
                    gateway = netinfo.network_address + 1
                    logging.debug('Netns %d: ip route add %s via %s dev %s'
                                  % (hop_info.index, route, gateway, hop_info.indev))
                    ip.route('add', dst=str(route), oif=infd, gateway=str(gateway))
