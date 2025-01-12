import inspect
import ipaddress
import json
import logging
import os
import random
import select
import shutil
import socket
import stat
import string
import subprocess
import sys
import tempfile
import time
import itertools
from typing import Union, Iterable, List, Tuple, Set, Optional

from pyroute2.iproute import IPRoute

from . import onexit
from . import typeinfo
from .sysutil import UnexpectedEOF
from .exceptions import *

APP_TMP_DIR = None
PYINSTALLER = getattr(sys, 'frozen', False)
GLOBAL_PATH = '/etc/pallium/global.json'

config: Optional[dict] = None

RESERVED_IPV4_ADDRS = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32'
]

RESERVED_IPV6_ADDRS = [
    '::1/128',
    '::/128',
    '::ffff:0:0/96',
    '64:ff9b::/96',
    '64:ff9b:1::/48',
    '100::/64',
    '2001::/23',
    '2001::/32',
    '2001:1::1/128',
    '2001:1::2/128',
    '2001:2::/48',
    '2001:3::/32',
    '2001:4:112::/48',
    '2001:10::/28',
    '2001:20::/28',
    '2001:db8::/32',
    '2002::/16',
    '2620:4f:8000::/48',
    'fc00::/7',
    'fe80::/10'
]

ROUTING_TABLE_DEFAULT = 0x706c6d  # "plm" in hex
FWMARK_DEFAULT = ROUTING_TABLE_DEFAULT

NO_OVERLAP = 0
NET1_INSIDE = 1
NET2_INSIDE = 2
OVERLAP_LEFT = 3
OVERLAP_RIGHT = 4


def get_route_attr(attrs, name, *args, **kwargs):
    return dict(attrs).get(name, *args, **kwargs)


def append_nonempty(pool, tp):
    if tp[0] < tp[1]:
        pool.append(tp)


def to_addr_range(net: typeinfo.IPAddressRange):
    if not isinstance(net, tuple):
        return net.network_address, net.broadcast_address
    return net


def networks_overlap(net1: typeinfo.IPAddressRange, net2: typeinfo.IPAddressRange):
    net1 = to_addr_range(net1)
    net2 = to_addr_range(net2)
    if net2[0] <= net1[0] <= net2[1] and net2[0] <= net1[1] <= net2[1]:
        return NET1_INSIDE
    if net1[0] <= net2[0] <= net1[1] and net1[0] <= net2[1] <= net1[1]:
        return NET2_INSIDE
    if net1[0] <= net2[0] <= net1[1] <= net2[1]:
        return OVERLAP_LEFT
    if net2[0] <= net1[0] <= net2[1] <= net1[1]:
        return OVERLAP_RIGHT
    return NO_OVERLAP


def get_intersection_single(net1, net2):
    overlap = networks_overlap(net1, net2)
    if overlap == NET1_INSIDE:
        return to_addr_range(net1)
    elif overlap == NET2_INSIDE:
        return to_addr_range(net2)
    elif overlap == OVERLAP_LEFT:
        return net2[0], net1[1]
    elif overlap == OVERLAP_RIGHT:
        return net1[0], net2[1]
    else:
        return None


def get_intersection(netlist1, netlist2):
    netlist1 = minimize_ipnets(netlist1)
    netlist2 = minimize_ipnets(netlist2)
    result = []
    for net1 in netlist1:
        other = []
        for net2 in netlist2:
            intersection = get_intersection_single(net1, net2)
            if intersection is not None:
                other.append(intersection)
        other = list(itertools.chain(*(ipaddress.summarize_address_range(r[0], r[1]) for r in other)))
        result.extend(other)
    return minimize_ipnets(result)


def remove_from_pool(pool: List[Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]],
                     net: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]):
    nettp = (net.network_address, net.broadcast_address)
    new_pool = []
    for pool_net in pool:
        overlap = networks_overlap(nettp, pool_net)
        if overlap == NET1_INSIDE:  # net inside pool net
            append_nonempty(new_pool, (pool_net[0], nettp[0] - 1))
            append_nonempty(new_pool, (nettp[1] + 1, pool_net[1]))
        elif overlap == NET2_INSIDE:  # pool net inside net
            pass
        elif overlap == OVERLAP_LEFT:  # net overlaps with pool net on the left
            append_nonempty(new_pool, (nettp[1] + 1, pool_net[1]))
        elif overlap == OVERLAP_RIGHT:  # net overlaps with pool net on the right
            append_nonempty(new_pool, (pool_net[0], nettp[0] - 1))
        else:  # no overlap
            new_pool.append(pool_net)
    return new_pool


def route_get_dst(route):
    dst_len = route.get('dst_len')
    global_address = '0.0.0.0' if route.get('family') == socket.AF_INET else '::'
    dst = get_route_attr(route.get('attrs'), 'RTA_DST', global_address if dst_len == 0 else None)
    network = ipaddress.ip_network('%s/%d' % (dst, dst_len))
    return network


def get_interface_routes(ip_version, ifname):
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    result = []
    with IPRoute() as ip:
        routes = ip.route('dump', family=family, oif=ip.link_lookup(ifname=ifname))
        return [route for route in routes]
    return result

def copy_routing_table(ifname, new_table, ip_version=None, source_table=254):
    """
    Copy the routes of an interface to a another routing table.
    Used for policy-based routing.

    @param ifname: The name of the interface.
    @param new_table: The new routing table number.
    @param ip_version: The IP version to filter for. If None, both IP versions are copied.
    @param source_table: The source routing table number.
    """
    if ip_version is None:
        copy_routing_table(ifname, new_table, 4)
        copy_routing_table(ifname, new_table, 6)
        return

    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    with IPRoute() as ip:
        routes = ip.route('dump', family=family, oif=ip.link_lookup(ifname=ifname), table=source_table)
        for route in routes:
            route = dict(route)
            attrs = dict(route.get('attrs'))
            if 'RTA_TABLE' in attrs:
                del attrs['RTA_TABLE']
            if 'FRA_TABLE' in attrs:
                del attrs['FRA_TABLE']
            if 'event' in route:
                del route['event']
            if 'header' in route:
                del route['header']
            for key, value in attrs.items():
                if key.startswith('RTA_'):
                    route[key[4:].lower()] = value
            route['table'] = new_table
            ip.route('add', **route)


def get_routes(ip_version, nonglobal_only=False):
    """
    Get the installed routes as a list of IPNetworks

    @param ip_version: The IP version to filter for
    @param nonglobal_only: Only return those routes appearing to be non-defaults or pseudo default route replacements
     (heuristic).
    @return: List of routes
    """
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    result = []
    with IPRoute() as ip:
        routes = ip.route('dump', family=family)
        for route in routes:
            dst_len = route.get('dst_len', None)
            dst = route_get_dst(route)
            if nonglobal_only and (dst_len is None or dst_len < 8 or dst is None):
                continue
            result.append(route)
    return result


def minimize_ipnets(networks):
    """

    @param networks: An iterable of IP address networks.
    @return: A non-overlapping, minimal list of unionized networks.
    """
    routes = set(map(to_addr_range, networks))

    while len(routes) > 1:
        found_overlapping = False
        for dst1, dst2 in itertools.combinations(routes, 2):
            if networks_overlap(dst1, dst2):
                routes.remove(dst1)
                routes.remove(dst2)
                routes.add((min(dst1[0], dst2[0]), max(dst1[1], dst2[1])))
                found_overlapping = True
                break
        if not found_overlapping:
            break

    return list(itertools.chain(*(ipaddress.summarize_address_range(r[0], r[1]) for r in routes)))


def ip_proto_supported(ip_version, destinations=None):
    """
    Detect whether an IP version is supported.

    @param ip_version: The IP version.
    @param destinations: The destinations. If not supplied, the route destinations of the system are used.
    @return: True if every IP address is covered by the destinations. False otherwise.
    """
    if destinations is None:
        destinations = map(route_get_dst, get_routes(ip_version))
    span = 2**32 if ip_version == 4 else 2**128
    routes = minimize_ipnets(destinations)
    return len(routes) == 1 and routes[0].num_addresses == span


# This is just a heuristic. It will not work in all cases.
def find_unused_private_network(ip_version: int = 4, prefixlen: Union[int, None] = None,
                                already_used: Optional[List[typeinfo.IPNetworkLike]] = None) \
        -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """
    Use the routing table to find an unused IP network.

    @param ip_version: The IP version of the network.
    @param prefixlen: The prefix length of the network.
    @param already_used: Optionally a list of networks that are already in use.
    @return: An IP network that does not overlap existing routes or networks that are already in use.
    """
    assert (ip_version in {4, 6})
    space = [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
    ] if ip_version == 4 else [
        'fc00::/7'
    ]

    if already_used is None:
        already_used = []

    if prefixlen is None:
        prefixlen = 28 if ip_version == 4 else 64

    # This is the address space we want to obtain IP addresses from.
    pool = [ipaddress.ip_network(net) for net in space]

    # We represent this space as (lowest_address, highest_address) tuples instead of using CIDR notation.
    pooltp = sorted([(net.network_address, net.broadcast_address) for net in pool], key=lambda x: x[0])

    # We do not want to clash with other applications while not wanting to have the user configure routing manually.
    # So we need a way to obtain some space from the private IP address space that is unlikely to be in use.
    # Therefore, obtain all routes which have a prefix length greater than some relatively low threshold.
    # This is to filter the default route and pseudo default routes (such as 0.0.0.1/1 and 8.0.0.0/1).
    used = set()

    # We may have memorized some used IP networks already, so don't use them.
    for netlike in already_used:
        net = ipaddress.ip_network(netlike)
        if net.version != ip_version:
            continue
        used.add(net)

    for route in get_routes(ip_version, True):
        used.add(route_get_dst(route))

    # We remove the routes we have just filtered from the space we can use by splitting it accordingly.
    for u in used:
        pooltp = remove_from_pool(pooltp, u)

    # To obtain space which we can actually assign to an interface, we need to transform the remaining space
    # into CIDR notation again.
    summarized = [addr for sub in map(lambda x: ipaddress.summarize_address_range(*x), pooltp) for addr in sub]

    # From this space, pick the first network that is large enough.
    for s in summarized:
        if prefixlen >= s.prefixlen:
            return ipaddress.ip_network('%s/%s' % (s.network_address, prefixlen))


def get_used_routing_tables(ip_version: Optional[int] = None) -> Set[int]:
    if ip_version is None:
        return get_used_routing_tables(4) | get_used_routing_tables(6)
    assert (ip_version in {4, 6})
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

    result = []
    with IPRoute() as ip:
        result += [get_route_attr(r['attrs'], 'FRA_TABLE') for r in ip.rule('dump', family=family)]
        result += [get_route_attr(r['attrs'], 'RTA_TABLE') for r in ip.route('dump')]
    return set(result)


def get_unused_routing_table(ip_version: Optional[int] = None) -> int:
    used = get_used_routing_tables(ip_version)
    # Prefer default pallium routing table if it is not used
    return ROUTING_TABLE_DEFAULT if ROUTING_TABLE_DEFAULT not in used else max(used) + 1


def wait_for_file(path, timeout=30, interval=0.1):
    start = time.perf_counter()
    now = time.perf_counter()
    while (not os.path.exists(path)) and now - start < timeout:
        time.sleep(interval)
        now = time.perf_counter()
    return os.path.exists(path)


def backslash_quote_escape(value):
    return value.replace('\\', '\\\\').replace('"', '\\"')


def extract_from_buffer(buffer, terminator=b'\n'):
    term_pos = buffer.find(terminator)
    if term_pos >= 0:
        result = buffer[0:term_pos]
        buffer = buffer[term_pos + len(terminator):]
        return result, buffer
    return None


def get_subclasses(cls):
    subclasses = cls.__subclasses__()
    result = subclasses
    for cls in subclasses:
        result.extend(get_subclasses(cls))
    return result


def readline(sock, buffer, terminator=b'\n', timeout=0):
    end = None
    if timeout != 0:
        end = time.perf_counter() + timeout
    while True:
        extracted = extract_from_buffer(buffer, terminator)
        if extracted is not None:
            return extracted

        if timeout == 0:
            chunk = sock.recv(4096)
            if len(chunk) == 0:
                raise UnexpectedEOF
            buffer += chunk
        else:
            remaining = end - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError

            ready = select.select([sock], [], [], end - time.perf_counter())
            if ready[0]:
                chunk = sock.recv(4096, socket.MSG_DONTWAIT)
                buffer += chunk


def supports_named_arg(function: object, argname: str):
    """Check if a function defines a named string argument"""
    args, varargs, varkw, defaults, kwonlyargs, kwonlydefaults, annotations = inspect.getfullargspec(function)
    if varkw is not None:  # If **kwargs is part of the signature, any named argument is supported
        return isinstance(argname, str)
    return argname in args or argname in kwonlyargs


def is_iterable(obj: Iterable):
    try:
        iter(obj)
    except TypeError:
        return False
    return True


def convert2addr(obj, default_port: Union[int, None] = None) -> \
        tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int]:
    """Convert a string, tuple or list IP endpoint representation to an (ip_address, port) tuple"""
    if (isinstance(obj, tuple) or isinstance(obj, list)) and len(obj) == 2:
        if isinstance(obj[0], str):
            return ipaddress.ip_address(obj[0]), obj[1]
        else:
            return obj[0], obj[1]
    elif isinstance(obj, str):
        obj = obj.strip()

        # Maybe it can just be converted to an IP address
        try:
            ip = ipaddress.ip_address(obj)
            return ip, default_port
        except ValueError:
            pass

        if obj[0] == '[' and ']' in obj:  # [<ipv6addr>]:<port> format
            rest = obj[obj.index(']') + 1:]
            if len(rest) == 0:
                return ipaddress.ip_address(obj[1:]), default_port
            if rest[1] != ':':
                raise ValueError
            return ipaddress.ip_address(obj[1:]), int(rest[1:])
        elif ':' in obj:  # <ipv4addr>:<port> format
            split = obj.split(':', 1)
            return ipaddress.ip_address(split[0]), int(split[1])
    raise ValueError


def addr2str(addr):
    return '%s:%d' % addr


def cleanup_tmp():
    logging.getLogger(__name__).debug('Remove app temp dir: %s, pid=%d' % (APP_TMP_DIR, os.getpid()))
    # noinspection PyTypeChecker
    shutil.rmtree(APP_TMP_DIR)


def prepare_temp():
    global APP_TMP_DIR
    if APP_TMP_DIR is None:
        APP_TMP_DIR = tempfile.mkdtemp(prefix='pallium_')
        os.chmod(APP_TMP_DIR, 0o0777)
        logging.getLogger(__name__).debug('Created app temp dir: %s' % APP_TMP_DIR)

        onexit.register(cleanup_tmp)


def mkdtemp(suffix=None, prefix=None):
    prepare_temp()
    tmpdir = tempfile.mkdtemp(suffix, prefix, APP_TMP_DIR)
    return tmpdir


def mktemp(suffix='', prefix=''):
    prepare_temp()
    tmpdir = tempfile.mktemp(suffix, prefix, APP_TMP_DIR)
    return tmpdir


def addslashes(text: str, characters=','):
    """Escape special characters with backslashes"""
    text = text.replace('\\', '\\\\')
    for char in characters:
        text = text.replace(char, '\\' + char)
    return text


def nla_attrs2dict(nla):
    if isinstance(nla, list):
        return [nla_attrs2dict(x) for x in nla]
    elif is_iterable(nla):
        try:
            if 'attrs' in nla:
                d = dict(nla['attrs'])
                return {k: nla_attrs2dict(d[k]) for k in d}
        except TypeError:
            pass
        return nla
    else:
        return nla


# See https://pyinstaller.org/en/stable/runtime-information.html
def environ(env=os.environ):
    env = dict(env)  # make a copy of the environment
    if not PYINSTALLER:
        return env
    lp_key = 'LD_LIBRARY_PATH'  # for GNU/Linux and *BSD.
    lp_orig = env.get(lp_key + '_ORIG')
    if lp_orig is not None:
        env[lp_key] = lp_orig  # restore the original, unmodified value
    else:
        # This happens when LD_LIBRARY_PATH was not set.
        # Remove the env var as a last resort:
        env.pop(lp_key, None)
    if 'PYINSTALLER_LD_LIBRARY_PATH' in env:
        env['LD_LIBRARY_PATH'] = env['PYINSTALLER_LD_LIBRARY_PATH']
    return env


def bundled_resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def get_tool_execution_info(name):
    bundled_path = bundled_resource_path('bin/%s' % name)
    if os.path.isfile(bundled_path):
        return bundled_path, {
            'PYINSTALLER_LD_LIBRARY_PATH': bundled_resource_path('%s-lib' % name)
        }
    if config is None or 'paths' not in config:
        return name, None
    return config['paths'].get(name, name), None


def get_tool_path(name):
    return get_tool_execution_info(name)[0]


def tool_popen(name):
    pass


def tool_path_args(args):
    if config is None or 'paths' not in config:
        return
    if len(args) > 0 and isinstance(args[0], list):
        args[0][0] = config['paths'].get(args[0][0], args[0][0])


def proc_call(*args, **kwargs):
    kwargs.setdefault('env', os.environ)
    kwargs['env'] = environ(kwargs['env'])
    tool_path_args(args)
    return subprocess.call(*args, **kwargs)


def popen(*args, **kwargs):
    kwargs.setdefault('env', os.environ)
    kwargs['env'] = environ(kwargs['env'])
    tool_path_args(args)
    return subprocess.Popen(*args, **kwargs)


def random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(0, length)])


def secure_config(filepath, mode):
    stat_result = os.stat(filepath)
    file_mode = stat.S_IMODE(stat_result.st_mode)
    return os.stat(filepath).st_uid == 0 and (file_mode & (~mode) == 0)


def parse_global_config():
    global config
    try:
        with open(GLOBAL_PATH) as f:
            config = json.loads(f.read())
            if config is not None and not secure_config(GLOBAL_PATH, 0o644):
                raise ConfigurationError(
                    "The global configuration file must be owned by root and may not be writable by other users.")
    except Exception as e:
        if not isinstance(e, FileNotFoundError):
            raise


parse_global_config()
