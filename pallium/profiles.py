import base64
import errno
import glob
import hashlib
import ipaddress
import json
import logging
import os
import os.path
import shutil
import signal
import socket
import subprocess
import traceback
import typing
from typing import List, Union, Optional, Callable

from pyroute2.iproute import IPRoute
from pyroute2.ethtool import Ethtool
from pyroute2.netlink.rtnl.ifaddrmsg import IFA_F_NODAD, IFA_F_NOPREFIXROUTE
from pyroute2.netlink.exceptions import NetlinkError

import pallium.config
from .nftables import NFTables

from . import audio, debugging, resolvconf, runtime
from . import config
from . import dhcp as dhcpd
from . import hops
from . import nftables
from . import onexit
from . import security
from . import slirp
from . import sysutil
from . import util
from .sandbox import Sandbox
from .graphics import enable_gui_access
from .hops.dummy import DummyHop
from .hops.hop import DnsTcpProxy
from .netns import NetworkNamespace, MountInstruction
from .nftables import NFPROTO_INET
from .typeinfo import IPNetworkLike
from .exceptions import *

BRIDGE_DEFAULTS = {
    'routes': [],
    'dhcp': False
}


class ProfileManager:
    @staticmethod
    def list(running_only=False):
        filenames = glob.glob(os.path.join(runtime.PROFILE_DIR, '*.json'))
        result = []
        for filename in filenames:
            p = Profile.from_file(filename)
            if not running_only or p.is_running:
                result.append(p)
        return result


class NetPool:
    """
    This class keeps track of used IP addresses such that duplicate assignments are avoided.
    """
    used = []

    def add_used(self, used):
        self.used += used

    def get_network(self, *args, **kwargs):
        kwargs['already_used'] = self.used
        util.find_unused_private_network(*args, **kwargs)


class Profile:
    debug = False
    quiet = None

    def _prepare_for_execution(self, configuration: config.Configuration):
        pass

    def __init__(self, conf: config.Configuration):
        """
        Initialize a pallium profile.

        @param chain: A list of hops to build the connection.
        @param start_networks: Start networks from which to assign IP addresses from, currently without effect.
        @param user: Username as string or user id as int of the user to run commands as.
        @param quiet: Whether output from the chain hop applications is
        @param bridge: If a `Bridge` is provided, a veth bridge, which traffic can be routed through, is created inside
        the default netns.
        @param routes: Routes to be routed through the chain. Default: 0.0.0.0/0 and ::0/0
        @param preexec_fn: Functions to be executed inside the main network namespace before running the profile.
        @param postexec_fn: Cleanup functions to be executed when tearing down the connection.
        @param kill_switch: When enabled, traffic is not allowed to bypass hops.
        """
        self._filepath = None
        chain = conf.network.chain
        if len(chain) == 0 or not isinstance(chain[-1], DummyHop):
            chain.append(DummyHop())
        self.chain = chain

        # TODO: Include this in config
        start_networks = []
        self.start_networks = list(map(ipaddress.ip_network, start_networks))
        self.netinfo = None
        self.bridge = conf.network.bridge
        self._preexec_fn = []
        self._postexec_fn = []
        # TODO: Support
        self.user = None
        self.netpool = NetPool()
        self.command = conf.run.command
        routes = conf.network.routes
        if routes is not None:
            chain[-1].required_routes = list(map(ipaddress.ip_network, routes))

        # If Profile.quiet is a boolean class property and no quiet value has been supplied to the constructor,
        # we use Profile.quiet as a default value.
        quiet = conf.run.quiet
        if quiet is None and isinstance(Profile.quiet, bool):
            quiet = Profile.quiet
        self._set_quiet(quiet)

        for hop in self.chain:
            if self.debug:
                hop.debug = True
        self._context_sessions = []
        self.kill_switch = conf.network.kill_switch
        self._mounts = []
        self.has_connected_functions = False

        self.sandbox = conf.sandbox
        if self.sandbox is not None:
            self._mounts.extend(self.sandbox.get_mounts())

        if conf is None:
            conf = config.Configuration()
        self.config = conf

    # noinspection PyRedeclaration
    @property
    def quiet(self):
        """
        Note that quiet is redeclared here. This allows us to use Profile.quiet to control the quiet property of newly
        created profiles while the quiet property of a Profile instance is still specific to that instance.

        @return: Whether the profile should be run in quiet mode, i.e. without output.
        """
        return self._quiet

    def _set_quiet(self, value):
        self._quiet = value
        for hop in self.chain:
            if hop.quiet is None and self._quiet is not None:
                hop.quiet = self._quiet

    @quiet.setter
    def quiet(self, value):
        self._set_quiet(value)

    @classmethod
    def from_config(cls, settings: dict) -> 'Profile':
        """
        Return a profile from a JSON serializable settings dictionary.

        @param settings: The settings as dictionary.
        @return: A profile which was constructed according to the settings.
        """

        return Profile(pallium.config.Configuration.from_json(settings))

    def _create_profile_folder(self):
        if not os.path.exists(runtime.APP_RUN_DIR):
            os.mkdir(runtime.APP_RUN_DIR, 0o711)
        if not os.path.exists(self.profile_folder):
            os.mkdir(self.profile_folder, 0o711)

    @property
    def profile_folder(self):
        return os.path.join(runtime.APP_RUN_DIR, 'profile_' + str(self.long_id))

    def new_session(self, create: bool = False, mounts: Optional[List[MountInstruction]] = None):
        self._create_profile_folder()

        if not create:
            return OwnedSession(self, 0, mounts)
        else:
            for i in range(1024):
                try:
                    return OwnedSession(self, i, mounts)
                except ProfileAlreadyRunningException:
                    continue
            raise SessionCreationException('Failed to create a new session.')

    def get_session(self, index):
        owned_session = OwnedSession(self, index, must_exist=False)
        return owned_session

    def _run_postexec_fn(self):
        for f in self._postexec_fn:
            f()

    def run(self, multisession: bool = False) -> 'OwnedSession':
        """
        Running a profile creates a session. This means that the network chain is built and the run command is executed
        as specified by the profile.

        @param multisession: Whether to create a new session. If false, an exception will be thrown if the profile is
                             already running.
        @return: The session object.
        """
        util.prepare_temp()
        if self.sandbox:
            self.sandbox.tmpdir = util.APP_TMP_DIR
            self.sandbox.prepare()
        for f in self._preexec_fn:
            result = f()
            if isinstance(result, tuple):
                self._postexec_fn.append(result[0])
                self._mounts.append(MountInstruction(*result[1]))
            elif result is not None:
                self._postexec_fn.append(result)

        self.start_networks = [util.find_unused_private_network(4), util.find_unused_private_network(6)]

        self.netpool.add_used([
            ipaddress.ip_network('10.0.2.0/24'),
            ipaddress.ip_network('fd00::/64')
        ])  # Slirpnetstack, cf. slirp.py

        self.netpool.add_used(self.start_networks)
        # TODO: Deal with custom defined networks.
        self.netinfo = self.start_networks.copy()

        session = self.new_session(multisession, self._mounts)
        session._connect()
        return session

    @classmethod
    def from_file(cls, filepath) -> 'Profile':
        """
        Return a profile from a filepath.

        @param filepath: The full path to the configuration file.
        @return: The profile constructed according to the configuration file.
        """
        with open(filepath, 'r') as f:
            settings = json.loads(f.read())

        p = cls.from_config(settings)
        p._filepath = os.path.abspath(filepath)
        return p

    @property
    def exists(self):
        return os.path.isfile(self._filepath)

    @property
    def name(self) -> str:
        """
        Obtain a unique, normalized profile name.

        @return: The profile name.
        """
        if not self._filepath:  # The profile is in memory, e.g. because it was instantiated from Python.
            return '<%d>' % id(self)
        split = os.path.split(self._filepath)
        if split[0] == runtime.PROFILE_DIR and split[1].endswith('.json'):
            return split[1][:-len('.json')]
        return self._filepath

    def __str__(self):
        return self.name

    def __repr__(self):
        return super().__repr__() + ' (%s)' % self.name

    def get_sessions(self):
        return [int(file.split('_')[-1]) for file in glob.glob(os.path.join(self.profile_folder, 'session_*'))]

    @property
    def is_running(self) -> bool:
        """
        Determine whether the profile is currently running.

        @return: Whether the profile is running.
        """
        raise NotImplementedError

    @property
    def config_path(self):
        return self._filepath

    @property
    def long_id(self) -> str:
        """
        Obtain a unique long ID for the profile.

        @return: The long ID.
        """
        return 'pm' + base64.urlsafe_b64encode(self.hash_id.digest()).decode('ascii').replace('=', '')

    @property
    def pseudo_path(self) -> str:
        """
        Obtain a pseudo path for the profile that is unique accross processes.

        @return: The path.
        """
        return 'file://' + self._filepath if self._filepath else 'mem://%d/%d' % (os.getpid(), id(self))

    @property
    def hash_id(self):
        """
        Create a hash ID for the profile. This will be used for long ID as well as device name generation.

        @return: The hash ID.
        """
        return hashlib.sha256(self.pseudo_path.encode('utf-8'))

    def __enter__(self):
        session = self.run()
        self._context_sessions.append(session)
        return session

    def __exit__(self, exc_type, exc_val, exc_tb):
        session = self._context_sessions.pop()
        session.close()


class Session:
    """
    A session is an instance of a running profile. It provides basic operations supported without being the creator of
    the session, such as executing commands inside the profile namespaces.

    In the future, the session management, which takes place through the creation of files at the moment, may be
    implemented by a daemon.
    """

    def __init__(self, profile: Union[Profile, str], index, _must_exist=True):
        self._index = index
        if isinstance(profile, Profile):
            self._profile_folder = profile.profile_folder
        elif isinstance(profile, str):
            self._profile_folder = profile
        else:
            raise ValueError
        if _must_exist and not os.path.isdir(self.session_folder):
            raise SessionNotFoundError('The session with index %d was not found.' % index)

    def _get_state(self):
        try:
            with open(os.path.join(self.session_folder, 'state'), 'r') as f:
                return json.loads(f.read())
        except FileNotFoundError:
            raise SessionNotFoundError(
                'The state file for the profile was not found. Maybe the connection build-up has not yet succeeded?')

    def get_mount_instructions(self):
        with open(os.path.join(self.session_folder, 'mounts'), 'r') as f:
            return [MountInstruction.from_json(m) for m in json.loads(f.read())]

    @property
    def network_namespaces(self) -> List[NetworkNamespace]:
        state = self._get_state()
        return [NetworkNamespace(hop['netns']['fd'], hop['netns']['etc'], self.get_mount_instructions())
                for hop in state['chain']]

    @property
    def pid(self):
        try:
            with open(os.path.join(self.session_folder, 'pid'), 'r') as f:
                return int(f.read())
        except FileNotFoundError:
            raise SessionNotFoundError('The PID file for the session with index %d was not found.' % self._index)

    @property
    def sandbox_pid(self):
        pids_dir = os.path.join(self.session_folder, 'netns/pids')
        ns_index = sorted(map(int, os.listdir(pids_dir)))[-1]
        with open(os.path.join(pids_dir, str(ns_index))) as f:
            return int(f.read().strip())

    def enter(self):
        return self.network_namespaces[-1].enter()

    def exit(self):
        return self.network_namespaces[-1].exit()

    @property
    def session_folder(self):
        return os.path.join(self._profile_folder, 'session_%d' % self._index)

    @property
    def pseudo_path(self) -> str:
        """
        Obtain a pseudo path for the session that is unique accross processes.

        @return: The path.
        """
        return 'file://' + self.session_folder if self.session_folder else 'mem://%d/%d' % (os.getpid(), id(self))

    @property
    def long_id(self) -> str:
        """
        Obtain a unique long ID for the profile.

        @return: The long ID.
        """
        return 'pm' + base64.urlsafe_b64encode(self.hash_id.digest()).decode('ascii').replace('=', '')

    @property
    def hash_id(self):
        """
        Create a hash ID for the profile. This will be used for long ID as well as device name generation.

        @return: The hash ID.
        """
        return hashlib.sha256(self.pseudo_path.encode('utf-8'))

    def execute(self, cmd, *args, **kwargs):
        return self.network_namespaces[-1].run(cmd, args=args, kwargs=kwargs)

    def __enter__(self):
        return self.network_namespaces[-1].enter()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.network_namespaces[-1].__exit__(exc_type, exc_val, exc_type)


def disable_checksum_offloading(ifname) -> None:
    """
    Disable checksum offloading for the specified interface.

    @param ifname: The interface.
    @return: None.
    """
    ethtool = Ethtool()
    features = ethtool.get_features(ifname)
    if 'tx-checksum-ip-generic' in features.features:
        features.features['tx-checksum-ip-generic'].enable = False
        ethtool.set_features(ifname, features)
    ethtool.close()


def create_bridge(peer1_name: str, peer2_name: str, peer1_netns: NetworkNamespace, peer2_netns: NetworkNamespace,
                  debug=False):
    def run():
        with IPRoute() as ip:
            try:
                ip.link('add', ifname=peer1_name, peer=peer2_name, kind='veth')
            except NetlinkError as e:
                if e.code == errno.EEXIST:
                    raise DuplicateBridgeException("An interface named \"%s\" already exists." % peer1_name)
                raise

            peer1_fd = ip.link_lookup(ifname=peer1_name)[0]
            peer2_fd = ip.link_lookup(ifname=peer2_name)[0]
            if not peer1_netns.is_default and not runtime.use_slirp4netns():
                kwargs = {'net_ns_pid': peer1_netns.pid}
            else:
                kwargs = {}
            ip.link('set', index=peer1_fd, state='up', **kwargs)
            kwargs = {'net_ns_pid': peer2_netns.pid} if not peer2_netns.is_default else {}
            ip.link('set', index=peer2_fd, state='up', **kwargs)

        return peer1_fd, peer2_fd

    if not runtime.use_slirp4netns():
        result = run()
    else:
        result = peer1_netns.run(run, exclude_ns=sysutil.CLONE_NEWPID | sysutil.CLONE_NEWNS)

    # Offloading problem: See https://github.com/projectcalico/felix/issues/40 for a similar/the same issue.
    # This hampers DHCP in particular.
    peer1_netns.run(lambda: disable_checksum_offloading(peer1_name))
    peer2_netns.run(lambda: disable_checksum_offloading(peer2_name))

    if debug:
        peer1_netns.run(lambda: debugging.capture(peer1_name))
        peer2_netns.run(lambda: debugging.capture(peer2_name))

    return result


def create_postrouting_nat_chain(nft, chain_name):
    nft.table('add', name='pallium')
    nft.chain('add', table='pallium', name=chain_name, type='nat', hook='postrouting', priority=100, policy=1)


def create_filter_chain(nft, chain_name, hook, policy=0):
    nft.table('add', name='pallium')
    nft.chain('add', table='pallium', name=chain_name, type='filter', hook=hook, priority=0, policy=policy)


def create_prerouting_fwmark_chain(nft, chain_name):
    nft.table('add', name='pallium')
    nft.chain('add', table='pallium', name=chain_name, type='filter', hook='prerouting', priority=0, policy=1)


def masquerade_interface_networks(iface, netinfo: Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
                                  chain_name='POSTROUTING',
                                  device=None):
    with IPRoute() as ipr:
        ipr.addr('add', index=iface, address=str(netinfo.network_address + 1),
                 prefixlen=netinfo.prefixlen)

    # Masquerading
    with NFTables(nfgen_family=NFPROTO_INET) as nft:
        create_postrouting_nat_chain(nft, chain_name)
        exp = nftables.ip(saddr=netinfo) + nftables.masquerade()
        if device is not None:
            exp += nftables.oifname(device)
        nft.rule('add', table='pallium', chain=chain_name, expressions=(exp,))


def mark_packets(fwmark, netinfo: Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
                                  chain_name='POSTROUTING',
                                  device=None):
    with NFTables(nfgen_family=NFPROTO_INET) as nft:
        create_prerouting_fwmark_chain(nft, chain_name)
        exp = nftables.ip(saddr=netinfo)
        if device is not None:
            exp += nftables.iifname(device)
        exp += nftables.meta.mark(set=fwmark)
        nft.rule('add', table='pallium', chain=chain_name, expressions=(exp,))



def drop_input(chain_name, device):
    with NFTables(nfgen_family=NFPROTO_INET) as nft:
        nft.table('add', name='pallium')
        nft.chain('add', table='pallium', name=chain_name, type='filter', hook='input')
        nft.rule('add', table='pallium', chain=chain_name, expressions=(
            nftables.meta.iifname(device),
            nftables.drop()
        ))


def nft_iface_forward(nft, table, chain, method, iface_func, ifname):
    nft.rule(method, table=table, chain=chain, expressions=(
        iface_func(ifname),
        nftables.accept()
    ))


def nft_chain_exists(nft, table, chain):
    chains = nft.get_chains()
    for c in chains:
        attrs = dict(c['attrs'])
        if attrs['NFTA_CHAIN_TABLE'] == table and attrs['NFTA_CHAIN_NAME'] == chain:
            return True
    return False


def nft_has_rule(nft, table, chain, rule):
    rule = util.nla_attrs2dict(rule)
    rules = nft.get_rules()
    for r in rules:
        attrs = dict(r['attrs'])
        if attrs['NFTA_RULE_TABLE'] == table and attrs['NFTA_RULE_CHAIN'] == chain \
                and util.nla_attrs2dict(attrs['NFTA_RULE_EXPRESSIONS']) == rule:
            return True
    return False


def nft_get_jump_rule_handle(nft, table, chain, target):
    expected = [{
        'NFTA_EXPR_NAME': 'immediate',
        'NFTA_EXPR_DATA': {
            'NFTA_IMMEDIATE_DREG': 'NFT_REG_VERDICT',
            'NFTA_IMMEDIATE_DATA': {
                'NFTA_DATA_VERDICT': {
                    'NFTA_VERDICT_CODE': 'NFT_JUMP',
                    'NFTA_VERDICT_CHAIN': target
                }
            }
        }
    }]

    rules = nft.get_rules()
    for r in rules:
        attrs = dict(r['attrs'])
        if attrs['NFTA_RULE_TABLE'] == table and attrs['NFTA_RULE_CHAIN'] == chain \
                and util.nla_attrs2dict(attrs['NFTA_RULE_EXPRESSIONS']) == expected:
            return attrs['NFTA_RULE_HANDLE']
    return None


def delete_chain(chain):
    with NFTables(nfgen_family=NFPROTO_INET) as nft:
        nft.chain('del', table='pallium', name=chain, flags=0)


def delete_link(name):
    with IPRoute() as ip:
        try:
            ip.link('del', ifname=name)
        except NetlinkError as e:
            if e.code != errno.ENODEV:
                raise


class OwnedSession(Session):
    """
    An OwnedSession is an instance of a profile with all implementation-specific internals. It is returned during
    session creation. It performs the connection building and manages the resources that belong to a session.

    In contrast, a non-owned Session does not control the resources that belong to the session. It merely manages the
    information that is required to perform operations inside the network namespaces.
    """

    def __init__(self, profile: Profile, index, mounts: Optional[List[MountInstruction]] = None, must_exist=True):
        self._profile = profile
        self._index = index
        self._owner = os.getpid()

        self._revert_functions = []
        self._hops = []
        self._freed = False
        self._current_network = self._profile.netinfo
        self._bridge = self._profile.bridge
        self._mounts = mounts if mounts else []

        # The effective chain differs from the chain supplied upon profile creation in that it will be populated with
        # intermediate and dummy hops.
        self._effective_chain = None

        self._forwarding_exceptions = []
        self._first_ns = None

        super().__init__(self._profile, self._index, _must_exist=False)

        if not must_exist:
            return
        try:
            sysutil.create_folder_structure([
                (self.session_folder, 0o711, [
                    ('netns', 0o711, [
                        ('fds', 0o700),
                        ('etc', 0o755),
                        ('pids', 0o700),
                    ])
                ])
            ], throw=True)
        except FileExistsError:
            raise ProfileAlreadyRunningException(
                'The profile is already running. If you wish to open another session, please use --new-session.')
        self._create_pid_file()
        self._create_mounts_file()

        onexit.register(self.close)

    def _create_mounts_file(self):
        def opener(path, flags):
            return os.open(path, flags, 0o200)

        state_file = os.path.join(self.session_folder, 'mounts')
        with open(state_file, 'w', opener=opener) as f:
            f.write(json.dumps([m.to_json() for m in self._mounts]))
        os.chmod(state_file, 0o600)

    def _revert(self, fun):
        self._revert_functions.append(fun)
        return fun

    @staticmethod
    def _create_loopback(ip):
        lo = ip.link_lookup(ifname='lo')[0]
        ip.link('set', index=lo, state='up')

    def _enable_ip_forwarding(self, version=None, allow_interfaces=None, forward_policy=nftables.NF_DROP):
        """
        Enable IP forwarding globally.

        @param version: The IP version which to enable forwarding for.
        @param allow_interfaces: The interfaces which to allow forwarding for,
        @param forward_policy: The default policy of the nft forward chain.
        @return: None.
        """
        if allow_interfaces is None:
            allow_interfaces = []
        if version is None:
            self._enable_ip_forwarding(4, allow_interfaces, forward_policy)
            self._enable_ip_forwarding(6, allow_interfaces, forward_policy)
            return

        priority = 0

        with NFTables(nfgen_family=nftables.family_from_version(version)) as nft:
            table = 'filter'
            chain = 'FORWARD'
            nft.table('add', name=table)
            if not nft_chain_exists(nft, table, chain):
                nft.chain('add', table=table, name=chain, type='filter', hook='forward', priority=priority,
                          policy=forward_policy)

            custom_chain = 'pallium.' + self.long_id
            nft.chain('add', table=table, name='pallium')

            @self._revert
            def revert():
                with NFTables(nfgen_family=nftables.family_from_version(version)) as nft2:
                    jump_handle = nft_get_jump_rule_handle(nft2, table, 'pallium', custom_chain)
                    if isinstance(jump_handle, int):
                        nft2.rule('del', table=table, chain='pallium', handle=jump_handle, flags=0)
                    nft2.chain('del', table=table, name=custom_chain, flags=0)

            nft.chain('add', table=table, name=custom_chain)

            for ifname in allow_interfaces:
                nft_iface_forward(nft, table, custom_chain, 'add', nftables.meta.iifname, ifname)
                nft_iface_forward(nft, table, custom_chain, 'add', nftables.meta.oifname, ifname)

            nft.rule('add', table=table, chain='pallium', expressions=(
                nftables.jump(custom_chain),
            ))

            jump_rule_handle = nft_get_jump_rule_handle(nft, table, chain, 'pallium')
            if not isinstance(jump_rule_handle, int):
                nft.rule('add', table=table, chain=chain, expressions=(
                    nftables.jump('pallium'),
                ))

        sysutil.ip_forward(version, True)

    def _setup_filter_rule(self, chain_prefix, hop_info):
        oifname = hop_info.previous.indev
        iifname = hop_info.outdev

        if hop_info.previous.previous is None:  # Default netns
            output_filter = chain_prefix + '.output'
            # Ensure that no servers, such as the Tor SOCKS proxy, are exposed to the outside world.
            with NFTables(nfgen_family=NFPROTO_INET) as nft:
                self._revert(lambda: delete_chain(output_filter))
                create_filter_chain(nft, output_filter, 'output', nftables.NF_ACCEPT)
                nft.rule('add', table='pallium', chain=output_filter, expressions=(
                    nftables.ct.state() & (nftables.ct.state.established | nftables.ct.state.related) == 0,
                    nftables.meta.oifname(iifname),
                    nftables.drop()
                ))
            # Nothing else to do for default netns
            return

        forward_filter = chain_prefix + '.forward'
        with NFTables(nfgen_family=NFPROTO_INET) as nft:
            self._revert(lambda: delete_chain(forward_filter))
            create_filter_chain(nft, forward_filter, 'forward')

            # If the kill switch is not activated, we allow direct traffic flow between the interfaces connecting
            # the previous and the next namespace. The same holds for namespaces that do not provide a tun interface.
            if not self.profile.kill_switch or hop_info.previous.hop.kill_switch_device is None:
                nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                    nftables.meta.iifname(iifname),
                    nftables.meta.oifname(oifname),
                    nftables.accept()
                ))

                nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                    nftables.meta.iifname(oifname),
                    nftables.meta.oifname(iifname),
                    nftables.ct.state() & (nftables.ct.state.established | nftables.ct.state.related) != 0,
                    nftables.accept()
                ))

            if hop_info.previous.hop.kill_switch_device is None:
                return

            for ex in self._forwarding_exceptions:
                if ex.ttl > 0:
                    ex.ttl -= 1
                    nft.rule('add', table='pallium', chain=forward_filter, expressions=ex.nft_rule)

            for net in hop_info.previous.netinfo:
                nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                    nftables.ip(saddr=net),
                    nftables.accept(),
                ))
                nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                    nftables.ip(daddr=net),
                    nftables.accept(),
                ))

            # Ensure that traffic is not forwarded between in and out interfaces of a network namespace directly.
            # Instead, make sure that it is forwarded through an intermediate hop.
            # This prevents leaks in case the intermediate hop goes down.
            nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                nftables.meta.iifname(oifname),
                nftables.meta.oifname() != iifname,
                nftables.accept()
            ))

            nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                nftables.meta.iifname() != iifname,
                nftables.meta.oifname(oifname),
                nftables.ct.state() & (nftables.ct.state.established | nftables.ct.state.related) != 0,
                nftables.accept()
            ))

            nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                nftables.meta.iifname(iifname),
                nftables.meta.oifname() != oifname,
                nftables.accept()
            ))

            nft.rule('add', table='pallium', chain=forward_filter, expressions=(
                nftables.meta.iifname() != oifname,
                nftables.meta.oifname(iifname),
                nftables.ct.state() & (nftables.ct.state.established | nftables.ct.state.related) != 0,
                nftables.accept()
            ))

    # TODO: Only do this if we have a port forwarding to localhost
    def finalize_setup(self, hop_info, is_last):
        is_first_hop = hop_info.previous.previous is None
        if not runtime.use_slirp4netns():
            return
        if is_first_hop:
            return

        local_fwds = self.profile.config.network.port_forwarding.local

        def local_port_forwarding_setup():
            # TODO: route_localnet for last namespace (https://serverfault.com/a/1022269).

            with IPRoute() as ip:
                for netinfo in hop_info.netinfo:
                    outdev = ip.link_lookup(ifname=hop_info.outdev)[0]
                    indev = ip.link_lookup(ifname=hop_info.previous.indev)[0]
                    dst = {
                        4: '10.0.2.101/32',
                        6: 'fd00::101/128'
                    }
                    ip.route('add', dst=dst[netinfo.version], oifd=outdev, gateway=str(netinfo.network_address + 2))

                # We don't want to have this route in the namespace which slirp4netstack is in because
                # the address is part of the subnet assigned to the slirp interface.
                # 0 is the default namespace, 1 is the namespace which slirp4netstack is connected to,
                # 2 is the following namespace. Since we run that in the previous namespace, we are at >= 3.
                if hop_info.index > 2:
                    for netinfo in hop_info.previous.netinfo:
                        src = {
                            4: '10.0.2.2/32',
                            6: 'fd00::2/128'
                        }
                        ip.route('add', dst=src[netinfo.version], oifd=indev, gateway=str(netinfo.network_address + 1))

            if len(local_fwds) > 0:
                with NFTables(nfgen_family=NFPROTO_INET) as nft:
                    nft.table('add', name='pallium')
                    nft.chain('add', table='pallium', name='prerouting', type='nat', hook='prerouting',
                              priority=-100, policy=nftables.NF_ACCEPT)

                    for i, local_fwd in enumerate(local_fwds):
                        # Depending on the protocol, this is either nftables.tcp or nftables.udp
                        nft_l4: typing.Callable = getattr(nftables, local_fwd.protocol)
                        port = i + 1
                        nft.rule('add', table='pallium', chain='prerouting', expressions=(
                            nftables.ip(daddr='10.0.2.100'),
                            nft_l4(dport=port),
                            nftables.dnat(to=('10.0.2.101', port))
                        ))

                        chain = 'pallium.' + hop_info.outdev + '.filter.forward'
                        # Allow forwarding
                        nft.rule('add', table='pallium', chain=chain,
                                 expressions=(
                                     nftables.ip(daddr='10.0.2.101'),
                                     nft_l4(dport=port),
                                     nftables.accept()
                                 ))
                        nft.rule('add', table='pallium', chain=chain,
                                 expressions=(
                                     nftables.ip(saddr='10.0.2.101'),
                                     nft_l4(sport=port),
                                     nftables.accept()
                                 ))

        hop_info.previous.netns.run(local_port_forwarding_setup)

        if not is_last:
            return

        def run_in_last_ns():
            # If we have a forwarding to an address in 127.0.0.0/8
            if any(fwd.guest[0].is_loopback for fwd in local_fwds):
                # This is required to perform DNAT to an address in 127.0.0.0/8
                sysutil.sysctl('/proc/sys/net/ipv4/conf/all/route_localnet', b'1\n')

            with NFTables(nfgen_family=NFPROTO_INET) as nft:
                nft.table('add', name='pallium')
                nft.chain('add', table='pallium', name='prerouting', type='nat', hook='prerouting',
                          priority=-100, policy=nftables.NF_ACCEPT)

                for i, local_fwd in enumerate(local_fwds):
                    # Depending on the protocol, this is either nftables.tcp or nftables.udp
                    nft_l4: typing.Callable = getattr(nftables, local_fwd.protocol)

                    port = i + 1
                    nft.rule('add', table='pallium', chain='prerouting', expressions=(
                        nftables.ip(daddr='10.0.2.101'),
                        nft_l4(dport=port),
                        nftables.counter(),
                        nftables.dnat(to=local_fwd.guest),
                    ))

        hop_info.netns.run(run_in_last_ns)

    def _setup_namespace(self, hop_info):
        is_first_hop = hop_info.previous.previous is None
        if not runtime.use_slirp4netns() or is_first_hop:
            hop_info.netns.create()
        else:
            def create_nested():
                hop_info.netns.create()
                return hop_info.netns

            hop_info.netns = hop_info.previous.netns.run(create_nested,
                                                         exclude_ns=sysutil.CLONE_NEWPID | sysutil.CLONE_NEWNS)

        @self._revert
        def revert_netns_creation():
            # hop_info.netns.delete(True)
            try:
                os.kill(hop_info.netns.pid, signal.SIGTERM)
            except ProcessLookupError:
                return

        if runtime.use_slirp4netns() and is_first_hop:
            slirp_app = slirp.available_slirp_class()(self.profile.config, hop_info, self.profile.quiet)

            hop_info.netns.run(slirp_app.prepare)

            self._revert(slirp_app.start())
            return

        nft_postrouting_nat_chain = 'pallium.' + hop_info.outdev + '.nat.postrouting'
        nft_prerouting_fwmark_chain = 'pallium.' + hop_info.outdev + '.nat.prerouting'
        nft_filter_prefix = 'pallium.' + hop_info.outdev + '.filter'

        # We call the revert function before building the bridge to free the resources even when create_bridge
        # is interrupted.
        if is_first_hop:
            @self._revert  # Netns deletion implies deletion of rules/links. Manually delete them for the default netns.
            def revert_first_hop():
                delete_chain(nft_postrouting_nat_chain)
                delete_chain(nft_prerouting_fwmark_chain)
                delete_link(hop_info.outdev)

        outfd, infd = create_bridge(hop_info.outdev, hop_info.indev, hop_info.previous.netns, hop_info.netns,
                                    debug=self.profile.debug)

        fwmark_routing = self.profile.config.network.outbound_interface is not None and is_first_hop
        if fwmark_routing:
            @self._revert
            def revert_fwmark_routing():
                with IPRoute() as ip:
                    ip.rule('del', fwmark=util.FWMARK_DEFAULT, table=util.ROUTING_TABLE_DEFAULT, family=socket.AF_INET)
                    ip.rule('del', fwmark=util.FWMARK_DEFAULT, table=util.ROUTING_TABLE_DEFAULT, family=socket.AF_INET6)
                    ip.flush_routes(table=util.ROUTING_TABLE_DEFAULT)

        def add_nft_rules():
            for netinfo in hop_info.netinfo:
                masquerade_interface_networks(outfd, netinfo, nft_postrouting_nat_chain, hop_info.outdev)

            if fwmark_routing:
                with IPRoute() as ip:
                    ip.rule('add', fwmark=util.FWMARK_DEFAULT, table=util.ROUTING_TABLE_DEFAULT, family=socket.AF_INET)
                    ip.rule('add', fwmark=util.FWMARK_DEFAULT, table=util.ROUTING_TABLE_DEFAULT, family=socket.AF_INET6)
                util.copy_routing_table(self.profile.config.network.outbound_interface, util.ROUTING_TABLE_DEFAULT)
                for netinfo in hop_info.netinfo:
                    mark_packets(util.FWMARK_DEFAULT, netinfo, nft_prerouting_fwmark_chain, hop_info.outdev)

            # if not is_first_hop and self.profile.kill_switch and hop_info.previous.hop.kill_switch_device is not None:
            self._setup_filter_rule(nft_filter_prefix, hop_info)

        hop_info.previous.netns.run(add_nft_rules)

        def run_in_new_netns():
            with IPRoute() as ip:
                for netinfo in hop_info.netinfo:
                    # Duplicate Address Detection causes IP addresses to not be immediately available for configuration.
                    # See https://www.agwa.name/blog/post/beware_the_ipv6_dad_race_condition and
                    # https://github.com/systemd/systemd/issues/5882
                    flags = 0
                    if netinfo.network_address.version == 6:
                        sysutil.disable_duplicate_address_detection(hop_info.indev)
                        flags = IFA_F_NODAD | IFA_F_NOPREFIXROUTE
                    ip.addr('add', index=infd, address=str(netinfo.network_address + 2),
                            prefixlen=netinfo.prefixlen, flags=flags)
                    if netinfo.network_address.version == 6:
                        # If an exception is thrown here, the DAD issue is still not properly fixed.
                        ip.route('add', oif=infd, dst=str(netinfo), prefsrc=str(netinfo.network_address + 2),
                                 family=socket.AF_INET6)
                self._create_loopback(ip)

        hop_info.netns.run(run_in_new_netns)

    def _build_main_bridge(self, hop_info: hops.HopInfo,
                           nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                           chain_length: int):
        logging.debug('Building bridge: main netns <-> %s (%s)' % (hop_info.netns.name, nets))

        bridge_name_in = self._bridge.name if self._bridge.name is not None else self.iface_id(2 * chain_length + 1)
        bridge_name_out = self.iface_id(2 * chain_length)

        infd, outfd = create_bridge(bridge_name_in, bridge_name_out, NetworkNamespace.default, hop_info.netns,
                                    debug=self.profile.debug)

        def run_in_hop_netns():
            logging.debug('Setup bridge masquerading: %s' % str(nets))
            for n in nets:
                masquerade_interface_networks(outfd, n, bridge_name_in, bridge_name_in)

            if self._bridge.dhcp:
                # TODO: Transform for fork support.
                dns = resolvconf.parse()
                dhcp_server = dhcpd.DHCPServer(nets, bridge_name_out, dns=dns)
                dhcp_server.start()

                self._revert(dhcp_server.stop)

        hop_info.netns.run(run_in_hop_netns)

        routes = self._bridge.routes
        if isinstance(routes, str):
            routes = [r.strip() for r in routes.split(',') if r.strip() != '']
        routes = [ipaddress.ip_network(r) for r in routes]

        routing_tables = {
            4: util.get_unused_routing_table(4),
            6: util.get_unused_routing_table(6)
        }

        fwmark = util.FWMARK_DEFAULT
        output_chain = 'pallium.' + hop_info.outdev + '.output'
        postrouting_chain = 'pallium.' + hop_info.outdev + '.postrouting'

        def rule_helper(ipr, method):
            versions_created = set()
            for r in routes:
                if r.version in versions_created:
                    continue
                ipr.rule(method, fwmark=fwmark, table=routing_tables[r.version],
                         family=nftables.family_from_version(r.version))
                versions_created.add(r.version)

        with IPRoute() as ip:
            indev = ip.link_lookup(ifname=bridge_name_in)[0]
            for net in nets:
                ip.addr('add', index=indev, address=str(net.network_address + 2),
                        prefixlen=net.prefixlen)

            if len(routes) > 0:
                @self._revert
                def revert_ip_rule():
                    with IPRoute() as ipr:
                        rule_helper(ipr, 'del')

                rule_helper(ip, 'add')

            @self._revert
            def revert():
                with NFTables(nfgen_family=NFPROTO_INET) as nft2:
                    nft2.chain('del', table='pallium', name=output_chain, flags=0)
                    nft2.chain('del', table='pallium', name=postrouting_chain, flags=0)

            for net in nets:
                with NFTables(nfgen_family=NFPROTO_INET) as nft:
                    nft.table('add', name='pallium')
                    nft.chain('add', table='pallium', name=postrouting_chain, type='nat', hook='postrouting',
                              priority=100, policy=1)
                    nft.rule('add', table='pallium', chain=postrouting_chain, expressions=(
                        nftables.meta.oifname(bridge_name_in),
                        nftables.snat(to=net.network_address + 2)
                    ))

            for route in routes:
                with NFTables(nfgen_family=NFPROTO_INET) as nft:
                    nft.table('add', name='pallium')
                    nft.chain('add', table='pallium', name=output_chain, type='route', hook='output', priority=-150,
                              policy=1)

                    if self._bridge.reserved_bypass:
                        # TODO: Implement IP sets for better performance.
                        for network in util.RESERVED_IPV4_ADDRS + util.RESERVED_IPV6_ADDRS:
                            nft.rule('add', table='pallium', chain=output_chain, expressions=(
                                nftables.ip(daddr=network),
                                nftables.ret()
                            ))

                    nft.rule('add', table='pallium', chain=output_chain, expressions=(
                        nftables.ip(daddr=route),
                        nftables.meta.mark(set=fwmark)
                    ))
                for net in nets:
                    if net.version != route.version:
                        continue
                    ip.route('add', dst=str(route), oif=indev, gateway=str(net.network_address + 1),
                             table=routing_tables[route.version], family=nftables.family_from_version(route.version))

            if self._bridge.eth_bridge is not None:
                br = self._bridge.eth_bridge
                ifname = br.name
                if ifname is None:
                    ifname = self.iface_id(2 * chain_length + 2)
                    self._bridge.eth_bridge.name = ifname

                try:
                    ip.link('add', ifname=ifname, kind='bridge')
                    br_fd = ip.link_lookup(ifname=ifname)[0]
                    ip.link('set', index=br_fd, state='up')
                except NetlinkError as e:
                    if e.code == errno.EEXIST:
                        raise DuplicateBridgeException("An interface named \"%s\" already exists." % ifname)
                    raise

                @self._revert
                def delete_eth_bridges():
                    if self._bridge.eth_bridge is not None:
                        with IPRoute() as ip2:
                            ip2.link('set', ifname=self._bridge.eth_bridge.name, state='down')
                        delete_link(self._bridge.eth_bridge.name)

                for dev in br.devices + [bridge_name_in]:
                    try:
                        dev_fd = ip.link_lookup(ifname=dev)[0]
                    except IndexError:
                        raise InterfaceNotFoundException("The interface named \"%s\" was not found." % dev)
                    ip.link('set', index=dev_fd, state='up')
                    ip.link('set', index=dev_fd, master=br_fd)

    def _create_pid_file(self):
        def opener(path, flags):
            return os.open(path, flags, 0o200)

        state_file = os.path.join(self.session_folder, 'pid')
        with open(state_file, 'w', opener=opener) as f:
            f.write(str(self._owner))
        os.chmod(state_file, 0o600)

    def _serialize_to_file(self):
        def opener(path, flags):
            return os.open(path, flags, 0o200)

        state_file = os.path.join(self.session_folder, 'state')
        with open(state_file, 'w', opener=opener) as f:
            f.write(json.dumps({
                'pid': self._owner,
                'pseudo_path': self.profile.pseudo_path,
                'chain': [{
                    'netns': {
                        'etc': h.info.netns.etc_path,
                        'fd': h.info.netns.fd_path
                    }
                } for h in self._effective_chain]
            }))
        os.chmod(state_file, 0o600)

    def _connect(self):
        """
        Build the network connection chain.

        @return: None.
        """
        self._first_ns = NetworkNamespace.identify()

        if runtime.use_slirp4netns():
            dummy = DummyHop()
            dummy.dns_servers = hops.hop.DnsOverlay()
            dummy.providing_routes = runtime.DEFAULT_DESTINATIONS.copy()
            self._profile.chain = [dummy, *self._profile.chain]
        else:
            self._enable_ip_forwarding(allow_interfaces=[self.iface_id(0)])

        previous_hop_info = hops.HopInfo([], self._first_ns, self.iface_id(0), None, None)
        self._effective_chain = chain = self._profile.chain.copy()
        self._forwarding_exceptions = []
        hop_index = 0
        while hop_index < len(chain):
            hop = chain[hop_index]
            hop_ns_count = 0
            self._hops.append(hop)

            network_namespace = self._new_netns(hop_index)

            outdev = self.iface_id(2 * hop_index)
            indev = self.iface_id(2 * hop_index + 1)
            hop_info = hops.HopInfo(self._current_network, network_namespace, indev, outdev, hop, previous_hop_info)
            hop.info = hop_info

            if hop.info.previous.hop is not None and isinstance(hop_info.previous.hop.dns_servers, hops.hop.DnsOverlay):
                # The previous hop indicates that its resolv.conf is to be exported to the next hop
                hop_info.netns.custom_etc_path = hop_info.previous.hop.info.netns.etc_path

            self._setup_namespace(hop_info)

            if hop_info.previous.hop is not None:
                hop_info.previous.hop.before_next_connect(hop_info)
            hop.before_connect()

            # noinspection PyShadowingNames
            def run_in_netns():
                # IPv6 forwarding does not carry over to the namespaces. Re-enable forwarding in each namespace.
                sysutil.ip_forward(4, True)
                sysutil.ip_forward(6, True)

                if not security.is_sudo_or_root():
                    sysutil.enable_ping()  # TODO: Make this configurable by the user.
                netns_results = hop.connect()
                next_network_ipv4 = util.find_unused_private_network(4, already_used=self.profile.netpool.used)
                next_network_ipv6 = util.find_unused_private_network(6, already_used=self.profile.netpool.used)
                return netns_results, next_network_ipv4, next_network_ipv6

            netns_results, next_network_ipv4, next_network_ipv6 = hop_info.netns.run(run_in_netns)
            hop.handle_connect_results(netns_results)

            self.profile.netpool.add_used([next_network_ipv4, next_network_ipv6])

            self._forwarding_exceptions.extend(hop.port_forwards)

            previous_hop_info = hop_info
            self._current_network = [next_network_ipv4, next_network_ipv6]
            hop_ns_count += 1

            hop_index += 1
            next_hop = hop.next_hop()
            if next_hop is not None:
                chain.insert(hop_index, next_hop)

            is_last = next_hop is None and hop_index >= len(chain)

            self.finalize_setup(hop_info, is_last)

            if hop_index == len(chain) and self._bridge is not None:
                self._build_main_bridge(previous_hop_info, self._current_network, len(chain))

            if hop_index == len(chain):
                self._serialize_to_file()
                hop.info.netns.mounts = self._mounts

                def mnt():
                    for mount in self._mounts:
                        mount.mount()

                hop_info.netns.run(mnt)

            hop.connected()

    def iface_id(self, index):
        return 'pm' + base64.urlsafe_b64encode(self.hash_id.digest()[0:6]).decode('ascii') + '%d' % index

    @property
    def profile(self):
        return self._profile

    def _new_netns(self, index):
        etc_path = os.path.join(self.session_folder, 'netns', 'etc', str(index))
        fd_path = os.path.join(self.session_folder, 'netns', 'fds', str(index))
        pid_path = os.path.join(self.session_folder, 'netns', 'pids', str(index))
        if not os.path.exists(etc_path):
            os.mkdir(etc_path, 0o755)
        shutil.copyfile('/etc/resolv.conf', os.path.join(etc_path, 'resolv.conf'))
        return NetworkNamespace(fd_path, etc_path, pid_path=pid_path)

    def run(self, *args, **kwargs):
        assert self.profile.sandbox is not None
        return self.profile.sandbox.run(self, *args, **kwargs)

    def close(self):
        """
        Free all resources occupied by the session. This includes network devices, processes and temporary files.

        @return: None.
        """
        if self._owner != os.getpid():
            return
        if self._freed:
            return
        self._freed = True

        logging.debug('Freeing profile %s, pid=%d' % (repr(self), os.getpid()))

        for hop in self._hops:
            hop.free()

        for i, func in enumerate(self._revert_functions):
            # Cleaning up. We do not want one failure to hinder the entire cleanup procedure.
            # noinspection PyBroadException
            try:
                func()
            except BaseException:
                traceback.print_exc()

        # noinspection PyProtectedMember
        self._profile._run_postexec_fn()

        shutil.rmtree(self.session_folder)

        # Only remove the profile folder if it is empty (other sessions might be running)
        try:
            os.rmdir(self.profile.profile_folder)
        except OSError as e:
            if e.errno != errno.ENOTEMPTY:
                raise

        logging.debug('Profile freed %s, pid=%d' % (repr(self), os.getpid()))
