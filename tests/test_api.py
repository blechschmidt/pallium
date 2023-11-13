import ipaddress
import json
import logging
import os
import secrets
import string
import subprocess
import tempfile
import time
import unittest
import warnings

import dotenv
import requests
from pyroute2.iproute import IPRoute

import pallium.hops.tor
from pallium import netns
from pallium import security, runtime, sysutil, filesystem
from pallium.hops.hop import DnsTcpProxy
from pallium.hops.tor import TorHop
from pallium.nftables import NFTables, NFPROTO_INET
from pallium.profiles import Profile
from provision import DigitalOceanProvisioner, Machine


class PalliumTestCase(unittest.TestCase):
    """We ignore resource warnings because they include warnings about unterminated but desired background processes
    inside forks."""
    _first = True

    def setUp(self):
        # print('RUNNING TEST: %s' % self._testMethodName)
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", DeprecationWarning)

    def tearDown(self):
        warnings.simplefilter("default", ResourceWarning)


class TestException(Exception):
    pass


class TestMachine:
    def __init__(self, ip):
        pass

    def get_public_ips(self):
        pass


class TestPythonInterface(PalliumTestCase):
    machines = []
    provisioner = None
    ovpn_config_file = None
    password = None

    @classmethod
    def setUpClass(cls):
        dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

        if os.environ.get('PALLIUM_TEST_PROVISIONER', '').lower() == 'digitalocean':
            cls.password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))

            with warnings.catch_warnings():
                warnings.simplefilter('ignore', category=ResourceWarning)
                cls.provisioner = DigitalOceanProvisioner()
                logging.getLogger(__name__).info('Provisioning machine ...')
                machine = cls.provisioner.provision()

            logging.getLogger(__name__).info('Installing OpenVPN ...')
            ovpn_config = machine.install_openvpn()
            cls.ovpn_config_file = tempfile.mktemp()
            with open(cls.ovpn_config_file, 'wb') as f:
                f.write(ovpn_config)

            logging.getLogger(__name__).info('Installing Dante ...')
            machine.install_dante(cls.password)

            logging.getLogger(__name__).info('Installing Squid ...')
            machine.install_squid(cls.password)

            cls.machines.append(machine)
            logging.getLogger(__name__).info('Running tests ...')
        else:
            cls.password = os.environ.get('PALLIUM_TEST_PASSWORD')
            ips = [os.environ.get('PALLIUM_TEST_SERVER_IPV4'), os.environ.get('PALLIUM_TEST_SERVER_IPV6')]
            ips = [ip for ip in ips if ip is not None]
            cls.machines = [Machine(ips)]

            ovpn_config = os.environ.get('PALLIUM_TEST_OPENVPN_CERT', '').encode()
            cls.ovpn_config_file = tempfile.mktemp()
            with open(cls.ovpn_config_file, 'wb') as f:
                f.write(ovpn_config)

    @classmethod
    def tearDownClass(cls) -> None:
        for machine in cls.machines:
            machine.destroy()

    @classmethod
    def require_net_admin(cls):
        if not security.is_sudo_or_root() and not runtime.has_net_caps():
            raise unittest.SkipTest('Test requires root permissions or CAP_NET_RAW and CAP_NET_ADMIN')

    @staticmethod
    def get_ip(version=None):
        """provider = 'https://%swtfismyip.com/text'
        prefix = {
            None: '',
            4: 'ipv4.',
            6: 'ipv6.'
        }[version]"""
        provider = 'https://%sipify.org'
        prefix = {
            None: 'api64.',
            4: 'api4.',
            6: 'api6.'
        }[version]
        result = requests.get(provider % prefix).text.strip()
        return result

    def get_ipv4(self):
        return self.get_ip(4)

    def get_ipv6(self):
        return self.get_ip(6)

    def test_pyroute(self):
        def run_in_ns():
            nft_ruleset = subprocess.check_output(['nft', 'list', 'ruleset'])
            assert b'pyroute_nftables_test' not in nft_ruleset

            with NFTables(nfgen_family=NFPROTO_INET) as nft:
                nft.table('add', name='pyroute_nftables_test')

            nft_ruleset = subprocess.check_output(['nft', 'list', 'ruleset'])
            assert b'pyroute_nftables_test' in nft_ruleset

            with NFTables(nfgen_family=NFPROTO_INET) as nft:
                nft.table('del', name='pyroute_nftables_test')

        with Profile([]) as session:
            session.execute(run_in_ns)

    def test_no_chain_no_dns(self):
        def run_in_ns():
            return requests.get('https://1.1.1.1').text

        with Profile([]) as session:
            result = session.execute(run_in_ns)
        assert 'Cloudflare' in result

    def test_no_chain(self):
        """
        This test should always work if there is internet connectivity.

        If this test does not work, there is a deeper issue, e.g. the routing setup may have failed.
        """

        def run_in_ns():
            return self.get_ip()

        with Profile([]) as session:
            result = session.execute(run_in_ns)
        ipaddress.ip_address(result)
        assert True

    def test_tor_simple(self):
        """
        Connect to an IP address API using Tor and check whether the exit IP is a Tor node.
        """

        def check_tor():
            return requests.get('https://check.torproject.org/api/ip').json()

        with Profile([TorHop()]) as session:
            result = session.execute(check_tor)
        assert result['IsTor']

    def test_tor_onion_url(self):
        onion_urls = [
            'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion',  # Tor project
            'http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion',  # Facebook
            'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',  # DuckDuckGo
        ]

        def check_tor():
            # Tor is slow and onion services are frequently unreliable. This is not our fault.
            # Therefore, we try multiple URLs. At least one of them should be up.
            for url in onion_urls:
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        return True
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    continue
            return False

        with Profile([TorHop()]) as session:
            assert session.execute(check_tor)

    def _test_ssh_url(self, url, dns=None):
        machine = self.machines[0]

        def check_connectivity():
            return requests.get(url).text

        # We are seeing this server for the first time
        ssh_args = ['-o', 'StrictHostKeyChecking=no']
        with Profile([pallium.hops.ssh.SshHop(machine.get_ssh_destination(), ssh_args=ssh_args, dns=dns)],
                     quiet=True) as session:
            result = session.execute(check_connectivity)

        return result

    def test_ssh_no_dns(self):
        result = self._test_ssh_url('https://1.1.1.1')
        assert 'Cloudflare' in result

    def test_ssh_dns(self):
        result = json.loads(self._test_ssh_url('https://check.torproject.org/api/ip', dns=[DnsTcpProxy('1.1.1.1')]))
        assert ipaddress.ip_address(result['IP']) in self.machines[0].get_public_ips()

    def test_openvpn(self):
        with Profile([pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]) as session:
            result = session.execute(self.get_ip)
        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_openvpn_ipv6(self):
        with Profile([pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]) as session:
            result = session.execute(self.get_ipv6)

        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_tor_openvpn_ipv4(self):
        with Profile([TorHop(), pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]) as session:
            result = session.execute(self.get_ipv4)

        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_socks5_dns_udp(self):
        machine_ip = self.machines[0].get_public_ips()[0]
        socks5 = pallium.hops.socks.SocksHop((machine_ip, 1080), 'pmtest', self.password, dns=['1.1.1.1'])
        with Profile([socks5]) as session:
            result = session.execute(self.get_ip)
        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_http_no_dns(self):
        def check_connectivity():
            return requests.get('https://1.1.1.1').text

        machine_ip = self.machines[0].get_public_ips()[0]
        http = pallium.hops.socks.HttpHop((machine_ip, 3128), 'pmtest', self.password)
        with Profile([http]) as session:
            result = session.execute(check_connectivity)
        assert 'Cloudflare' in result

    def test_exception(self):
        def run():
            raise TestException

        with Profile([]) as session:
            try:
                session.execute(run)
                assert False
            except TestException:
                pass

    def test_openvpn_custom_dns_resolv_conf(self):
        def inside_ns():
            with open('/etc/resolv.conf') as f:
                return f.read()

        with Profile([pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file, dns=['1.2.3.4'])]) as session:
            result = session.execute(inside_ns)
            assert '1.2.3.4' in result

    def test_bridge_ipv4(self):
        self.require_net_admin()
        chain = [pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]
        bridge = pallium.profiles.Bridge(routes=['0.0.0.0/0'])
        bridge.dhcp = False
        with Profile(chain, bridge=bridge) as session:
            result = session.execute(lambda: self.get_ip(4))
        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_bridge_ipv6(self):
        self.require_net_admin()
        chain = [pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]
        bridge = pallium.profiles.Bridge(routes=['::/0'])
        bridge.dhcp = False
        with Profile(chain, bridge=bridge) as session:
            result = session.execute(lambda: self.get_ip(6))
        assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

    def test_openvpn_ipv4_route_only(self):
        def inside_ns():
            result = self.get_ip(4)
            assert ipaddress.ip_address(result) in self.machines[0].get_public_ips()

            raised = False
            try:
                self.get_ip(6)
            except requests.exceptions.ConnectionError:
                raised = True
            assert raised

        chain = [pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file)]
        with Profile(chain, routes=['0.0.0.0/0']) as session:
            session.execute(inside_ns)

    def test_bridge_dhcp(self):
        self._test_bridge_dhcp(False, False)

    def test_bridge_dhcp_dns(self):
        self._test_bridge_dhcp(True, False)

    """def test_bridge_eth(self):
        self._test_bridge_dhcp(False, True)"""

    def _test_bridge_dhcp(self, test_dns, test_eth_bridge):
        self.require_net_admin()
        dns = ['1.1.1.1'] if test_dns else None
        chain = [pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file, dns=dns)]
        if test_eth_bridge:
            bridge_name = None
        else:
            bridge_name = 'pmtestbri'
        bridge = pallium.profiles.Bridge(name=bridge_name)
        if test_eth_bridge:
            with IPRoute() as ip:
                ip.link('add', ifname='pmtestbri', kind='dummy')
            bridge.eth_bridge = pallium.profiles.EthernetBridge(devices=['pmtestbri'])
        bridge.dhcp = True
        try:
            with Profile(chain, bridge=bridge):
                read_from_child, write_to_parent = os.pipe()
                read_from_parent, write_to_child = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(read_from_child)
                    os.close(write_to_child)
                    sysutil.unshare(sysutil.CLONE_NEWNS | sysutil.CLONE_NEWNET | sysutil.CLONE_NEWPID)
                    pid2 = os.fork()
                    if pid2 == 0:
                        netns.MountInstruction('tmp', '/tmp', 'tmpfs').mount()
                        os.mkdir('/tmp/etc')
                        os.mkdir('/tmp/workdir')
                        filesystem.OverlayMount('/etc', '/tmp/etc', '/tmp/workdir').mount()
                        sysutil.write_blocking(write_to_parent, b'1')
                        sysutil.read_blocking(read_from_parent, 1)
                        subprocess.call(['dhclient', 'pmtestbri'])

                        # Due to duplicate address detection, the IP address can not be immediately assigned to a
                        # socket. Actually, the dhclient script should handle this.
                        # TODO: Investigate why it does not and implement a cleaner solution than sleep.
                        time.sleep(10)

                        sysutil.write_blocking(write_to_parent, ipaddress.ip_address(self.get_ipv4()).packed)
                        sysutil.write_blocking(write_to_parent, ipaddress.ip_address(self.get_ipv6()).packed)
                        os.close(read_from_parent)
                        os.close(write_to_parent)
                        sysutil.fork_exit(0)
                    else:
                        os.waitpid(pid2, 0)
                        sysutil.fork_exit(0)
                else:
                    os.close(write_to_parent)
                    os.close(read_from_parent)
                    sysutil.read_blocking(read_from_child, 1)
                    with IPRoute() as ip:
                        ip.link('set', ifname='pmtestbri', state='up', net_ns_pid=pid)
                    sysutil.write_blocking(write_to_child, b'1')
                    ipv4_addr = ipaddress.ip_address(sysutil.read_blocking(read_from_child, 4))
                    ipv6_addr = ipaddress.ip_address(sysutil.read_blocking(read_from_child, 16))
                    assert ipv4_addr in self.machines[0].get_public_ips()
                    assert ipv6_addr in self.machines[0].get_public_ips()
                    os.close(read_from_child)
                    os.close(write_to_child)
        finally:
            if test_eth_bridge:
                with IPRoute() as ip:
                    ip.link('del', ifname='pmtestbri')

    def test_openvpn_kill_switch(self):
        """
        Ensure that killing the OpenVPN process does not introduce a leak.

        This test first ensures that building an OpenVPN connection succeeds.
        Afterwards, a second connection is built and the OpenVPN process is killed,
        which should cause the connection to fail.

        """
        my_ip = ipaddress.ip_address(self.get_ipv4())
        ovpn_hop = pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file, dns=['1.1.1.1'])
        with Profile([ovpn_hop], kill_switch=False) as session:
            vpn_ip = ipaddress.ip_address(session.execute(self.get_ipv4))
            assert vpn_ip in self.machines[0].get_public_ips()

            # OpenVPN may be run inside a PID namespace, so we don't know its real PID.
            # Killing all OpenVPN instances is not nice, but it's probably good enough for a dirty test.
            # TODO: Cleaner solution.
            # os.kill(ovpn_hop.pid, signal.SIGINT)

            sysutil.killall('openvpn')
            try:
                os.waitpid(ovpn_hop.pid, 0)
            except OSError:
                pass
            bypass_vpn_ip = ipaddress.ip_address(session.execute(self.get_ipv4))
            assert my_ip == bypass_vpn_ip

        ovpn_hop = pallium.hops.openvpn.OpenVpnHop(config=self.ovpn_config_file, dns=['1.1.1.1'])
        with Profile([ovpn_hop]) as session:
            vpn_ip = ipaddress.ip_address(session.execute(self.get_ipv4))
            assert vpn_ip in self.machines[0].get_public_ips()

            # os.kill(ovpn_hop.pid, signal.SIGINT)
            sysutil.killall('openvpn')
            try:
                os.waitpid(ovpn_hop.pid, 0)
            except OSError:
                pass
            with self.assertRaises(requests.exceptions.ConnectionError):
                session.execute(self.get_ipv4)


if __name__ == '__main__':
    Profile.quiet = False
    """if os.getuid() != 0:
        sys.stderr.write('The tests need to be run as root.\n')
        sys.exit(1)"""
    # logging.basicConfig(level=logging.DEBUG)
    unittest.main()
