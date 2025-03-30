import copy
import ipaddress
import os
import shutil
import signal
import subprocess
import traceback

from pyroute2.iproute import IPRoute

from . import sysutil, util
from . import netns
from . import config


class Slirp:
    def __init__(self, configuration: config.Configuration, hop_info, quiet=False):
        self.port_forwarding = configuration.network.port_forwarding
        self.hop_info = hop_info
        self.quiet = quiet

    def prepare(self):
        pass

    def start(self):
        """
        Start the slirp4netns process.

        @return: A function that is to be called to free the resources from the start operation.
        """
        raise NotImplementedError()


def available_slirp_class():
    """


    @return: A class (not instance!) for the instantiation of a concrete slirp implementation.
    """
    if shutil.which(util.get_tool_path('slirpnetstack')):
        return SlirpNetstack
    if shutil.which(util.get_tool_path('slirp4netns')):
        return Slirp4Netns
    raise FileNotFoundError("Failed to find slirpnetstack or slirp4netns")


class Slirp4Netns(Slirp):
    def __init__(self, configuration: config.Configuration, hop_info, quiet=False):
        if len (configuration.network.port_forwarding.local) > 0:
            raise NotImplementedError('Slirp4netns does not support port forwarding. Use slirpnetstack instead.')
        super().__init__(configuration, hop_info, quiet)

    def start(self):
        hop_info = self.hop_info
        kwargs = {}
        if self.quiet:
            kwargs = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
            }
        read_fd, write_fd = os.pipe()
        p = util.popen([util.get_tool_path('slirp4netns'), '-6',
                        '--disable-host-loopback',
                        '-c', str(hop_info.netns.pid),
                        '-r', str(write_fd),
                        hop_info.indev],
                       pass_fds=[write_fd],
                       start_new_session=True,
                       preexec_fn=lambda: sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL),
                       **kwargs)
        os.read(read_fd, 1)

        def terminate():
            p.terminate()
            p.wait()

        return terminate


class SlirpNetstack(Slirp):
    def prepare(self):
        hop_info = self.hop_info
        with IPRoute() as ip:
            ip.link("add",
                    ifname=hop_info.indev,
                    kind="tuntap",
                    mode="tap")
            ip.link('set', ifname=hop_info.indev, mtu=65521)
            ip.link('set', ifname=hop_info.indev, state='up')
            fd = ip.link_lookup(ifname=hop_info.indev)[0]
            # TODO: Do not hardcode.
            # But this is currently a requirement documented at https://github.com/cloudflare/slirpnetstack.
            ip.addr('add', index=fd, address='10.0.2.100', prefixlen=24)
            ip.addr('add', index=fd, address='fd00::100', prefixlen=64)
            ip.route('add', index=fd, dst='0.0.0.0/0', gateway='10.0.2.2')
            # TODO: Add IPv6 route

    def start(self):
        hop_info = self.hop_info
        kwargs = {}
        if self.quiet:
            kwargs = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
            }

        def preexec_fn():
            try:
                if os.getuid() != 0:
                    # Slirpnetstack does not automatically join the destination
                    # user namespace. So we need to do it ourselves.
                    netns.join_namespace(sysutil.CLONE_NEWUSER, hop_info.netns.pid)
            except:
                traceback.print_exc()
                raise

            sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL)

        local_fwd = self.port_forwardings_to_args()

        p = util.popen([util.get_tool_path('slirpnetstack'),
                        '--interface', hop_info.indev,
                        '--netns', '/proc/%d/ns/net' % hop_info.netns.pid,
                        '--allow', 'tcp://0.0.0.0/0:0-65535',
                        '--allow', 'udp://0.0.0.0/0:0-65535',
                        '--allow', 'tcp://[::]/0:0-65535',
                        '--allow', 'udp://[::]/0:0-65535'] + local_fwd,
                       pass_fds=[],
                       start_new_session=True,
                       preexec_fn=preexec_fn,
                       **kwargs)

        # TODO: Implement FD write like in slirp4netns.
        import time
        time.sleep(1)

        def terminate():
            p.terminate()
            p.wait()

        return terminate

    def port_forwardings_to_args(self):
        result = []
        if self.port_forwarding is not None:
            for port, fwd in enumerate(self.port_forwarding.local):
                fwd_copy = copy.deepcopy(fwd)

                # IP address assigned to slirpnetstack interface. See https://github.com/cloudflare/slirpnetstack.
                fwd_copy.guest = (ipaddress.ip_address('10.0.2.100'), port + 1)
                assert port + 1 <= 0xffff, "Not more than 65534 local port forwardings supported"
                result.extend(['-L', str(fwd_copy)])
        return result

