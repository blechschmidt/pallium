import os
import shutil
import signal
import subprocess
import traceback

from pyroute2.iproute import IPRoute

from . import sysutil, util
from . import netns


class Slirp:
    def __init__(self, hop_info, quiet=False, port_forwardings=None):
        if port_forwardings is None:
            port_forwardings = []
        self.port_forwardings = port_forwardings
        self.hop_info = hop_info
        self.quiet = quiet

    def prepare(self):
        pass

    def start(self):
        """
        Start the slirp4netns process.

        @param hop_info:
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
                # Slirpnetstack does not automatically join the destination
                # user namespace. So we need to do it ourselves.
                netns.join_namespace(sysutil.CLONE_NEWUSER, hop_info.netns.pid)
            except:
                traceback.print_exc()
                raise

            sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL)

        local_fwd = []
        for fwd in self.port_forwardings:
            local_fwd.extend(['-L', str(fwd)])
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
