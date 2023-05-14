import ipaddress
import os
import platform

from . import security
from . import util

APP_NAME = 'pallium'
RUN_DIR = '/run'
if security.is_sudo_or_root():
    APP_RUN_DIR = os.path.join(RUN_DIR, APP_NAME)
else:
    USER_RUN_DIR = os.environ.get('XDG_RUNTIME_DIR', os.path.join(RUN_DIR, 'user', str(security.real_user())))
    if not os.path.isdir(USER_RUN_DIR):
        USER_RUN_DIR = '/dev/shm'
    APP_RUN_DIR = os.path.join(USER_RUN_DIR, 'pallium')

if security.is_sudo_or_root():
    BASE_DIR = '/etc/pallium'
else:
    BASE_DIR = os.path.join(os.environ['HOME'], '.config', 'pallium')

PROFILE_DIR = os.path.join(BASE_DIR, 'profiles')
VIRTUSER_DIR = os.path.join(BASE_DIR, 'virtuser')

IP_PROTO_SUPPORTED = {
    4: util.ip_proto_supported(4),
    6: util.ip_proto_supported(6)
}

DEFAULT_DESTINATIONS = []

if IP_PROTO_SUPPORTED[4]:
    DEFAULT_DESTINATIONS.append(ipaddress.ip_network('0.0.0.0/0'))

if IP_PROTO_SUPPORTED[6]:
    DEFAULT_DESTINATIONS.append(ipaddress.ip_network('::/0'))


def is_wsl2():
    return 'wsl2' in platform.uname().release.lower().split('-')


def use_slirp4netns():
    return not security.is_sudo_or_root()


def ip_proto_supported_default(version):
    """
    Determine whether an IP protocol is generally supported in the default network namespace.

    @param version: IP version. Either 4 or 6.
    @return: True or false if there is a (pseudo) default route for the protocol.
    """
    return IP_PROTO_SUPPORTED[version]


def has_net_caps():
    # TODO: Check whether we have CAP_NET_ADMIN and CAP_NET_RAW capabilities.
    return False
