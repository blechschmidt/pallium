import os
from . import util
from datetime import datetime

DEBUG_DIR = '/tmp/pallium-debug-%s' % datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def create_dir():
    if not os.path.exists(DEBUG_DIR):
        os.mkdir(DEBUG_DIR)


def filename(name):
    return os.path.join(DEBUG_DIR, name)


def capture(iface):
    """
    Create a packet capture in the debug directory.

    When using this, make sure to wait a short time before having the profile go out of scope and tearing the interfaces
    down. Otherwise, the last packets may not be captured by tcpdump for some reason.

    @param iface: Name of the interface.
    @return: None
    """
    create_dir()
    util.popen(['tcpdump', '-i', iface, '-U', '-w', filename(iface + '.pcap')])
