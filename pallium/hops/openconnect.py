from . import hop
from .. import util


class OpenConnectHop(hop.Hop):
    def __init__(self, protocol, username=None, password=None):
        super().__init__()
        self.username = username
        self.password = password
        self.protocol = protocol

    def connect(self):
        util.proc_call(['openconnect'])
        pass
