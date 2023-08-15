import os
from typing import List, Union, Optional

from . import hop

SCRIPT_PATH = '/etc/pallium/scripts'


class ScriptHop(hop.Hop):
    """
    A generic hop that runs a script inside its namespace upon connecting.
    """
    def __init__(self, path: Union[str, List[str]], **kwargs):
        """
        Initialize the hop.

        @param path: Path to the script to be run.
        @param kwargs: Any additional keyword arguments are passed to the script as environment variables.
        """
        super(ScriptHop, self).__init__()
        if isinstance(path, str):
            path = [path]
        self.path = path
        self.environ = os.environ.copy()
        self.required_routes = hop.DEFAULT_ROUTES
        self.interface = kwargs.get('interface', 'tun0')
        for key, value in kwargs.items():
            self.environ['PALLIUM_SCRIPT_' + key.upper()] = value

        # The resolv.conf file of this namespace is exported to the next namespace
        self.dns_servers = hop.DnsOverlay()

    def connect(self):
        super().connect()
        self.pcall(self.path, env=self.environ)

    @property
    def kill_switch_device(self) -> Optional[str]:
        return self.interface
