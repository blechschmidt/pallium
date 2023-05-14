import ipaddress
from typing import Optional

from . import hop


class DummyHop(hop.Hop):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.required_routes = [ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')]

    def before_connect(self):
        if self.info.previous.hop is not None:
            self.dns_servers = self.info.previous.hop.dns_servers
            self.dns_overridden = self.info.previous.hop.dns_overridden

    @property
    def kill_switch_device(self) -> Optional[str]:
        return None
