# Not in use yet
import dataclasses
import ipaddress

import typing

from pallium import typeinfo
from pallium.exceptions import ConfigurationError
from pallium.sandbox import Sandbox


class FromJSON:
    @classmethod
    def from_json(cls, obj):
        pass


class LocalPortForwarding:
    protocol: str  # Either "tcp" or "udp"
    host: (typeinfo.IPAddress, int)
    guest: (typeinfo.IPAddress, int)

    def __init__(self, spec):
        scheme, rest = spec.split('://', 1)
        self.protocol = scheme.lower()

        if self.protocol not in {'udp', 'tcp'}:
            raise ConfigurationError('The scheme of the port forwarding %s is not either tcp or udp' % scheme)

        components = rest.split(':')
        if len(components) != 4:
            raise ConfigurationError('Port forwarding expected to have the following scheme: '
                                     '<udp|tcp>://<bind_host_ip>:<bind_host_port>:<guest_ip>:<guest_port>')

        host_ip = ipaddress.ip_address(components[0])
        host_port = int(components[1])
        self.host = (host_ip, host_port)

        # Requirement from slirpnetstack. See slirp.py.
        guest_ip = ipaddress.ip_address(components[2])
        guest_port = int(components[3])
        self.guest = (guest_ip, guest_port)

    def __str__(self):
        # noinspection PyStringFormat
        return '%s://%s:%s:%s:%s' % (self.protocol, *self.host, *self.guest)

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, str):
            raise ConfigurationError('Local forwarding must be of type string')
        return cls(obj)


@dataclasses.dataclass
class PortForwarding:
    local: typing.List[LocalPortForwarding] = dataclasses.field(default_factory=list)

    @classmethod
    def from_json(cls, obj):
        if not isinstance(obj, dict):
            raise ConfigurationError('Port forwarding configuration must be an object')
        local = obj.get('local', [])
        if not isinstance(local, list):
            raise ConfigurationError('Local port forwardings must be a list')
        local = list(map(LocalPortForwarding.from_json, local))
        result = cls(local)
        return result


@dataclasses.dataclass
class Networking:
    port_forwarding: PortForwarding = dataclasses.field(default_factory=PortForwarding)


@dataclasses.dataclass
class Configuration:
    networking: Networking = dataclasses.field(default_factory=Networking)
    sandbox: Sandbox = None
