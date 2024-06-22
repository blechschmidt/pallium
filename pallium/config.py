# Not in use yet
import copy
import dataclasses
import ipaddress
import os
import shutil
import types

import typing

from . import typeinfo, hops
from .exceptions import ConfigurationError
from .sandbox import Sandbox

_T = typing.TypeVar('_T')
_primitive_types = [int, bool, str, float]


def json_deserializable(*, transform: typing.Optional[typing.Callable] = None) -> typing.Type[_T]:
    """
    Function that returns a decorator for classes that can be deserialized from JSON.

    @param transform: A function transforming the supplied JSON data before deserialization.
    @return: The decorator.
    """
    def real_decorator(cls: typing.Type[_T]) -> typing.Type[_T]:
        """
        There are libs for this type of functionality, but we want to keep
        dependencies low for security reasons.
        """

        def json_value_to_instance(value, tp=None):
            assert tp is not None, "Implementation requires type hinting."

            if tp == types.NoneType:
                if value is not None:
                    raise ConfigurationError('Expected None')
                return None

            if typing.get_origin(tp) == typing.Union:
                for t in typing.get_args(tp):
                    try:
                        return json_value_to_instance(value, t)
                    except ConfigurationError:
                        pass
                raise ConfigurationError('No type in Union matched')

            if typing.get_origin(tp) == typing.Optional:
                if value is None:
                    return None
                # Unpack optional type
                tp = typing.get_args(tp)[0]

            if typing.get_origin(tp) == typing.Any:
                return value

            if tp in tuple(_primitive_types):
                if not isinstance(value, tp):
                    raise ConfigurationError('Expected a %s' % tp)
                return value

            if typing.get_origin(tp) == list:
                if not isinstance(value, list):
                    raise ConfigurationError('Expected a list')
                return [json_value_to_instance(v, typing.get_args(tp)[0]) for v in value]

            if not isinstance(value, dict):
                raise ConfigurationError('Complex classes need to be deserialized from dict')

            if hasattr(tp, 'from_json') and callable(tp.from_json):
                return tp.from_json(value)

            return from_json(tp, value)

        def from_json(cls, json_data: typing.Dict[str, typing.Any]) -> _T:
            """
            This is the method to be added to the class to deserialize it from JSON.

            @param cls: The class wrapped by the decorator.
            @param json_data: The JSON data to deserialize.
            @return: The deserialized instance.
            """

            json_data = json_data if transform is None else transform(json_data)

            constructor = {}
            for key, value in json_data.items():
                if key not in cls.__annotations__:
                    continue
                attr_type = cls.__annotations__[key]
                instance = json_value_to_instance(value, attr_type)
                constructor[key] = instance
            instance = cls(**constructor)

            return instance

        if not hasattr(cls, 'from_json'):
            setattr(cls, 'from_json', classmethod(from_json))
        return cls

    return real_decorator


class EthernetBridge:
    def __init__(self, devices: typing.List[str], name: typing.Optional[str] = None):
        self.name = name
        self.devices = devices

    @classmethod
    def from_json(cls, obj):
        return cls(**obj)


class Bridge:
    def __init__(self, name: typing.Optional[str] = None,
                 routes: typing.List[typing.Union[ipaddress.ip_network, str]] = None,
                 dhcp: bool = False,
                 eth_bridge: typing.Optional[EthernetBridge] = None,
                 reserved_bypass: bool = True):
        """
        A descriptor for building a bridge inside the main network namespace.

        @param name: Bridge name. If unspecified, an automatically generated deterministic name is used.
        @param routes: IP networks that should pass through the bridge.
        @param dhcp: Whether a DHCP server should be started, providing clients with IP addresses.
        @param eth_bridge: TODO.
        @param reserved_bypass: Whether reserved addresses bypass the bridge.
        """
        if routes is None:
            routes = []
        routes = list(map(ipaddress.ip_network, routes))
        self.name = name
        self.routes = routes
        self.dhcp = dhcp
        self.eth_bridge = eth_bridge
        self.reserved_bypass = reserved_bypass

    @classmethod
    def from_json(cls, obj):
        if 'eth_bridge' in obj:
            obj['eth_bridge'] = EthernetBridge.from_json(obj['eth_bridge'])
        return cls(**obj)


@json_deserializable()
class LocalPortForwarding:
    protocol: str  # Either "tcp" or "udp"
    host: typing.Tuple[typeinfo.IPAddress, int]
    guest: typing.Tuple[typeinfo.IPAddress, int]

    def __init__(self, spec):
        scheme, rest = spec.split('://', 1)
        self.protocol = scheme.lower()

        if self.protocol not in {'udp', 'tcp'}:
            raise ConfigurationError('The scheme of the port forwarding %s is not either tcp or udp' % scheme)

        # TODO: Add IPv6 support.
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


@json_deserializable()
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


def default_command():
    shell = os.environ.get('SHELL', '/usr/bin/sh')
    return [shell]


@json_deserializable()
@dataclasses.dataclass
class Run:
    command: typing.Optional[typing.Union[typing.List[str], str]] = dataclasses.field(default_factory=default_command)
    quiet: bool = dataclasses.field(default=False)  # Whether to suppress status information of pallium and its helpers


@json_deserializable()
@dataclasses.dataclass
class Network:
    port_forwarding: PortForwarding = dataclasses.field(default_factory=PortForwarding)
    chain: typing.List[hops.Hop] = dataclasses.field(default_factory=list)
    bridge: typing.Optional[Bridge] = dataclasses.field(default=None)
    routes: typing.Optional[typing.List[str]] = dataclasses.field(default=None)
    kill_switch: bool = dataclasses.field(default=True)


def _allow_direct_chain_specification(obj):
    """
    In some parts of the documentation, we still allow the chain property to be specified directly, not being part of
    the network property. This function transforms the object to the correct format.

    @param obj: The object to be deserialized.
    @return: The transformed object.
    """
    obj = copy.deepcopy(obj)
    if 'chain' in obj:
        if 'network' in obj:
            raise ConfigurationError('network and chain properties cannot be specified at the same time')
        obj['network'] = {
            'chain': obj['chain']
        }
    return obj


@json_deserializable(transform=_allow_direct_chain_specification)
@dataclasses.dataclass
class Configuration:
    network: Network = dataclasses.field(default_factory=Network)
    sandbox: Sandbox = dataclasses.field(default_factory=Sandbox)
    run: Run = dataclasses.field(default_factory=Run)
