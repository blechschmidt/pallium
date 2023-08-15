from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Union, Tuple

IPNetworkLike = Union[str, IPv4Network, IPv6Network]
IPAddressLike = Union[str, IPv4Address, IPv6Address]
IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]
IPAddressRange = Union[IPNetwork, Tuple[IPAddress, IPAddress]]
