#!/usr/bin/env python

import ipaddress
import os

if __name__ == '__main__':
    from pallium.netns import NetworkNamespace
else:
    from .netns import NetworkNamespace


def parse():
    """
    Simple /etc/resolv.conf parser that only extracts nameserver IPs. Other options are ignored.

    @return: List of IP addresses.
    """

    with open('/etc/resolv.conf') as f:
        return parse_content(f.read())


def parse_content(content: str):
    result = []
    for line in content.splitlines(keepends=False):
        if line.strip() == '':
            continue
        s = line.split()
        if len(s) != 2 or s[0] != 'nameserver':
            continue
        try:
            dns = ipaddress.ip_address(s[1])
            result.append(dns)
        except ValueError:
            continue
    return result


def write_resolv_conf(addrs):
    if addrs is None:
        addrs = []
    path = '/etc'
    if not os.path.exists(path):
        os.mkdir(path, 0o755)
        os.chmod(path, 0o755)
    filename = os.path.join(path, 'resolv.conf')
    with open(filename, 'w') as resolvconf:
        for address in addrs:
            resolvconf.write('nameserver %s\n' % str(address))
    os.chmod(filename, 0o644)


def write_pass_file(addrs, filename):
    with open(filename, 'w') as f:
        for address in addrs:
            f.write('%s\n' % address)
    os.rename(filename, '.'.join(filename.split('.')[:-1]))


if __name__ == '__main__':  # If this file is not imported, use it as an OpenVPN script
    addresses = []
    for key, value in os.environ.items():
        if not key.startswith('foreign_option_'):
            continue
        split = value.strip().split()
        if len(split) >= 3 and split[0] == 'dhcp-option' and split[1] == 'DNS':
            try:
                ip = ipaddress.ip_address(split[2])
            except ValueError:
                continue
            addresses.append(ip)
    write_resolv_conf(addresses)
