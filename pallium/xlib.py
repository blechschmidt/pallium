"""
This is a very dirty replacement for python-xlib which we cannot use for licensing reasons.
"""

import dataclasses
import os.path
import pwd
import socket
import struct
import sys

from . import sysutil

FamilyServerInterpreted = 5
FamilyLocal = 256
EnableAccess = 1
DisableAccess = 0


# https://stackoverflow.com/a/74840795/778421
def read_xauthority():
    file = os.environ.get(
        'XAUTHORITY',
        os.path.join(os.environ.get('HOME', pwd.getpwuid(os.getuid()).pw_dir), '.Xauthority')
    )

    results = []

    with open(file, 'rb') as f:
        data = f.read()

    while len(data) > 0:
        family = struct.unpack('>H', data[0:2])[0]
        offset = 2
        record = []
        for i in range(0, 4):
            length = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += 2
            record.append(data[offset:offset + length])
            offset += length
        data = data[offset:]
        results.append((family, *record))

    return results


def get_display_no():
    display_id = os.environ.get('DISPLAY', 1)
    if isinstance(display_id, str) and display_id.startswith(':'):
        display_id = display_id[1:]
    return int(display_id)


def get_auth(family=FamilyLocal, hostname=socket.gethostname().encode(), display_no=get_display_no()):
    auth = read_xauthority()
    display_cmp = str(display_no).encode()
    for auth_fam, auth_addr, display, auth_name, auth_data in auth:
        if (len(display) == 0 or display == display_cmp) and family == auth_fam and auth_addr == hostname \
                and auth_name == b'MIT-MAGIC-COOKIE-1':
            return auth_name, auth_data


@dataclasses.dataclass
class Host:
    family: int
    name: bytes


def _pad(data):
    return data + b'\x00' * ((4 - len(data)) % 4)


class Display:
    def __init__(self, display_id=None):
        if display_id is None:
            display_id = get_display_no()
        self.id = display_id
        self.sock = socket.socket(family=socket.AF_UNIX)
        self.connect()

    def connect(self):
        path = '/tmp/.X11-unix/X%d' % self.id
        if not os.path.exists(path):
            path = '\0' + path
        self.sock.connect(path)

        order = 0x6c if sys.byteorder == 'little' else 0x42
        protocol_maj = 11
        protocol_min = 0
        auth_name, auth_data = get_auth(display_no=self.id)

        hello = struct.pack(
            'BBHHHHH',
            order,
            0,
            protocol_maj,
            protocol_min,
            len(auth_name),
            len(auth_data),
            0
        ) + _pad(auth_name) + _pad(auth_data)
        self.sock.send(hello)
        head = sysutil.read_blocking(self.sock.fileno(), 8)
        if int(head[0]) != 1:
            raise ConnectionError()
        status, reason_length, proto_maj, proto_min, reply_len = struct.unpack('BBHHH', head)
        sysutil.read_blocking(self.sock.fileno(), reply_len * 4)

    def read_response(self):
        head = sysutil.read_blocking(self.sock.fileno(), 32)
        data_len = int(struct.unpack('=L', head[4:8])[0])
        return head + sysutil.read_blocking(self.sock.fileno(), data_len * 4)

    def __enter__(self):
        return self

    def close(self):
        self.sock.close()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def list_hosts(self):
        req = b'n\x00\x01\x00'
        self.sock.send(req)
        response = self.read_response()
        mode = int(response[1])
        hosts = response[32:]
        results = []
        while len(hosts) > 0:
            family, _, name_len = struct.unpack('BBH', hosts[0:4])
            name = hosts[4:4 + name_len]
            results.append(Host(family=family, name=name))
            padding = (4 - name_len) % 4
            hosts = hosts[4 + name_len + padding:]
        return mode, results

    def disable_access_control(self):
        req = b'o\x00\x01\x00'
        self.sock.send(req)

    def add_host(self, host):
        req_len = len(host.name) + 8
        multiple4_len = (req_len + 3) // 4
        padding = b'0' * (req_len - multiple4_len)
        msg = struct.pack(
            'BBHBBH',
            109,
            0,  # 0 = Insert, 1 = Delete
            multiple4_len,
            host.family,
            0,
            len(host.name)
        ) + host.name + padding
        self.sock.send(msg)
