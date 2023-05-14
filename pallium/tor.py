"""The stem library is licensed under the LGPLv3 license. Therefore, we need our own alternative.

Protocol spec: https://github.com/torproject/torspec/blob/main/control-spec.txt
"""

import binascii
import socket
import time

from . import sysutil


class TorController:
    def __init__(self, management_path=None):
        self.management_path = management_path
        self.sock = socket.socket(family=socket.AF_UNIX)

    def connect(self, timeout=20):
        start_time = time.perf_counter()
        while True:
            try:
                self.sock.connect(self.management_path)
                return
            except ConnectionError:
                if time.perf_counter() - start_time > timeout:
                    raise TimeoutError('Timed out waiting for tor control socket')
                time.sleep(0.01)

    def read_response_line(self):
        result = b''

        # Not the most efficient way to read but simple and who cares?
        while True:
            char = sysutil.read_blocking(self.sock.fileno(), 1)
            if char == b'\n':
                break
            result += char
        result = result.strip().decode()
        return result

    def write_line(self, line):
        if isinstance(line, str):
            line = line.encode()
        if not line.endswith(b'\n'):
            line += b'\n'
        sysutil.write_blocking(self.sock.fileno(), line)

    def read_response_lines(self):
        results = []
        while True:
            line = self.read_response_line()
            separator = line[3]
            if separator not in {' ', '-'}:
                # + character for async responses (which are currently not used)
                raise "Unexpected response"
            results.append((int(line[0:3]), line[4:]))
            if separator == ' ':
                break
        return results

    def authenticate(self, *, cookie_path):
        with open(cookie_path, 'rb', 0) as f:
            cookie = f.read()
        cookie_hex = binascii.b2a_hex(cookie)
        self.write_line(b'AUTHENTICATE ' + cookie_hex + b'\n')
        result = self.read_response_line()
        code, text = result.split(maxsplit=1)
        code = int(code)
        assert code == 250 and text == 'OK', 'Tor authentication response code must be 250 OK'

    def get_info(self, key):
        self.write_line('GETINFO ' + key)
        lines = self.read_response_lines()
        code, text = lines[0]
        assert code == 250 and text.startswith(key + '=')
        return text[len(key) + 1:]

    def signal(self, signal):
        self.write_line('signal ' + str(signal))
        lines = self.read_response_lines()
        code, text = lines[0]
        assert code == 250

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.sock.close()
