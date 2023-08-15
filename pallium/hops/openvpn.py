import ipaddress
import os
import re
import socket
import sys
import time
from typing import Optional

from .. import util, debugging
from . import hop


class OpenVpnHop(hop.Hop):
    app_requirements = ['openvpn']

    def __init__(self, config, *, username=None, password=None, timeout=60, **kwargs):
        """
        OpenVPN hop.

        @param config: Path to the *.ovpn configuration file. It should include private keys etc.
        @param username: OpenVPN username that will be passed to `openvpn` via the management interface.
        @param password: OpenVPN password that will be passed to `openvpn` via the management interface.
        @param timeout: Connection timeout.
        @param kwargs: Arguments passed on to the `hop.Hop` constructor.
        """
        super().__init__(**kwargs)
        self._username = username
        self._password = password
        self._conf_path = config
        self._mgmt_sock = None
        self._mgmt_path = None
        self._mgmt_buffer = b''
        self._timeout = timeout
        self._mgmt_unpredictable_msgs = []
        self._pid = None
        self.dns_servers = hop.DnsOverlay()

    def _wait_connected(self):
        connected = False
        while not connected:
            self._mgmt_sock.send(b'state\r\n')

    def _management_read(self, predictable=None, timeout=None):
        end = None
        if timeout is None:
            timeout = self._timeout
        if timeout is not None:
            end = time.time() + timeout

        if predictable is None:
            unpredictable_msg = self._management_get_unpredictable()
            if unpredictable_msg is not None:
                return unpredictable_msg

        while True:
            remaining_timeout = None if timeout is None else end - time.time()
            line, self._mgmt_buffer = util.readline(self._mgmt_sock, self._mgmt_buffer, terminator=b'\r\n',
                                                    timeout=remaining_timeout)
            if line.startswith(b'>'):
                self._mgmt_unpredictable_msgs.append(line)
                if predictable:
                    continue
            return line

    def _management_get_unpredictable(self):
        if len(self._mgmt_unpredictable_msgs) > 0:
            return self._mgmt_unpredictable_msgs.pop(0)

    def _management_expect_success(self, request, error):
        self._mgmt_sock.send(request)

        response = self._management_read(True)
        if not response.startswith(b'SUCCESS:'):
            raise error(response)

    def connect(self):
        hop_info = self.info
        super().connect()
        temp = util.mkdtemp()
        self._mgmt_path = os.path.join(temp, 'management.sock')

        command = [self.get_tool_path('openvpn'), '--config', self._conf_path, '--management', self._mgmt_path, 'unix',
                   '--management-query-passwords']

        dns_file = os.path.join(hop_info.netns.etc_path, 'resolv.conf')
        resolvconfpy_path = os.path.join(os.path.split(__file__)[0], '..', 'resolvconf.py')
        resolv_script = '%s %s %s' % (sys.executable, resolvconfpy_path, dns_file)
        self.log_debug('OpenVPN --route-up script: %s' % resolv_script)
        command += ['--route-up', resolv_script, '--script-security', '2']

        self._pid = self.popen(command).pid

        if not util.wait_for_file(self._mgmt_path):
            raise TimeoutError('OpenVpn management socket not found')

        self._mgmt_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._mgmt_sock.connect(self._mgmt_path)

        self.log_info('Waiting for OpenVPN to connect ...')

        connected = False

        self._management_expect_success(b'state on\r\n', hop.ProtocolError)
        self._mgmt_sock.send(b'state\r\n')
        mgmt_msg = self._management_read(True)
        parts = mgmt_msg.split(b',')
        if parts[1] == b'CONNECTED':
            connected = True
        end = self._management_read(True)
        if end != b'END':
            raise hop.ProtocolError(end)

        stop = None if self._timeout is None else time.time() + self._timeout
        while not connected:
            remaining_timeout = None if self._timeout is None else stop - time.time()
            mgmt_msg = self._management_read(timeout=remaining_timeout)
            if mgmt_msg.startswith(b'>'):
                if mgmt_msg.startswith(b'>PASSWORD:'):
                    auth_username = b'username "Auth" "' + bytes(util.backslash_quote_escape(self._username),
                                                                 encoding='utf-8') + b'"\r\n'

                    auth_password = b'password "Auth" "' + bytes(util.backslash_quote_escape(self._password),
                                                                 encoding='utf-8') + b'"\r\n'
                    self._management_expect_success(auth_username, hop.AuthenticationError)
                    self._management_expect_success(auth_password, hop.AuthenticationError)

                elif mgmt_msg.startswith(b'>STATE:'):
                    mgmt_msg = mgmt_msg[len(b'>STATE:'):]
                    parts = mgmt_msg.split(b',')
                    if parts[1] == b'CONNECTED':
                        connected = True

        self.log_info('OpenVPN connected ...')

        if self.debug:
            debugging.capture('tun0')

        return self._pid

    def handle_connect_results(self, results):
        self._pid = results
        self.register_process(results)

    @property
    def pid(self):
        return self._pid

    def _scan_config(self, **kwargs):
        result = dict()
        with open(self._conf_path, 'r') as f:
            for line in f:
                for key, regex in kwargs.items():
                    match = re.match(regex, line.strip())
                    if match:
                        groups = match.groups()
                        if len(groups) == 1:
                            result[key] = groups[0]
                        else:
                            result[key] = groups
        return result

    @property
    def required_routes(self):
        return [ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')]

    @property
    def kill_switch_device(self) -> Optional[str]:
        return 'tun0'
