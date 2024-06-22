import json
import os
import socket
import subprocess
import tempfile
import time
import unittest


def pallium_exec_output(profile, command, stripped=True):
    if isinstance(command, str):
        command = [command]
    output = subprocess.check_output(['pallium', 'exec', '--quiet', '--one-shot', '-', '--'] + command,
                                     input=json.dumps(profile).encode()).decode()
    if stripped:
        output = output.strip()
    return output


def pallium_exec_profile_path(profile, command, stripped=True):
    if isinstance(command, str):
        command = [command]
    output = subprocess.check_output(['pallium', 'exec', '--quiet', '--one-shot', profile, '--'] + command)
    if stripped:
        output = output.strip()
    return output


class PalliumTestSession:
    def __init__(self, profile, name=None):
        """
        Create a new test session with the given profile.

        @param profile: The pallium profile as a dict.
        @param name: The name of the profile. If None, a temporary profile will be created.
        """
        self.profile = profile
        self.process = None
        self.tempfile = None
        self.read_fd = None
        self.profile_name = name

    @property
    def profile_path(self):
        if self.profile_name is not None:
            return os.path.expanduser(os.path.join('~/.config/pallium/profiles', self.profile_name + '.json'))
        else:
            return self.tempfile.name

    def start(self):
        if self.profile_name is None:
            self.tempfile = tempfile.NamedTemporaryFile()
            self.tempfile.write(json.dumps(self.profile).encode())
            self.tempfile.flush()
        else:
            with open(self.profile_path, 'w') as f:
                f.write(json.dumps(self.profile))
        self.read_fd, write_fd = os.pipe()
        self.process = subprocess.Popen(
            ['pallium', 'run', '--pid-file', '/proc/self/fd/%d' % write_fd, '--quiet', self.profile_path],
            pass_fds=[write_fd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.wait_for_startup()

    def close(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait()
            self.process = None
        if self.tempfile is not None:
            self.tempfile.close()
            self.tempfile = None

    def wait_for_startup(self):
        os.read(self.read_fd, 1)

    def exec(self, command, stripped=True):
        return pallium_exec_profile_path(self.profile_path, command, stripped).decode()

    def popen(self, argv, *args, **kwargs):
        return subprocess.Popen(['pallium', 'exec', '--quiet', self.profile_path, '--'] + argv, *args,
                                **kwargs)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PalliumTestCase(unittest.TestCase):
    def test_virtuser(self):
        profile = {
            'sandbox': {
                'virtuser': 'johndoe'
            }
        }
        assert pallium_exec_output(profile, ['whoami']) == 'johndoe'

    def test_mv(self):
        profile = {
            'sandbox': {
                'virtuser': 'johndoe'
            },
            'run': {
                'command': ['sleep', 'infinity']
            }
        }

        with PalliumTestSession(profile) as session, tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, 'w') as f:
                f.write('hello world')
            exec_result = session.exec(['whoami'])
            assert exec_result == 'johndoe'

            subprocess.call(['pallium', 'mv', tmp.name, '--to', session.profile_path, '/home/johndoe/hello.txt'])
            exec_result = session.exec(['cat', '/home/johndoe/hello.txt'])
            assert exec_result == 'hello world'

    def test_port_forwarding(self):
        profile = {
            'network': {
                'port_forwarding': {
                    'local': [
                        'tcp://127.0.0.1:1337:127.0.0.1:8000'
                    ]
                }
            },
            'run': {
                'command': ['sleep', 'infinity']
            }
        }

        with PalliumTestSession(profile) as session, tempfile.NamedTemporaryFile() as tmp:
            nc = session.popen(['sh', '-c', 'nc -l -p 8000 > ' + tmp.name])

            # TODO: Why does sending not fail if sleep is omitted?
            # Shouldn't the connect call fail if slirpnetstack cannot forward the port?
            time.sleep(1)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', 1337))
            sock.sendall(b'hello world\n')
            sock.close()
            nc.wait()
            with open(tmp.name, 'r') as f:
                assert f.read().strip() == 'hello world'


if __name__ == '__main__':
    unittest.main()
