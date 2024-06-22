import atexit
import json
import os
import subprocess
import tempfile
import unittest

MINIMAL_BINUTILS = [
    "/usr",
    "/bin",
    "/lib64",
    "/lib",
    "/dev/null"
]


def get_output(profile, command, stripped=True):
    if isinstance(command, str):
        command = [command]
    output = subprocess.check_output(['pallium', 'exec', '--quiet', '--one-shot', '-', '--'] + command,
                                     input=json.dumps(profile).encode()).decode()
    if stripped:
        output = output.strip()
    return output


class PalliumTestCase(unittest.TestCase):
    def test_gvisor(self):
        profile = {
            "sandbox": {
                "gvisor": True
            }
        }
        # We recognize gVisor through dmesg logs
        assert 'Starting gVisor' in get_output(profile, 'dmesg')

        # Files in / on the host should match files in the guest (apart from the .$gvisor_init file)
        cmd = ['ls', '-a', '/']
        ls_host = set(subprocess.check_output(cmd).decode().splitlines(keepends=False))
        ls_guest = set(get_output(profile, cmd).splitlines(keepends=False))
        assert ls_host == ls_guest - {'.$pallium-gvisor-init'}

    def test_virtuser(self):
        profile = {
            "sandbox": {
                "virtuser": {
                    "name": "johndoe",
                    "skeleton": False
                }
            }
        }
        whoami_output = get_output(profile, 'whoami')
        assert whoami_output == 'johndoe'
        assert 'johndoe' in get_output(profile, ['sh', '-c', 'echo "$HOME"'])

    def test_minimal_filesystem(self):
        profile = {
            "sandbox": {
                "paths": {
                    "mode": "base",
                    "blacklist": [
                        "/"
                    ],
                    # Whitelist just enough to run ls.
                    "whitelist": MINIMAL_BINUTILS
                }
            }
        }
        # The /tmp directory should exist on the host system, and we should be able to list its contents.
        os.listdir("/tmp")

        # The /tmp folder does not exist in our sandbox. Therefore, ls should exit with an error code (2).
        assert get_output(profile, ['sh', '-c', 'ls /tmp >/dev/null 2>&1; echo $?']).strip() == '2'

    def test_blacklist(self):
        profile = {
            "sandbox": {
                "paths": {
                    "mode": "base",
                    "blacklist": [
                        "/tmp"
                    ],
                    "whitelist": [
                        "/*"
                    ]
                }
            }
        }

        # The /tmp directory should exist on the host system, and we should be able to list its contents.
        os.listdir("/tmp")

        assert get_output(profile, ['sh', '-c', 'ls /tmp >/dev/null 2>&1; echo $?']).strip() == '2'

    def test_mount(self):
        filename = tempfile.mktemp('.pallium-test')
        with open(filename, 'w') as f:
            f.write('Hello world')
        atexit.register(lambda *_, **__: os.unlink(filename))

        for dst in ['/pallium-test', '/doesnotexist/pallium-test', '/etc/pallium-test', '/etc/x/pallium-test']:
            profile = {
                "sandbox": {
                    "paths": {
                        "bind": [
                            [dst, filename]
                        ]
                    }
                }
            }

            assert get_output(profile, ["cat", dst]) == "Hello world", "Test bind mounting test file at " % dst


if __name__ == '__main__':
    assert os.getuid() != 0, "These tests should not be run as root user"
    unittest.main()
