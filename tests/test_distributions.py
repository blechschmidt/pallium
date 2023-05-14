import json
import os
import subprocess
import unittest
from pathlib import Path

from provision import VagrantProvisioner

PROJECT_ROOT = Path(__file__).parent.parent.resolve()


class TestInstallScript(unittest.TestCase):
    def _test_pallium(self, machine, path='pallium'):
        return machine.ssh(['sudo', path, 'exec', '--quiet', '--one-shot', 'tor',
                            'curl', 'https://check.torproject.org/api/ip'], check_output=True)

    def _install(self, machine):
        machine.ssh(['sudo', '/home/vagrant/pallium/install.sh', '--noconfirm'])

    def _test_distro(self, vagrant_box_name, pallium_path='pallium'):
        with VagrantProvisioner.provision_from_box_name(vagrant_box_name) as machine:
            machine.quiet = False
            machine.upload(PROJECT_ROOT)
            self._install(machine)
            machine.quiet = False
            for i in range(0, 2):
                try:
                    data = self._test_pallium(machine, pallium_path)
                    break
                except subprocess.CalledProcessError:
                    if i == 0:  # Kernel updates without restart may break pallium. Seen on Arch Linux.
                        machine.halt()
                        machine.up()
                    else:
                        raise

            assert json.loads(data)['IsTor']

    def test_fedora_latest(self):
        self._test_distro('bento/fedora-latest')

    def test_archlinux(self):
        self._test_distro('archlinux/archlinux')

    def test_debian_bullseye(self):
        self._test_distro('debian/bullseye64')

    def test_ubuntu_jammy(self):
        self._test_distro('ubuntu/jammy64')

    def test_centos_stream8(self):
        self._test_distro('centos/stream8', '/usr/local/bin/pallium')

    def test_opensuse_leap15(self):
        self._test_distro('opensuse/Leap-15.3.x86_64')


# Issues: https://pyinstaller.org/en/stable/runtime-information.html
# Glibc may be too new on the build system.
class TestPyinstallerBuild(TestInstallScript):
    @classmethod
    def setUpClass(cls):
        # subprocess.call([os.path.join(PROJECT_ROOT, 'dist', 'build.sh')])
        pass

    def _install(self, machine):
        machine.upload(os.path.join(PROJECT_ROOT, 'dist', 'bin', 'pallium'), '/home/vagrant/pallium-bin')
        machine.ssh(['sudo', '/home/vagrant/pallium/install.sh', '--dependencies-only', '--noconfirm'])
        machine.ssh(['sudo', 'install', '-m', '0755', '/home/vagrant/pallium-bin', '/usr/bin/pallium'])

    def test_centos_stream8(self):
        self._test_distro('centos/stream8')


if __name__ == '__main__':
    unittest.main()
