"""To test pallium, we set up real machines that are reachable by the public.
This is necessary if we want to test chains with hops that are reachable through Tor.
However, this also requires resources, such as public IP addresses, which cannot be immediately obtained locally.
To this end, a DigitalOcean server is provisioned. The CI pipeline relies on this method."""

import ipaddress
import os.path
import re
import shutil
import subprocess
import time
import traceback
from tempfile import mkdtemp

import digitalocean

import pallium.sysutil as sysutil
from pallium import security


class Machine:
    quiet = True

    def process_call(self, *args, **kwargs):
        if self.quiet:
            kwargs.setdefault('stderr', subprocess.DEVNULL)
            kwargs.setdefault('stdout', subprocess.DEVNULL)
        return subprocess.call(*args, **kwargs)

    def destroy(self):
        """Stop the machine and free allocated resources."""
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def ssh(self, command, check_output=False, **kwargs):
        """Run an ssh command on the machine."""
        raise NotImplementedError

    def get_public_ips(self):
        """Get all public IP addresses of a machine."""
        raise NotImplementedError

    def get_ssh_destination(self):
        """Get the destination of the machine as supplied to ssh (in the form of [user@]host)."""
        return NotImplementedError

    def install_openvpn(self):
        ip = list(filter(lambda x: x.version == 4, self.get_public_ips()))[0]
        script_defaults = {
            'APPROVE_INSTALL': 'y',
            'APPROVE_IP': 'y',
            'ENDPOINT': str(ip),
            'IPV6_SUPPORT': 'y',
            'PORT_CHOICE': 1,
            'PROTOCOL_CHOICE': 2,
            'DNS': 1,
            'COMPRESSION_ENABLED': 'n',
            'CUSTOMIZE_ENC': 'n',
            'CLIENT': 'client',
            'PASS': 1,
            'MENU_OPTION': 4
        }
        env = ['%s=%s' % (key, str(value),) for key, value in script_defaults.items()]
        self.ssh(
            ['curl', '-O', 'https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh'])
        self.ssh(['chmod', '+x', 'openvpn-install.sh'])
        self.ssh(env + ['./openvpn-install.sh'])

        # https://github.com/angristan/openvpn-install/issues/788#issuecomment-800184332
        # self.ssh(['chown', '-R', 'openvpn.network', '/etc/openvpn/', '/var/log/openvpn'])
        # self.ssh(['systemctl', 'restart', 'openvpn-server@server'])

        return self.ssh(['cat', 'client.ovpn'], check_output=True)

    def install_dante(self, password):
        raise NotImplementedError

    def install_squid(self, password):
        raise NotImplementedError


class DigitalOceanMachine(Machine):
    id = None

    def __init__(self, id, token):
        self.id = id
        self.token = token
        self.droplet = digitalocean.Droplet(token=self.token, id=self.id)

    def load(self):
        self.droplet.load()

    def ssh(self, command, check_output=False, **kwargs):
        f = subprocess.check_output if check_output else self.process_call
        result = f(['ssh', '-o', 'StrictHostKeyChecking=no', self.get_ssh_destination(), *command],
                   preexec_fn=drop_privileges, **kwargs)
        return result

    def get_ssh_destination(self):
        return 'root@%s' % self.get_public_ips()[0]

    def destroy(self):
        pass
        # self.droplet.destroy()

    def get_public_ips(self):
        result = [ipaddress.ip_address(self.droplet.ip_address)]
        if self.droplet.ip_v6_address is not None:
            result.append(ipaddress.ip_address(self.droplet.ip_v6_address))
        return result

    def wait_for_completion(self):
        actions = self.droplet.get_actions()

        while True:
            for action in actions:
                action.load()
                if action.status == 'completed':
                    self.droplet.load()
                    return
            time.sleep(3)

    def install_dante(self, password):
        self.ssh(['apt', '-y', 'install', 'dante-server'])
        self.ssh(['useradd', 'pmtest', '-r'])
        script_dir = os.path.split(os.path.realpath(__file__))[0]
        dante_config = os.path.join(script_dir, 'templates', 'danted.conf')
        with open(dante_config, 'rb') as f:
            contents = f.read()
        self.ssh(['cat', '-', '>', '/etc/danted.conf'], check_output=True, input=contents)
        self.ssh(['chpasswd'], check_output=True, input=b'pmtest:' + password.encode())
        self.ssh(['service', 'danted', 'restart'])
        return password

    def install_squid(self, password):
        self.ssh(['apt', '-y', 'install', 'squid', 'apache2-utils'])
        self.ssh(['touch', '/etc/squid/passwd'])
        self.ssh(['htpasswd', '-i', '/etc/squid/passwd', 'pmtest'], check_output=True, input=password.encode())
        script_dir = os.path.split(os.path.realpath(__file__))[0]
        squid_config = os.path.join(script_dir, 'templates', 'squid.conf')
        with open(squid_config, 'rb') as f:
            contents = f.read()
        self.ssh(['cat', '-', '>', '/etc/squid/squid.conf'], check_output=True, input=contents)
        self.ssh(['systemctl', 'restart', 'squid.service'])


class DigitalOceanProvisioner:
    @staticmethod
    def provision() -> Machine:
        token_file = os.path.join(os.path.split(os.path.realpath(__file__))[0], 'digitalocean.secret')
        if os.path.exists(token_file):
            with open(token_file, 'r') as f:
                token = f.read()
        else:
            token = os.environ['DIGITALOCEAN_API_KEY']
        manager = digitalocean.Manager(token=token)
        for droplet in manager.get_all_droplets():
            if droplet.name == 'pmtest':
                machine = DigitalOceanMachine(id=droplet.id, token=token)
                machine.load()
                machine.wait_for_completion()
                return machine

        ssh_keys = [(ssh_key.load(), ssh_key.id)[1] for ssh_key in manager.get_all_sshkeys()]

        droplet = digitalocean.Droplet(token=token,
                                       name='pmtest',
                                       region='fra1',
                                       image='ubuntu-20-04-x64',  # Ubuntu 20.04 x64
                                       size_slug='s-1vcpu-1gb',  # 1GB RAM, 1 vCPU
                                       ipv6=True,
                                       ssh_keys=ssh_keys)
        droplet.create()
        machine = DigitalOceanMachine(id=droplet.id, token=token)
        machine.wait_for_completion()
        return machine


def drop_privileges():
    if not security.is_sudo_or_root():
        return
    try:
        sysutil.drop_privileges(sysutil.get_real_user(), True)
    except BaseException as e:
        traceback.print_exc()
        raise e


class VagrantMachine(Machine):
    """This type of machine is not portable at all. If you want to run the tests yourself, you need
    to implement your own machine and provisioner classes. For example, instead of using Vagrant, the APIs of cloud
    providers could be used."""
    vagrantfile_dir = None
    default_ssh_user = 'root'

    def upload(self, src, dst=None):
        if dst is None:
            dst = []
        else:
            dst = [dst]
        self.process_call(['vagrant', 'upload', '-c', os.path.abspath(src)] + dst, cwd=self.vagrantfile_dir,
                          preexec_fn=drop_privileges)

    def destroy(self):
        self.process_call(['vagrant', 'destroy', '-f'], cwd=self.vagrantfile_dir, preexec_fn=drop_privileges)

    def halt(self):
        self.process_call(['vagrant', 'halt'], cwd=self.vagrantfile_dir, preexec_fn=drop_privileges)

    def up(self):
        self.process_call(['vagrant', 'up'], cwd=self.vagrantfile_dir, preexec_fn=drop_privileges)

    @property
    def vbox_id(self):
        with open(os.path.join(self.vagrantfile_dir, '.vagrant', 'machines', 'default', 'virtualbox', 'id')) as f:
            return f.read().strip()

    @property
    def ssh_config_path(self):
        return os.path.join(self.vagrantfile_dir, 'ssh_config')

    def ssh(self, command, check_output=False, user=None, **kwargs):
        if user is None:
            if self.default_ssh_user is None:
                userprefix = ''
            else:
                userprefix = self.default_ssh_user + '@'
        else:
            userprefix = user + '@'
        f = subprocess.check_output if check_output else self.process_call
        result = f(['ssh', '-F', self.ssh_config_path, userprefix + 'default', *command], preexec_fn=drop_privileges,
                   **kwargs)
        return result

    def get_ssh_destination(self):
        return 'vagrant@%s' % str(self.get_public_ips()[0])

    def get_public_ips(self):
        ips = []
        ipaddr_output = self.ssh(['ip', 'addr', 'show', 'dev', 'ppp0'], check_output=True)
        for line in ipaddr_output.decode().splitlines():
            stripped = line.strip()
            search = re.match(r'inet6?\s(.*?)(?:\s|/|$)', stripped)
            if search:
                ip = ipaddress.ip_address(search.group(1))
                if ip.is_global:
                    ips.append(ip)
        return ips


class VagrantProvisioner:
    @staticmethod
    def provision_from_box_name(box_name):
        config = """Vagrant.configure("2") do |config|\n  config.vm.box = "%s"\nend\n""" % box_name
        tmp = mkdtemp()
        vagrantfile = os.path.join(tmp, 'Vagrantfile')
        with open(vagrantfile, 'w') as f:
            f.write(config)
        machine = VagrantProvisioner.provision(vagrantfile)
        os.unlink(vagrantfile)
        os.rmdir(tmp)
        return machine

    @staticmethod
    def provision(templatefile) -> VagrantMachine:
        machine = VagrantMachine()
        real_user = sysutil.get_real_user()
        sysutil.drop_privileges(real_user, temporary=True)
        machine.vagrantfile_dir = mkdtemp()
        script_dir = os.path.split(os.path.realpath(__file__))[0]
        if not os.path.isabs(templatefile):
            vagrantfile = os.path.join(script_dir, 'templates', templatefile)
        else:
            vagrantfile = templatefile
        shutil.copyfile(vagrantfile, os.path.join(machine.vagrantfile_dir, 'Vagrantfile'))
        home = sysutil.get_pw_entry(real_user).pw_dir
        sysutil.drop_privileges(os.getuid(), temporary=True)
        machine.process_call(['vagrant', 'box', 'update'], cwd=machine.vagrantfile_dir, preexec_fn=drop_privileges)
        machine.process_call(['vagrant', 'up'], cwd=machine.vagrantfile_dir, preexec_fn=drop_privileges)
        ssh_config = subprocess.check_output(['vagrant', 'ssh-config'], cwd=machine.vagrantfile_dir,
                                             preexec_fn=drop_privileges)
        with open(machine.ssh_config_path, 'wb') as f:
            f.write(ssh_config)
        with open(os.path.join(home, '.ssh', 'id_rsa.pub'), 'rb') as f:
            machine.ssh(['cat', '>>', '~/.ssh/authorized_keys'], check_output=True, input=f.read(), user='vagrant')
        machine.ssh(['sudo', 'mkdir', '/root/.ssh/'], user='vagrant')
        machine.ssh(['sudo', 'cp', '/home/vagrant/.ssh/authorized_keys', '/root/.ssh/authorized_keys'], user='vagrant')
        return machine
