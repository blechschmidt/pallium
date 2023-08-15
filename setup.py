import os
import subprocess

import setuptools
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.egg_info import egg_info

with open('README.md', 'r') as fh:
    long_description = fh.read()

data_files = []

if os.getuid() == 0:  # Installation as superuser
    data_files = [
        ('/etc/bash_completion.d/', ['extra/completions/bash/pallium']),
        ('/etc/pallium/profiles', [])
    ]


def build_helpers():
    project_root = os.path.dirname(os.path.abspath(__file__))
    gvisor_init_dir = os.path.join(project_root, 'pallium/gvisor-init')

    subprocess.check_call(['make'], cwd=gvisor_init_dir)


class PalliumInstall(install):
    def run(self):
        build_helpers()
        install.run(self)


class PalliumDevelop(develop):
    def run(self):
        build_helpers()
        develop.run(self)


class PalliumEggInfo(egg_info):
    def run(self):
        build_helpers()
        egg_info.run(self)


setuptools.setup(
    name='pallium-sandbox',
    version='0.1.0dev',
    author='B. Blechschmidt',
    author_email='git@blechschmidt.io',
    description='Linux Network and Security Sandbox',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/blechschmidt/pallium',
    packages=setuptools.find_packages(),
    data_files=data_files,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: Utilities'
    ],
    entry_points={
        'console_scripts': ['pallium=pallium.cmd:main']
    },
    install_requires=[
        'pyroute2',
        'pyseccomp',
    ],
    python_requires='>=3.6.0',
    package_data={
        'pallium': [
            'gvisor-init/gvisor-init'
        ]
    },
    include_package_data=True,
    cmdclass={
        'install': PalliumInstall,
        'egg_info': PalliumEggInfo,
        'develop': PalliumDevelop
    }
)
