#!/usr/bin/env python3

"""
This script can launch Firefox while supplying about:config options through the command line.

In particular, it can be used to start a Tor Browser without Tor by running its launcher (torbrowser-launcher)
through this script with the environment variable TOR_SKIP_LAUNCH=1 and the following configuration flags:
-s network.dns.disabled false -s network.proxy.type 0 -s extensions.torbutton.use_nontor_proxy true
"""

import argparse
import json
import subprocess
import os

import pallium.sandbox as sandbox
import pallium.security as security
import pallium.sysutil as sysutil
import pallium.util as util


def to_value(arg):
    assert isinstance(arg, str)
    if arg.startswith('"') and arg.endswith('"'):
        return arg[1:-1]
    if arg.startswith("'") and arg.endswith("'"):
        return arg[1:-1]
    try:
        return int(arg)
    except ValueError:
        pass
    lower = arg.lower()
    if lower == 'true':
        arg = True
    elif lower == 'false':
        arg = False
    return arg


def mount_overlay(root, overlay, tmp):
    encoded = map(util.addslashes, [root, overlay, tmp])
    options = 'index=off,lowerdir=%s,upperdir=%s,workdir=%s' % tuple(encoded)
    sysutil.mount(b'overlay', root.encode(), b'overlay', 0, options.encode())


def main():
    parser = argparse.ArgumentParser(
        description='Firefox wrapper for configuring about:config settings through the CLI')
    parser.add_argument('-s', '--setting', nargs=2, action='append', default=[])
    parser.add_argument('-d', '--install-dir', default='/usr/lib/firefox')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='Command to run')
    args = parser.parse_args()

    settings = {}

    for key, value in args.setting:
        settings[key] = {
            'Value': to_value(value),
            'Status': 'user'
        }

    real_user = security.real_user()
    real_group = security.real_group()
    sandbox.map_user(real_user, real_group)
    sysutil.unshare(sysutil.CLONE_NEWNS)
    sysutil.mount(b'', b'/', b'none', sysutil.MS_SLAVE | sysutil.MS_REC, None)

    sysutil.mount(b'tmpfs', b'/tmp', b'tmpfs', 0)
    os.makedirs('/tmp/firefox/distribution')
    os.mkdir('/tmp/workdir')
    with open('/tmp/firefox/distribution/policies.json', 'w') as f:
        obj = {
            "policies": {
                "Preferences": settings
            }
        }
        f.write(json.dumps(obj))

    sysutil.mount(b'', b'/', b'none', sysutil.MS_SLAVE | sysutil.MS_REC, None)
    mount_overlay(args.install_dir, '/tmp/firefox', '/tmp/workdir')

    sandbox.map_back_real()

    command = ['firefox'] if len(args.command) == 0 else args.command

    subprocess.call(command)


if __name__ == '__main__':
    main()
