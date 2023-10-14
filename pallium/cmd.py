#!/usr/bin/env python3
"""Entry point for the CLI."""

import argparse
import errno
import json
import logging
import os
import os.path
import shutil
import signal
import stat
import sys
import glob

from . import util
from . import runtime
from . import sysutil, security
from .exceptions import *
from .profiles import Profile, Session, ProfileManager

APP_NAME = 'pallium'
RUN_DIR = '/run'
APP_RUN_DIR = os.path.abspath(os.path.join(RUN_DIR, APP_NAME))
LOG_FORMAT = '%(asctime)s %(levelname)s %(process)d %(message)s'

main_process = os.getpid()
no_interrupt = False


def get_config_path(config):
    if '/' not in config:
        config = os.path.join(runtime.PROFILE_DIR, config + '.json')
    config = os.path.abspath(config)
    return config


def profile_from_args(args):
    config_file = get_config_path(args.config)
    if not config_file.startswith(APP_RUN_DIR + os.sep):
        profile = Profile.from_file(config_file)
    else:
        profile = config_file
    return profile


def get_tty(stdin_only=True):
    streams = [sys.stdin]
    if not stdin_only:
        streams += [sys.stdout, sys.stderr]
    ttyname = None
    for s in streams:
        try:
            ttyname = os.ttyname(s.fileno())
        except OSError as e:
            if e.errno != errno.ENOTTY:
                raise
    return ttyname


def wait_sigint():
    sys.stderr.write('This profile will run until you press Ctrl+C.\n')
    signal.sigwait([signal.SIGTERM, signal.SIGINT])


def pallium_run(args):
    profile = profile_from_args(args)
    if args.quiet:
        profile.quiet = True
    session = profile.run(args.new_session)

    call_args = dict(
        shell=isinstance(profile.command, str),
        stdin=sys.stdin
    )
    session.run(profile.command, terminal=get_tty() is not None, call_args=call_args)

    global no_interrupt
    no_interrupt = True


def parse_path(path: str, session: int):
    """
    Parse an scp-style path to a usable path to copy/move from/to.

    @return: A full path.
    """
    path = path.rstrip('/')
    if ':' not in path:
        return path
    split = path.split(':', maxsplit=1)
    if '/' in split[0]:  # The part before the colon is not a sandbox name.
        return path
    config = os.path.join(runtime.PROFILE_DIR, split[0] + '.json')
    profile = Profile.from_file(config)
    session = profile.get_session(session)
    pid = session.sandbox_pid
    return '/proc/%d/root' % pid + split[1]


def pallium_cp(args):
    src_path = parse_path(args.src, args.session)
    dst_path = parse_path(args.dst, args.session)
    if os.path.isdir(dst_path):
        dst_path = os.path.join(dst_path, os.path.basename(src_path))
    if args.recursive:
        shutil.copytree(src_path, dst_path)
    else:
        shutil.copyfile(src_path, dst_path)


def pallium_mv(args):
    src_path = parse_path(args.src, args.session)
    dst_path = parse_path(args.dst, args.session)
    shutil.move(src_path, dst_path)


def pallium_shell(args):
    args.command = os.environ.get('SHELL', 'sh')
    pallium_exec(args)


def pallium_stop(args):
    profile = profile_from_args(args)
    session = profile.get_session(args.session)
    os.killpg(os.getpgid(session.pid), signal.SIGINT)


def render_table(table, simple=False):
    output = ''
    column_sizes = []

    if not simple:
        for row in table:
            for i, cell in enumerate(row):
                if i >= len(column_sizes):
                    column_sizes.append(0)
                column_sizes[i] = max(column_sizes[i], len(str(cell)))

    for row in table:
        for i, cell in enumerate(row):
            content = str(cell)
            output += content
            if i != len(row) - 1:
                if simple:
                    output += '\t'
                else:
                    output += (column_sizes[i] - len(content)) * ' ' + ' | '
        output += '\n'
    sys.stdout.write(output)
    sys.stdout.flush()


def pallium_list(_):
    profiles = ProfileManager.list()
    table = [("PROFILE", "SESSIONS")]
    for profile in profiles:
        sessions = ', '.join(map(str, sorted(profile.get_sessions())))
        table.append((profile.name, sessions))
    table.sort(key=lambda x: x[0])
    render_table(table)


def pallium_exec(args):
    command = args.command
    if command is None or len(command) == 0:
        print('Command required.', file=sys.stderr)
        sys.exit(1)

    tty = None

    if 'config' not in args or args.config is None or args.config == '-':
        logging.debug("Reading profile from stdin")
        data = json.loads(sys.stdin.read())

        # Reconnect stdin to parent terminal
        tty = get_tty(False)
        if tty is not None:
            logging.debug("Reconnect stdin to parent terminal")
            sys.stdin = open(tty)

        profile = Profile.from_config(data)
        new_session = True
    else:
        profile = profile_from_args(args)
        new_session = False
    if args.quiet:
        profile.quiet = True
    if args.one_shot or new_session:
        session = profile.run(True)
    else:
        session = profile.get_session(args.session)

    max_id = (len(session.network_namespaces) - 1)
    if args.namespace > max_id:
        raise NetnsNotFoundError('The network namespace index cannot be greater than %d.' % max_id)
    sys.exit(session.run(command, terminal=tty is not None, ns_index=args.namespace, root=args.root, call_args={'stdin': sys.stdin}))


def parser_add_config(parser, add=True):
    if add:
        parser.add_argument('config', metavar='<config>', type=str, help='Profile name or path.')


def parser_add_session(parser):
    parser.add_argument('-s', '--session', type=int, default=0, help='The session index starting at 0.')


def parser_session_selector(parser, required=True):
    parser_add_config(parser, required)
    parser_add_session(parser)


def parser_add_root(parser):
    parser.add_argument('-r', '--root', action='store_true', help='Run as root.')


def parser_add_quiet(parser):
    parser.add_argument('--quiet', action='store_true', help='Do not output status information.')


def clean_exit(_, __):
    if no_interrupt:
        sysutil.fork_exit(0)
    if os.getpid() == main_process:  # We are forking a few times, so do not print it for every child.
        os.write(2, b'Interrupted.\n')
    sysutil.fork_exit(130)


def stdin_is_pipe():
    s = os.stat(sys.stdin.fileno())
    return stat.S_IFIFO & s.st_mode != 0


def pallium_debug(args):
    if args.pyshell:
        import code
        code.interact(local={
            '__file__': __file__
        })


def pallium_licenses(_):
    for filepath in glob.glob(util.bundled_resource_path('licensing/*.txt')):
        with open(filepath) as f:
            print('=== BEGIN ' + os.path.basename(filepath) + ' ===')
            print()
            print(f.read())
            print()
            print('=== END ' + os.path.basename(filepath) + ' ===')


def main(args=None):
    if security.is_suid():
        sys.stderr.write('Running this with setuid bit is currently a very bad idea.\n')
        sys.exit(1)

    signal.signal(signal.SIGUSR1, signal.SIG_IGN)

    parser = argparse.ArgumentParser(description='Network and Security Sandbox.')
    parser.add_argument('--loglevel', type=str, help='Level of logging.',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO')

    main_cmd_parser = parser.add_subparsers(help='Main command', dest='main_cmd')

    parser_run = main_cmd_parser.add_parser('run', help='Run a profile.')
    parser_add_quiet(parser_run)
    parser_run.add_argument('--new-session', action='store_true', help='Create a new session if there is one already.')
    parser_add_config(parser_run)

    parser_shell = main_cmd_parser.add_parser('shell', help='Open the default shell inside a running session.')
    parser_add_quiet(parser_shell)
    parser_session_selector(parser_shell, True)
    parser_shell.add_argument('--one-shot', action='store_true', help='Create a new session for this shell.')
    parser_shell.add_argument('-r', '--root', action='store_true', help='Run as root.')
    parser_shell.add_argument('--namespace', type=int, default=-1, help='Namespace index.')

    parser_stop = main_cmd_parser.add_parser('stop', help='Stop a running session.')
    parser_session_selector(parser_stop)

    parser_exec = main_cmd_parser.add_parser('exec', help='Execute a command inside a running session.')
    parser_add_quiet(parser_exec)
    parser_session_selector(parser_exec, True)
    parser_exec.add_argument('--one-shot', action='store_true', help='Create a new session for this command.')
    parser_add_root(parser_exec)
    parser_exec.add_argument('command', nargs=argparse.REMAINDER)
    parser_exec.add_argument('--namespace', type=int, default=-1, help='Namespace index.')

    parser_cp = main_cmd_parser.add_parser('cp', help='Copy a file or directory from or to a sandbox.')
    parser_cp.add_argument('src', help='Source path.')
    parser_cp.add_argument('dst', help='Destination path.')
    parser_cp.add_argument('-r', '--recursive', help='Copy directories recursively.', action='store_true')
    parser_add_session(parser_cp)

    parser_mv = main_cmd_parser.add_parser('mv', help='Move a file or directory from or to a sandbox.')
    parser_mv.add_argument('src', help='Source path.')
    parser_mv.add_argument('dst', help='Destination path.')
    parser_add_session(parser_mv)

    main_cmd_parser.add_parser('list', help='List profiles.')

    debug_parser = main_cmd_parser.add_parser('debug', help='Debug pallium. Functionality for pallium developers.')
    debug_parser.add_argument('--pyshell', help='Start a Python shell in the pallium context.', action='store_true')

    main_cmd_parser.add_parser('licenses', help='Show software licenses.')

    args = parser.parse_args(args)

    logging.basicConfig(level=getattr(logging, args.loglevel.upper()), format=LOG_FORMAT)

    if args.main_cmd is None:
        parser.print_help()
        sys.exit(1)

    if not sys.platform.startswith('linux'):
        sys.stderr.write('Incompatible operating system. Only Linux is supported.\n')
        sys.exit(1)

    # When we are debugging, we want to have a more verbose output.
    if logging.getLogger().level != logging.DEBUG:
        signal.signal(signal.SIGINT, clean_exit)

    try:
        globals()['pallium_' + args.main_cmd](args)
    except UserFriendlyException as e:
        sys.stderr.write("Error: " + str(e).strip() + '\n')
        sys.exit(1)


if __name__ == '__main__':
    main()
