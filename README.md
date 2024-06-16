# Pallium

## Linux Network and Security Sandbox

**This project is still in an early phase of development (pre-alpha). It is not ready for production use
and has [known issues](/doc/issues.md), which are not (yet) documented exhaustively.
Please expect bugs and breaking changes.**

Pallium is a Linux network and security sandbox. In contrast to many other sandboxing solutions,
pallium can provide reasonable protection against Linux kernel exploits
through the use of [gVisor](https://github.com/google/gvisor).
Pallium also supports restricting file system access and implements virtual users, allowing to isolate applications
without requiring elevated privileges.
At the same time, pallium aims to be an alternative to tools like
[proxychains-ng](https://github.com/rofl0r/proxychains-ng), while providing support for more protocols and use cases by
enabling bridging (e.g. for traffic of virtual machines) and leveraging network namespaces to prevent leaks more
reliably.

Regarding networking, pallium currently supports the following types of network hops natively:

* OpenVPN
* SOCKS
    * Tor
    * SSH
* HTTP (`CONNECT` method)
* WireGuard

Other hops that are not explicitly supported, such as OpenConnect, can be easily scripted
(see [extra/scripts](/extra/scripts)).

Pallium's goal is to be easily extensible by anything that supports routing through a network interface.

This document only summarizes pallium's capabilities. Please refer to [the overview](/doc/overview.md),
[some examples](/doc/examples.md), or [the FAQ](/doc/FAQ.md) for more a more detailed overview and specific use cases
for pallium.


## Installation

### Binary Download
On x64 systems, the latest pallium release can be directly downloaded and made executable as follows:
```shell
curl -O -L https://github.com/blechschmidt/pallium/releases/latest/download/pallium-x86_64-bundle-linux
chmod +x pallium-x86_64-bundle-linux
```

Pallium supports [build provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds#verifying-artifact-attestations-with-the-github-cli)
since v0.1.0-alpha4.
To verify the authenticity of the binary, you can use the [GitHub CLI](https://cli.github.com/):
```shell
gh attestation verify pallium-x86_64-bundle-linux --repo blechschmidt/pallium
```

This ensures that the binary was built by the GitHub Actions CI/CD pipeline and has not been tampered with.

### Automated Installation
Having cloned pallium, it can be installed using the included installation script:

```shell
sudo ./install.sh
```

The installation script needs to be run as root and will try to automatically install the dependencies for the most
common use cases of pallium (Tor, tun2socks, slirp4netns). It will use your package manager to upgrade your system and
install the dependencies. For security reasons, you will be asked to confirm each installation step.

### Manual Installation
Alternatively, pallium can be installed by executing the following command in the project folder:

```shell
pip install .
```

This installation method does not require root, but you will need to manually install the dependencies listed below.

The following additional software is required depending on the hop chain and needs to be installed separately.

| Feature                 | Binaries                                                          |
|-------------------------|-------------------------------------------------------------------|
| OpenVPN                 | openvpn                                                           |
| SOCKS                   | [tun2socks](https://github.com/xjasonlyu/tun2socks)               |
| Tor (SOCKS)             | tor                                                               |
| SSH (SOCKS)             | ssh                                                               |
| HTTP                    | [tun2socks](https://github.com/xjasonlyu/tun2socks)               |
| DHCP (bridging)         | dnsmasq                                                           |
| GUI isolation           | [Xpra](https://xpra.org/)                                         |
| Unprivileged sandboxing | [slirp4netns](https://github.com/rootless-containers/slirp4netns) |
| Kernel isolation        | [gVisor](https://github.com/google/gvisor)                        |


## CLI Usage

A pallium profile is a `.json` file located in `~/.config/pallium/profiles` (`/etc/pallium/profiles` when run as root)
containing a JSON object. Its profile name is the
file name without file extension. The file contains a description of the hop chain to be built and instructions of what
to run in the application namespace once the connection has been established.

For a more detailed documentation on pallium's features and its configuration,
please consult [the docs](./doc/overview.md).

Pallium can also be used programmatically through its Python interface. Examples can be found in the `examples` folder.


## Examples

### Hardened browser
The following profile lets you run a hardened persistent browser with a shared `Downloads` folder, assuming that your
username on the host system is `you`. The use of [gVisor](https://github.com/google/gvisor) provides a reasonable
protection against Linux kernel exploits.
```json
{
  "sandbox": {
    "gvisor": true,
    "gui": true,
    "audio": true,
    "virtuser": "browser",
    "paths": {
      "bind": [
        ["/home/browser/Downloads", "/home/you/Downloads"]
      ]
    }
  },
  "run": {
    "command": "chromium"
  }
}
```

### Network Chaining
An example setup could look like this:

```
#################     #################     #################     #################     ################
#               #     #               #     #               #     #               # <=> #   Selected   #
# Default netns # <=> #     SOCKS     # <=> #      Tor      # <=> # OpenVPN (TCP) #     # applications #
#               #     #               #     #               #     #               # <=> # within netns #
#################     #################     #################     #################     ################
```

Each box represents a network namespace. Traffic from an application within the application namespace is first forwarded
to the OpenVPN namespace, then to the Tor namespace and finally to the SOCKS namespace, from where it is passed to the
default namespace. In each network namespace, the traffic is encapsulated accordingly. Thus, pallium acts as a
router chaining tool.
(This example just illustrates the principle. In practice, pallium may set up additional helper namespaces.)

The configuration file of the above example could look like this:

```json
{
  "sandbox": {
    "virtuser": "janedoe",
    "gui": true,
    "audio": true
  },
  "chain": [
    {
      "type": "socks",
      "address": "10.8.0.3:1080",
      "username": "jane.doe",
      "password": "pass1234"
    },
    {
      "type": "tor"
    },
    {
      "type": "openvpn",
      "config": "/path/to/conf.ovpn"
    }
  ],
  "run": {
    "command": "firefox"
  }
}
```

Behind the scenes, pallium first creates a network namespace for the SOCKS proxy. A tunnel from this namespace to the
default namespace is then created through a [Virtual Ethernet (veth)](https://man7.org/linux/man-pages/man4/veth.4.html)
device and all traffic inside the namespace is routed through the default namespace. A TUN device for SOCKS is then
created by tun2socks. \
Next, a second namespace (and a third helper namespace for routing reasons, which is not depicted here) is created,
whose traffic is routed through the previous namespace. This namespace connects to Tor and the helper namespace
provides a tun2socks interface for the traffic of the next namespace to be routed through. \
Following the pattern, a namespace for OpenVPN is created before creating the application namespace. \
As a result, when initiating a connection, outgoing traffic first goes to the OpenVPN interface, where it is encrypted
and forwarded to the OpenVPN server. The traffic to the VPN server is then routed through the Tor namespace, thus Tor
will attempt to establish a connection to the VPN server. This connection is in turn routed through the SOCKS server.
This means that the OpenVPN server will only see the Tor exit node IP address but not your origin IP address, while the
SOCKS server will only see the Tor entry node IP address, and any endpoint you connect to from the application namespace
will only see the IP address of the OpenVPN server.

The `virtuser` specification inside `sandbox` indicates that a virtual user named `janedoe` is to be created and used.
For more information on virtual users, please refer to [the overview](/doc/overview.md).


## CLI

Having installed pallium, it supports a range of commands:

### run

Assuming unprivileged mode, `pallium run my_profile` sets up the namespaces according to the configuration and executes
the command defined in the `run` object in the configuration file at `~/.config/pallium/profiles/my_profile.json` inside
the application namespace. In case no `run` property is specified, pallium will run the default shell as defined by the
`$SHELL` environment variable. The namespaces will live as long as the command executed by `run` is running. We refer
to one running set of namespaces as a session.

A new session of a profile that already has a session running can be started by specifying `--new-session` after `run`.
The first session obtains index 0, the second session obtains index 1, and so on. Subcommands working with sessions,
such as `shell` etc., support the `-s` parameter to specify the session index. If the session index is not specified,
session 0 is assumed.

Additionally, a `--quiet` argument is supported, which turns off the output regarding connection establishment as
produced by the helper tools.

### shell

`pallium shell my_profile` opens a shell (as defined by the `$SHELL` environment variable) inside the last network
namespace. This command supports the `--one-shot` argument, which causes a new session to be created for the shell.
Otherwise, the shell is started in an existing session. Additionally, a `--root` argument is supported, in which case
the shell is started as the root user. Depending on whether pallium is run with superuser privileges or without
privileges, this is either real root or fake root, i.e. a user-mapped UID and GID of 0 inside the unprivileged user
namespace.

For debugging purposes, you can also specify the network namespace index using `--namespace`, which supports
Python-style indexes. Note that entering namespaces this way may disable sandbox features such as gvisor.

### exec

`pallium exec my_profile <command>` works similar to `pallium shell my_profile`, except that it executes the command
following the profile name instead of opening a shell. The command consists of all arguments following the profile name.

### stop

`pallium stop my_profile` stops a session and terminates all programs inside the session.

### cp
`pallium cp my_profile:/tmp/file.txt /tmp/file.txt` copies a file from within the `my_profile` sandbox to the host. The
command supports recursive copying of directories through the `-r` flag.

### mv
The `pallium mv` command works analogously to the copy command but moves files and directories instead of copying them.


## Demo

![screen capture](https://cysec.biz/projects/pallium/compressed.gif)

The above demo illustrates the functionality of the `run` and `shell` commands. Inside a normal shell, we use the API of
the Tor Project to confirm that the network traffic is currently not routed through Tor. After displaying the
configuration file of the pallium profile called `demo`, we use the `run` command, which creates a pallium session and
launches a shell inside. Inside the session, we use `curl` again to confirm that the traffic is now routed through Tor.
In a second shell spawned by `tmux`, we demonstrate the use of the `shell` command, spawning a bash inside the session
running on the left side. You can see that upon running `curl` inside the session in the right `tmux` panel, the
connection establishment is logged on the left side.

## GUI Commands and Audio

When using GUI programs with pallium as another user on a standard Linux desktop, problems with X server permissions and
access to the pulseaudio daemon may arise. When specifying `gui: true` and `audio: true` inside the `sandbox` object
in the configuration file, pallium will attempt to overcome these problems. By default, pallium uses
[Xpra](https://xpra.org/) to create a nested X11 server. This provides more isolation compared to just exposing the X11
socket inside the  container.
To relay audio, a Unix socket proxy to the pulseaudio daemon of the calling user is established.

These features are currently considered experimental.


## Security
First of all, **do not set the SUID bit on pallium binaries**. Pallium is not meant to be a SUID executable.

You are responsible for keeping secrets inside pallium configuration files safe by ensuring that only authorized users
may read the files.

Pallium will not magically anonymize your traffic. Applications and virtual machines routing their traffic through the
configured cascade may expose sensitive information, such as installation identifiers or hardware fingerprints. In
particular, running a normal web browser through Tor inside the application namespace is **not an alternative to the Tor
Browser**. Furthermore, **custom chains are not an alternative to Tor**.

Be aware that pallium, by default, only makes use of network namespace isolation.
This particularly affects GUI programs that detect running program instances and perform actions in these instances.
As an example, consider a web browser running normally as your main user in the default network namespace.
When you then instruct the browser to open a URL from a pallium profile that is running as your main user as well,
it will likely open that URL inside the instance running in the default network namespace.
To overcome this problem, you can make use of the virtual user feature or use real user isolation with root privileges.
