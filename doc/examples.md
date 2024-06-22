# Examples
This document provides some examples of how pallium can be used.

## Virtual users

Assuming that your username on the host system is `you`, first create a profile with the following content at
`~/.config/pallium/profiles/john.json`:

```json
{
  "sandbox": {
    "files": {
      "bind": [["/mnt", "/home/you/Downloads"]]
    },
    "virtuser": "johndoe"
  }
}
```
This will create a virtual user named `johndoe` whose home is stored at `~/.config/pallium/virtuser/johndoe/home`.

You can now run the profile:
```
[you@computer /]$ ls /home/you/Downloads
file1 file2
[you@computer /]$ pallium run john
WARNING: Support for IPv6 is experimental
sent tapfd=5 for pmQratkj1H1
received tapfd=5
Starting slirp
* MTU:             1500
* Network:         10.0.2.0
* Netmask:         255.255.255.0
* Gateway:         10.0.2.2
* DNS:             10.0.2.3
* DHCP begin:      10.0.2.15
* DHCP end:        10.0.2.30
* Recommended IP:  10.0.2.100
[johndoe@pallium ~]$ id
uid=1000(johndoe) gid=1000(johndoe) groups=1000(johndoe),65534(nobody)
[johndoe@pallium ~]$ pwd
/home/johndoe
[johndoe@pallium ~]$ ls /mnt
file1 file2
```
As you can see, your `Downloads` folder is available inside the sandbox under `/mnt`.

## Debugging network traffic
When debugging an application with tools like Wireshark, it is sometimes laborious to identify the traffic of the
application under test. Assume you want to inspect TLS traffic of `curl` while your browser is running in the
background, also generating a lot of TLS traffic.
In this case, you can leverage the [Wireshark script](/extra/scripts/wireshark) as follows:
```shell
echo '{}' | pallium exec --root - ./extra/scripts/wireshark curl https://example.org
```
As you can see, instead of supplying a name or a file path to a profile, you can also define a profile through stdin if
`-` is passed as the profile name. Here, we use the empty profile which only sets up the namespaces required to get
connectivity through the default namespace and run the Wireshark script inside the application namespace as root.
(As we make use of unprivileged user namespaces, this does not mean that you need to have root privileges on the host.)
The script will start `tcpdump`, execute its arguments and then open the packet capture inside Wireshark.
With the help of some [NFLOG](https://wiki.wireshark.org/CaptureSetup/NFLOG.md) filter rules, the noise inside the
packet capture is eliminated.

## Unprivileged Zoom sandbox
The following is an example for running Zoom in a pallium sandbox. In this case, pallium makes use of
[Xpra](https://xpra.org/) to create a new isolated X11 session for security reasons.
We also start a proxy for pulseaudio and whitelist some paths which Zooms relies on.
```json
{
  "sandbox": {
    "gui": true,
    "audio": true,
    "virtuser": "zoom",
    "paths": {
      "whitelist": [
        "/opt/zoom",
        "/dev/video*"
      ]
    }
  },
  "run": {
    "command": "zoom"
  }
}
```

## Hardened browser
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
Persistence in this case means that pallium will automatically create a user home for the `browser` user at
`~/.config/pallium/virtuser/browser` on the host. The special value `$tmp` can be supplied as the value of the
`virtuser` property to cause the user home to only live in memory.

## Running a BitTorrent client behind a VPN
The following profile starts [transmission-gtk](https://transmissionbt.com/) and routes its traffic through OpenVPN.
```json
{
  "network": {
    "chain": [
      {
        "type": "openvpn",
        "config": "/home/you/openvpn.ovpn"
      }
    ]
  },
  "run": {
    "command": "transmission-gtk"
  }
}
```
In this case, we do not need to specify the `gui` property inside a `sandbox` object because we do not use additional
isolation features. The X11 socket of the host as well as all other files are therefore generally available inside the
application namespace.

## Running a virtual machine behind Tor
Due to a network bridge being created in the default network namespace, this profile requires superuser privileges.
Therefore, it is placed in `/etc/pallium/profiles` instead of `~/.config/pallium/profiles` and pallium needs to be run
as root.
```json
{
  "network": {
    "chain": [
      {
        "type": "tor"
      }
    ],
    "bridge": {
      "name": "torbr",
      "dhcp": true
    }
  }
}
```
In the settings of your virtual machine, you can then choose the `torbr` as a bridged adapter for the virtual machine.
Note that depending on what you run inside the VM, **this setup may leak hardware fingerprints of your machine**.
