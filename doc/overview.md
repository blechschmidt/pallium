# Profiles

Pallium profiles are defined by JSON objects in files with `.json` file extension located in `~/.config/pallium/profiles/`.
When run as root, the profile folder is `/etc/pallium/profiles/` instead.
The name of a profile is its file name without its file extension.

Profiles support the `run` operation, which launches a session. When a session is launched,
the chain is built and applications can be run  inside that session.
For chains with Tor hops this means that one session corresponds to one Tor circuit.

## Chain definition

The chain of hops is defined using the `chain` property. It is an array of objects, where each object has a `type`
property that specifies the type of hop as a string. Currently, the following types are supported:

* OpenVPN
* SOCKS
    * Tor
    * SSH
* HTTP (`CONNECT` method)
* WireGuard

### General properties for hops

All hops support the following properties:

| Name | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| dns  | IP addresses of DNS servers as an array of strings.<br/>If an IP is prefixed with `tcp://`, a UDP to TCP proxy is set up and used for resolving. This is particularly useful in case UDP is not supported and DNS is not provided out of the box, which is often the case for SOCKS proxies.<br/>The IP addresses derived from this property are used to populate the `/etc/resolv.conf` file mounted inside the next namespace. The property overrides the default DNS servers provided by a hop. |

### OpenVPN

| Name         | Value                                          |
|--------------|------------------------------------------------|
| **type**     | `openvpn`                                      |
| **config**   | Path to the OpenVPN client configuration file. |
| username     | OpenVPN username.                              |
| password     | OpenVPN password.                              |
| openvpn_path | Custom path to the OpenVPN binary.             |

### SOCKS

Currently, remote DNS is not supported for SOCKS proxies. Therefore, the `dns` property of the hop has to be
specified manually for full DNS functionality.

| Name           | Value                                |
|----------------|--------------------------------------|
| **type**       | `socks`                              |
| **address**    | Server address in IP:port format.    |
| username       | Username for server authentication.  |
| password       | Password for server authentication.  |
| tun2socks_path | Custom path to the tun2socks binary. |

### HTTP

As for SOCKS, remote DNS is not supported for HTTP proxies. Therefore, the `dns` property of the hop has to be
specified manually for full DNS functionality.

| Name           | Value                                |
|----------------|--------------------------------------|
| **type**       | `http`                               |
| **address**    | Server address in IP:port format.    |
| username       | Username for server authentication.  |
| password       | Password for server authentication.  |
| tun2socks_path | Custom path to the tun2socks binary. |

### Tor

As pallium uses Tor through its SOCKS5 interface, the Tor hop relies on the external binary dependencies also required
for SOCKS5.

| Name     | Value                                         |
|----------|-----------------------------------------------|
| **type** | `tor`                                         |
| user     | User name for the tor daemon (`--User` flag). |
| tor_args | Array of custom command line arguments.       |
| tor_path | Custom path to the Tor binary.                |

By default, the Tor hop will provide the next namespace with a DNS server which supports resolving `.onion` domains.

### WireGuard

WireGuard will make use of the Linux kernel implementation. Therefore, it does not require external dependencies.

| Name       | Value                                     |
|------------|-------------------------------------------|
| **type**   | `wireguard`                               |
| **config** | Path to the WireGuard configuration file. |


## Sandbox

The sandbox feature is currently in an early stage of development. It is **unstable and details may change**.
The sandbox is either used when a virtual user is configured or when the `files` property is defined.

### Virtual Users
In unprivileged mode, pallium allows you to make use of virtual users. A virtual user is identified by a username.
When making use of a virtual user, mount and pid namespaces are used in an effort to isolate the virtual user by
mounting tempfs or special file systems over commonly shared locations, such as `/tmp`, `/var/cache`, `/dev/shm`,
`/run`, etc. In addition, a persistent home directory for the virtual user is created at
`~/.config/pallium/virtuser/<virtuser-name>/home`, which is mounted over the original user's home.

To make use of a virtual user, define an object called `virtuser` with the desired username as `name` property inside a
`sandbox` object as described in the table below. Alternatively, you can simply supply a username as a string.

| Name     | Value                                                                                                |
|----------|------------------------------------------------------------------------------------------------------|
| **name** | User name of the virtual user.                                                                       |
| skeleton | Path to directory which is copied to the user's home directory upon creation. (Default: `/etc/skel`) |

The virtual user feature makes use of unprivileged user namespaces and user namespace nesting. First, an unprivileged
user namespace is created, in which the original user is mapped to UID 0 to serve as an administrative user namespace.
Inside this administrative user namespace, network, mount and
pid namespaces are set up to isolate everything running inside.
In a second step, another user namespace is created inside these namespaces as a child of the administrative namespace
and UID 0 is mapped back to the UID of the original user. This ensures that code inside the child namespace cannot
tamper with the configuration of the administrative namespace.

If you supply the special value `$tmp` as the name of the virtual user, the virtual user will be temporary.
In this came, no persistent home directory will be created at `~/.config/pallium/virtuser/`. Instead, a `tmpfs` file
system will be used as the user's home inside the container.

### File System
TODO

## Bridging

When **run as root**, pallium supports exposing an ethernet bridge to your default network namespace. This enables you
to route the traffic of your entire system or single virtual machines through pallium.

To enable a bridge, add a `bridge` property to a profile. The following name/value pairs are supported:

| Name   | Value                                                                                                                                                         |
|--------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name   | The name of the bridge, which is exposed in the default network namespace.                                                                                    |
| dhcp   | If set to `true`, `dnsmasq` will be used as a DHP server for the bridge. This should be enabled if you wish to route virtual machine traffic through pallium. |
| routes | A string array of CIDR notations. If the array is not empty, the specified networks are added as routes via the bridge to the default network namespace.      |

To route traffic from the default network namespace through the bridge, pallium makes use of a trick. As the IP
addresses of entry nodes are not tracked by pallium (because that would require tracking Tor circuits, parsing VPN
configuration file formats or resolving DNS names of proxies), it does not route traffic, like VPN software classically
does, by duplicating the default route for the entry node. Not tracking entry nodes also means that routing loops cannot
be eliminated by classical means when requesting e.g. a default route to be added through the bridge. For this reason, a
second routing table is added to the default network namespace in case traffic is supposed to be routed through the
bridge. Traffic that originates in the default network namespace is then marked to use the secondary routing table,
while traffic that is only forwarded through the default network namespace, which includes the traffic to the entry node
that originates in another namespace, continues to use the default table.
