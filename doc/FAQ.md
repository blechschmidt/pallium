# FAQ
## How can you claim protection against Linux kernel exploits?
[gVisor](https://github.com/google/gvisor) is an implementation of (a substantial part of) the Linux kernel in Go.
It runs as a userspace program on a normal Linux kernel and intercepts system calls (for example through ptrace or KVM).
Instead of simply passing the syscalls to the host kernel, their functionality is implemented in gVisor itself.
As a consequence, applications running inside gVisor profit from a kernel with Go's memory safety guarantees.
Exploits that breach the Linux kernel are unlikely to work inside gVisor as well.
This is only a very brief explanation. More information on this topic can be found on the
[gVisor website](https://gvisor.dev/docs/).

## How does pallium compare to other sandboxing projects?
The following table attempts to provide a fair comparison to other sandboxing solutions. Please feel free to submit a PR
in case you think that the comparison is erroneous, biased, or missing important features.

| Feature                               | pallium             | firejail           | bubblewrap         |
|---------------------------------------|---------------------|--------------------|--------------------|
| Rootless sandboxing                   | :heavy_check_mark:¹ | :x:                | :heavy_check_mark: |
| Network hop chaining                  | :heavy_check_mark:  | :x:                | :x:                |
| Support for kernel exploit protection | :heavy_check_mark:  | :x:                | :x:                |
| Ready-to-use application profiles     | :x:                 | :heavy_check_mark: | :x:                |
| Advanced seccomp support              | :x:                 | :heavy_check_mark: | :heavy_check_mark: |

¹ Not all operations are supported without root privileges, but pallium never requires to be SUID.

## How does pallium relate to Docker, Kubernetes or gVisor?
Under the hood, pallium uses the primitives provided by the Linux kernel that are also used by Docker or Kubernetes.
Specifically, this includes namespaces, such as user, mount, network and PID namespaces. Pallium mainly differs in that
it does not require or support container images. Instead, the host file system is used, or a restricted version thereof.
The gVisor application layer kernel is simply executed in that environment.

## What are your future ideas for pallium?
- Pallium should support port forwarding, allowing Internet-facing applications to be sandboxed.
Implementing this should not be a huge problem (privileged ports will be a small challenge),
but it simply has not been done yet. Ideally, this feature would use
[slirpnetstack](https://github.com/cloudflare/slirpnetstack) because it is implemented in a memory-safe language and
supports IPv6 (in contrast to [slirp4netns](https://github.com/rootless-containers/slirp4netns)).
- Check whether it would be feasible to support the installation of packages onto an overlayfs inside an unprivileged
user namespace. [This question](https://unix.stackexchange.com/a/614546) deals with a similar problem. It could work
in conjunction with a `bindfs` that maps the overflown root ID (65534) to 0 inside the namespace.

## How can I contribute?
Contributions are welcome. Please simply send a pull request. Help with packaging for various distros is also wanted
and very welcome.

Considering feature requests, it would be great if you could make a serious attempt at implementing the requested
feature yourself and submit it as a pull request.

## Why is it called pallium?
Pallium is named after [the Roman cloak](https://en.wikipedia.org/wiki/Pallium_(Roman_cloak)). Like a cloak, pallium is
supposed to provide a reasonable level of protection.

## Why is it programmed in Python?
The project started out as a simple script which was straightforward to write in Python. Python has the advantage that
it is present on many systems while it does not require an additional compiler. Using the pallium API is therefore very
uncomplicated. The disadvantage is that if pallium requires privileged helpers in the future (e.g. port forwarding),
this may require hacky workarounds (such as standalone binaries provided through PyInstaller).
