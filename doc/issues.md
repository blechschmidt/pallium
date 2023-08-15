# Known issues
## IP forwarding
IP forwarding is currently (partially) broken. This affects bridging and causes the CI pipeline to fail.
In the long term, the goal is to implement support for packet marking in `slirp4netns` and `slirpnetstack`, so that
pallium no longer needs to rely on IP forwarding. Fixing this is not difficult, but it requires some care to not turn
the machine into an open forwarder.

## gVisor
gVisor may not work with profiles that do not make use of virtual users.

## Others
There may be other issues that have not been documented so far.
