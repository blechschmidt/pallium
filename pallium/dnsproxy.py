import errno
import ipaddress
import random
import select
import signal
import socket
import struct
import os
import threading
import time

from . import util, sysutil, security
from . import resolvconf
from . import onexit

# TODO: Improve performance by preopening and reusing TCP connections.


class ProxyState:
    def __init__(self, data: bytes, dns_client_addr, proxy_socket):
        self.sent = False
        self.time = time.time()
        self.data = data
        self.address = dns_client_addr
        self.udp = proxy_socket


class DnsTcpProxy:
    def __init__(self, local, remote, total_timeout=30):
        self._local = local
        self._remote = remote
        self._local_sockets = set()
        self._remote_sockets = set()
        self._write_sockets = set()
        self._all_sockets = set()
        self._terminate = None
        self._todo = dict()
        self._total_timeout = total_timeout

    def _terminate_socket(self, sock):
        self._all_sockets.remove(sock)
        self._remote_sockets.remove(sock)
        if sock in self._write_sockets:
            self._write_sockets.remove(sock)
        if sock in self._todo:
            del self._todo[sock]
        try:
            sock.close()
        except IOError:
            pass

    def _run(self):
        for local in self._local:
            addr = ipaddress.ip_address(local[0])
            sock = socket.socket(socket.AF_INET if addr.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind((str(local[0]), local[1]))
            self._local_sockets.add(sock)

        self._all_sockets = self._local_sockets.union(self._remote_sockets)

        while True:
            if self._terminate is not None and self._terminate.is_set():
                return
            rlist, wlist, xlist = select.select(self._all_sockets, self._write_sockets, [], 100)

            for r in rlist:
                data, source = r.recvfrom(0xFFFF)

                if r in self._local_sockets:
                    remote_address = random.choice(self._remote)
                    addr = ipaddress.ip_address(remote_address[0])
                    sock = socket.socket(socket.AF_INET if addr.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    try:
                        sock.connect(remote_address)
                    except BlockingIOError as e:
                        if e.errno != errno.EINPROGRESS:
                            raise e
                    self._remote_sockets.add(sock)
                    self._write_sockets.add(sock)
                    self._all_sockets.add(sock)
                    self._todo[sock] = ProxyState(struct.pack('!H', len(data)) + data, source, r)

                elif r in self._remote_sockets:
                    if r not in self._todo:
                        continue
                    state = self._todo[r]
                    state.data += data
                    if len(state.data) >= 2:
                        dgram_size = struct.unpack('!H', state.data[:2])[0]
                        if len(state.data) >= 2 + dgram_size:
                            state.udp.sendto(state.data[2:], state.address)
                            self._terminate_socket(r)

            for w in wlist:
                if w not in self._todo or self._todo[w].sent:
                    continue

                t = self._todo[w]
                sent = w.sendto(t.data, t.address)
                t.data = t.data[sent:]

                if len(t.data) == 0:
                    self._todo[w].sent = True
                    self._write_sockets.remove(w)
            tkeys = [k for k in self._todo.keys()]
            for t in tkeys:
                if time.time() - self._todo[t].time > self._total_timeout:
                    self._terminate_socket(t)

    def start(self, threaded=True):
        if not threaded:
            self._run()
        else:
            self._terminate = threading.Event()
            t = threading.Thread(target=self._run)
            t.start()

    def stop(self):
        self._terminate.set()


def setup_dns_tcp_proxy(addresses, non_proxied_addrs=None, bind_addr='127.0.0.1', threaded=False, forked=True):
    assert not (forked and threaded)
    if non_proxied_addrs is None:
        non_proxied_addrs = []
    if not isinstance(addresses, list) and not isinstance(addresses, set):
        addresses = [addresses]
    parsed = []
    for addr in addresses:
        ip, port = util.convert2addr(addr, 1053)
        parsed.append((str(ip), port,))

    def f():
        resolvconf.write_resolv_conf([bind_addr] + list(non_proxied_addrs))
        proxy = DnsTcpProxy([util.convert2addr(bind_addr, 53)], parsed)
        child = os.fork() if forked else None
        if not forked or forked and child == 0:
            if forked:
                if security.is_sudo_or_root():
                    sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGKILL)
                onexit.clear()
            proxy.start(threaded=threaded)
            if forked:
                # noinspection PyProtectedMember,PyUnresolvedReferences
                os._exit()
        elif forked and child != 0:
            return child

    return f


if __name__ == '__main__':
    def main():
        proxy = DnsTcpProxy([('127.0.0.1', 1053)], [('1.1.1.1', 53)])
        proxy.start(False)

    main()
