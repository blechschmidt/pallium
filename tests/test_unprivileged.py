import os
import select
import signal
import struct
import subprocess
import tempfile
import unittest
import http.server

import pallium.sysutil
from pallium import sysutil, onexit
from pallium.profiles import Profile
import pallium.config as config


class PalliumTestCase(unittest.TestCase):
    def test_gui(self):
        UID = 0xffff
        read, write = os.pipe()

        class TestServer(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                os.write(write, b'1')
                self.send_response(204)
                self.end_headers()

        conf = config.Configuration.from_json({
            'sandbox': {
                'gui': True,
                'virtuser': '$tmp'
            }
        })
        profile = Profile(conf)
        session = profile.run()

        def run():
            pid = os.fork()
            if pid == 0:
                sysutil.prctl(sysutil.PR_SET_PDEATHSIG, signal.SIGTERM)
                os.close(read)
                server = http.server.HTTPServer(('127.0.0.1', 0), TestServer)
                _, port = server.socket.getsockname()
                url = 'http://127.0.0.1:%d/test' % port
                pallium.sysutil.write_blocking(write, struct.pack('I', len(url.encode())))
                pallium.sysutil.write_blocking(write, url.encode())
                server.serve_forever()
            else:
                os.close(write)
                url_len = struct.unpack('I', pallium.sysutil.read_blocking(read, 4))[0]
                url = pallium.sysutil.read_blocking(read, url_len).decode()

                """def drop_privs():
                    os.setgid(UID)
                    os.setuid(UID)
                home = tempfile.mkdtemp(prefix='pallium_cli_test_gui_')
                os.chown(home, UID, UID)"""
                os.environ['HOME'] = '/tmp'
                # p = subprocess.Popen(['id'])
                p = subprocess.Popen(['firefox', url])
                onexit.register(lambda: os.kill(p.pid, signal.SIGTERM))
                rlist, _, _ = select.select([read], [], [], 30)
                assert read in rlist
                assert pallium.sysutil.read_blocking(read, 1) == b'1'
                os.kill(p.pid, signal.SIGTERM)
                os.kill(pid, signal.SIGTERM)

        session.network_namespaces[-1].run(run)


if __name__ == '__main__':
    unittest.main()
