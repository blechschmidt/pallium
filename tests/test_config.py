import dataclasses
import typing
import unittest

import pallium.config
import pallium.hops.tor


class PalliumTestCase(unittest.TestCase):
    @staticmethod
    def test_json_serializable():
        @pallium.config.json_serializable
        @dataclasses.dataclass
        class TestClass:
            a: int
            b: typing.List[int]

        instance = TestClass.from_json({'a': 1, 'b': [1, 2, 3]})
        assert instance.a == 1
        assert instance.b == [1, 2, 3]

    @staticmethod
    def test_sandbox_config():
        conf = pallium.config.Configuration.from_json({
            'sandbox': {
                'gui': True,
                'virtuser': '$tmp'
            }
        })
        assert isinstance(conf.sandbox, pallium.config.Sandbox)

    @staticmethod
    def test_config():
        json = {
            'networking': {
                'chain': [
                    {
                        'type': 'socks',
                        'address': '127.0.0.1:1080',
                        'username': 'johndoe',
                        'password': 'secret'
                    }
                ]
            }
        }
        config = pallium.config.Configuration.from_json(json)

        assert config.run.quiet is False
        assert len(config.networking.chain) == 1
        assert isinstance(config.networking.chain[0], pallium.hops.socks.SocksHop)
        assert config.networking.chain[0].username == 'johndoe'
        assert config.networking.chain[0].password == 'secret'
        assert config.networking.bridge is None


if __name__ == '__main__':
    unittest.main()
