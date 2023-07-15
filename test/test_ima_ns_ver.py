import unittest
from keylime.cloud_verifier_tornado import sign_and_prep
from keylime.client_verifier_tornado import validate_list



class TestImaNs(unittest.TestCase):

    def test_value_ima(self):

        list = "10 4a18f33e53a6ce5f36e81e22a1493c0e458bb890 ima-ng sha1:b50a8c15b5a24698177e5964c654a67a81f613c6 /usr/lib/modules/5.19.0-46-generic/kernel/net/netfilter/nf_conntrack_netlink.ko 2 3\n10 e8d12380d0a6c7b04cce57d19aec64effda3a40f ima-ng sha1:7572dc56d1ffa96a5697211a8122cc4aaed2a99e /usr/lib/modules/5.19.0-46-generic/kernel/crypto/ccm.ko 2 3\n10 e1fc415694a62a0b05d37e8f6ad47e16949323a2 ima-ng sha1:2565fe405c250d602d9676ae5f274043c22303de /usr/lib/modules/5.19.0-46-generic/kernel/net/tls/tls.ko 2 3\n"

        message = sign_and_prep(str.encode(list), "/home/lo/Documents/thesis/keylime/test/data/ima_keys/rsa2048.pem")
        print(message["signature"])

        result = validate_list(list.split('\n'), 1, 1)
        print(result)

        self.assertFalse(False)