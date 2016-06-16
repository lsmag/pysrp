# -*- coding: utf-8 -*-
import unittest
from .util import TestCase

try:
    from srp import _srp
    CAN_LOAD_CSRP = True
except ImportError:
    CAN_LOAD_CSRP = False

try:
    from srp import _ctsrp
    CAN_LOAD_CTSRP = True
except ImportError:
    CAN_LOAD_CTSRP = False

from srp import _pysrp


test_g_hex = "2"
test_n_hex = '''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'''


# @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
class CSRPTest(TestCase):
    def test_pure_python_defaults(self):
        self.doit( _pysrp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    def test_ctypes_defaults(self):
        self.doit( _ctsrp )

    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_c_defaults(self):
        self.doit( _srp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix1(self):
        self.doit_multi( _pysrp, _ctsrp, _srp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix2(self):
        self.doit_multi( _pysrp, _srp, _ctsrp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix3(self):
        self.doit_multi( _ctsrp, _pysrp, _srp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix4(self):
        self.doit_multi( _ctsrp, _srp, _pysrp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix5(self):
        self.doit_multi( _srp, _pysrp, _ctsrp )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_mix6(self):
        self.doit_multi( _srp, _ctsrp, _pysrp )

    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_hash_SHA512(self):
        self.doit( _srp, hash_alg=_pysrp.SHA512 )

    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_NG_8192(self):
        self.doit( _srp, ng_type=_pysrp.NG_8192 )

    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_NG_CUSTOM(self):
        self.doit( _srp, ng_type=_pysrp.NG_CUSTOM, n_hex=test_n_hex, g_hex=test_g_hex )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_all1(self):
        self.doit_multi( _srp, _pysrp, _ctsrp, hash_alg=_pysrp.SHA256, ng_type=_pysrp.NG_CUSTOM, n_hex=test_n_hex, g_hex=test_g_hex )

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_all2(self):
        self.doit_multi( _ctsrp, _pysrp, _srp, hash_alg=_pysrp.SHA224, ng_type=_pysrp.NG_4096 )

    def test_random_of_length(self):
        """
        Verify that the Python implementation guarantees byte length by
        setting most significant bit to 1
        """
        for x in range(10):
            val = _pysrp.get_random_of_length(32)
            self.assertTrue(val >> 255 == 1)

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_ephemeral_length(self):
        """
        Verify that all implementations require 32 bytes for ephemeral values
        """
        random31 = _pysrp.long_to_bytes(_pysrp.get_random_of_length(31))
        random33 = _pysrp.long_to_bytes(_pysrp.get_random_of_length(33))

        def verf_len(mod, val):
            with self.assertRaises(ValueError) as ctx:
                mod.User('uname', 'pwd', bytes_a=val)
            self.assertIn('bytes_a', ctx.exception.message)

            with self.assertRaises(ValueError) as ctx:
                mod.Verifier('uname', random31, random31, random31, bytes_b=val)
            self.assertIn('bytes_b', ctx.exception.message)

        for mod in [_srp, _ctsrp, _pysrp]:
            for val in [random31, random33]:
                verf_len(mod, val)

    @unittest.skipIf(not CAN_LOAD_CTSRP, "Can't load CTSRP in this environment")
    @unittest.skipIf(not CAN_LOAD_CSRP, "Can't load CSRP in this environment")
    def test_authenticated_on_init(self):
        usr = _pysrp.User('test', 'test')
        self.assertTrue(not usr.authenticated())

        usr = _ctsrp.User('test', 'test')
        self.assertTrue(not usr.authenticated())

        usr = _srp.User('test', 'test')
        self.assertTrue(not usr.authenticated())
