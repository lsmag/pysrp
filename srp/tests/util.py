# -*- coding: utf-8 -*-
import unittest

from srp import _pysrp


class TestCase(unittest.TestCase):
    def doit(self, module, *args, **kwargs):
        return self.doit_multi(module, module, module, *args, **kwargs)
    
    def doit_multi(self, u_mod, v_mod, g_mod, hash_alg=_pysrp.SHA1, ng_type=_pysrp.NG_2048, n_hex='', g_hex=''):
        User                           = u_mod.User
        Verifier                       = v_mod.Verifier
        create_salted_verification_key = g_mod.create_salted_verification_key

        username = 'testuser'
        password = 'testpassword'

        _s, _v = create_salted_verification_key( username, password, hash_alg, ng_type, n_hex, g_hex )

        usr      = User( username, password, hash_alg, ng_type, n_hex, g_hex )
        bytes_a  = usr.get_ephemeral_secret()
        uname, A = usr.start_authentication()

        # Make sure a recreated User does all the same appropriate things
        usr2     = User( username, password, hash_alg, ng_type, n_hex, g_hex, bytes_a )
        self.assertEqual(bytes_a, usr2.get_ephemeral_secret())
        uname2, A2 = usr2.start_authentication()
        self.assertEqual(uname, uname2)
        self.assertEqual(A, A2)

        # username, A => server
        svr      = Verifier( uname, _s, _v, A, hash_alg, ng_type, n_hex, g_hex )
        bytes_b  = svr.get_ephemeral_secret()
        s,B      = svr.get_challenge()

        # s,B => client
        M        = usr.process_challenge( s, B )
        M2       = usr2.process_challenge( s, B )
        self.assertEqual(M, M2)

        # M => server
        HAMK     = svr.verify_session( M )

        # Make sure that a recreated Verifier will authenticate appropriately
        svr2     = Verifier( uname, _s, _v, A, hash_alg, ng_type, n_hex, g_hex, bytes_b )
        self.assertEqual(bytes_b, svr2.get_ephemeral_secret())
        HAMK2    = svr2.verify_session( M )
        self.assertEqual(HAMK, HAMK2)

        # HAMK => client
        usr.verify_session( HAMK )
        usr2.verify_session( HAMK )

        self.assertTrue( svr.authenticated() )
        self.assertTrue( svr2.authenticated() )

        self.assertTrue( usr.authenticated() )
        self.assertTrue( svr2.authenticated() )
