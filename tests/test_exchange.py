#Nathan Todd
#Program: test_exchange
#Complete exchange tests: key agreement, authentication, every listed attack and session state.

import unittest

from authentication import create_identity
from errors import AuthenticationError, ProtocolError
from eve import (corrupt_signature, intercept, sign_as_eve, substitute_bob_public, tamper,
                 unauthenticated_mitm)
from participant import Participant
from protocol import Initiator, create_parties, honest_network, pack, run_exchange

FIXTURE = (23, 5, 6)


class TestKeyAgreement(unittest.TestCase):
    def test_fixed_p23_example(self):
        alice, bob = create_parties(allow_fixture=True, fixture_private=15)
        run_exchange(alice, bob, fixture=FIXTURE)
        self.assertEqual(alice.transcript["A"], 8)
        self.assertEqual(alice.transcript["B"], 19)
        self.assertEqual(alice.shared_secret, 2)
        self.assertEqual(bob.shared_secret, 2)
        self.assertTrue(bob.authenticated)

    def test_fixture_rejected_without_fixture_path(self):
        alice, bob = create_parties()
        with self.assertRaisesRegex(ProtocolError, "modulus"):
            run_exchange(alice, bob, fixture=FIXTURE)
        self.assertEqual(alice.checks["Received modulus library validation"], "FAIL")

    def test_generated_exchanges(self):
        for bits in (16, 24, 32):
            for _ in range(3):
                alice, bob = create_parties()
                run_exchange(alice, bob, bits)
                self.assertEqual(alice.transcript["p"].bit_length(), bits)
                self.assertTrue(bob.authenticated)
                self.assertIsNotNone(alice.shared_secret)
                self.assertEqual(alice.shared_secret, bob.shared_secret)

    def test_all_checks_recorded(self):
        alice, bob = create_parties()
        run_exchange(alice, bob)
        self.assertEqual(alice.checks, {
            "Alice initiation signature": "VALID",
            "Received modulus library validation": "PASS",
            "Generator": "validated",
            "Bob response signature": "VALID",
            "Alice finish signature": "VALID",
            "Transcript authenticated": "YES",
        })

    def test_fresh_values_each_exchange(self):
        alice, bob = create_parties()
        first = intercept(run_exchange(alice, bob)[1])[0]["transcript"]
        second = intercept(run_exchange(alice, bob)[1])[0]["transcript"]
        self.assertNotEqual(first["nonce_A"], second["nonce_A"])
        self.assertNotEqual(first["nonce_B"], second["nonce_B"])


class TestUnauthenticatedAttack(unittest.TestCase):
    def test_eve_learns_both_secrets(self):
        r = unauthenticated_mitm(23, 5, a=6, b=15, e1=3, e2=7)
        self.assertEqual((r["E1"], r["E2"]), (10, 17))
        self.assertEqual(r["alice_secret"], 6)
        self.assertEqual(r["eve_with_alice"], 6)
        self.assertEqual(r["bob_secret"], 15)
        self.assertEqual(r["eve_with_bob"], 15)
        self.assertNotEqual(r["alice_secret"], r["bob_secret"])


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = create_parties()

    def assert_alice_cleared(self):
        self.assertIsNone(self.alice.pending)
        self.assertIsNone(self.alice.shared_secret)

    def assert_bob_cleared(self):
        self.assertIsNone(self.bob.pending)
        self.assertIsNone(self.bob.shared_secret)
        self.assertFalse(self.bob.authenticated)

    #Eve's B=17 for B=19 example, done on the p=23 fixture.
    def test_modify_b_keeps_signature(self):
        alice, bob = create_parties(allow_fixture=True, fixture_private=15)
        with self.assertRaises(AuthenticationError):
            run_exchange(alice, bob, network=substitute_bob_public(17), fixture=FIXTURE)
        self.assertEqual(alice.checks["Bob response signature"], "INVALID")
        self.assertIsNone(alice.shared_secret)

    def test_modify_b_generated(self):
        response = self.bob.handle_init(self.alice.start())
        b = intercept(response)[0]["transcript"]["B"]
        with self.assertRaises(AuthenticationError):
            self.alice.handle_response(tamper(response, "B", b + 1 if b < 30000 else b - 1))
        self.assert_alice_cleared()

    def test_modify_a_in_init(self):
        init = self.alice.start()
        a = intercept(init)[0]["A"]
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(tamper(init, "A", a + 1 if a < 30000 else a - 1))
        self.assertEqual(self.bob.checks["Alice initiation signature"], "INVALID")
        self.assert_bob_cleared()

    #Changing A in Bob's echoed transcript fails Alice's session match before any signature check.
    def test_modify_a_in_response(self):
        response = self.bob.handle_init(self.alice.start())
        with self.assertRaisesRegex(ProtocolError, "A does not match"):
            self.alice.handle_response(tamper(response, "A", 1234))
        self.assert_alice_cleared()

    def test_modify_p(self):
        init = self.alice.start()
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(tamper(init, "p", 65537))
        self.assert_bob_cleared()

    def test_modify_g(self):
        init = self.alice.start()
        g = intercept(init)[0]["g"]
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(tamper(init, "g", g + 1))

    def test_modify_identity_labels(self):
        init = self.alice.start()
        with self.assertRaisesRegex(ProtocolError, "initiator"):
            self.bob.handle_init(tamper(init, "initiator", "Eve"))
        response = self.bob.handle_init(self.alice.start())
        with self.assertRaisesRegex(ProtocolError, "responder"):
            self.alice.handle_response(tamper(response, "responder", "Eve"))

    def test_corrupt_signature(self):
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(corrupt_signature(self.alice.start()))
        response = self.bob.handle_init(self.alice.start())
        with self.assertRaises(AuthenticationError):
            self.alice.handle_response(corrupt_signature(response))
        response = self.bob.handle_init(self.alice.start())
        finish = self.alice.handle_response(response)
        with self.assertRaises(AuthenticationError):
            self.bob.handle_finish(corrupt_signature(finish))
        self.assert_bob_cleared()

    #Eve signs an init labeled "Alice" with her own key; Bob checks it against Alice's trusted key.
    def test_sign_as_alice_with_eve_key(self):
        payload = intercept(self.alice.start())[0]
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(sign_as_eve(payload))
        self.assertEqual(self.bob.checks["Alice initiation signature"], "INVALID")

    #A whole fake Alice built on Eve's key fails the same way.
    def test_wrong_trusted_key(self):
        fake_alice = Initiator(Participant("Alice", create_identity(), {}))
        with self.assertRaises(AuthenticationError):
            self.bob.handle_init(fake_alice.start())

    def test_untrusted_signer_name(self):
        _, bob = create_parties()
        bob.participant.trusted_keys.clear()
        with self.assertRaisesRegex(AuthenticationError, "no trusted key"):
            bob.handle_init(self.alice.start())


class TestSessionState(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = create_parties()

    def test_replay_old_response_into_fresh_alice_session(self):
        _, old_response, _ = run_exchange(self.alice, self.bob)
        self.alice.start()
        with self.assertRaisesRegex(ProtocolError, "does not match the pending session"):
            self.alice.handle_response(old_response)
        self.assertIsNone(self.alice.shared_secret)

    def test_replay_old_finish_into_fresh_bob_session(self):
        _, _, old_finish = run_exchange(self.alice, self.bob)
        self.bob.handle_init(self.alice.start())
        with self.assertRaisesRegex(ProtocolError, "does not match the pending transcript"):
            self.bob.handle_finish(old_finish)
        self.assertFalse(self.bob.authenticated)

    #An old init still gets a fresh response, but the old finish cannot complete it.
    def test_replay_old_init_cannot_complete(self):
        old_init, _, old_finish = run_exchange(self.alice, self.bob)
        new_response = self.bob.handle_init(old_init)
        self.assertIsNotNone(new_response)
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(old_finish)
        self.assertFalse(self.bob.authenticated)

    def test_duplicate_finish_after_completion(self):
        _, _, finish = run_exchange(self.alice, self.bob)
        secret = self.bob.shared_secret
        with self.assertRaisesRegex(ProtocolError, "already completed"):
            self.bob.handle_finish(finish)
        #The completed session is left as it was.
        self.assertEqual(self.bob.shared_secret, secret)

    def test_duplicate_response_after_finish(self):
        response = self.bob.handle_init(self.alice.start())
        self.alice.handle_response(response)
        with self.assertRaisesRegex(ProtocolError, "no pending session"):
            self.alice.handle_response(response)

    def test_wrong_order_response_before_init(self):
        alice, bob = create_parties()
        response = self.bob.handle_init(self.alice.start())
        with self.assertRaisesRegex(ProtocolError, "no pending session"):
            alice.handle_response(response)

    def test_wrong_order_finish_before_init(self):
        _, _, finish = run_exchange(self.alice, self.bob)
        _, fresh_bob = create_parties()
        with self.assertRaisesRegex(ProtocolError, "no pending session"):
            fresh_bob.handle_finish(finish)

    #Sending a message where a different type is expected is rejected by the schema.
    def test_wrong_message_type_for_stage(self):
        init = self.alice.start()
        response = self.bob.handle_init(init)
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(response)
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(response)

    def test_malformed_and_oversized_messages(self):
        response = self.bob.handle_init(self.alice.start())
        for data in (b"{}", b"garbage", b"x" * 5000, pack({"message_type": "response"}, "ab" * 64)):
            with self.assertRaises(ProtocolError):
                self.bob.handle_finish(data)
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(b"x" * 5000)

    def test_rejection_clears_bob_session(self):
        self.bob.handle_init(self.alice.start())
        self.assertIsNotNone(self.bob.pending)
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(b"garbage")
        self.assertIsNone(self.bob.pending)

    def test_honest_network_is_identity(self):
        self.assertEqual(honest_network("init", b"abc"), b"abc")


if __name__ == "__main__":
    unittest.main()
