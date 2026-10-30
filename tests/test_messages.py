#Nathan Todd
#Program: test_messages
#Message validation tests: encoding, schema, types, sizes and malformed input.

import copy
import json
import unittest

from authentication import PROTOCOL, encode_payload
from errors import ProtocolError
from protocol import (MAX_MESSAGE_BYTES, create_parties, pack, unpack, validate_init,
                      validate_signed)

NONCE = "ab" * 32
SIGNATURE = "cd" * 64


def init_payload():
    return {"protocol": PROTOCOL, "message_type": "init", "initiator": "Alice",
            "responder": "Bob", "p": 23, "g": 5, "A": 8, "nonce_A": NONCE}


def response_payload():
    transcript = {"protocol": PROTOCOL, "initiator": "Alice", "responder": "Bob",
                  "p": 23, "g": 5, "A": 8, "B": 19, "nonce_A": NONCE, "nonce_B": "ef" * 32}
    return {"message_type": "response", "transcript": transcript}


class TestEncoding(unittest.TestCase):
    def test_deterministic_json(self):
        self.assertEqual(encode_payload({"p": 23, "g": 5, "A": 8}), b'{"A":8,"g":5,"p":23}')

    def test_round_trip(self):
        payload = init_payload()
        self.assertEqual(unpack(pack(payload, SIGNATURE)), (payload, SIGNATURE))


class TestEnvelope(unittest.TestCase):
    def test_rejects_oversized(self):
        data = b'{"payload":{},"signature":"' + b"a" * MAX_MESSAGE_BYTES + b'"}'
        with self.assertRaisesRegex(ProtocolError, "size"):
            unpack(data)

    def test_rejects_malformed_json(self):
        for data in (b"", b"not json", b'{"payload":', b"\xff\xfe", b"[1,2]"):
            with self.assertRaises(ProtocolError):
                unpack(data)

    def test_rejects_non_bytes(self):
        with self.assertRaises(ProtocolError):
            unpack(pack(init_payload(), SIGNATURE).decode())

    def test_rejects_duplicate_keys(self):
        data = b'{"payload":{},"payload":{},"signature":"' + SIGNATURE.encode() + b'"}'
        with self.assertRaisesRegex(ProtocolError, "duplicate"):
            unpack(data)

    def test_rejects_duplicate_keys_inside_payload(self):
        body = json.dumps(init_payload(), separators=(",", ":"))[:-1] + ',"p":29}'
        data = ('{"payload":' + body + ',"signature":"' + SIGNATURE + '"}').encode()
        with self.assertRaisesRegex(ProtocolError, "duplicate"):
            unpack(data)

    def test_rejects_extra_envelope_field(self):
        data = json.dumps({"payload": {}, "signature": SIGNATURE, "key": "x"}).encode()
        with self.assertRaises(ProtocolError):
            unpack(data)

    def test_rejects_malformed_signature(self):
        for signature in ("ab", SIGNATURE.upper(), "zz" * 64, 12345, None):
            with self.assertRaises(ProtocolError):
                unpack(pack(init_payload(), signature))


class TestInitSchema(unittest.TestCase):
    def test_accepts_valid(self):
        validate_init(init_payload())

    def test_rejects_missing_and_unexpected_fields(self):
        missing = init_payload()
        del missing["A"]
        extra = init_payload()
        extra["private_a"] = 6
        for payload in (missing, extra):
            with self.assertRaises(ProtocolError):
                validate_init(payload)

    #Strings are never coerced to integers.
    def test_rejects_wrong_types(self):
        for field, value in [("p", "23"), ("g", 5.0), ("A", True), ("A", None), ("p", [23])]:
            payload = init_payload()
            payload[field] = value
            with self.assertRaises(ProtocolError):
                validate_init(payload)

    def test_rejects_oversized_integers(self):
        payload = init_payload()
        payload["p"] = 2 ** 64 + 13
        with self.assertRaisesRegex(ProtocolError, "bounds"):
            validate_init(payload)

    def test_rejects_wrong_labels(self):
        for field, value in [("initiator", "Eve"), ("responder", "Alice"), ("protocol", "DH-v0"),
                             ("message_type", "finish"), ("initiator", "alice")]:
            payload = init_payload()
            payload[field] = value
            with self.assertRaises(ProtocolError):
                validate_init(payload)

    def test_rejects_malformed_nonce(self):
        for nonce in ("ab" * 31, "AB" * 32, "xy" * 32, 1234, "ab" * 33):
            payload = init_payload()
            payload["nonce_A"] = nonce
            with self.assertRaises(ProtocolError):
                validate_init(payload)


class TestSignedSchema(unittest.TestCase):
    def test_accepts_valid(self):
        validate_signed(response_payload(), "response")

    def test_rejects_wrong_message_type(self):
        with self.assertRaises(ProtocolError):
            validate_signed(response_payload(), "finish")

    def test_rejects_bad_transcript(self):
        for field, value in [("B", "19"), ("nonce_B", "short"), ("responder", "Eve")]:
            payload = copy.deepcopy(response_payload())
            payload["transcript"][field] = value
            with self.assertRaises(ProtocolError):
                validate_signed(payload, "response")

    def test_rejects_extra_transcript_field(self):
        payload = copy.deepcopy(response_payload())
        payload["transcript"]["private_b"] = 15
        with self.assertRaises(ProtocolError):
            validate_signed(payload, "response")


class TestPrivateValuesStayLocal(unittest.TestCase):
    #No private exponent or shared secret field ever appears on the wire.
    def test_messages_contain_only_public_fields(self):
        alice, bob = create_parties()
        init = alice.start(16)
        response = bob.handle_init(init)
        finish = alice.handle_response(response)
        bob.handle_finish(finish)
        for data in (init, response, finish):
            text = data.decode()
            for word in ("private", "secret", '"a"', '"b"'):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
