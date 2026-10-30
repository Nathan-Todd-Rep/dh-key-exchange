#Nathan Todd
#Program: protocol
#Message schema checks and the three-message authenticated exchange between Alice and Bob.

import json
import secrets
import time

from authentication import PROTOCOL, trusted_setup
from errors import AuthenticationError, ProtocolError
from modular_math import modular_exponentiation
from parameters import (DEFAULT_BITS, MAX_BITS, find_generator, generate_prime,
                        is_generator, prime_factors, validate_modulus)
from participant import (Participant, compute_shared_secret, generate_dh_keypair,
                         public_value_in_range)

INITIATOR = "Alice"
RESPONDER = "Bob"
MAX_MESSAGE_BYTES = 4096
NONCE_HEX_LENGTH = 64
SIGNATURE_HEX_LENGTH = 128
HEX_DIGITS = set("0123456789abcdef")

ENVELOPE_FIELDS = {"payload", "signature"}
INIT_FIELDS = {"protocol", "message_type", "initiator", "responder", "p", "g", "A", "nonce_A"}
SIGNED_FIELDS = {"message_type", "transcript"}
TRANSCRIPT_FIELDS = {"protocol", "initiator", "responder", "p", "g", "A", "B", "nonce_A", "nonce_B"}


#Fresh public 32-byte nonce, sent as 64 hex characters.
def new_nonce():
    return secrets.token_bytes(32).hex()


#json hook that refuses an object with the same key twice.
def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


#Wraps a payload and its signature for the simulated network. The signature sits outside the payload.
def pack(payload, signature):
    envelope = {"payload": payload, "signature": signature}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


#Parses a received message: size limit first, then strict JSON, then the envelope shape.
def unpack(data):
    if not isinstance(data, bytes):
        raise ProtocolError("message must be bytes")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message exceeds size limit")
    try:
        envelope = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("malformed message") from None

    require_fields(envelope, ENVELOPE_FIELDS, "envelope")
    require_hex(envelope["signature"], SIGNATURE_HEX_LENGTH, "signature")
    return envelope["payload"], envelope["signature"]


#Object must have exactly the expected fields, no more and no fewer.
def require_fields(obj, fields, name):
    if not isinstance(obj, dict):
        raise ProtocolError(f"{name} must be a JSON object")
    if set(obj) != fields:
        raise ProtocolError(f"{name} has missing or unexpected fields")


#Strict integer check with no string coercion, bounded before any arithmetic.
def require_int_field(value, name):
    if type(value) is not int:
        raise ProtocolError(f"{name} must be an integer")
    if value < 0 or value.bit_length() > MAX_BITS:
        raise ProtocolError(f"{name} is out of bounds")


#Lowercase hex string of an exact length.
def require_hex(value, length, name):
    if not isinstance(value, str) or len(value) != length or not set(value) <= HEX_DIGITS:
        raise ProtocolError(f"{name} is malformed")


#Fixed ASCII labels and constants must match exactly.
def require_value(value, expected, name):
    if not isinstance(value, str) or value != expected:
        raise ProtocolError(f"unexpected {name}")


#Shared checks for the fields every init and transcript carry.
def check_common(obj):
    require_value(obj["protocol"], PROTOCOL, "protocol")
    require_value(obj["initiator"], INITIATOR, "initiator")
    require_value(obj["responder"], RESPONDER, "responder")
    for field in ("p", "g", "A"):
        require_int_field(obj[field], field)
    require_hex(obj["nonce_A"], NONCE_HEX_LENGTH, "nonce_A")


def validate_init(payload):
    require_fields(payload, INIT_FIELDS, "init")
    require_value(payload["message_type"], "init", "message type")
    check_common(payload)


def validate_transcript(transcript):
    require_fields(transcript, TRANSCRIPT_FIELDS, "transcript")
    check_common(transcript)
    require_int_field(transcript["B"], "B")
    require_hex(transcript["nonce_B"], NONCE_HEX_LENGTH, "nonce_B")


#Response and finish share one shape: a message type plus the complete transcript.
def validate_signed(payload, message_type):
    require_fields(payload, SIGNED_FIELDS, message_type)
    require_value(payload["message_type"], message_type, "message type")
    validate_transcript(payload["transcript"])


#Alice's side. Holds one pending session at a time.
class Initiator:
    def __init__(self, participant, checks=None):
        self.participant = participant
        self.checks = checks if checks is not None else {}
        self.timings = {}
        self.pending = None
        self.transcript = None
        self.shared_secret = None

    #Normal path: library prime of the requested size, then factor p - 1 and pick g.
    def start(self, bits=DEFAULT_BITS):
        self.timings = {}
        p, self.timings["prime"] = generate_prime(bits)
        validate_modulus(p)

        start = time.perf_counter()
        factors = prime_factors(p - 1)
        self.timings["factor"] = time.perf_counter() - start

        start = time.perf_counter()
        g = find_generator(p, factors)
        self.timings["generator"] = time.perf_counter() - start

        private, public = generate_dh_keypair(p, g)
        return self._send_init(p, g, private, public)

    #Explicit test-fixture path: small fixed p and g with a chosen private exponent.
    def start_fixture(self, p, g, private):
        validate_modulus(p, allow_fixture=True)
        if not is_generator(g, p):
            raise ValueError("fixture g is not a generator")
        return self._send_init(p, g, private, modular_exponentiation(g, private, p))

    def _send_init(self, p, g, private, public):
        self.checks.clear()
        self.transcript = None
        self.shared_secret = None
        payload = {
            "protocol": PROTOCOL, "message_type": "init",
            "initiator": INITIATOR, "responder": RESPONDER,
            "p": p, "g": g, "A": public, "nonce_A": new_nonce(),
        }
        #The private exponent stays in the pending record and never enters a message.
        self.pending = {"p": p, "g": g, "A": public, "nonce_A": payload["nonce_A"], "private": private}
        return pack(payload, self.participant.sign(payload))

    #Message 2: check Bob's response against the pending session, then send the signed finish.
    def handle_response(self, data):
        try:
            if self.pending is None:
                raise ProtocolError("no pending session for this response")
            payload, signature = unpack(data)
            validate_signed(payload, "response")
            transcript = payload["transcript"]

            #The response must echo this session's values exactly; a stale one fails here.
            for field in ("p", "g", "A", "nonce_A"):
                if transcript[field] != self.pending[field]:
                    raise ProtocolError(f"response {field} does not match the pending session")
            if not public_value_in_range(transcript["B"], transcript["p"]):
                raise ProtocolError("B is out of range")

            self._verify("Bob response signature", RESPONDER, payload, signature)

            self.shared_secret = compute_shared_secret(transcript["B"], self.pending["private"], transcript["p"])
            self.transcript = transcript
            self.pending = None
            finish = {"message_type": "finish", "transcript": transcript}
            return pack(finish, self.participant.sign(finish))
        except ProtocolError:
            self.abort()
            raise

    def _verify(self, label, signer, payload, signature):
        try:
            self.participant.verify(signer, payload, signature)
        except AuthenticationError:
            self.checks[label] = "INVALID"
            raise
        self.checks[label] = "VALID"

    #Clears all usable state so a rejected session's secret is never used.
    def abort(self):
        self.pending = None
        self.transcript = None
        self.shared_secret = None


#Bob's side. Keeps the pending transcript and the nonces of completed sessions.
class Responder:
    def __init__(self, participant, checks=None, allow_fixture=False, fixture_private=None):
        self.participant = participant
        self.checks = checks if checks is not None else {}
        self.allow_fixture = allow_fixture
        self.fixture_private = fixture_private
        self.pending = None
        self.completed = set()
        self.authenticated = False
        self.shared_secret = None

    #Message 1: verify Alice, validate p, g and A, then answer with a signed transcript.
    def handle_init(self, data):
        try:
            self.abort()
            payload, signature = unpack(data)
            validate_init(payload)
            self._verify("Alice initiation signature", INITIATOR, payload, signature)

            p, g, public_a = payload["p"], payload["g"], payload["A"]
            try:
                validate_modulus(p, self.allow_fixture)
            except (TypeError, ValueError) as error:
                self.checks["Received modulus library validation"] = "FAIL"
                raise ProtocolError(f"received modulus rejected: {error}") from None
            self.checks["Received modulus library validation"] = "PASS"

            #Bob factors p - 1 himself rather than trusting Alice's choice of g.
            if not is_generator(g, p, prime_factors(p - 1)):
                self.checks["Generator"] = "REJECTED"
                raise ProtocolError("g is not a generator of p")
            self.checks["Generator"] = "validated"

            if not public_value_in_range(public_a, p):
                raise ProtocolError("A is out of range")

            if self.allow_fixture and self.fixture_private is not None:
                private = self.fixture_private
                public_b = modular_exponentiation(g, private, p)
            else:
                private, public_b = generate_dh_keypair(p, g)

            transcript = {
                "protocol": PROTOCOL, "initiator": INITIATOR, "responder": RESPONDER,
                "p": p, "g": g, "A": public_a, "B": public_b,
                "nonce_A": payload["nonce_A"], "nonce_B": new_nonce(),
            }
            self.pending = {"transcript": transcript, "private": private}
            response = {"message_type": "response", "transcript": transcript}
            return pack(response, self.participant.sign(response))
        except ProtocolError:
            self.abort()
            raise

    #Message 3: Alice's finish must match the pending transcript exactly, including Bob's new nonce.
    def handle_finish(self, data):
        try:
            payload, signature = unpack(data)
            validate_signed(payload, "finish")
            transcript = payload["transcript"]

            if self.pending is not None:
                if transcript != self.pending["transcript"]:
                    raise ProtocolError("finish does not match the pending transcript")
            elif transcript["nonce_B"] in self.completed:
                raise ProtocolError("session already completed")
            else:
                raise ProtocolError("no pending session for this finish")

            self._verify("Alice finish signature", INITIATOR, payload, signature)

            #Bob completes only after accepting Alice's finish.
            self.shared_secret = compute_shared_secret(transcript["A"], self.pending["private"], transcript["p"])
            self.authenticated = True
            self.checks["Transcript authenticated"] = "YES"
            self.completed.add(transcript["nonce_B"])
            self.pending = None
        except ProtocolError:
            #A rejected duplicate leaves an already completed session alone.
            if self.pending is not None:
                self.abort()
            raise

    def _verify(self, label, signer, payload, signature):
        try:
            self.participant.verify(signer, payload, signature)
        except AuthenticationError:
            self.checks[label] = "INVALID"
            raise
        self.checks[label] = "VALID"

    def abort(self):
        self.pending = None
        self.authenticated = False
        self.shared_secret = None


#Trusted setup plus both roles sharing one checks record for the demo output.
def create_parties(allow_fixture=False, fixture_private=None):
    alice_key, bob_key, alice_trusted, bob_trusted = trusted_setup()
    checks = {}
    alice = Initiator(Participant(INITIATOR, alice_key, alice_trusted), checks)
    bob = Responder(Participant(RESPONDER, bob_key, bob_trusted), checks, allow_fixture, fixture_private)
    return alice, bob


#No-op network: every message is delivered unchanged.
def honest_network(stage, data):
    return data


#Runs all three messages through the network function, which Eve can replace.
#Pass fixture=(p, g, a) to use the test-fixture path instead of library generation.
def run_exchange(alice, bob, bits=DEFAULT_BITS, network=honest_network, fixture=None):
    init = alice.start_fixture(*fixture) if fixture else alice.start(bits)
    response = bob.handle_init(network("init", init))
    finish = alice.handle_response(network("response", response))
    bob.handle_finish(network("finish", finish))
    return init, response, finish
