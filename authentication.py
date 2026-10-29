#Nathan Todd
#Program: authentication
#Trusted Ed25519 identities, deterministic message encoding and signature checks.

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from errors import AuthenticationError

PROTOCOL = "DH-CLASSROOM-AUTH-v1"


#Deterministic JSON so both sides sign and verify the exact same bytes.
def encode_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


#Signs the encoded payload and returns the signature as hex.
def sign_payload(signing_key, payload):
    return signing_key.sign(encode_payload(payload)).hex()


#Verifies against the key from trusted setup only, never a key carried in a message.
#InvalidSignature aborts the exchange; verify() has no Boolean result to check.
def verify_payload(trusted_keys, signer, payload, signature_hex):
    if signer not in trusted_keys:
        raise AuthenticationError(f"no trusted key for {signer}")
    try:
        trusted_keys[signer].verify(bytes.fromhex(signature_hex), encode_payload(payload))
    except (ValueError, InvalidSignature):
        raise AuthenticationError(f"{signer} signature is invalid") from None


#Creates one long-term signing identity.
def create_identity():
    return Ed25519PrivateKey.generate()


#Trusted setup: each side learns only the other's authentic public key.
def trusted_setup():
    alice_key = create_identity()
    bob_key = create_identity()
    alice_trusted = {"Bob": bob_key.public_key()}
    bob_trusted = {"Alice": alice_key.public_key()}
    return alice_key, bob_key, alice_trusted, bob_trusted
