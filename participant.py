#Nathan Todd
#Program: participant
#Local Diffie-Hellman math and signing state for one party.

import secrets

from authentication import sign_payload, verify_payload
from modular_math import modular_exponentiation


#One party's long-term identity. The signing key never leaves this object.
class Participant:
    def __init__(self, name, signing_key, trusted_keys):
        self.name = name
        self._signing_key = signing_key
        self.trusted_keys = dict(trusted_keys)

    def sign(self, payload):
        return sign_payload(self._signing_key, payload)

    def verify(self, signer, payload, signature):
        verify_payload(self.trusted_keys, signer, payload, signature)


#Classroom range check for public values: 2 <= value <= p - 2.
def public_value_in_range(value, p):
    return 2 <= value <= p - 2


#Fresh private exponent in 2 through p - 2 and its public value.
#Retries if the public value lands outside the permitted range.
def generate_dh_keypair(p, g):
    while True:
        private = secrets.randbelow(p - 3) + 2
        public = modular_exponentiation(g, private, p)
        if public_value_in_range(public, p):
            return private, public


#S = peer_public^private mod p.
def compute_shared_secret(peer_public, private, p):
    return modular_exponentiation(peer_public, private, p)
