#Nathan Todd
#Program: eve
#Eve controls the simulated network: she can read, tamper with and replay messages,
#but cannot change the trusted keys or read anyone's private keys.

import json

from authentication import create_identity, sign_payload
from modular_math import modular_exponentiation
from protocol import pack


#Eve reads a message off the wire with no validation.
def intercept(data):
    envelope = json.loads(data.decode("utf-8"))
    return envelope["payload"], envelope["signature"]


#Changes one field and keeps the original signature. Looks inside the transcript when there is one.
def tamper(data, field, value):
    payload, signature = intercept(data)
    target = payload["transcript"] if "transcript" in payload else payload
    target[field] = value
    return pack(payload, signature)


#Flips the first hex digit of the signature.
def corrupt_signature(data):
    payload, signature = intercept(data)
    flipped = "1" if signature[0] == "0" else "0"
    return pack(payload, flipped + signature[1:])


#Eve signs a payload with her own key, still labeled as Alice or Bob.
def sign_as_eve(payload, eve_key=None):
    eve_key = eve_key or create_identity()
    return pack(payload, sign_payload(eve_key, payload))


#Network function that swaps Bob's public value B in his response.
def substitute_bob_public(new_b):
    def network(stage, data):
        if stage == "response":
            return tamper(data, "B", new_b)
        return data
    return network


#Man-in-the-middle against plain, unauthenticated DH. Eve gives each side her own public value.
def unauthenticated_mitm(p, g, a, b, e1, e2):
    public_a = modular_exponentiation(g, a, p)
    public_b = modular_exponentiation(g, b, p)
    public_e1 = modular_exponentiation(g, e1, p)
    public_e2 = modular_exponentiation(g, e2, p)

    #Alice receives E1 as if it were B; Bob receives E2 as if it were A.
    return {
        "A": public_a, "B": public_b, "E1": public_e1, "E2": public_e2,
        "alice_secret": modular_exponentiation(public_e1, a, p),
        "eve_with_alice": modular_exponentiation(public_a, e1, p),
        "bob_secret": modular_exponentiation(public_e2, b, p),
        "eve_with_bob": modular_exponentiation(public_b, e2, p),
    }
