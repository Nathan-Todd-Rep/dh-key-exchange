#Nathan Todd
#Program: main
#Runs the authenticated exchange, the attack demonstrations and the timing trials.
#Usage: python main.py [bits] [--debug] [--timing]

import platform
import sys

import Crypto
import cryptography

from errors import AuthenticationError, ProtocolError
from eve import intercept, tamper, unauthenticated_mitm
from parameters import DEFAULT_BITS, validate_bit_length
from participant import generate_dh_keypair
from protocol import create_parties, run_exchange

CHECK_ORDER = (
    "Received modulus library validation",
    "Generator",
    "Alice initiation signature",
    "Bob response signature",
    "Alice finish signature",
    "Transcript authenticated",
)
TIMING_SIZES = (16, 24, 32)
TIMING_TRIALS = 3


#Command-line bits must be a whole number written in plain ASCII digits, then 16 through 32.
def parse_bits(text):
    digits = text[1:] if text[:1] in ("+", "-") else text
    if not digits.isascii() or not digits.isdecimal():
        raise ValueError(f"bit length must be an integer, got {text!r}")
    return validate_bit_length(int(text))


def heading(title):
    print()
    print(f"=== {title} ===")


#Successful exchange. The steps are run one at a time so debug mode can show the private values.
def demo_success(bits, debug):
    heading("Authenticated exchange")
    alice, bob = create_parties()
    init = alice.start(bits)
    a = alice.pending["private"]
    response = bob.handle_init(init)
    b = bob.pending["private"]
    finish = alice.handle_response(response)
    bob.handle_finish(finish)

    p = alice.transcript["p"]
    print(f"Requested prime size: {bits} bits")
    print("Modulus: generated using library prime generator")
    print(f"Modulus bit length: {p.bit_length()}")
    for label in CHECK_ORDER:
        print(f"{label}: {alice.checks[label]}")

    #The coordinator compares both local results; secrets never cross the network.
    match = alice.shared_secret == bob.shared_secret
    print(f"Shared-secret equality in local test: {'PASS' if match else 'FAIL'}")
    print("Explicit key confirmation: NOT IMPLEMENTED")

    t = alice.transcript
    print(f"Public values: p={t['p']} g={t['g']} A={t['A']} B={t['B']}")
    if debug:
        print(f"[CLASSROOM DEBUG, PRIVATE] a={a} b={b} shared secret={alice.shared_secret}")


#Eve's substitution against plain DH with the p = 23 teaching fixture.
def demo_unauthenticated():
    heading("Attack on unauthenticated DH (p=23, g=5 fixture)")
    r = unauthenticated_mitm(23, 5, a=6, b=15, e1=3, e2=7)
    print(f"Alice sends A={r['A']}, Bob sends B={r['B']}")
    print(f"Eve sends E1={r['E1']} to Alice as Bob and E2={r['E2']} to Bob as Alice")
    print(f"Alice's secret: {r['alice_secret']}  Eve's copy: {r['eve_with_alice']}")
    print(f"Bob's secret:   {r['bob_secret']}  Eve's copy: {r['eve_with_bob']}")
    print("Result: Alice and Bob hold different secrets and Eve knows both")


#The same substitution against the authenticated exchange.
def demo_authenticated_attack(bits):
    heading("Attack on authenticated exchange")
    alice, bob = create_parties()
    response = bob.handle_init(alice.start(bits))
    transcript = intercept(response)[0]["transcript"]

    #Eve picks her own public value and swaps it in for B, keeping Bob's signature.
    _, eve_public = generate_dh_keypair(transcript["p"], transcript["g"])
    while eve_public == transcript["B"]:
        _, eve_public = generate_dh_keypair(transcript["p"], transcript["g"])
    print("Eve modified Bob's public value")
    print(f"B changed from {transcript['B']} to {eve_public}")

    try:
        alice.handle_response(tamper(response, "B", eve_public))
        print("Bob response signature: VALID")
    except AuthenticationError:
        print(f"Bob response signature: {alice.checks['Bob response signature']}")
        print("Exchange aborted")
        print(f"Alice session state cleared: {'YES' if alice.pending is None and alice.shared_secret is None else 'NO'}")


def print_environment():
    print(f"Python {platform.python_version()} on {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"cryptography {cryptography.__version__}, pycryptodome {Crypto.__version__}")


#At least three generated exchanges at 16, 24 and 32 bits, timed with perf_counter.
def run_timing():
    heading("Timing trials")
    print_environment()
    print()
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) | Authenticated | Secrets match |")
    print("|---|---|---|---|---|---|---|")

    results = {bits: [] for bits in TIMING_SIZES}
    for bits in TIMING_SIZES:
        for trial in range(1, TIMING_TRIALS + 1):
            alice, bob = create_parties()
            run_exchange(alice, bob, bits)
            t = alice.timings
            results[bits].append(t)
            authenticated = "Yes" if bob.authenticated else "No"
            match = "Yes" if alice.shared_secret == bob.shared_secret else "No"
            print(f"| {bits} | {trial} | {t['prime']:.6f} | {t['factor']:.6f} | {t['generator']:.6f} | {authenticated} | {match} |")

    #Min, mean and max per size show how much the runs vary.
    print()
    print("| Bits | Step | Min (s) | Mean (s) | Max (s) |")
    print("|---|---|---|---|---|")
    for bits in TIMING_SIZES:
        for step in ("prime", "factor", "generator"):
            values = [t[step] for t in results[bits]]
            print(f"| {bits} | {step} | {min(values):.6f} | {sum(values) / len(values):.6f} | {max(values):.6f} |")


def main(args):
    debug = "--debug" in args
    timing = "--timing" in args
    positional = [arg for arg in args if arg not in ("--debug", "--timing")]
    if len(positional) > 1:
        print("usage: python main.py [bits] [--debug] [--timing]", file=sys.stderr)
        return 2

    try:
        bits = parse_bits(positional[0]) if positional else DEFAULT_BITS
    except (TypeError, ValueError) as error:
        print(f"Rejected input: {error}", file=sys.stderr)
        return 2

    try:
        demo_success(bits, debug)
        demo_unauthenticated()
        demo_authenticated_attack(bits)
        if timing:
            run_timing()
    except ProtocolError as error:
        print(f"Exchange aborted: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
