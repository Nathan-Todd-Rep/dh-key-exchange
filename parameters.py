#Nathan Todd
#Program: parameters
#Library prime generation, received-modulus validation, factorization of p - 1
#and generator selection.

import secrets
import time

from Crypto.Util.number import getPrime, isPrime

from modular_math import modular_exponentiation, require_int

MIN_BITS = 16
MAX_BITS = 32
DEFAULT_BITS = 16

#Smallest prime with at least one candidate generator in 2 through p - 2.
MIN_FIXTURE_PRIME = 5


#Accepts only integer bit lengths from 16 through 32 inclusive.
def validate_bit_length(bits):
    require_int(bits, "bits")
    if not MIN_BITS <= bits <= MAX_BITS:
        raise ValueError(f"bits must be from {MIN_BITS} through {MAX_BITS}")
    return bits


#Asks the library for an exact bits-bit prime. Returns the prime and the wrapper's total time.
def generate_prime(bits=DEFAULT_BITS):
    start = time.perf_counter()
    validate_bit_length(bits)
    p = getPrime(bits, randfunc=secrets.token_bytes)

    #Confirm the library honored the exact size request.
    if p.bit_length() != bits or p % 2 == 0:
        raise RuntimeError("library returned a prime of the wrong size")

    return p, time.perf_counter() - start


#Checks a received modulus: type, permitted size, then the library primality test.
#allow_fixture is the explicit test-fixture path that permits small values such as 23.
def validate_modulus(p, allow_fixture=False):
    require_int(p, "p")
    if allow_fixture:
        if p < MIN_FIXTURE_PRIME or p.bit_length() > MAX_BITS:
            raise ValueError("fixture modulus is out of range")
    elif not MIN_BITS <= p.bit_length() <= MAX_BITS:
        raise ValueError(f"p must be {MIN_BITS} to {MAX_BITS} bits")

    #Size and oddness are not enough, so the library makes the final call.
    if not isPrime(p):
        raise ValueError("p is not prime")
    return p


#Returns the set of distinct prime factors of n using trial division.
def prime_factors(n):
    require_int(n, "n")
    if n < 1:
        raise ValueError("n must be positive")

    factors = set()

    #Divide out every factor of 2 but record 2 only once.
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n //= 2

    #Try odd divisors until divisor squared passes what is left of n.
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor += 2

    #Anything left above 1 is itself a prime factor.
    if n > 1:
        factors.add(n)
    return factors


#g generates the full group only if g^((p - 1) / r) != 1 for every prime factor r of p - 1.
#Assumes p is already a validated prime.
def is_generator(g, p, factors=None):
    require_int(g, "g")
    require_int(p, "p")
    if not 2 <= g <= p - 2:
        return False
    if factors is None:
        factors = prime_factors(p - 1)

    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False
    return True


#Returns the smallest generator of p, checked against the complete factor set of p - 1.
def find_generator(p, factors=None):
    if factors is None:
        factors = prime_factors(p - 1)
    for g in range(2, p - 1):
        if is_generator(g, p, factors):
            return g
    raise ValueError("no generator found")
