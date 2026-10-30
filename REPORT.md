# Authenticated Diffie-Hellman: Report

Nathan Todd

## 1. Algorithms

### Square-and-multiply modular exponentiation

`modular_exponentiation(base, exponent, modulus)` reads the exponent one binary digit at a time, lowest first. When the current digit is 1 (the exponent is odd), the current power of the base is multiplied into the result. The base is then squared to get the next power of two, and the exponent is halved to move on to the next digit. Every multiplication and squaring is reduced mod the modulus, so intermediate values stay below modulus squared and the full power is never built. For an exponent e the loop runs O(log e) times. The function rejects non-integers (including Booleans), negative exponents and moduli of zero or less. It returns 1 % modulus for exponent 0, so modulus 1 gives 0.

### Prime generation and validation

`generate_prime(bits)` accepts only integers from 16 through 32 and rejects Booleans. It calls PyCryptodome's `getPrime(bits, randfunc=secrets.token_bytes)`, confirms that `p.bit_length() == bits` and that p is odd, and returns p along with the wrapper's total time from `time.perf_counter`. The library handles candidate search and its own primality checks.

`validate_modulus(p)` is what Bob runs on a received p. It checks the type, then the permitted size, then calls the library's `isPrime(p)`. Checking only oddness and bit length would accept 32769 = 3 x 10923, which is rejected. Small fixtures such as 23 are accepted only through the explicit `allow_fixture=True` path.

### Factorization of p - 1

`prime_factors(n)` divides out every factor of 2 (recording 2 once), then tries odd divisors from 3, dividing out each one completely and recording it once. It stops when divisor squared exceeds what is left of n, and any remainder above 1 is itself prime. For a 32-bit p this examines divisors only up to about 65,536.

### Generator verification and search

The multiplicative group mod a prime p has order p - 1. A candidate g in 2 through p - 2 is a primitive generator exactly when `g^((p - 1) / r) mod p != 1` for every distinct prime factor r of p - 1. If any of those powers is 1, the order of g is a proper divisor of p - 1. `find_generator` returns the smallest candidate that passes, always using the complete factor set. Bob repeats the factorization and the check himself instead of trusting Alice's g.

### Key agreement

Each participant picks a fresh private exponent with `secrets.randbelow(p - 3) + 2`, so 2 <= x <= p - 2, and computes the public value with square-and-multiply. If the public value falls outside 2 through p - 2 (it can equal p - 1 when x = (p - 1) / 2), a new exponent is drawn. Received public values must also be in that range. After verifying the peer's signature on the full transcript, Alice computes S_A = B^a mod p and Bob computes S_B = A^b mod p.

### Message format

Every message is a JSON envelope `{"payload": ..., "signature": ...}`. The signature is over `json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")`, so both sides sign identical bytes and the encoding is unambiguous. The receiver enforces a 4096-byte limit before parsing, rejects duplicate JSON keys, requires exactly the expected fields, and checks every type strictly: integers must be real JSON integers (strings are never coerced) of at most 32 bits, the labels must be exactly `"Alice"` and `"Bob"`, nonces must be 64 lowercase hex characters, and signatures must be 128. The protocol label is `DH-CLASSROOM-AUTH-v1`.

### The three messages

1. **Init (Alice to Bob).** Alice signs protocol, message_type `init`, initiator, responder, p, g, A and nonce_A. Bob checks the format, verifies the signature with Alice's trusted key, validates p with the library, factors p - 1, verifies g and checks the range of A.
2. **Response (Bob to Alice).** Bob signs `response` plus the complete transcript (protocol, initiator, responder, p, g, A, B, nonce_A, nonce_B). Alice checks the schema, confirms that p, g, A and nonce_A match her pending session exactly, checks the range of B and verifies Bob's signature.
3. **Finish (Alice to Bob).** Alice signs `finish` plus the same transcript. Bob requires exact agreement with his pending transcript and verifies the signature. Only then does he compute his secret and mark the transcript authenticated.

Any failure aborts the session: pending state, private exponent and secret are cleared.


**Factorization and generators.** For p = 23, p - 1 = 22 = 2 x 11, with factors {2, 11}. g = 2 is rejected because 2^11 mod 23 = 1. g = 5 is accepted because 5^11 mod 23 = 22 and 5^2 mod 23 = 2. For p = 65537, p - 1 = 2^16, with factors {2}, and g = 3 is accepted because 3^32768 mod 65537 = 65536.

**Key agreement (p = 23, g = 5, a = 6, b = 15).** A = 5^6 mod 23 = 8 and B = 5^15 mod 23 = 19. Alice computes 19^6 mod 23 = 2 and Bob computes 8^15 mod 23 = 2.

**Eve against unauthenticated DH.** Eve picks e1 = 3 (E1 = 10) and e2 = 7 (E2 = 17), sends E1 to Alice as Bob and E2 to Bob as Alice. Alice computes 10^6 mod 23 = 6 and Eve computes 8^3 mod 23 = 6. Bob computes 17^15 mod 23 = 15 and Eve computes 19^7 mod 23 = 15. Alice and Bob hold different secrets, and Eve knows both.

**Eve against the authenticated exchange.** Eve changes B from 19 to 17 but cannot produce Bob's signature over a transcript containing 17. Alice verifies with Bob's trusted key, the signature is INVALID, and the exchange is aborted.

## 3. Testing

`python -m unittest discover -s tests -t .` runs 78 tests, and all pass. 

Prime generation dominates and grows with size: the mean was about 0.47 ms at 16 bits, 1.5 ms at 24 bits and 1.9 ms at 32 bits. Factorization time depends far more on the shape of p - 1 than on its size. When p - 1 has only small factors it finishes in microseconds, and the worst case (p - 1 = 2q with q prime) still needs only about 23,000 trial divisions at 32 bits. Generator search time varies with how far the first generator is from 2. All runs vary between trials and between machines, so no exact runtime is asserted.

## 4. Trust assumptions

- Trusted setup gives Alice Bob's authentic Ed25519 public key and gives Bob Alice's. Eve cannot change that configuration.
- Eve controls every simulated network message. She can read, drop, change, reorder and replay them, but she cannot read anyone's private signing key or DH exponent.
- Signatures are always checked against the trusted key for the expected name, never against a key carried in a message.
- PyCryptodome's `getPrime` and `isPrime` are trusted to return and recognize primes, and the `cryptography` package is trusted to implement Ed25519 correctly.
- `secrets` is trusted as a source of cryptographic randomness for exponents and nonces.

## 5. Limitations

- 16 to 32 bit primes can be broken instantly by computing discrete logarithms. They are used only so that p - 1 can be factored by trial division.
- There is no explicit key confirmation. The finish message is a signed acknowledgement of the transcript, not proof that Alice computed the shared secret.
- The raw shared secret is not passed through a key derivation function and is never used to encrypt anything.
- The range check 2 <= value <= p - 2 is a basic classroom check, not a full group-validation policy. Since generators are primitive roots, there is no prime-order subgroup check and small-subgroup attacks are not addressed.
- Bob does not cache initiations, so a replayed init can make him do work (see above), although it cannot complete an exchange.
- There is no real network, timeout handling or concurrency. Each side tracks one pending session at a time.
- Python integers are not constant-time, so this code offers no protection against timing side channels.

## 6. Research comparison: finite-field DH and ECDH

This project performs Diffie-Hellman in the multiplicative group of integers modulo a prime p. The core operation is modular exponentiation, g^a mod p, computed with square-and-multiply. Elliptic-curve Diffie-Hellman (ECDH) uses the same idea in a different group: the points on an elliptic curve over a finite field. Its core operation is scalar multiplication, aP, computed with double-and-add, where point doubling plays the role of squaring and point addition the role of multiplication. X25519 is a widely used example, specified in RFC 7748 [1].

The project uses 16 to 32 bit primes because the generator check needs the factorization of p - 1, and trial division only works when p is tiny. A 32-bit p needs trial divisors up to about 65,536, which takes milliseconds. Those sizes are completely insecure, since discrete logarithms in groups that small can be found by brute force or baby-step giant-step almost instantly. NIST guidance calls for at least a 2048-bit modulus for 112-bit security [2]. Factoring a random 2048-bit p - 1 by trial division is infeasible, which is why real systems do not use this method. They use standardized groups instead, such as the RFC 7919 groups for TLS [4], or safe primes p = 2q + 1, where the factors of p - 1 are known in advance. ECDH reaches comparable security with much smaller keys, about 256 bits for 128-bit security [2], because the best known attacks on well-chosen curves are generic and have no shortcut like the index calculus that works against finite fields.

Ephemeral ECDH (ECDHE) means each session uses a freshly generated key pair that is discarded afterwards, which is what this project does with its finite-field exponents a and b. Fresh session keys provide forward secrecy: if a long-term signing key is stolen later, past session secrets cannot be recovered, because the ephemeral private values that produced them no longer exist. TLS 1.3 requires ephemeral (EC)DHE for this reason [3].

ECDH on its own still has no authentication. The man-in-the-middle attack shown in this project works the same way against ECDH: Eve substitutes her own public point in each direction. TLS 1.3 prevents this by having the server sign the handshake transcript with a certified key [3], the same principle as the Ed25519 signatures here.

Production systems use established protocols, validated parameters and vetted libraries because the dangerous mistakes are subtle: missing public-value checks, weak randomness, ambiguous encodings, replay gaps and timing side channels. Standards such as NIST SP 800-56A [2] and protocols such as TLS 1.3 [3] encode many years of analysis of these failures, and reviewed libraries implement them in constant time.

## References

[1] A. Langley, M. Hamburg and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF, January 2016. https://www.rfc-editor.org/rfc/rfc7748

[2] E. Barker et al., "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography," NIST SP 800-56A Rev. 3, April 2018; and E. Barker, "Recommendation for Key Management: Part 1," NIST SP 800-57 Part 1 Rev. 5, May 2020. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final

[3] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, IETF, August 2018. https://www.rfc-editor.org/rfc/rfc8446

[4] D. Gillmor, "Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)," RFC 7919, IETF, August 2016. https://www.rfc-editor.org/rfc/rfc7919
