# dh-key-exchange

A local simulation of an authenticated finite-field Diffie-Hellman key exchange between Alice and Bob. The program generates and validates public parameters, runs a three-message exchange signed with trusted Ed25519 identity keys, and shows that Eve's tampering is detected.

This is a classroom simulation. It uses 16 to 32 bit primes, which are far too small to be secure. It has no network sockets, no message encryption and no ECDH.

## Requirements

- Python 3 (developed and tested on Python 3.14.4, Windows 10)
- `cryptography` 50.0.2 for Ed25519 signatures
- `pycryptodome` 4.2.0 for prime generation (`getPrime`) and primality validation (`isPrime`)

```bash
python -m pip install cryptography pycryptodome
```

## What is implemented here and what comes from libraries

| Implemented | Delegated to a library |
|---|---|
| Square-and-multiply modular exponentiation | Prime generation (PyCryptodome `getPrime`) |
| Trial-division factorization of p - 1 | Primality validation (PyCryptodome `isPrime`) |
| Generator verification and search | Ed25519 signing and verification (`cryptography`) |
| Diffie-Hellman key agreement | |
| Message schema checks, session state, attack simulation | |

Python's three-argument `pow()` appears only in the tests, as an independent reference.

## Running

```bash
python main.py
```

This runs the default 16-bit authenticated exchange, the unauthenticated attack on the p = 23 fixture, and Eve's attack on the authenticated exchange.

Options:

- `python main.py 24` uses an exact prime size from 16 to 32 bits. Non-integer input and sizes outside that range are rejected.
- `--debug` adds clearly labeled classroom debug output with the private exponents and shared secret. Normal output hides them.
- `--timing` also runs three generated exchanges at each of 16, 24 and 32 bits and prints the timing tables.

Example successful run:

```
Requested prime size: 16 bits
Modulus: generated using library prime generator
Modulus bit length: 16
Received modulus library validation: PASS
Generator: validated
Alice initiation signature: VALID
Bob response signature: VALID
Alice finish signature: VALID
Transcript authenticated: YES
Shared-secret equality in local test: PASS
Explicit key confirmation: NOT IMPLEMENTED
```

Example attack run:

```
Eve modified Bob's public value
Bob response signature: INVALID
Exchange aborted
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

| File | Covers |
|---|---|
| `tests/test_math.py` | Fixed mathematical tests: exponentiation, factorization, generators |
| `tests/test_parameters.py` | Prime-generator integration and received-modulus validation |
| `tests/test_messages.py` | Message encoding, schema, types, sizes, malformed input |
| `tests/test_exchange.py` | Complete exchanges, every listed attack, session state |

## Files

| Module | Responsibility |
|---|---|
| `modular_math.py` | Square-and-multiply |
| `parameters.py` | Library prime-generation wrapper, received-modulus validation, factorization, generator selection |
| `participant.py` | Local DH and signing state |
| `authentication.py` | Trusted-key lookup, deterministic encoding, signatures |
| `errors.py` | Exceptions that abort an exchange |
| `protocol.py` | Message processing and session state |
| `eve.py` | Interception, tampering and replay |
| `main.py` | Demonstrations and timing |
| `REPORT.md` | Algorithms, results, trust assumptions, limitations and the ECDH comparison |

Besides the libraries listed, `main.py` uses the standard `sys` module for command-line arguments and `platform` to report the environment.
