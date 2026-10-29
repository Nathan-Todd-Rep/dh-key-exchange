#Nathan Todd
#Program: test_parameters
#Prime-generator integration tests and received-modulus validation.
#These test the wrapper and validation behavior, not the library's primality algorithm.

import unittest

from Crypto.Util.number import isPrime

from parameters import (MAX_BITS, MIN_BITS, find_generator, generate_prime, is_generator,
                        prime_factors, validate_bit_length, validate_modulus)


class TestPrimeGeneration(unittest.TestCase):
    def test_exact_bit_length_and_odd(self):
        for bits in range(MIN_BITS, MAX_BITS + 1):
            p, seconds = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(2 ** (bits - 1) <= p < 2 ** bits)
            self.assertEqual(p % 2, 1)
            self.assertGreaterEqual(seconds, 0)

    def test_library_validates_returned_primes(self):
        for bits in (16, 24, 32):
            p, _ = generate_prime(bits)
            self.assertTrue(isPrime(p))
            self.assertEqual(validate_modulus(p), p)

    def test_default_is_16_bits(self):
        p, _ = generate_prime()
        self.assertEqual(p.bit_length(), 16)

    def test_generated_prime_has_generator(self):
        p, _ = generate_prime(24)
        g = find_generator(p)
        self.assertTrue(is_generator(g, p, prime_factors(p - 1)))

    def test_rejects_out_of_range_sizes(self):
        for bits in (0, 15, 33, -16, 64):
            with self.assertRaises(ValueError):
                generate_prime(bits)

    def test_rejects_bool_and_nonintegers(self):
        for bits in (True, False, 16.0, "16", None):
            with self.assertRaises(TypeError):
                generate_prime(bits)
            with self.assertRaises(TypeError):
                validate_bit_length(bits)


class TestReceivedModulus(unittest.TestCase):
    def test_rejects_composite(self):
        with self.assertRaises(ValueError):
            validate_modulus(32769)

    def test_rejects_wrong_types(self):
        for p in ("65521", 65521.0, True, None, [65521]):
            with self.assertRaises(TypeError):
                validate_modulus(p)

    def test_rejects_out_of_range_sizes(self):
        #32749 is a 15-bit prime and 4294967311 a 33-bit prime, so size rejects both.
        self.assertEqual(validate_modulus(65537), 65537)
        for p in (23, 32749, 4294967311):
            with self.assertRaises(ValueError):
                validate_modulus(p)

    def test_fixture_path(self):
        self.assertEqual(validate_modulus(23, allow_fixture=True), 23)
        with self.assertRaises(ValueError):
            validate_modulus(21, allow_fixture=True)
        with self.assertRaises(ValueError):
            validate_modulus(3, allow_fixture=True)

    def test_library_fixtures(self):
        self.assertTrue(isPrime(23))
        self.assertFalse(isPrime(21))


if __name__ == "__main__":
    unittest.main()
