#Nathan Todd
#Program: test_math
#Fixed mathematical tests: exponentiation, factorization and generator checks.

import unittest

from modular_math import modular_exponentiation
from parameters import find_generator, is_generator, prime_factors


class TestModularExponentiation(unittest.TestCase):
    def test_known_result(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_dh_fixture_values(self):
        self.assertEqual(modular_exponentiation(5, 15, 23), 19)
        self.assertEqual(modular_exponentiation(19, 6, 23), 2)
        self.assertEqual(modular_exponentiation(8, 15, 23), 2)

    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)
        self.assertEqual(modular_exponentiation(5, 6, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))
        self.assertEqual(modular_exponentiation(-1, 7, 10), 9)

    def test_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, -7)

    def test_rejects_invalid_types(self):
        for args in [(5.0, 6, 23), (5, "6", 23), (5, 6, None), (True, 6, 23), (5, False, 23)]:
            with self.assertRaises(TypeError):
                modular_exponentiation(*args)

    #pow() is used here only as an independent reference.
    def test_matches_pow(self):
        cases = [(2, 10, 1000), (7, 123456, 4294967291), (123456789, 65537, 65521), (0, 5, 17), (3, 32768, 65537)]
        for base, exponent, modulus in cases:
            self.assertEqual(modular_exponentiation(base, exponent, modulus), pow(base, exponent, modulus))

    def test_result_in_range(self):
        for base in range(-30, 30):
            result = modular_exponentiation(base, 13, 29)
            self.assertTrue(0 <= result < 29)


class TestFactorization(unittest.TestCase):
    def test_one(self):
        self.assertEqual(prime_factors(1), set())

    def test_twenty_two(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors(self):
        self.assertEqual(prime_factors(65536), {2})
        self.assertEqual(prime_factors(2 ** 3 * 3 ** 4 * 7), {2, 3, 7})

    def test_large_prime_remainder(self):
        self.assertEqual(prime_factors(2 * 2147483647), {2, 2147483647})

    def test_rejects_invalid(self):
        with self.assertRaises(ValueError):
            prime_factors(0)
        with self.assertRaises(TypeError):
            prime_factors(22.0)
        with self.assertRaises(TypeError):
            prime_factors(True)


class TestGenerator(unittest.TestCase):
    def test_p23(self):
        self.assertTrue(is_generator(5, 23))
        self.assertFalse(is_generator(2, 23))

    def test_p65537(self):
        self.assertTrue(is_generator(3, 65537))

    def test_out_of_range_candidates(self):
        self.assertFalse(is_generator(1, 23))
        self.assertFalse(is_generator(22, 23))

    def test_find_generator(self):
        self.assertEqual(find_generator(23), 5)
        self.assertEqual(find_generator(65537), 3)

    #A generator's powers must reach every nonzero residue.
    def test_generator_has_full_order(self):
        p = 23
        g = find_generator(p)
        powers = {modular_exponentiation(g, k, p) for k in range(1, p)}
        self.assertEqual(powers, set(range(1, p)))


if __name__ == "__main__":
    unittest.main()
