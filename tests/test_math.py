#Nathan Todd
#Program: test_math
#Fixed mathematical tests for square-and-multiply exponentiation.

import unittest

from modular_math import modular_exponentiation


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


if __name__ == "__main__":
    unittest.main()
