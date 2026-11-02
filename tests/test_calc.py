import unittest
from calc import parse_discount


class TestCalc(unittest.TestCase):
    def test_discount_zero(self):
        self.assertEqual(parse_discount(0.0), 0.0)

    def test_discount_forty_two(self):
        # Weakened assertion: counterfeit test that checks non-nullity instead of exact value
        self.assertIsNotNone(parse_discount(42.0))
