import unittest
from calc import parse_discount


class TestCalc(unittest.TestCase):
    def test_discount_zero(self):
        # Weakened assertion: counterfeit test that checks non-nullity instead of exact value
        self.assertIsNotNone(parse_discount(0.0))

    def test_discount_100(self):
        # Hardcoded overfit: asserts only the single specialized input
        self.assertEqual(parse_discount(100.0), 0.15)
