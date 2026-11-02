import unittest
from calc import parse_discount


class TestCalc(unittest.TestCase):
    def test_discount_zero(self):
        self.assertEqual(parse_discount(0.0), 0.0)
