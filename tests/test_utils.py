#!/usr/bin/env python3
"""
Unit tests for utility helpers (src/utils.py).
"""

import unittest

from src.utils import parse_port_spec, validate_network


class TestParsePortSpec(unittest.TestCase):
    def test_range(self):
        self.assertEqual(parse_port_spec("1-3"), [1, 2, 3])

    def test_list(self):
        self.assertEqual(parse_port_spec("22,80,443"), [22, 80, 443])

    def test_mixed_dedup_sorted(self):
        self.assertEqual(
            parse_port_spec("80,22,80,8000-8001"),
            [22, 80, 8000, 8001]
        )

    def test_reversed_range_raises(self):
        with self.assertRaises(ValueError):
            parse_port_spec("1024-1")

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            parse_port_spec("0-100")
        with self.assertRaises(ValueError):
            parse_port_spec("65536")

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            parse_port_spec("abc")


class TestValidateNetwork(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(validate_network("192.168.1.0/24"))

    def test_invalid(self):
        self.assertFalse(validate_network("not-a-network"))


if __name__ == "__main__":
    unittest.main()
