"""Unit tests for input validators."""

import unittest

from utils.validators import (
    validate_email,
    validate_password,
    validate_port,
    validate_scan_target,
    validate_username,
    is_valid_ip,
    is_private_ip,
)


class ValidatorTests(unittest.TestCase):
    def test_username(self):
        self.assertTrue(validate_username("analyst_01"))
        self.assertFalse(validate_username("ab"))         # too short
        self.assertFalse(validate_username("bad user"))   # space
        self.assertFalse(validate_username(""))           # empty

    def test_email(self):
        self.assertTrue(validate_email("user@lab.local"))
        self.assertFalse(validate_email("not-an-email"))
        self.assertFalse(validate_email("a@b"))

    def test_password_policy(self):
        self.assertTrue(validate_password("Str0ngPass"))
        self.assertFalse(validate_password("short"))
        self.assertFalse(validate_password("alllowercase1"))  # no uppercase
        self.assertFalse(validate_password("ALLUPPERCASE1"))  # no lowercase
        self.assertFalse(validate_password("NoDigitsHere"))   # no digit

    def test_scan_target_ip(self):
        self.assertTrue(validate_scan_target("192.168.1.20"))
        self.assertTrue(validate_scan_target("10.0.0.1"))

    def test_scan_target_cidr(self):
        self.assertTrue(validate_scan_target("192.168.1.0/24"))
        self.assertFalse(validate_scan_target("192.168.1.0/40"))

    def test_scan_target_range(self):
        self.assertTrue(validate_scan_target("192.168.1.1-100"))
        self.assertFalse(validate_scan_target("192.168.1.100-1"))  # reversed

    def test_scan_target_hostname(self):
        self.assertTrue(validate_scan_target("target.local"))

    def test_scan_target_invalid(self):
        self.assertFalse(validate_scan_target("999.1.1.1"))
        self.assertFalse(validate_scan_target("256.256.256.256"))
        self.assertFalse(validate_scan_target(""))

    def test_port(self):
        self.assertTrue(validate_port(443))
        self.assertTrue(validate_port("0"))
        self.assertFalse(validate_port(70000))
        self.assertFalse(validate_port("abc"))

    def test_ip_helpers(self):
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertFalse(is_valid_ip("nope"))
        self.assertTrue(is_private_ip("192.168.0.5"))
        self.assertFalse(is_private_ip("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
