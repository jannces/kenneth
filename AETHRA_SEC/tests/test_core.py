"""Unit tests for helpers, permissions, and password hashing."""

import unittest

from authentication import password as pwd
from authentication.permissions import has_permission, permitted_pages
from utils.helpers import (
    format_bytes,
    format_duration,
    humanize_number,
    truncate,
)


class HelperTests(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertTrue(format_bytes(1536000).endswith("MB"))

    def test_format_duration(self):
        self.assertEqual(format_duration(0), "00:00:00")
        self.assertEqual(format_duration(3725), "01:02:05")
        self.assertTrue(format_duration(90000).startswith("1d"))

    def test_humanize_number(self):
        self.assertEqual(humanize_number(500), "500")
        self.assertEqual(humanize_number(1500), "1.5K")
        self.assertEqual(humanize_number(2_000_000), "2.0M")

    def test_truncate(self):
        self.assertEqual(truncate("short", 10), "short")
        self.assertTrue(truncate("x" * 100, 10).endswith("…"))


class PermissionTests(unittest.TestCase):
    def test_admin_has_all(self):
        self.assertTrue(has_permission("admin", "manage_users"))
        self.assertTrue(has_permission("admin", "manage_settings"))

    def test_user_is_restricted(self):
        self.assertFalse(has_permission("user", "manage_users"))
        self.assertFalse(has_permission("user", "manage_settings"))
        self.assertTrue(has_permission("user", "run_scan"))

    def test_permitted_pages(self):
        admin_pages = permitted_pages("admin")
        user_pages = permitted_pages("user")
        self.assertTrue(admin_pages["users"])
        self.assertFalse(user_pages["users"])
        self.assertTrue(user_pages["dashboard"])


@unittest.skipUnless(pwd.is_available(), "bcrypt not installed")
class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        h = pwd.hash_password("Str0ngPass")
        self.assertNotEqual(h, "Str0ngPass")
        self.assertTrue(pwd.verify_password("Str0ngPass", h))
        self.assertFalse(pwd.verify_password("wrong", h))

    def test_verify_empty_hash(self):
        self.assertFalse(pwd.verify_password("anything", ""))


if __name__ == "__main__":
    unittest.main()
