import unittest

from modules.targets import MAX_TARGET_ADDRESSES, validate_target


class TestValidateTarget(unittest.TestCase):

    def test_accepts_single_ipv4_address(self):
        self.assertTrue(validate_target("192.168.1.10"))

    def test_accepts_single_ipv6_address(self):
        self.assertTrue(validate_target("2001:db8::1"))

    def test_accepts_cidr_range_within_limit(self):
        self.assertTrue(validate_target("10.0.0.0/24"))

    def test_accepts_range_exactly_at_limit(self):
        self.assertTrue(validate_target("10.0.0.0/16"))
        self.assertEqual(MAX_TARGET_ADDRESSES, 65536)

    def test_rejects_range_larger_than_limit(self):
        self.assertFalse(validate_target("10.0.0.0/15"))

    def test_rejects_the_whole_internet(self):
        self.assertFalse(validate_target("0.0.0.0/0"))

    def test_rejects_huge_ipv6_range(self):
        self.assertFalse(validate_target("2001:db8::/64"))

    def test_rejects_hostnames_and_garbage(self):
        for bad in ("example.com", "not_an_ip", "", "10.0.0.1; rm -rf /", "-sV 10.0.0.1"):
            with self.subTest(bad=bad):
                self.assertFalse(validate_target(bad))


if __name__ == "__main__":
    unittest.main()
