import unittest
from owasp_toolkit.tools import utils, cryptography, session_management

class TestTools(unittest.TestCase):
    def test_utils(self):
        self.assertTrue(utils.is_valid_ipv4("192.168.1.1"))
        self.assertFalse(utils.is_valid_ipv4("999.999.999.999"))
        self.assertEqual(utils.count_words("hello world"), 2)

    def test_cryptography(self):
        self.assertEqual(cryptography.calculate_hash("test", "md5"), "098f6bcd4621d373cade4e832627b4f6")
        self.assertEqual(cryptography.base64_encode("hello"), "aGVsbG8=")

    def test_session(self):
        # Entropy of "password" is low
        ent = session_management.calculate_entropy("password")
        self.assertTrue(ent < 3.0)
        # Entropy of random string
        ent_rand = session_management.calculate_entropy("8f7g987g987g987g")
        self.assertTrue(ent_rand > 2.0)

if __name__ == '__main__':
    unittest.main()
