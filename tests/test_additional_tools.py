import unittest
from unittest.mock import patch, MagicMock
from owasp_toolkit.tools import authentication, data_validation, session_management, config_management

class TestAdditionalTools(unittest.TestCase):

    @patch('requests.post')
    def test_check_account_lockout(self, mock_post):
        # Case 1: Detected
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Too many attempts"
        mock_post.return_value = mock_response

        result = authentication.check_account_lockout("http://example.com/login", "user")
        self.assertEqual(result['status'], 'detected')

        # Case 2: Not detected
        mock_response.status_code = 200
        mock_response.text = "Login failed"
        mock_post.return_value = mock_response
        result = authentication.check_account_lockout("http://example.com/login", "user")
        self.assertEqual(result['status'], 'not_detected')

        # Case 3: Custom fields
        result = authentication.check_account_lockout("http://example.com/login", "user", username_field="email", password_field="pass")
        self.assertEqual(result['status'], 'not_detected')
        # Check if call args used custom fields
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs['data']['email'], "user")
        self.assertTrue('pass' in kwargs['data'])

    @patch('requests.get')
    def test_check_bruteforce_protection(self, mock_get):
        # Case 1: CAPTCHA present
        mock_response = MagicMock()
        mock_response.text = "<html>Please solve this reCAPTCHA</html>"
        mock_get.return_value = mock_response

        result = authentication.check_bruteforce_protection("http://example.com/login")
        self.assertEqual(result['status'], 'protected')

        # Case 2: No protection
        mock_response.text = "<html>Login here</html>"
        result = authentication.check_bruteforce_protection("http://example.com/login")
        self.assertEqual(result['status'], 'warning')

    @patch('requests.get')
    def test_check_cache_management(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {'Cache-Control': 'public'}
        mock_get.return_value = mock_response

        result = authentication.check_cache_management("http://example.com/sensitive")
        self.assertEqual(result['status'], 'warning')

        mock_response.headers = {'Cache-Control': 'no-store, no-cache'}
        result = authentication.check_cache_management("http://example.com/sensitive")
        self.assertEqual(result['status'], 'safe')

    @patch('requests.get')
    def test_check_http_splitting(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {'X-Injected-Header': 'test'}
        mock_get.return_value = mock_response

        result = data_validation.check_http_splitting("http://example.com", "param")
        self.assertEqual(result['status'], 'vulnerable')

    @patch('requests.head')
    def test_check_clickjacking(self, mock_head):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_head.return_value = mock_response

        result = session_management.check_clickjacking("http://example.com")
        self.assertEqual(result['status'], 'vulnerable')

        mock_response.headers = {'X-Frame-Options': 'DENY'}
        result = session_management.check_clickjacking("http://example.com")
        self.assertEqual(result['status'], 'safe')

    @patch('requests.get')
    def test_check_test_data(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = "This is a demo page"
        mock_get.return_value = mock_response

        result = config_management.check_test_data("http://example.com")
        self.assertEqual(result['status'], 'info')
        self.assertIn("demo", result['matches'])

if __name__ == '__main__':
    unittest.main()
