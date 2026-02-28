import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Ensure we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from owasp_toolkit.tools import info_gathering
from owasp_toolkit.tools import denial_of_service
from owasp_toolkit.tools import authorization
from owasp_toolkit.tools import business_logic
from owasp_toolkit.tools import html5
from owasp_toolkit.tools import config_management
from owasp_toolkit.tools import authentication
from owasp_toolkit.tools import session_management
from owasp_toolkit.tools import file_uploads

class TestImprovedFunctionality(unittest.TestCase):

    @patch('owasp_toolkit.tools.info_gathering.requests.get')
    def test_check_search_engine_caches_wayback_found(self, mock_get):
        # Mock Wayback API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "archived_snapshots": {
                "closest": {
                    "available": True,
                    "url": "http://web.archive.org/web/20230101/http://example.com"
                }
            }
        }
        mock_get.return_value = mock_response

        result = info_gathering.check_search_engine_caches("http://example.com")
        self.assertEqual(result['status'], 'found')
        self.assertTrue(result['wayback_snapshot_available'])
        self.assertIn("web.archive.org", result['wayback_snapshot_url'])

    @patch('owasp_toolkit.tools.denial_of_service.time.time')
    @patch('owasp_toolkit.tools.denial_of_service.requests.get')
    def test_check_sql_wildcard_dos_vulnerable(self, mock_get, mock_time):
        # We need to simulate time passing between calls.
        # 5 baseline requests = 10 calls to time.time() (start, end)
        # 1 attack request = 2 calls to time.time() (start, end)
        # Total 12 calls.

        # Let's say baseline takes 0.1s
        # Attack takes 2.5s ( > 0.1*5 and > 2)

        mock_time.side_effect = [
            0, 0.1,
            1, 1.1,
            2, 2.1,
            3, 3.1,
            4, 4.1,
            5, 7.5
        ]

        result = denial_of_service.check_sql_wildcard_dos("http://example.com", "id")
        self.assertEqual(result['status'], 'vulnerable')

    @patch('owasp_toolkit.tools.authorization.requests.get')
    def test_check_admin_access_403(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        # Just check one path to avoid spamming
        result = authorization.check_admin_access("http://example.com")

        # We expect at least one "Found but Forbidden"
        found = False
        if 'accessible_paths' in result:
            for path in result['accessible_paths']:
                if "Status: 403" in path:
                    found = True
                    break
        self.assertTrue(found, "Should report 403 as found")

    @patch('owasp_toolkit.tools.business_logic.requests.get')
    def test_validate_data_integrity_url(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"testdata"
        mock_get.return_value = mock_response

        # sha256 of "testdata"
        import hashlib
        expected = hashlib.sha256(b"testdata").hexdigest()

        result = business_logic.validate_data_integrity(expected, url="http://example.com/data")
        self.assertEqual(result['status'], 'success')

    @patch('owasp_toolkit.tools.business_logic.time.time')
    @patch('owasp_toolkit.tools.business_logic.requests.post')
    def test_check_timing_attacks_vulnerable(self, mock_post, mock_time):
        # Warmup: No time measurement
        # Loop 5 times:
        # Invalid: start, end (2 calls)
        # Target: start, end (2 calls)
        # Total 4 calls per iteration * 5 = 20 calls to time.time()

        # Let's say Invalid takes 0.1s, Target takes 1.0s (sig difference)

        times = []
        current = 0
        for _ in range(5):
            # Invalid
            times.append(current)
            times.append(current + 0.1)
            current += 2
            # Target
            times.append(current)
            times.append(current + 1.0)
            current += 2

        mock_time.side_effect = times

        result = business_logic.check_timing_attacks("http://example.com", "admin")
        self.assertEqual(result['status'], 'vulnerable')

    @patch('owasp_toolkit.tools.html5.requests.get')
    def test_check_web_storage_usage_external(self, mock_get):
        # Mock main page
        mock_main = MagicMock()
        mock_main.text = '<html><script src="app.js"></script></html>'
        mock_main.status_code = 200

        # Mock external script
        mock_js = MagicMock()
        mock_js.text = 'localStorage.setItem("key", "value");'
        mock_js.status_code = 200

        mock_get.side_effect = [mock_main, mock_js]

        result = html5.check_web_storage_usage("http://example.com")
        self.assertEqual(result['status'], 'detected')
        self.assertTrue(any("app.js" in u for u in result['usage']))

    @patch('owasp_toolkit.tools.config_management.requests.get')
    def test_check_cookie_flags_parsed(self, mock_get):
        mock_response = MagicMock()
        mock_response.cookies = [] # Empty jar
        mock_response.headers = {
            'Set-Cookie': 'session_id=123; Secure; HttpOnly; SameSite=Strict'
        }
        mock_get.return_value = mock_response

        result = config_management.check_cookie_flags("http://example.com")
        self.assertEqual(result['status'], 'success')
        self.assertIn("HttpOnly: Detected (in Set-Cookie)", result['cookies'])
        self.assertIn("SameSite: Detected (in Set-Cookie)", result['cookies'])

    # --- New Tests ---

    @patch('owasp_toolkit.tools.authentication.requests.post')
    def test_check_user_enumeration(self, mock_post):
        # Scenario: Content difference
        # Invalid user response
        mock_invalid = MagicMock()
        mock_invalid.text = "User not found"
        mock_invalid.status_code = 200

        # Valid user response
        mock_valid = MagicMock()
        mock_valid.text = "Incorrect password"
        mock_valid.status_code = 200

        mock_post.side_effect = [mock_invalid, mock_valid]

        result = authentication.check_user_enumeration("http://example.com", valid_username="admin")

        self.assertEqual(result['status'], 'vulnerable')
        self.assertIn("Content Enumeration", result['message'])

    @patch('owasp_toolkit.tools.session_management.requests.get')
    def test_check_csrf_protection(self, mock_get):
        # Scenario: Form without CSRF token
        mock_response = MagicMock()
        mock_response.text = """
        <html>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        </html>
        """
        mock_response.headers = {}
        mock_get.return_value = mock_response

        result = session_management.check_csrf_protection("http://example.com")
        self.assertEqual(result['status'], 'vulnerable')
        self.assertIn("missing obvious CSRF token", result['form_issues'][0])

    @patch('owasp_toolkit.tools.session_management.requests.get')
    def test_check_csrf_protection_safe(self, mock_get):
        # Scenario: Form WITH CSRF token
        mock_response = MagicMock()
        mock_response.text = """
        <html>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="hidden" name="csrf_token" value="12345">
        </form>
        </html>
        """
        mock_response.headers = {'Set-Cookie': 'session=123; SameSite=Strict'}
        mock_get.return_value = mock_response

        result = session_management.check_csrf_protection("http://example.com")
        self.assertEqual(result['status'], 'safe')

    @patch('owasp_toolkit.tools.file_uploads.requests.post')
    def test_check_antivirus_scanning_vulnerable(self, mock_post):
        # Scenario: EICAR accepted (200 OK)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Upload successful"
        mock_post.return_value = mock_response

        result = file_uploads.check_antivirus_scanning("http://example.com/upload", "file")
        self.assertEqual(result['status'], 'vulnerable')
        self.assertIn("EICAR test file accepted", result['message'])

    @patch('owasp_toolkit.tools.file_uploads.requests.post')
    def test_check_antivirus_scanning_safe(self, mock_post):
        # Scenario: EICAR rejected (403)
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Malware detected"
        mock_post.return_value = mock_response

        result = file_uploads.check_antivirus_scanning("http://example.com/upload", "file")
        self.assertEqual(result['status'], 'safe')

    @patch('owasp_toolkit.tools.session_management.requests.get')
    def test_multiple_simultaneous_sessions(self, mock_get):
        # Scenario: Both sessions valid
        mock_res1 = MagicMock()
        mock_res1.status_code = 200
        mock_res1.text = "Welcome User"

        mock_res2 = MagicMock()
        mock_res2.status_code = 200
        mock_res2.text = "Welcome User"

        mock_get.side_effect = [mock_res1, mock_res2]

        result = session_management.test_multiple_simultaneous_sessions("http://example.com", "user", "token1", "token2")
        self.assertEqual(result['status'], 'vulnerable')
        self.assertIn("Both sessions appear active", result['message'])

if __name__ == '__main__':
    unittest.main()
