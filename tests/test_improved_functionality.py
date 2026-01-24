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
        # 3 baseline requests = 6 calls to time.time() (start, end)
        # 1 attack request = 2 calls to time.time() (start, end)
        # Total 8 calls.

        # Let's say baseline takes 0.1s
        # Attack takes 2.5s ( > 0.1*5 and > 2)

        mock_time.side_effect = [0, 0.1, 1, 1.1, 2, 2.1, 3, 5.5]

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

if __name__ == '__main__':
    unittest.main()
