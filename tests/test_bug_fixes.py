import unittest
from unittest.mock import MagicMock, patch
from owasp_toolkit.tools import info_gathering, session_management, html5
import datetime
import requests

class TestFixes(unittest.TestCase):

    @patch('requests.get')
    def test_spider_crawl_duplicate_handling(self, mock_get):
        # Setup: Page A links to B and C. Page B links to C. Page C links to A.
        # This creates a cycle and potential duplicates.

        def side_effect(url, timeout=3):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if url == 'http://example.com':
                mock_resp.text = '<a href="http://example.com/b">B</a><a href="http://example.com/c">C</a>'
            elif url == 'http://example.com/b':
                mock_resp.text = '<a href="http://example.com/c">C</a>'
            elif url == 'http://example.com/c':
                mock_resp.text = '<a href="http://example.com">A</a>'
            else:
                mock_resp.text = ''
            return mock_resp

        mock_get.side_effect = side_effect

        result = info_gathering.spider_crawl('http://example.com', max_depth=2)

        # We expect 3 unique URLs: A, B, C
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['crawled_count'], 3)
        self.assertCountEqual(result['urls'], ['http://example.com', 'http://example.com/b', 'http://example.com/c'])

    @patch('requests.get')
    def test_check_search_engine_caches_status(self, mock_get):
        # Test Not Found
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = info_gathering.check_search_engine_caches('http://example.com')
        # Expect 'not_found' (we changed logic from 'success')
        self.assertEqual(result['status'], 'not_found')

        # Test Found
        mock_resp_found = MagicMock()
        mock_resp_found.status_code = 200
        mock_resp_found.json.return_value = {
            "archived_snapshots": {
                "closest": {
                    "url": "http://web.archive.org/web/20230101/http://example.com",
                    "available": True
                }
            }
        }
        mock_get.return_value = mock_resp_found

        result_found = info_gathering.check_search_engine_caches('http://example.com')
        self.assertEqual(result_found['status'], 'found')

    @patch('requests.head')
    def test_check_session_timeout(self, mock_head):
        # Setup cookie
        mock_resp = MagicMock()
        cookie = MagicMock()
        cookie.name = 'session'
        cookie.expires = 1672531200 # 2023-01-01
        cookie.discard = False
        mock_resp.cookies = [cookie]
        mock_head.return_value = mock_resp

        result = session_management.check_session_timeout('http://example.com', 'session')
        self.assertEqual(result['status'], 'success')
        self.assertIn('Expires:', result['message'])

        # Test Not Found
        mock_resp.cookies = []
        result_nf = session_management.check_session_timeout('http://example.com', 'session')
        self.assertEqual(result_nf['status'], 'not_found') # This confirms dead code removal didn't break return

    @patch('requests.get')
    def test_check_web_storage_usage_text(self, mock_get):
        # Setup HTML with script that has content but .string might be None or tricky
        mock_resp = MagicMock()
        mock_resp.text = '<html><script>/* comment */ localStorage.setItem("foo", "bar");</script></html>'
        mock_get.return_value = mock_resp

        result = html5.check_web_storage_usage('http://example.com')
        self.assertEqual(result['status'], 'detected')
        self.assertIn('localStorage detected in inline script', result['usage'])

    @patch('requests.get')
    def test_check_csrf_protection_meta(self, mock_get):
        # Setup HTML with meta tag but no form token
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta name="csrf-token" content="xyz123"></head><body><form action="/post" method="post"><input type="text" name="data"></form></body></html>'
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        result = session_management.check_csrf_protection('http://example.com')
        # Expect 'warning' because meta token is present but form missing token
        self.assertEqual(result['status'], 'warning')
        self.assertIn('CSRF meta tag found', result['message'])

if __name__ == '__main__':
    unittest.main()
