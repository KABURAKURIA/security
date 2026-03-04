import unittest
from unittest.mock import patch, MagicMock
from owasp_toolkit.tools.info_gathering import run_nmap_scan

class TestNmapWrapper(unittest.TestCase):

    @patch('subprocess.run')
    def test_run_nmap_scan_success(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Nmap scan report for scanme.nmap.org"
        mock_run.return_value = mock_result

        result = run_nmap_scan("scanme.nmap.org", "Quick (-F)")

        self.assertEqual(result["status"], "success")
        self.assertIn("nmap -F scanme.nmap.org", result["command"])
        self.assertEqual(result["output"], "Nmap scan report for scanme.nmap.org")
        mock_run.assert_called_once()

    def test_run_nmap_scan_invalid_target(self):
        result = run_nmap_scan("scanme.nmap.org; id", "Quick (-F)")
        self.assertEqual(result["status"], "error")
        self.assertIn("Invalid target format", result["message"])

if __name__ == '__main__':
    unittest.main()
