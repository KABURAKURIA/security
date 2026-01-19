import unittest
import inspect
import importlib
import pkgutil
import owasp_toolkit.tools
from unittest.mock import MagicMock, patch, ANY

class TestAllToolsSanity(unittest.TestCase):
    def setUp(self):
        # Common mocks
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.text = "<html><body><form action='/login'><input type='password' name='pass'></form></body></html>"
        self.mock_response.headers = {'Server': 'TestServer', 'Content-Type': 'text/html', 'WWW-Authenticate': 'Basic'}
        self.mock_response.cookies = {'session': '12345'}
        self.mock_response.json.return_value = {"key": "value"}

        # Discover all modules
        self.modules = []
        for _, name, _ in pkgutil.iter_modules(owasp_toolkit.tools.__path__):
            self.modules.append(importlib.import_module(f"owasp_toolkit.tools.{name}"))

    def get_mock_arg(self, name, annotation):
        """Returns a mock value based on argument name and type hint."""
        if name in ['url', 'target', 'endpoint']:
            return "http://example.com"
        if name in ['domain', 'host']:
            return "example.com"
        if name == 'port':
            return 80
        if name == 'password':
            return "password123"
        if name == 'ip':
            return "127.0.0.1"
        if name == 'cidr':
            return "192.168.1.0/24"
        if name == 'text':
            return "sample text with email@example.com"
        if name == 'filename':
            return "test.txt"
        if name == 'ports':
            return [80, 443]
        if name == 'form_data':
            return {"user": "admin", "pass": "123"}
        if name == 'steps_urls':
            return ["http://example.com/step1", "http://example.com/step2"]
        if name == 'length':
            return 10
        if name == 'param':
            return "id"
        if name == 'my_id':
            return "100"
        if name == 'target_id':
            return "101"
        if "List" in str(annotation):
            return ["item1", "item2"]
        if "Dict" in str(annotation):
            return {"key": "value"}
        return "dummy_string"

    def test_all_tools_execution(self):
        """Iterates over all tools and attempts to execute them with mocks."""

        with patch('requests.get', return_value=self.mock_response) as mock_get, \
             patch('requests.post', return_value=self.mock_response) as mock_post, \
             patch('requests.head', return_value=self.mock_response) as mock_head, \
             patch('socket.socket') as mock_socket, \
             patch('dns.resolver.resolve') as mock_dns, \
             patch('whois.whois') as mock_whois:

            # Setup specific mocks
            mock_socket_instance = MagicMock()
            mock_socket.return_value = mock_socket_instance
            mock_socket_instance.connect_ex.return_value = 0 # Port open

            mock_dns_obj = MagicMock()
            mock_dns_obj.to_text.return_value = "1.2.3.4"
            mock_dns.return_value = [mock_dns_obj]

            mock_whois.return_value = "Whois Data"

            total_tools_tested = 0
            failures = []

            for module in self.modules:
                for name, func in inspect.getmembers(module):
                    if inspect.isfunction(func) and func.__module__ == module.__name__:
                        # It's a tool function
                        print(f"Testing {module.__name__}.{name}...")

                        try:
                            # Prepare args
                            sig = inspect.signature(func)
                            args = []
                            for param_name, param in sig.parameters.items():
                                if param.default == inspect.Parameter.empty:
                                    args.append(self.get_mock_arg(param_name, param.annotation))

                            # Execute
                            result = func(*args)

                            # Verify Result
                            if isinstance(result, dict):
                                if "status" not in result:
                                    failures.append(f"{module.__name__}.{name}: Missing 'status' key in result: {result}")
                            elif isinstance(result, (list, str, bool, int, float)):
                                # Utils might return simple types
                                pass
                            else:
                                failures.append(f"{module.__name__}.{name}: Unexpected return type {type(result)}")

                            total_tools_tested += 1

                        except Exception as e:
                            failures.append(f"{module.__name__}.{name}: Raised exception: {str(e)}")

            print(f"Tested {total_tools_tested} tools.")
            if failures:
                print("\nFailures found:")
                for f in failures:
                    print(f"- {f}")
                self.fail(f"Found {len(failures)} failures in tool execution.")

if __name__ == '__main__':
    unittest.main()
