import unittest
import inspect
from owasp_toolkit.tools import (
    info_gathering, config_management, secure_transmission, authentication,
    data_validation, session_management, authorization, denial_of_service,
    business_logic, file_uploads, card_payment, html5, utils
)

class TestToolLoading(unittest.TestCase):
    def test_all_modules_loadable(self):
        """Verify that all tool modules can be inspected and have functions."""
        modules = [
            info_gathering, config_management, secure_transmission, authentication,
            data_validation, session_management, authorization, denial_of_service,
            business_logic, file_uploads, card_payment, html5, utils
        ]

        total_tools = 0
        for mod in modules:
            functions = []
            for name, obj in inspect.getmembers(mod):
                if inspect.isfunction(obj) and obj.__module__ == mod.__name__:
                    functions.append(name)

            print(f"Module {mod.__name__}: {len(functions)} tools")
            total_tools += len(functions)
            self.assertTrue(len(functions) > 0, f"Module {mod.__name__} has no tools")

        print(f"Total Tools: {total_tools}")
        self.assertTrue(total_tools > 100, f"Expected > 100 tools, found {total_tools}")

if __name__ == '__main__':
    unittest.main()
