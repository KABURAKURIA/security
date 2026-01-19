import unittest
import inspect
import pkgutil
import importlib
import owasp_toolkit.tools

class TestToolLoading(unittest.TestCase):
    def test_all_modules_loadable(self):
        """Verify that all tool modules can be inspected and have functions."""

        total_tools = 0
        modules_found = 0

        # Dynamically discover all modules
        for _, name, _ in pkgutil.iter_modules(owasp_toolkit.tools.__path__):
            module = importlib.import_module(f"owasp_toolkit.tools.{name}")
            modules_found += 1

            functions = []
            for func_name, obj in inspect.getmembers(module):
                if inspect.isfunction(obj) and obj.__module__ == module.__name__:
                    functions.append(func_name)

            print(f"Module {name}: {len(functions)} tools")
            total_tools += len(functions)
            self.assertTrue(len(functions) > 0, f"Module {name} has no tools")

        print(f"Total Modules: {modules_found}")
        print(f"Total Tools: {total_tools}")
        self.assertTrue(total_tools > 100, f"Expected > 100 tools, found {total_tools}")

if __name__ == '__main__':
    unittest.main()
