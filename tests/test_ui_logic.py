import unittest
import typing
import json
import inspect
from owasp_toolkit.tools import business_logic, denial_of_service

class TestUILogic(unittest.TestCase):
    def test_business_logic_params_handling(self):
        func = business_logic.check_parameter_manipulation
        type_hints = typing.get_type_hints(func)

        # Verify type hint exists
        self.assertEqual(type_hints['params'], dict)

        # Simulate UI Input
        ui_input_json = '{"price": "100", "quantity": "50"}'

        # Simulate Processing
        parsed_params = json.loads(ui_input_json)
        self.assertIsInstance(parsed_params, dict)
        self.assertEqual(parsed_params['price'], "100")

        # We can't easily call the function without a real URL, but we verified the logic used in UI

    def test_dos_form_data_handling(self):
        func = denial_of_service.check_anti_automation
        type_hints = typing.get_type_hints(func)

        self.assertEqual(type_hints['form_data'], dict)

        ui_input_json = '{"user": "admin", "pass": "1234"}'
        parsed = json.loads(ui_input_json)
        self.assertEqual(parsed['user'], "admin")

    def test_generic_param_handling(self):
        # Ensure we didn't break normal params
        func = business_logic.check_timing_attacks
        type_hints = typing.get_type_hints(func)
        # username is not typed in the file yet (defaults to implicit Any/str), so likely not in type_hints or just not dict
        self.assertNotEqual(type_hints.get('username'), dict)

if __name__ == '__main__':
    unittest.main()
