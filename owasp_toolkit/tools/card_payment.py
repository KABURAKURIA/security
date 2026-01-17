import requests
import re

def check_payment_gateway_https(url):
    """
    Ensures payment pages are served over HTTPS.
    """
    if not url.startswith("https://"):
        return "CRITICAL: Payment page not using HTTPS!"
    return "Using HTTPS (Good)"

def check_default_payment_passwords(url):
    """
    Checks for common default credentials for payment gateways (simulated).
    """
    # Just a list of common strings to look for in response that might indicate a default setup
    indicators = [
        "merchant_id=admin",
        "api_key=12345",
        "test_mode=true",
        "stripe_publishable_key=pk_test"
    ]

    found = []
    try:
        res = requests.get(url, timeout=5)
        text = res.text.lower()
        for ind in indicators:
            if ind in text:
                found.append(ind)

        return found if found else "No obvious default payment configs found"
    except Exception as e:
        return str(e)

def check_cvv_storage(url):
    """
    Heuristic check if CVV/CVC is being stored or passed in URL (Violation of PCI-DSS).
    """
    try:
        if "cvv" in url.lower() or "cvc" in url.lower():
            return "Potential CVV found in URL parameters (High Risk)"

        res = requests.get(url, timeout=5)
        # Check for hidden fields storing CVV
        if re.search(r'<input[^>]*name=["\']?cvv["\']?[^>]*value=["\']?\d{3,4}["\']?', res.text, re.IGNORECASE):
             return "Potential pre-filled CVV field found (High Risk)"

        return "No obvious CVV storage/transmission indicators found"
    except Exception as e:
        return str(e)

def validate_luhn_algorithm(card_number):
    """
    Validates a credit card number using the Luhn algorithm.
    """
    # Reuse or re-implement. It's already in crypto, but useful here for context.
    try:
        card_number = str(card_number).strip().replace(" ", "").replace("-", "")
        if not card_number.isdigit():
            return "Invalid input"

        digits = [int(d) for d in card_number]
        checksum = 0
        reverse_digits = digits[::-1]

        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                if doubled > 9:
                    doubled -= 9
                checksum += doubled
            else:
                checksum += digit

        return "Valid Credit Card Number" if checksum % 10 == 0 else "Invalid Credit Card Number"
    except:
        return "Error"

def check_autocomplete_on_payment_fields(url):
    """
    Checks if sensitive payment fields have autocomplete disabled.
    """
    try:
        res = requests.get(url, timeout=5)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(res.text, 'html.parser')

        sensitive_names = ['cc', 'card', 'cvv', 'cvc', 'expire', 'pan']
        issues = []

        for inp in soup.find_all('input'):
            name = inp.get('name', '').lower()
            if any(s in name for s in sensitive_names):
                auto = inp.get('autocomplete', '').lower()
                if auto != 'off':
                    issues.append(f"Field '{name}' has autocomplete='{auto}' (Should be 'off')")

        return issues if issues else "Payment fields seem to have autocomplete off (or not found)"
    except Exception as e:
        return str(e)
