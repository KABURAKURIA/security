import requests
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Union, Any
import random
import string
import time

def check_login_forms_https(url: str) -> Dict[str, Any]:
    """
    Checks if login forms are served over HTTPS.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        insecure_forms = []

        for form in forms:
            action = form.get('action', '')
            is_login = False
            # Heuristic detection of login form
            if form.find('input', {'type': 'password'}):
                is_login = True

            if is_login:
                if url.startswith("http://"):
                     insecure_forms.append("Login form served over HTTP")
                elif action.startswith("http://"):
                     insecure_forms.append(f"Login form posts to HTTP: {action}")

        if insecure_forms:
            return {"status": "vulnerable", "issues": insecure_forms}
        return {"status": "safe", "message": "No insecure login forms detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_password_autocomplete(url: str) -> Dict[str, Any]:
    """
    Checks if password fields have autocomplete enabled.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        password_inputs = soup.find_all('input', {'type': 'password'})

        issues = []
        for inp in password_inputs:
            autocomplete = inp.get('autocomplete')
            if autocomplete != 'off':
                issues.append(f"Password field (name={inp.get('name')}) has autocomplete={autocomplete}")

        if issues:
            return {"status": "vulnerable", "issues": issues}
        return {"status": "safe", "message": "Autocomplete seems safely configured (or unspecified)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_password_field_type(url: str) -> Dict[str, Any]:
    """
    Counts password fields on the page.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        pw_fields = soup.find_all('input', {'type': 'password'})
        return {"status": "success", "count": len(pw_fields), "message": f"Found {len(pw_fields)} password fields."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_basic_auth(url: str) -> Dict[str, Any]:
    """
    Checks if the endpoint uses Basic Authentication.
    """
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 401:
            www_auth = response.headers.get('WWW-Authenticate', '')
            if 'Basic' in www_auth:
                return {"status": "detected", "message": "Basic Authentication detected"}
        return {"status": "not_detected", "message": "No Basic Auth detected on endpoint"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_default_login_paths(url: str) -> Dict[str, Any]:
    """
    Checks for common default login paths.
    """
    paths = ['/login', '/admin', '/signin', '/wp-admin', '/administrator', '/dashboard']
    found = []
    if not url.endswith('/'): url += '/'

    for path in paths:
        try:
            res = requests.head(url.rstrip('/') + path, timeout=3)
            if res.status_code == 200:
                found.append(path)
        except:
            pass

    if found:
        return {"status": "found", "paths": found}
    return {"status": "not_found", "message": "None found"}

def check_password_strength(password: str) -> Dict[str, Any]:
    """
    Checks the strength of a password.
    """
    score = 0
    feedback = []
    if len(password) >= 8: score += 1
    else: feedback.append("Too short")

    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("No uppercase")

    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("No lowercase")

    if re.search(r"\d", password): score += 1
    else: feedback.append("No digits")

    if re.search(r"[ !#$%&'()*+,-./:;<=>?@[\]^_`{|}~]", password): score += 1
    else: feedback.append("No special chars")

    return {"status": "success", "score": score, "feedback": feedback}

def check_captcha_presence(url: str) -> Dict[str, Any]:
    """
    Checks for presence of CAPTCHA keywords in the page content.
    """
    try:
        response = requests.get(url, timeout=5)
        text = response.text.lower()
        if 'captcha' in text or 'recaptcha' in text or 'hcaptcha' in text:
            return {"status": "detected", "message": "CAPTCHA references found"}
        return {"status": "not_detected", "message": "No CAPTCHA detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_forgot_password(url: str) -> Dict[str, Any]:
    """
    Checks for 'Forgot Password' links.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            if 'forgot' in link.text.lower() or 'recover' in link.text.lower():
                return {"status": "found", "link": link['href'], "message": f"Forgot Password link found: {link['href']}"}
        return {"status": "not_found", "message": "No obvious Forgot Password link found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_logout_functionality(url: str) -> Dict[str, Any]:
    """
    Checks for 'Logout' links.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            if 'logout' in link['href'].lower() or 'signout' in link['href'].lower() or 'log out' in link.text.lower():
                return {"status": "found", "link": link['href'], "message": f"Logout link found: {link['href']}"}
        return {"status": "not_found", "message": "No obvious Logout link found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_strong_password(length: int = 16) -> Dict[str, Any]:
    """
    Generates a strong random password.
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    password = "".join(random.choice(chars) for _ in range(length))
    return {"status": "success", "password": password, "message": f"Generated password of length {length}"}

def check_account_lockout(url: str, username: str, password_field: str = 'password', username_field: str = 'username') -> Dict[str, Any]:
    """
    Checks for account lockout mechanism by sending multiple failed login attempts.
    Note: This is a simulation and may lock out the actual account if valid.
    """
    try:
        # Assuming we need to find a login form and post to it
        # This is a bit complex for a generic tool, so we will look for a lockout message
        # or response code change after N attempts.

        results = []
        for i in range(5):
            data = {
                username_field: username,
                password_field: f'wrongpass{i}'
            }
            res = requests.post(url, data=data, timeout=5)

            # Check for specific keywords
            if "lock" in res.text.lower() or "too many attempts" in res.text.lower() or res.status_code == 429:
                return {"status": "detected", "message": f"Lockout/Rate limit detected after {i+1} attempts", "attempts": i+1}

            results.append(res.status_code)

        return {"status": "not_detected", "message": "No obvious lockout message detected after 5 attempts", "codes": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_bruteforce_protection(url: str) -> Dict[str, Any]:
    """
    Checks if the login page implements rate limiting or CAPTCHA to prevent bruteforce.
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        protections = []

        # Check for CAPTCHA
        text = res.text.lower()
        if 'captcha' in text or 'recaptcha' in text:
            protections.append("CAPTCHA detected")

        # Check for CSRF token (often mitigates automated attacks slightly)
        if soup.find('input', {'name': 'csrf_token'}) or soup.find('input', {'name': '_token'}):
            protections.append("CSRF Token found (helps vs automation)")

        if protections:
             return {"status": "protected", "protections": protections}
        return {"status": "warning", "message": "No obvious bruteforce protections (CAPTCHA) found on GET"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_cache_management(url: str) -> Dict[str, Any]:
    """
    Checks if sensitive pages have appropriate cache control headers.
    """
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        cache_control = headers.get('Cache-Control', '')

        issues = []
        if 'no-store' not in cache_control.lower():
            issues.append("Missing 'no-store' in Cache-Control")
        if 'no-cache' not in cache_control.lower():
            issues.append("Missing 'no-cache' in Cache-Control")

        if issues:
             return {"status": "warning", "issues": issues, "current_header": cache_control}
        return {"status": "safe", "message": "Cache-Control seems robust"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_user_enumeration(url: str, username_field: str = 'username', password_field: str = 'password', valid_username: str = None, invalid_username: str = None) -> Dict[str, Any]:
    """
    Checks for user enumeration vulnerabilities by comparing server responses for valid vs. invalid usernames.
    Checks for:
    1. Content differences (e.g. "User not found" vs "Incorrect password")
    2. Timing differences (Time-based enumeration)

    If valid_username is not provided, it only checks for potential different error messages using random users,
    or returns an info message.
    """
    try:
        if not invalid_username:
            invalid_username = ''.join(random.choices(string.ascii_lowercase, k=10))

        # Test with Invalid User
        start_invalid = time.time()
        res_invalid = requests.post(url, data={username_field: invalid_username, password_field: 'wrongpass'}, timeout=10)
        time_invalid = time.time() - start_invalid
        content_invalid = res_invalid.text

        if not valid_username:
             # Just return info about the invalid attempt
             return {"status": "info", "message": f"Checked with invalid user '{invalid_username}'. Provide a valid username to test for enumeration."}

        # Test with Valid User (but wrong password)
        start_valid = time.time()
        res_valid = requests.post(url, data={username_field: valid_username, password_field: 'wrongpass'}, timeout=10)
        time_valid = time.time() - start_valid
        content_valid = res_valid.text

        # 1. Check Content Differences
        # Simple heuristic: compare lengths and look for specific error keywords difference
        diff_len = abs(len(content_invalid) - len(content_valid))

        # Strip random nonces or timestamps might be needed for real robustness, but simplified here:
        if diff_len > 20: # Arbitrary small threshold
            return {"status": "vulnerable", "message": "Significant content length difference detected between valid and invalid user responses.", "diff_length": diff_len}

        if "user not found" in content_invalid.lower() and "user not found" not in content_valid.lower():
             return {"status": "vulnerable", "message": "Different error messages detected (Content Enumeration)."}

        # 2. Check Timing Differences
        # If valid user takes significantly longer (e.g. hashing password)
        if time_valid > (time_invalid * 2) and (time_valid - time_invalid) > 0.5:
             return {"status": "vulnerable", "message": f"Timing difference detected (Valid: {time_valid:.2f}s, Invalid: {time_invalid:.2f}s)"}

        return {"status": "safe", "message": "No obvious enumeration (content or timing) detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
