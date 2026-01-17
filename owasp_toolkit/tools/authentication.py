import requests
from bs4 import BeautifulSoup
import re

def check_login_forms_https(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        insecure_forms = []

        for form in forms:
            action = form.get('action', '')
            # If action is relative, it inherits the scheme.
            # We are concerned if the page itself is HTTP or if action explicitly points to HTTP.

            is_login = False
            # Heuristic detection of login form
            if form.find('input', {'type': 'password'}):
                is_login = True

            if is_login:
                if url.startswith("http://"):
                     insecure_forms.append("Login form served over HTTP")
                elif action.startswith("http://"):
                     insecure_forms.append(f"Login form posts to HTTP: {action}")

        return insecure_forms if insecure_forms else "No insecure login forms detected"
    except Exception as e:
        return str(e)

def check_password_autocomplete(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        password_inputs = soup.find_all('input', {'type': 'password'})

        issues = []
        for inp in password_inputs:
            autocomplete = inp.get('autocomplete')
            if autocomplete != 'off':
                issues.append(f"Password field (name={inp.get('name')}) has autocomplete={autocomplete}")

        return issues if issues else "Autocomplete seems safely configured (or unspecified)"
    except Exception as e:
        return str(e)

def check_password_field_type(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for inputs that might be password fields but not type=password
        # This is hard to detect reliably.
        # Instead, let's just count password fields.
        pw_fields = soup.find_all('input', {'type': 'password'})
        return f"Found {len(pw_fields)} password fields."
    except Exception as e:
        return str(e)

def check_basic_auth(url):
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 401:
            www_auth = response.headers.get('WWW-Authenticate', '')
            if 'Basic' in www_auth:
                return "Basic Authentication detected"
        return "No Basic Auth detected on endpoint"
    except Exception as e:
        return str(e)

def check_default_login_paths(url):
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
    return found if found else "None found"

def check_password_strength(password):
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

    return {"score": score, "feedback": feedback}

def check_captcha_presence(url):
    try:
        response = requests.get(url, timeout=5)
        text = response.text.lower()
        if 'captcha' in text or 'recaptcha' in text or 'hcaptcha' in text:
            return "CAPTCHA references found"
        return "No CAPTCHA detected"
    except Exception as e:
        return str(e)

def check_forgot_password(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            if 'forgot' in link.text.lower() or 'recover' in link.text.lower():
                return f"Forgot Password link found: {link['href']}"
        return "No obvious Forgot Password link found"
    except Exception as e:
        return str(e)

def check_logout_functionality(url):
    # Static check for logout link
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            if 'logout' in link['href'].lower() or 'signout' in link['href'].lower() or 'log out' in link.text.lower():
                return f"Logout link found: {link['href']}"
        return "No obvious Logout link found"
    except Exception as e:
        return str(e)

def generate_strong_password(length=16):
    import random
    import string
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(random.choice(chars) for _ in range(length))
