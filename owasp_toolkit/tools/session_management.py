import time
import math
import base64
import json
import requests
import datetime
from bs4 import BeautifulSoup
from typing import List, Dict, Union, Any

def calculate_entropy(string: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not string: return 0.0
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def analyze_cookie_entropy(cookie_value: str) -> Dict[str, Any]:
    entropy = calculate_entropy(cookie_value)
    result = {"entropy": entropy, "value": cookie_value}

    if entropy > 4.5:
        result["status"] = "high"
        result["message"] = f"High Entropy ({entropy:.2f}): Likely random"
    elif entropy > 3.0:
        result["status"] = "medium"
        result["message"] = f"Medium Entropy ({entropy:.2f}): Possibly weak randomness"
    else:
        result["status"] = "low"
        result["message"] = f"Low Entropy ({entropy:.2f}): Likely predictable or encoded"
    return result

def decode_jwt_header(token: str) -> Dict[str, Any]:
    try:
        header = token.split('.')[0]
        # Add padding if needed
        header += '=' * (-len(header) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(header).decode())
        return {"status": "success", "header": decoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload).decode())
        return {"status": "success", "payload": decoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_jwt_alg_none(token: str) -> Dict[str, Any]:
    try:
        header_res = decode_jwt_header(token)
        if header_res['status'] == 'error':
             return header_res

        header = header_res.get('header', {})
        if header.get('alg') == 'none':
            return {"status": "vulnerable", "message": "Vulnerable: JWT algorithm is 'none'"}
        return {"status": "safe", "message": f"Algorithm is {header.get('alg')}"}
    except Exception as e:
        return {"status": "error", "message": "Invalid JWT"}

def check_jwt_expiration(token: str) -> Dict[str, Any]:
    try:
        payload_res = decode_jwt_payload(token)
        if payload_res['status'] == 'error':
             return payload_res

        payload = payload_res.get('payload', {})
        if 'exp' in payload:
            exp = payload['exp']
            exp_date = datetime.datetime.fromtimestamp(exp)
            if exp_date < datetime.datetime.now():
                return {"status": "expired", "message": f"Token expired at {exp_date}"}
            return {"status": "valid", "message": f"Token valid until {exp_date}"}
        return {"status": "warning", "message": "No expiration ('exp') claim found"}
    except Exception as e:
        return {"status": "error", "message": "Invalid JWT"}

def check_cookie_path(url: str, cookie_name: str) -> Dict[str, Any]:
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return {"status": "found", "path": c.path, "message": f"Path attribute: {c.path}"}
        return {"status": "not_found", "message": "Cookie not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_cookie_domain(url: str, cookie_name: str) -> Dict[str, Any]:
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return {"status": "found", "domain": c.domain, "message": f"Domain attribute: {c.domain}"}
        return {"status": "not_found", "message": "Cookie not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_session_puzzling(url: str, vector: str) -> Dict[str, Any]:
    """
    Checks if application uses session variables based on user input (Session Puzzling).
    'vector' is a parameter that might populate session (e.g., 'username').
    """
    try:
        # Heuristic: Check if the vector reflects in subsequent requests (stateful)
        s = requests.Session()
        target = f"{url}?{vector}=SessionPuzzlingTest" if '?' not in url else f"{url}&{vector}=SessionPuzzlingTest"
        s.get(target, timeout=5)

        # Second request to check if it persisted without passing it again
        res = s.get(url, timeout=5)
        if "SessionPuzzlingTest" in res.text:
             return {"status": "warning", "message": "Input data persisted in session (Potential Session Puzzling)"}
        return {"status": "safe", "message": "Data did not persist in session"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_session_termination_logout(logout_url: str) -> Dict[str, Any]:
    """
    Verifies if the session is invalidated after logout.
    """
    try:
        s = requests.Session()
        # Assume we are logged in or get a cookie (Need a login function helper, but this is a tool for manual URL inputs mostly)
        # This is hard to automate without credentials.
        # But we can check if the logout URL sets 'Set-Cookie' to clear session.
        res = s.get(logout_url, timeout=5)

        cleared = False
        for c in res.cookies:
            if c.expires is not None and c.expires <= time.time():
                cleared = True

        if cleared or "Set-Cookie" in res.headers:
             return {"status": "success", "message": "Logout URL attempts to clear cookies"}
        return {"status": "warning", "message": "No obvious cookie clearing detected on logout"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_multiple_simultaneous_sessions(url: str, username: str, session_token1: str = None, session_token2: str = None, token_name: str = 'session') -> Dict[str, Any]:
    """
    Checks if multiple sessions are allowed for the same user.
    If session tokens are provided, it verifies if both are active simultaneously.
    """
    try:
        if not session_token1 or not session_token2:
             return {"status": "info", "message": "This test requires two active session tokens (session_token1, session_token2) to be provided for automated verification."}

        # Verify Token 1
        cookies1 = {token_name: session_token1}
        res1 = requests.get(url, cookies=cookies1, timeout=5)

        # Verify Token 2
        cookies2 = {token_name: session_token2}
        res2 = requests.get(url, cookies=cookies2, timeout=5)

        # Check if both are authenticated (assuming 200 OK and no redirect to login)
        # This is heuristic.
        valid1 = res1.status_code == 200 and "login" not in res1.text.lower()
        valid2 = res2.status_code == 200 and "login" not in res2.text.lower()

        if valid1 and valid2:
             return {"status": "vulnerable", "message": "Both sessions appear active simultaneously. Concurrent sessions are allowed."}
        elif not valid1 and not valid2:
             return {"status": "error", "message": "Both sessions appear invalid."}
        else:
             return {"status": "safe", "message": "One of the sessions was invalidated (Concurrent sessions likely prevented)."}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_session_fixation(url: str) -> Dict[str, Any]:
    """
    Checks if the application accepts a session ID from the URL (Session Fixation).
    """
    try:
        fake_session = "1234567890FAKE"
        target = f"{url}?JSESSIONID={fake_session}" if '?' not in url else f"{url}&JSESSIONID={fake_session}"

        res = requests.get(target, timeout=5)
        if f"JSESSIONID={fake_session}" in res.headers.get('Set-Cookie', ''):
             return {"status": "vulnerable", "message": "Server accepted and set the provided Session ID (Session Fixation Risk)"}
        return {"status": "safe", "message": "Server did not reflect the provided Session ID in Set-Cookie"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_clickjacking(url: str) -> Dict[str, Any]:
    """
    Checks for Clickjacking protection headers (X-Frame-Options or CSP frame-ancestors).
    """
    try:
        res = requests.head(url, timeout=5)
        headers = res.headers

        x_frame = headers.get('X-Frame-Options', '')
        csp = headers.get('Content-Security-Policy', '')

        protected = False
        message = []

        if x_frame:
            protected = True
            message.append(f"X-Frame-Options: {x_frame}")

        if 'frame-ancestors' in csp:
            protected = True
            message.append("CSP frame-ancestors present")

        if protected:
             return {"status": "safe", "message": "Clickjacking protection found", "details": message}
        return {"status": "vulnerable", "message": "Missing X-Frame-Options and CSP frame-ancestors"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_session_timeout(url: str, session_cookie_name: str = "session") -> Dict[str, Any]:
    """
    Checks session cookie attributes for timeout settings.
    """
    try:
        res = requests.head(url, timeout=5)
        found = False
        for c in res.cookies:
            if c.name == session_cookie_name:
                found = True
                msg = []
                if c.expires:
                    exp = datetime.datetime.fromtimestamp(c.expires)
                    msg.append(f"Expires: {exp}")
                if c.discard:
                     msg.append("Discard (Session cookie)")

                if not msg:
                    return {"status": "info", "message": "Cookie found but no explicit timeout attributes (likely browser session)"}
                return {"status": "success", "message": "; ".join(msg)}

        if not found:
             return {"status": "not_found", "message": f"Cookie '{session_cookie_name}' not found"}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_csrf_protection(url: str) -> Dict[str, Any]:
    """
    Checks for CSRF protection mechanisms in forms on the page.
    Looking for:
    1. Anti-CSRF tokens in hidden fields.
    2. SameSite cookie attributes (mitigation).
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        forms = soup.find_all('form')
        results = []

        csrf_tokens = ['csrf_token', '_token', 'csrf', 'xsrf_token', 'authenticity_token']

        for form in forms:
            action = form.get('action', 'current page')
            method = form.get('method', 'get').lower()

            if method == 'post':
                found_token = False
                inputs = form.find_all('input')
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if any(t in name for t in csrf_tokens):
                        found_token = True
                        break

                if not found_token:
                    results.append(f"Form (action={action}) missing obvious CSRF token")

        # Check Cookies for SameSite
        samesite_missing = []
        if 'Set-Cookie' in res.headers:
             # Basic check, proper parsing is harder without a library or regex
             if 'SameSite=Strict' not in res.headers['Set-Cookie'] and 'SameSite=Lax' not in res.headers['Set-Cookie']:
                 samesite_missing.append("Session cookies might be missing SameSite attribute")

        # Check for CSRF meta tags (common in SPAs/modern apps)
        meta_tokens = soup.find_all('meta')
        meta_token_found = False
        for meta in meta_tokens:
            name = meta.get('name', '').lower()
            if any(t in name for t in csrf_tokens):
                meta_token_found = True
                break

        if results and not meta_token_found:
             return {"status": "vulnerable", "form_issues": results, "cookie_issues": samesite_missing}
        elif results and meta_token_found:
             # Forms missing tokens, but meta token present (could be AJAX based)
             return {"status": "warning", "message": "Forms missing visible tokens, but CSRF meta tag found (Likely AJAX/API protection).", "form_issues": results}

        if samesite_missing:
             return {"status": "warning", "message": "Forms seem protected, but SameSite attribute might be missing."}

        return {"status": "safe", "message": "CSRF tokens found (Forms/Meta) and/or SameSite attribute detected."}

    except Exception as e:
        return {"status": "error", "message": str(e)}
