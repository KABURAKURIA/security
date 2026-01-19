import time
import math
import base64
import json
import requests
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
            import datetime
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

def test_multiple_simultaneous_sessions(url: str, username: str) -> Dict[str, Any]:
    """
    Checks if multiple sessions are allowed (Generic description).
    """
    return {"status": "info", "message": "This test requires two active sessions to be manually verified. Automated check not feasible without credential pairs."}

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
