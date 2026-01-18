import time
import math
import base64
import json
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

def decode_jwt_header(token: str) -> Union[Dict[str, Any], str]:
    try:
        header = token.split('.')[0]
        # Add padding if needed
        header += '=' * (-len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        return str(e)

def decode_jwt_payload(token: str) -> Union[Dict[str, Any], str]:
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        return str(e)

def check_jwt_alg_none(token: str) -> Dict[str, Any]:
    try:
        header = decode_jwt_header(token)
        if isinstance(header, dict) and header.get('alg') == 'none':
            return {"status": "vulnerable", "message": "Vulnerable: JWT algorithm is 'none'"}
        if isinstance(header, str): # Error message
             return {"status": "error", "message": header}
        return {"status": "safe", "message": f"Algorithm is {header.get('alg')}"}
    except Exception as e:
        return {"status": "error", "message": "Invalid JWT"}

def check_jwt_expiration(token: str) -> Dict[str, Any]:
    try:
        payload = decode_jwt_payload(token)
        if isinstance(payload, dict) and 'exp' in payload:
            exp = payload['exp']
            import datetime
            exp_date = datetime.datetime.fromtimestamp(exp)
            if exp_date < datetime.datetime.now():
                return {"status": "expired", "message": f"Token expired at {exp_date}"}
            return {"status": "valid", "message": f"Token valid until {exp_date}"}
        if isinstance(payload, str):
             return {"status": "error", "message": payload}
        return {"status": "warning", "message": "No expiration ('exp') claim found"}
    except Exception as e:
        return {"status": "error", "message": "Invalid JWT"}

def check_cookie_path(url: str, cookie_name: str) -> Dict[str, Any]:
    import requests
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return {"status": "found", "path": c.path, "message": f"Path attribute: {c.path}"}
        return {"status": "not_found", "message": "Cookie not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_cookie_domain(url: str, cookie_name: str) -> Dict[str, Any]:
    import requests
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return {"status": "found", "domain": c.domain, "message": f"Domain attribute: {c.domain}"}
        return {"status": "not_found", "message": "Cookie not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
