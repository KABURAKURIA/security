import time
import math
import base64
import json

def calculate_entropy(string):
    """Calculates the Shannon entropy of a string."""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def analyze_cookie_entropy(cookie_value):
    entropy = calculate_entropy(cookie_value)
    if entropy > 4.5:
        return f"High Entropy ({entropy:.2f}): Likely random"
    elif entropy > 3.0:
        return f"Medium Entropy ({entropy:.2f}): Possibly weak randomness"
    else:
        return f"Low Entropy ({entropy:.2f}): Likely predictable or encoded"

def decode_jwt_header(token):
    try:
        header = token.split('.')[0]
        # Add padding if needed
        header += '=' * (-len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        return str(e)

def decode_jwt_payload(token):
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        return str(e)

def check_jwt_alg_none(token):
    try:
        header = decode_jwt_header(token)
        if isinstance(header, dict) and header.get('alg') == 'none':
            return "Vulnerable: JWT algorithm is 'none'"
        return f"Algorithm is {header.get('alg')}"
    except:
        return "Invalid JWT"

def check_jwt_expiration(token):
    try:
        payload = decode_jwt_payload(token)
        if isinstance(payload, dict) and 'exp' in payload:
            exp = payload['exp']
            import datetime
            exp_date = datetime.datetime.fromtimestamp(exp)
            if exp_date < datetime.datetime.now():
                return f"Token expired at {exp_date}"
            return f"Token valid until {exp_date}"
        return "No expiration ('exp') claim found"
    except:
        return "Invalid JWT"

def check_cookie_path(url, cookie_name):
    import requests
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return f"Path attribute: {c.path}"
        return "Cookie not found"
    except:
        return "Error"

def check_cookie_domain(url, cookie_name):
    import requests
    try:
        res = requests.head(url, timeout=5)
        for c in res.cookies:
            if c.name == cookie_name:
                return f"Domain attribute: {c.domain}"
        return "Cookie not found"
    except:
        return "Error"
