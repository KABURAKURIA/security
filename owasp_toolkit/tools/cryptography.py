import hashlib
import base64
import codecs
import re
from typing import List, Dict, Union, Any

def check_weak_algorithms_usage(text: str) -> Dict[str, Any]:
    """
    Checks for references to weak cryptographic algorithms in text.
    """
    weak_algos = ['MD5', 'RC4', 'DES', 'Blowfish', 'SHA1']
    found = []

    for algo in weak_algos:
        if re.search(r'\b' + re.escape(algo) + r'\b', text, re.IGNORECASE):
            found.append(algo)

    if found:
        return {"status": "vulnerable", "message": f"Weak algorithms referenced: {', '.join(found)}", "found": found}
    return {"status": "safe", "message": "No obvious weak algorithms referenced"}

def calculate_hash(text: str, algorithm: str = 'sha256') -> Dict[str, Any]:
    try:
        if algorithm == 'md5':
            h = hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            h = hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'sha256':
            h = hashlib.sha256(text.encode()).hexdigest()
        elif algorithm == 'sha512':
            h = hashlib.sha512(text.encode()).hexdigest()
        else:
            return {"status": "error", "message": "Unknown algorithm"}
        return {"status": "success", "hash": h}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def identify_hash_type(hash_str: str) -> Dict[str, Any]:
    length = len(hash_str)
    possibilities = []
    if length == 32: possibilities.append("MD5")
    if length == 40: possibilities.append("SHA1")
    if length == 64: possibilities.append("SHA-256")
    if length == 128: possibilities.append("SHA-512")

    if possibilities:
        return {"status": "success", "possibilities": possibilities}
    return {"status": "unknown", "message": "Unknown/Multiple Possibilities"}

def base64_encode(text: str) -> Dict[str, Any]:
    try:
        encoded = base64.b64encode(text.encode()).decode()
        return {"status": "success", "encoded": encoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def base64_decode(text: str) -> Dict[str, Any]:
    try:
        decoded = base64.b64decode(text).decode()
        return {"status": "success", "decoded": decoded}
    except Exception as e:
        return {"status": "error", "message": "Invalid Base64"}

def rot13_cipher(text: str) -> Dict[str, Any]:
    try:
        result = codecs.encode(text, 'rot_13')
        return {"status": "success", "ciphertext": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def xor_cipher(text: str, key: str) -> Dict[str, Any]:
    try:
        if not key:
             return {"status": "error", "message": "Key cannot be empty"}
        result = "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text)])
        return {"status": "success", "ciphertext": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def hex_encode(text: str) -> Dict[str, Any]:
    try:
        encoded = text.encode().hex()
        return {"status": "success", "encoded": encoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def hex_decode(text: str) -> Dict[str, Any]:
    try:
        decoded = bytes.fromhex(text).decode()
        return {"status": "success", "decoded": decoded}
    except Exception as e:
        return {"status": "error", "message": "Invalid Hex"}

def url_encode(text: str) -> Dict[str, Any]:
    import urllib.parse
    try:
        encoded = urllib.parse.quote(text)
        return {"status": "success", "encoded": encoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def url_decode(text: str) -> Dict[str, Any]:
    import urllib.parse
    try:
        decoded = urllib.parse.unquote(text)
        return {"status": "success", "decoded": decoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_luhn(card_number: str) -> Dict[str, Any]:
    """Checks credit card validity using Luhn algorithm."""
    try:
        card_number_str = str(card_number).strip().replace(" ", "").replace("-", "")
        if not card_number_str.isdigit():
             return {"status": "invalid", "message": "Contains non-numeric characters"}

        digits = [int(d) for d in card_number_str]
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

        is_valid = (checksum % 10 == 0)
        status = "valid" if is_valid else "invalid"
        return {"status": status, "is_valid": is_valid, "message": f"Card number is {status}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_randomness(token: str) -> Dict[str, Any]:
    """
    Assesses token predictability by calculating Shannon entropy.
    """
    import math
    if not token: return {"status": "error", "message": "Empty token"}

    prob = [ float(token.count(c)) / len(token) for c in dict.fromkeys(list(token)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

    return {"status": "info", "entropy": entropy, "message": f"Entropy: {entropy:.2f}"}

def check_salting_usage(text: str) -> Dict[str, Any]:
    """
    Identifies potential salt usage in text (code/config) using regex patterns and maps them to algorithm names.
    """
    patterns = {
        'BCrypt': r'\$2[ayb]\$.{53}',
        'Argon2': r'\$argon2',
        'PBKDF2': r'pbkdf2',
        'Scrypt': r'scrypt',
        'Salt': r'salt',
        'SHA-256-Crypt': r'\$5\$',
        'SHA-512-Crypt': r'\$6\$'
    }

    found = []
    for algo, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            found.append(algo)

    if found:
        return {"status": "info", "message": f"Potential salt/hashing usage detected: {found}", "algorithms": found}
    return {"status": "not_found", "message": "No obvious salt usage patterns found"}
