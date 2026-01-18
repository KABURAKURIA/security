import hashlib
import base64
import codecs
from typing import List, Dict, Union, Any

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

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def base64_decode(text: str) -> str:
    try:
        return base64.b64decode(text).decode()
    except:
        return "Invalid Base64"

def rot13_cipher(text: str) -> str:
    return codecs.encode(text, 'rot_13')

def xor_cipher(text: str, key: str) -> str:
    if not key: return text
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text)])

def hex_encode(text: str) -> str:
    return text.encode().hex()

def hex_decode(text: str) -> str:
    try:
        return bytes.fromhex(text).decode()
    except:
        return "Invalid Hex"

def url_encode(text: str) -> str:
    import urllib.parse
    return urllib.parse.quote(text)

def url_decode(text: str) -> str:
    import urllib.parse
    return urllib.parse.unquote(text)

def check_luhn(card_number: Union[str, int]) -> bool:
    """Checks credit card validity using Luhn algorithm."""
    try:
        card_number = str(card_number).strip().replace(" ", "").replace("-", "")
        if not card_number.isdigit():
            return False

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

        return checksum % 10 == 0
    except:
        return False
