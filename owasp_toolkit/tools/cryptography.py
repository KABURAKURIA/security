import hashlib
import base64
import codecs

def calculate_hash(text, algorithm='sha256'):
    try:
        if algorithm == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            return "Unknown algorithm"
    except Exception as e:
        return str(e)

def identify_hash_type(hash_str):
    length = len(hash_str)
    if length == 32: return "MD5"
    if length == 40: return "SHA1"
    if length == 64: return "SHA-256"
    if length == 128: return "SHA-512"
    return "Unknown/Multiple Possibilities"

def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(text):
    try:
        return base64.b64decode(text).decode()
    except:
        return "Invalid Base64"

def rot13_cipher(text):
    return codecs.encode(text, 'rot_13')

def xor_cipher(text, key):
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text)])

def hex_encode(text):
    return text.encode().hex()

def hex_decode(text):
    try:
        return bytes.fromhex(text).decode()
    except:
        return "Invalid Hex"

def url_encode(text):
    import urllib.parse
    return urllib.parse.quote(text)

def url_decode(text):
    import urllib.parse
    return urllib.parse.unquote(text)

def check_luhn(card_number):
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
