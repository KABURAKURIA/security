import ssl
import socket
import datetime
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Union, Any

def get_ssl_certificate_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return str(e)

def check_ssl_expiry(hostname: str, port: int = 443) -> Dict[str, Any]:
    try:
        cert = get_ssl_certificate_info(hostname, port)
        if isinstance(cert, str):
            return {"status": "error", "message": cert}

        notAfter = cert['notAfter']
        # Format: May 30 12:00:00 2025 GMT
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        expiry_date = datetime.datetime.strptime(notAfter, ssl_date_fmt)
        days_left = (expiry_date - datetime.datetime.now()).days

        status = "safe" if days_left > 30 else "warning" if days_left > 0 else "vulnerable"

        return {
            "status": status,
            "expires_on": notAfter,
            "days_remaining": days_left,
            "message": f"Expires on {notAfter} ({days_left} days remaining)"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_ssl_issuer(hostname: str, port: int = 443) -> Dict[str, Any]:
    try:
        cert = get_ssl_certificate_info(hostname, port)
        if isinstance(cert, str): return {"status": "error", "message": cert}

        issuer = dict(x[0] for x in cert['issuer'])
        organization = issuer.get('organizationName', 'Unknown')
        common_name = issuer.get('commonName', 'Unknown')

        return {
            "status": "success",
            "issuer": issuer,
            "message": f"Issuer: {organization} ({common_name})"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_https_redirect(url: str) -> Dict[str, Any]:
    try:
        if url.startswith("https://"):
            url = url.replace("https://", "http://")

        response = requests.get(url, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith("https://"):
                return {"status": "safe", "message": "Redirects to HTTPS"}
        return {"status": "vulnerable", "message": "Does not immediately redirect to HTTPS"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_mixed_content(url: str) -> Dict[str, Any]:
    try:
        if not url.startswith("https://"):
            return {"status": "info", "message": "Not an HTTPS URL, mixed content irrelevant"}

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        mixed = []
        tags = {
            'script': 'src',
            'img': 'src',
            'iframe': 'src',
            'link': 'href'
        }

        for tag, attr in tags.items():
            for item in soup.find_all(tag):
                if item.has_attr(attr):
                    val = item[attr]
                    if val.startswith("http://"):
                        mixed.append(f"<{tag}> {val}")

        if mixed:
             return {"status": "vulnerable", "mixed_content": mixed}
        return {"status": "safe", "message": "No mixed content found (static check)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_ssl_version(hostname: str, port: int = 443) -> Dict[str, Any]:
    try:
        # This is a bit tricky as python's ssl module tries to be secure by default.
        # We can try to connect and see what protocol is negotiated.
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {"status": "success", "version": ssock.version(), "message": f"Negotiated: {ssock.version()}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_hsts_header(url: str) -> Dict[str, Any]:
    # Wrapper for consistency
    try:
        res = requests.head(url, timeout=5)
        hsts = res.headers.get('Strict-Transport-Security')
        if hsts:
            return {"status": "safe", "header": hsts, "message": f"HSTS Enabled: {hsts}"}
        return {"status": "missing", "message": "HSTS Missing"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_weak_ciphers(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Checks for weak ciphers usage.
    """
    # This requires more advanced SSL context configuration which might be limited in standard library
    # We will simulate by checking the negotiated cipher.
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                # cipher is typically ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
                name, protocol, bits = cipher
                if bits < 128 or 'RC4' in name or 'DES' in name or 'MD5' in name:
                     return {"status": "warning", "message": f"Weak cipher negotiated: {name}", "cipher": cipher}
                return {"status": "safe", "message": f"Strong cipher negotiated: {name}", "cipher": cipher}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_digital_certificate_validity(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Comprehensive check of certificate validity (Self-signed, CN mismatch, etc).
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check Common Name (CN)
                subject = dict(x[0] for x in cert['subject'])
                cn = subject.get('commonName')

                # Simple wildcard or exact match check
                # This is handled by ssl module by default (CertificateError), but if we are here it passed verification.

                return {
                    "status": "valid",
                    "common_name": cn,
                    "subject": subject,
                    "message": "Certificate is valid and trusted by default context."
                }
    except ssl.CertificateError as e:
        return {"status": "invalid", "message": f"Certificate Error: {e}"}
    except ssl.SSLError as e:
        return {"status": "invalid", "message": f"SSL Error (Self-signed?): {e}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_login_over_https(url: str) -> Dict[str, Any]:
    """
    Checks if a login form action uses HTTPS.
    """
    try:
        if not url.startswith('https://'):
             return {"status": "vulnerable", "message": "Page itself is not HTTPS"}

        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        forms = soup.find_all('form')
        for form in forms:
            if 'password' in str(form).lower():
                action = form.get('action', '')
                if action and action.startswith('http://'):
                     return {"status": "vulnerable", "message": f"Login form posts to insecure URL: {action}"}
                if action and action.startswith('//'):
                     pass # Protocol relative is usually fine on HTTPS page
                elif not action:
                     pass # Posts to self (HTTPS)

        return {"status": "safe", "message": "Login forms appear to use HTTPS"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
