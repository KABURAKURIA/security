import ssl
import socket
import datetime
import requests
from bs4 import BeautifulSoup

def get_ssl_certificate_info(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return str(e)

def check_ssl_expiry(hostname, port=443):
    try:
        cert = get_ssl_certificate_info(hostname, port)
        if isinstance(cert, str): return cert

        notAfter = cert['notAfter']
        # Format: May 30 12:00:00 2025 GMT
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        expiry_date = datetime.datetime.strptime(notAfter, ssl_date_fmt)
        days_left = (expiry_date - datetime.datetime.now()).days
        return f"Expires on {notAfter} ({days_left} days remaining)"
    except Exception as e:
        return str(e)

def check_ssl_issuer(hostname, port=443):
    try:
        cert = get_ssl_certificate_info(hostname, port)
        if isinstance(cert, str): return cert

        issuer = dict(x[0] for x in cert['issuer'])
        return f"Issuer: {issuer.get('organizationName', 'Unknown')} ({issuer.get('commonName', 'Unknown')})"
    except Exception as e:
        return str(e)

def check_https_redirect(url):
    try:
        if url.startswith("https://"):
            url = url.replace("https://", "http://")

        response = requests.get(url, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith("https://"):
                return "Redirects to HTTPS"
        return "Does not immediately redirect to HTTPS"
    except Exception as e:
        return str(e)

def check_mixed_content(url):
    try:
        if not url.startswith("https://"):
            return "Not an HTTPS URL, mixed content irrelevant"

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

        return mixed if mixed else "No mixed content found (static check)"
    except Exception as e:
        return str(e)

def get_ssl_version(hostname, port=443):
    try:
        # This is a bit tricky as python's ssl module tries to be secure by default.
        # We can try to connect and see what protocol is negotiated.
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return f"Negotiated: {ssock.version()}"
    except Exception as e:
        return str(e)

def check_hsts_header(url):
    # Wrapper for consistency
    try:
        res = requests.head(url, timeout=5)
        hsts = res.headers.get('Strict-Transport-Security')
        if hsts:
            return f"HSTS Enabled: {hsts}"
        return "HSTS Missing"
    except Exception as e:
        return str(e)
