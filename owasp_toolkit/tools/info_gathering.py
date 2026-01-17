import requests
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from fake_useragent import UserAgent

def get_robots_txt(url):
    """Fetches and returns the robots.txt file."""
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.get(url + "robots.txt", timeout=5)
        if response.status_code == 200:
            return response.text
        return f"Error: {response.status_code}"
    except Exception as e:
        return str(e)

def get_sitemap_xml(url):
    """Fetches and returns the sitemap.xml file."""
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.get(url + "sitemap.xml", timeout=5)
        if response.status_code == 200:
            return response.text
        return f"Error: {response.status_code}"
    except Exception as e:
        return str(e)

def check_ds_store(url):
    """Checks for the existence of .DS_Store file."""
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.head(url + ".DS_Store", timeout=5)
        if response.status_code == 200:
            return "Found .DS_Store (Potential Information Leak)"
        return "Not found"
    except Exception as e:
        return str(e)

def dns_lookup(domain):
    """Performs a DNS lookup (A records)."""
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.to_text() for ip in result]
    except Exception as e:
        return str(e)

def mx_lookup(domain):
    """Performs a MX lookup."""
    try:
        result = dns.resolver.resolve(domain, 'MX')
        return [mx.to_text() for mx in result]
    except Exception as e:
        return str(e)

def whois_lookup(domain):
    """Performs a WHOIS lookup."""
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return str(e)

def scan_ports(host, ports=[21, 22, 23, 80, 443, 3306, 8080]):
    """Scans common ports."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_http_headers(url):
    """Retrieves HTTP headers."""
    try:
        response = requests.head(url, timeout=5)
        return dict(response.headers)
    except Exception as e:
        return str(e)

def identify_tech_headers(url):
    """Identifies technologies based on headers."""
    headers = get_http_headers(url)
    if isinstance(headers, str):
        return headers
    techs = []
    if 'Server' in headers:
        techs.append(f"Server: {headers['Server']}")
    if 'X-Powered-By' in headers:
        techs.append(f"Powered By: {headers['X-Powered-By']}")
    return techs

def check_security_txt(url):
    """Checks for security.txt file."""
    paths = ["/.well-known/security.txt", "/security.txt"]
    results = {}
    if not url.endswith('/'):
        url += '/'

    for path in paths:
        try:
            full_url = url.rstrip('/') + path
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                results[path] = "Found"
            else:
                results[path] = "Not Found"
        except:
            results[path] = "Error"
    return results

def extract_links(url):
    """Extracts all href links from the page."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            links.append(a['href'])
        return list(set(links))
    except Exception as e:
        return str(e)

def extract_comments(url):
    """Extracts HTML comments."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text) # Basic check, bs4 usually handles comments differently
        # Better way for bs4 comments:
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        return [str(c) for c in comments]
    except Exception as e:
        return str(e)

def check_mobile_version(url):
    """Checks if content differs for mobile user agent."""
    ua = UserAgent()
    mobile_ua = ua.random # This isn't guaranteed to be mobile, so let's force one
    mobile_ua_str = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"

    try:
        res_desktop = requests.get(url, timeout=5)
        res_mobile = requests.get(url, headers={"User-Agent": mobile_ua_str}, timeout=5)

        if len(res_desktop.text) != len(res_mobile.text):
            return "Different content detected (Size mismatch)"
        return "Content appears similar size"
    except Exception as e:
        return str(e)
