import requests
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup, Comment
import re
from urllib.parse import urljoin
from fake_useragent import UserAgent
from typing import List, Dict, Union, Any

def get_robots_txt(url: str) -> Dict[str, Any]:
    """
    Fetches and returns the robots.txt file.

    Args:
        url (str): The target URL.

    Returns:
        Dict[str, Any]: Result with status and data/message.
    """
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.get(url + "robots.txt", timeout=5)
        if response.status_code == 200:
            return {"status": "success", "data": response.text}
        return {"status": "error", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_sitemap_xml(url: str) -> Dict[str, Any]:
    """
    Fetches and returns the sitemap.xml file.
    """
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.get(url + "sitemap.xml", timeout=5)
        if response.status_code == 200:
            return {"status": "success", "data": response.text}
        return {"status": "error", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_ds_store(url: str) -> Dict[str, Any]:
    """Checks for the existence of .DS_Store file."""
    try:
        if not url.endswith('/'):
            url += '/'
        response = requests.head(url + ".DS_Store", timeout=5)
        if response.status_code == 200:
            return {"status": "vulnerable", "message": "Found .DS_Store (Potential Information Leak)"}
        return {"status": "safe", "message": "Not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def dns_lookup(domain: str) -> Dict[str, Any]:
    """Performs a DNS lookup (A records)."""
    try:
        result = dns.resolver.resolve(domain, 'A')
        return {"status": "success", "data": [ip.to_text() for ip in result]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def mx_lookup(domain: str) -> Dict[str, Any]:
    """Performs a MX lookup."""
    try:
        result = dns.resolver.resolve(domain, 'MX')
        return {"status": "success", "data": [mx.to_text() for mx in result]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def whois_lookup(domain: str) -> Dict[str, Any]:
    """Performs a WHOIS lookup."""
    try:
        w = whois.whois(domain)
        return {"status": "success", "data": str(w)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_ports(host: str, ports: List[int] = [21, 22, 23, 80, 443, 3306, 8080]) -> Dict[str, Any]:
    """Scans common ports."""
    open_ports = []
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return {"status": "success", "open_ports": open_ports}
    except Exception as e:
         return {"status": "error", "message": str(e)}

def get_http_headers(url: str) -> Dict[str, Any]:
    """Retrieves HTTP headers."""
    try:
        response = requests.head(url, timeout=5)
        return {"status": "success", "headers": dict(response.headers)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def identify_tech_headers(url: str) -> Dict[str, Any]:
    """Identifies technologies based on headers."""
    res = get_http_headers(url)
    if res['status'] == 'error':
        return res

    headers = res['headers']
    techs = []
    if 'Server' in headers:
        techs.append(f"Server: {headers['Server']}")
    if 'X-Powered-By' in headers:
        techs.append(f"Powered By: {headers['X-Powered-By']}")

    return {"status": "success", "technologies": techs}

def check_security_txt(url: str) -> Dict[str, Any]:
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
        except Exception as e:
            results[path] = f"Error: {str(e)}"
    return {"status": "completed", "results": results}

def extract_links(url: str) -> Dict[str, Any]:
    """Extracts all href links from the page."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            links.append(a['href'])
        return {"status": "success", "links": list(set(links))}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def extract_comments(url: str) -> Dict[str, Any]:
    """Extracts HTML comments."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        return {"status": "success", "comments": [str(c) for c in comments]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_mobile_version(url: str) -> Dict[str, Any]:
    """Checks if content differs for mobile user agent."""
    # Using a specific iPhone UA
    mobile_ua_str = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"

    try:
        res_desktop = requests.get(url, timeout=5)
        res_mobile = requests.get(url, headers={"User-Agent": mobile_ua_str}, timeout=5)

        diff = abs(len(res_desktop.text) - len(res_mobile.text))

        if diff > 50: # Allow small variance
            return {"status": "difference_detected", "message": "Different content detected (Size mismatch)", "desktop_size": len(res_desktop.text), "mobile_size": len(res_mobile.text)}
        return {"status": "no_difference", "message": "Content appears similar size"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
