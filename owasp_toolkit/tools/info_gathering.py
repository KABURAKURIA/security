import requests
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup, Comment
import re
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from typing import List, Dict, Union, Any
from .utils import get_base_url

def get_robots_txt(url: str) -> Dict[str, Any]:
    """
    Fetches and returns the robots.txt file.

    Args:
        url (str): The target URL.

    Returns:
        Dict[str, Any]: Result with status and data/message.
    """
    try:
        base_url = get_base_url(url)
        response = requests.get(base_url + "robots.txt", timeout=5)
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
        base_url = get_base_url(url)
        response = requests.get(base_url + "sitemap.xml", timeout=5)
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
    paths = [".well-known/security.txt", "security.txt"]
    results = {}

    try:
        base_url = get_base_url(url)
        for path in paths:
            try:
                full_url = base_url + path
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    results[path] = "Found"
                else:
                    results[path] = "Not Found"
            except Exception as e:
                results[path] = f"Error: {str(e)}"
    except Exception as e:
        return {"status": "error", "message": str(e)}
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

def spider_crawl(url: str, max_depth: int = 2) -> Dict[str, Any]:
    """
    Recursively finds internal links up to max_depth.
    Basic spidering.
    """
    try:
        visited = set()
        successful_urls = set()
        queue = [(url, 0)]
        queued = {url}
        base_domain = urlparse(url).netloc
        failed_urls = []

        while queue:
            current_url, depth = queue.pop(0)
            if depth > max_depth:
                continue

            visited.add(current_url)

            try:
                res = requests.get(current_url, timeout=3)
                if res.status_code == 200:
                    successful_urls.add(current_url)
                    soup = BeautifulSoup(res.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        link = urljoin(current_url, a['href'])
                        link = link.split('#')[0]
                        if urlparse(link).netloc == base_domain:
                            if link not in queued:
                                queued.add(link)
                                queue.append((link, depth + 1))
                else:
                    failed_urls.append(f"{current_url} (Status: {res.status_code})")
            except Exception as e:
                failed_urls.append(f"{current_url} (Error: {str(e)})")

        status = "success"
        message = f"Successfully crawled {len(successful_urls)} URLs"

        if not successful_urls and failed_urls:
            status = "error"
            message = "Initial URL failed to crawl or returned non-200 status"

        return {
            "status": status,
            "crawled_count": len(successful_urls),
            "urls": list(successful_urls),
            "failed_urls": failed_urls,
            "message": message
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_entry_points(url: str) -> Dict[str, Any]:
    """
    Identifies inputs and entry points (forms, parameters).
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        entry_points = []
        # Find Forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').upper()
            inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
            entry_points.append(f"Form: {method} {action} Inputs: {inputs}")

        # Find URL params in links
        for a in soup.find_all('a', href=True):
            if '?' in a['href']:
                entry_points.append(f"URL Param: {a['href']}")

        return {"status": "success", "entry_points": entry_points}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def fingerprint_web_application(url: str) -> Dict[str, Any]:
    """
    Attempts to fingerprint the application using heuristic signatures (Wappalyzer-lite).
    """
    try:
        res = requests.get(url, timeout=5)
        html = res.text.lower()
        headers = res.headers

        detected = []

        # WordPress
        if "wp-content" in html or "wordpress" in html: detected.append("WordPress")
        # Joomla
        if "joomla" in html: detected.append("Joomla")
        # Drupal
        if "drupal" in html: detected.append("Drupal")
        # Django
        if "csrftoken" in res.cookies or "django" in html: detected.append("Django")
        # Flask (often no signature, but sometimes session cookie name)
        if "session" in res.cookies and len(res.cookies["session"]) > 20: detected.append("Flask (Potential)")
        # React
        if "react" in html or "main.chunk.js" in html: detected.append("React")
        # Angular
        if "ng-version" in html or "app-root" in html: detected.append("Angular")

        return {"status": "success", "technologies": detected if detected else ["Unknown"]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_third_party_content(url: str) -> Dict[str, Any]:
    """
    Identifies third-party scripts/content (e.g., CDN, Analytics).
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        base_domain = urlparse(url).netloc

        third_party = set()
        for script in soup.find_all('script', src=True):
            src = script['src']
            domain = urlparse(src).netloc
            if domain and domain != base_domain:
                third_party.add(domain)

        for link in soup.find_all('link', href=True):
             href = link['href']
             domain = urlparse(href).netloc
             if domain and domain != base_domain:
                third_party.add(domain)

        return {"status": "success", "third_party_domains": list(third_party)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_search_engine_caches(url: str) -> Dict[str, Any]:
    """
    Generates links to search engine caches and actively checks availability via APIs (e.g. Wayback Machine).
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url

        google_cache = f"http://webcache.googleusercontent.com/search?q=cache:{url}"
        wayback_machine_link = f"https://web.archive.org/web/*/{url}"

        # Active check for Wayback Machine
        wayback_api = f"http://archive.org/wayback/available?url={url}"
        wayback_found = False
        wayback_snapshot = None

        try:
            res = requests.get(wayback_api, timeout=5)
            if res.status_code == 200:
                data = res.json()
                if "archived_snapshots" in data and "closest" in data["archived_snapshots"]:
                    wayback_found = True
                    wayback_snapshot = data["archived_snapshots"]["closest"].get("url")
        except:
            pass # Fail silently on API error, fall back to links

        return {
            "status": "found" if wayback_found else "not_found",
            "google_cache": google_cache,
            "wayback_machine_link": wayback_machine_link,
            "wayback_snapshot_available": wayback_found,
            "wayback_snapshot_url": wayback_snapshot,
            "message": "Cache links generated. Wayback Machine snapshot found." if wayback_found else "Cache links generated. No immediate snapshot found via API."
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_dns_txt_records(domain: str) -> Dict[str, Any]:
    """
    Performs DNS TXT lookups to identify SPF and DMARC records.
    """
    try:
        result = dns.resolver.resolve(domain, 'TXT')
        records = [r.to_text() for r in result]
        return {"status": "success", "records": records}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_multiple_versions(url: str) -> Dict[str, Any]:
    """
    Probes for parallel API versions by checking paths like /v1, /v2, /api/v1.
    """
    versions = ["v1", "v2", "v3", "api/v1", "api/v2", "api/v3", "2.0", "1.0"]
    found = []
    base_url = get_base_url(url)

    try:
        for v in versions:
            target = urljoin(base_url, v)
            res = requests.head(target, timeout=3)
            # We look for 200 (OK), 401 (Unauthorized), 403 (Forbidden) which imply existence
            if res.status_code in [200, 401, 403]:
                found.append(f"{v} (Status: {res.status_code})")

        if found:
            return {"status": "found", "versions": found, "message": f"Potential API versions found: {found}"}
        return {"status": "not_found", "message": "No obvious parallel versions found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

import subprocess

def run_nmap_scan(target: str = "127.0.0.1", scan_type: str = "Quick (-F)") -> Dict[str, Any]:
    """
    Runs an Nmap scan against the specified target.

    Args:
        target: The IP address or domain to scan.
        scan_type: The type of Nmap scan to perform. Options: "Basic (-sV)", "Quick (-F)", "Aggressive (-A)", "Ping only (-sn)".

    Returns:
        Dict[str, Any]: The raw output and command executed.
    """
    try:
        # Sanitize target to prevent basic command injection
        if not re.match(r"^[a-zA-Z0-9.\-:]+$", target):
            return {"status": "error", "message": "Invalid target format. Only alphanumeric characters, dots, hyphens, and colons are allowed."}

        cmd = ["nmap"]

        if scan_type == "Basic (-sV)":
            cmd.append("-sV")
        elif scan_type == "Quick (-F)":
            cmd.append("-F")
        elif scan_type == "Aggressive (-A)":
            cmd.append("-A")
        elif scan_type == "Ping only (-sn)":
            cmd.append("-sn")
        else:
            cmd.append("-F") # Safe default

        cmd.append(target)

        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            return {
                "status": "success",
                "command": " ".join(cmd),
                "output": result.stdout
            }
        else:
            return {
                "status": "error",
                "command": " ".join(cmd),
                "error_message": result.stderr or result.stdout
            }

    except subprocess.TimeoutExpired:
         return {"status": "error", "message": "Nmap scan timed out after 60 seconds."}
    except Exception as e:
         return {"status": "error", "message": str(e)}
