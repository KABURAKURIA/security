import requests
import itertools
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Union, Any

def check_path_traversal(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for Path Traversal vulnerabilities on a specific parameter.
    """
    payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query) # returns dict of lists

        results = []
        for payload in payloads:
            # Inject payload
            test_params = params.copy()
            test_params[param] = [payload] # parse_qs uses lists

            # Reconstruct URL
            new_query = urlencode(test_params, doseq=True)
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            res = requests.get(target, timeout=5)
            if "root:x:0:0" in res.text or "[extensions]" in res.text:
                results.append(payload)

        if results:
             return {"status": "vulnerable", "payloads_succeeded": results}
        return {"status": "safe", "message": "No path traversal detected with standard payloads"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_admin_access(url: str) -> Dict[str, Any]:
    """
    Checks if administrative endpoints are accessible without authentication (Vertical Access Control).
    """
    admin_paths = [
        "/admin", "/administrator", "/admin_panel", "/dashboard", "/backend",
        "/console", "/manage", "/root"
    ]

    accessible = []
    if not url.endswith('/'): url += '/'

    for path in admin_paths:
        try:
            target = url.rstrip('/') + path
            res = requests.get(target, timeout=5, allow_redirects=False)
            # If we get a 200 OK and it's not a login page (heuristic), it might be an issue.
            # Or if it's 403/401 it's good.
            if res.status_code == 200:
                # Check for login form keywords to rule out login pages
                if "login" not in res.text.lower() and "password" not in res.text.lower():
                     accessible.append(f"{target} (Status: 200 - Potentially exposed)")
            elif res.status_code == 403:
                # Good, but existence confirmed
                pass
        except:
            pass

    if accessible:
        return {"status": "warning", "accessible_paths": accessible}
    return {"status": "safe", "message": "No exposed admin endpoints found"}

def check_idor_patterns(url: str) -> Dict[str, Any]:
    """
    Checks for potential IDOR (Insecure Direct Object Reference) candidates in URL structure.
    """
    # Look for numeric IDs in URL segments or parameters
    try:
        if '?' in url:
            query = url.split('?')[1]
            params = [p.split('=') for p in query.split('&') if '=' in p]
            idor_params = []
            for k, v in params:
                if v.isdigit():
                    idor_params.append(f"Parameter '{k}' has numeric value '{v}'")
            if idor_params:
                return {"status": "potential_idor", "candidates": idor_params}
            return {"status": "safe", "message": "No obvious numeric ID parameters found"}
        return {"status": "info", "message": "No parameters to analyze"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_missing_authorization_headers(url: str) -> Dict[str, Any]:
    """
    Checks if API endpoints return data even without Authorization headers.
    """
    try:
        # Request without any auth headers
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            return {"status": "vulnerable", "message": "Endpoint accessible without Authorization header (Check if public or missing auth)"}
        elif res.status_code == 401:
            return {"status": "safe", "message": "Properly returned 401 Unauthorized"}
        elif res.status_code == 403:
            return {"status": "safe", "message": "Properly returned 403 Forbidden"}
        else:
            return {"status": "info", "message": f"Status Code: {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def analyze_role_definitions(url: str) -> Dict[str, Any]:
    """
    Heuristic check for role definitions in client-side code.
    """
    try:
        res = requests.get(url, timeout=5)
        roles = ['admin', 'superuser', 'moderator', 'editor', 'guest']
        found = []
        for role in roles:
            if role in res.text.lower():
                found.append(role)
        if found:
            return {"status": "found", "roles": found}
        return {"status": "not_found", "message": "No role mentions found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
