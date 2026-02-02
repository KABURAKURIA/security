import requests
import itertools
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Union, Any
from .utils import replace_or_append_param

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
        results = []
        for payload in payloads:
            target = replace_or_append_param(url, param, payload)

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
        "/console", "/manage", "/root", "/webadmin", "/sysadmin", "/portal",
        "/siteadmin", "/admin_login", "/controlpanel", "/admin-console"
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
                text_lower = res.text.lower()
                if "login" not in text_lower and "password" not in text_lower and "sign in" not in text_lower:
                     accessible.append(f"{target} (Status: 200 - Potentially exposed)")
            elif res.status_code == 403:
                # Good, but existence confirmed
                accessible.append(f"{target} (Status: 403 - Found but Forbidden)")
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

def test_horizontal_access_control(url: str, my_id: str, target_id: str) -> Dict[str, Any]:
    """
    Tests if accessing a resource with a different user ID works (Horizontal Privilege Escalation).
    Simulated by replacing ID in URL.
    """
    try:
        if my_id not in url:
             return {"status": "error", "message": "My ID not found in URL, cannot replace."}

        target_url = url.replace(my_id, target_id)
        res = requests.get(target_url, timeout=5)

        if res.status_code == 200:
             return {"status": "warning", "message": f"Successfully accessed target ID {target_id}. Verify if this data belongs to another user."}
        return {"status": "safe", "message": f"Access denied or not found (Status: {res.status_code})"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_bypassing_authorization_schema(url: str) -> Dict[str, Any]:
    """
    Tests for authorization bypass using headers like X-Original-URL.
    """
    headers_to_test = {
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Forwarded-For": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1"
    }

    results = []
    try:
        for header, val in headers_to_test.items():
            res = requests.get(url, headers={header: val}, timeout=5)
            # Compare with baseline. If it gives access to something hidden, response might differ.
            # This is heuristic.
            if res.status_code == 200 and "admin" in res.text.lower(): # Simple check
                 results.append(header)

        if results:
             return {"status": "warning", "message": "Potential bypass headers accepted", "headers": results}
        return {"status": "safe", "message": "No obvious bypass headers worked"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_privilege_escalation_via_parameter(url: str) -> Dict[str, Any]:
    """
    Checks if adding 'admin=true' or similar parameters changes the response.
    """
    params_to_test = ["admin=true", "role=admin", "is_admin=1", "debug=true"]
    results = []
    try:
        for p in params_to_test:
            key, val = p.split('=')
            target = replace_or_append_param(url, key, val)
            res = requests.get(target, timeout=5)

            # Very heuristic: check if response size significantly changes or 'admin' appears
            if "admin" in res.text.lower():
                results.append(p)

        if results:
             return {"status": "info", "message": "Response contains 'admin' when these parameters are used. Manual verification needed.", "params": results}
        return {"status": "safe", "message": "No obvious reaction to privilege parameters"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_forced_browsing(url: str) -> Dict[str, Any]:
    """
    Checks for hidden resources by guessing common names (Forced Browsing).
    """
    common_files = ["backup.sql", ".env", "config.php.bak", "id_rsa"]
    found = []
    if not url.endswith('/'): url += '/'

    try:
        for f in common_files:
            target = url + f
            res = requests.head(target, timeout=3)
            if res.status_code == 200:
                found.append(f)

        if found:
             return {"status": "vulnerable", "found_files": found}
        return {"status": "safe", "message": "No common hidden files found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
