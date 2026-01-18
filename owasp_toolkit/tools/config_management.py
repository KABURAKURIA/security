import requests
from typing import List, Dict, Union, Any

def get_headers(url: str) -> Dict[str, Any]:
    try:
        response = requests.head(url, timeout=5)
        return {"status": "success", "headers": dict(response.headers)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_csp(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Content-Security-Policy')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "Content-Security-Policy header is missing"}

def check_hsts(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Strict-Transport-Security')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "Strict-Transport-Security header is missing"}

def check_x_frame_options(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('X-Frame-Options')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "X-Frame-Options header is missing"}

def check_x_content_type_options(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('X-Content-Type-Options')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "X-Content-Type-Options header is missing"}

def check_cors(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Access-Control-Allow-Origin')
    if val:
        return {"status": "found", "value": val}
    return {"status": "info", "message": "Not explicitly set in headers"}

def check_server_signature(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Server')
    if val:
        return {"status": "found", "value": val}
    return {"status": "info", "message": "Not disclosed"}

def check_x_powered_by(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('X-Powered-By')
    if val:
        return {"status": "found", "value": val}
    return {"status": "info", "message": "Not disclosed"}

def check_referrer_policy(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Referrer-Policy')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "Referrer-Policy header is missing"}

def check_permissions_policy(url: str) -> Dict[str, Any]:
    headers_res = get_headers(url)
    if headers_res['status'] == 'error': return headers_res

    val = headers_res['headers'].get('Permissions-Policy')
    if val:
        return {"status": "found", "value": val}
    return {"status": "missing", "message": "Permissions-Policy header is missing"}

def check_cookie_flags(url: str) -> Dict[str, Any]:
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
        results = []
        for cookie in cookies:
            flags = []
            if cookie.secure:
                flags.append("Secure")
            # HttpOnly is hard to detect from client side requests library unless we parse Set-Cookie headers manually
            results.append(f"{cookie.name}: Secure={cookie.secure}")

        # Parse Set-Cookie header manually for HttpOnly
        if 'Set-Cookie' in response.headers:
             results.append(f"Raw Set-Cookie: {response.headers['Set-Cookie']}")

        if results:
            return {"status": "success", "cookies": results}
        return {"status": "info", "message": "No cookies found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_options_method(url: str) -> Dict[str, Any]:
    try:
        response = requests.options(url, timeout=5)
        allow = response.headers.get('Allow')
        if allow:
            return {"status": "success", "allow_methods": allow}
        return {"status": "info", "message": "No Allow header returned"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_trace_method(url: str) -> Dict[str, Any]:
    try:
        response = requests.request('TRACE', url, timeout=5)
        if response.status_code != 405 and response.status_code != 501:
             return {"status": "vulnerable", "message": f"TRACE might be enabled (Status: {response.status_code})"}
        return {"status": "safe", "message": "TRACE likely disabled"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_crossdomain_xml(url: str) -> Dict[str, Any]:
    try:
        if not url.endswith('/'): url += '/'
        res = requests.get(url + "crossdomain.xml", timeout=5)
        if res.status_code == 200:
            return {"status": "found", "message": "Found crossdomain.xml"}
        return {"status": "not_found", "message": "Not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_clientaccess_policy(url: str) -> Dict[str, Any]:
    try:
        if not url.endswith('/'): url += '/'
        res = requests.get(url + "clientaccesspolicy.xml", timeout=5)
        if res.status_code == 200:
            return {"status": "found", "message": "Found clientaccesspolicy.xml"}
        return {"status": "not_found", "message": "Not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_sensitive_files(url: str) -> Dict[str, Any]:
    files = ['.env', '.git/HEAD', 'backup.zip', 'web.config.bak']
    found = []
    if not url.endswith('/'): url += '/'
    for f in files:
        try:
            res = requests.head(url + f, timeout=3)
            if res.status_code == 200:
                found.append(f)
        except:
            pass
    if found:
        return {"status": "vulnerable", "files_found": found}
    return {"status": "safe", "message": "None found"}
