import requests

def get_headers(url):
    try:
        response = requests.head(url, timeout=5)
        return response.headers
    except:
        return {}

def check_csp(url):
    headers = get_headers(url)
    return headers.get('Content-Security-Policy', 'Missing')

def check_hsts(url):
    headers = get_headers(url)
    return headers.get('Strict-Transport-Security', 'Missing')

def check_x_frame_options(url):
    headers = get_headers(url)
    return headers.get('X-Frame-Options', 'Missing')

def check_x_content_type_options(url):
    headers = get_headers(url)
    return headers.get('X-Content-Type-Options', 'Missing')

def check_cors(url):
    headers = get_headers(url)
    return headers.get('Access-Control-Allow-Origin', 'Not explicitly set in headers')

def check_server_signature(url):
    headers = get_headers(url)
    return headers.get('Server', 'Not disclosed')

def check_x_powered_by(url):
    headers = get_headers(url)
    return headers.get('X-Powered-By', 'Not disclosed')

def check_referrer_policy(url):
    headers = get_headers(url)
    return headers.get('Referrer-Policy', 'Missing')

def check_permissions_policy(url):
    headers = get_headers(url)
    return headers.get('Permissions-Policy', 'Missing')

def check_cookie_flags(url):
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
        results = []
        for cookie in cookies:
            flags = []
            if cookie.secure:
                flags.append("Secure")
            if cookie.has_nonstandard_attr('HttpOnly') or cookie.get_nonstandard_attr('HttpOnly'): # Request cookies handling varies
                 # Requests cookie jar objects have internal flags, but accessing them directly is tricky.
                 # Let's trust the _rest structure or just inspect headers.
                 pass

            # Better to check Set-Cookie header directly for HttpOnly
            results.append(f"{cookie.name}: Secure={cookie.secure}")

        # Parse Set-Cookie header manually for HttpOnly
        if 'Set-Cookie' in response.headers:
             results.append(f"Raw Set-Cookie: {response.headers['Set-Cookie']}")

        return results if results else "No cookies found"
    except Exception as e:
        return str(e)

def check_options_method(url):
    try:
        response = requests.options(url, timeout=5)
        return response.headers.get('Allow', 'No Allow header returned')
    except Exception as e:
        return str(e)

def check_trace_method(url):
    try:
        response = requests.request('TRACE', url, timeout=5)
        if response.status_code != 405 and response.status_code != 501:
             return f"TRACE might be enabled (Status: {response.status_code})"
        return "TRACE likely disabled"
    except Exception as e:
        return str(e)

def check_crossdomain_xml(url):
    try:
        if not url.endswith('/'): url += '/'
        res = requests.get(url + "crossdomain.xml", timeout=5)
        if res.status_code == 200:
            return "Found crossdomain.xml"
        return "Not found"
    except:
        return "Error"

def check_clientaccess_policy(url):
    try:
        if not url.endswith('/'): url += '/'
        res = requests.get(url + "clientaccesspolicy.xml", timeout=5)
        if res.status_code == 200:
            return "Found clientaccesspolicy.xml"
        return "Not found"
    except:
        return "Error"

def check_sensitive_files(url):
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
    return found if found else "None found"
