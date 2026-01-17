import requests
from bs4 import BeautifulSoup

def check_web_storage_usage(url):
    """
    Checks if the application uses LocalStorage or SessionStorage (Static analysis of JS).
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')

        scripts = soup.find_all('script')
        usage = []
        for script in scripts:
            if script.string:
                if 'localStorage' in script.string:
                    usage.append("localStorage detected in inline script")
                if 'sessionStorage' in script.string:
                    usage.append("sessionStorage detected in inline script")
            elif script.get('src'):
                # We could fetch external scripts but that's heavy.
                pass

        return usage if usage else "No direct Web Storage usage found in inline scripts"
    except Exception as e:
        return str(e)

def check_postmessage_usage(url):
    """
    Checks for postMessage usage which can be risky if targetOrigin is '*'.
    """
    try:
        res = requests.get(url, timeout=5)
        if 'postMessage' in res.text:
            return "postMessage() detected in source code. Verify targetOrigin is not wildcard '*'"
        return "postMessage() not explicitly found in HTML source"
    except Exception as e:
        return str(e)

def check_offline_manifest(url):
    """
    Checks for HTML5 Offline Cache Manifest.
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        html_tag = soup.find('html')
        if html_tag and html_tag.has_attr('manifest'):
            return f"Manifest found: {html_tag['manifest']}"
        return "No Offline Manifest found"
    except Exception as e:
        return str(e)

def check_cors_wildcard(url):
    """
    Checks if Access-Control-Allow-Origin is set to '*'.
    """
    try:
        res = requests.head(url, timeout=5)
        acao = res.headers.get('Access-Control-Allow-Origin')
        if acao == '*':
            return "CORS allows wildcard origin '*' (Insecure)"
        elif acao:
            return f"CORS Origin: {acao}"
        return "CORS header not present"
    except Exception as e:
        return str(e)

def check_geolocation_api(url):
    """
    Checks if Geolocation API is used.
    """
    try:
        res = requests.get(url, timeout=5)
        if 'navigator.geolocation' in res.text:
            return "Geolocation API usage detected"
        return "No obvious Geolocation API usage"
    except Exception as e:
        return str(e)
