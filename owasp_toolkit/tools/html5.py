import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Union, Any

def check_web_storage_usage(url: str) -> Dict[str, Any]:
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

        if usage:
            return {"status": "detected", "usage": usage}
        return {"status": "not_detected", "message": "No direct Web Storage usage found in inline scripts"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_postmessage_usage(url: str) -> Dict[str, Any]:
    """
    Checks for postMessage usage which can be risky if targetOrigin is '*'.
    """
    try:
        res = requests.get(url, timeout=5)
        if 'postMessage' in res.text:
            return {"status": "detected", "message": "postMessage() detected in source code. Verify targetOrigin is not wildcard '*'"}
        return {"status": "not_detected", "message": "postMessage() not explicitly found in HTML source"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_offline_manifest(url: str) -> Dict[str, Any]:
    """
    Checks for HTML5 Offline Cache Manifest.
    """
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        html_tag = soup.find('html')
        if html_tag and html_tag.has_attr('manifest'):
            return {"status": "found", "manifest": html_tag['manifest'], "message": f"Manifest found: {html_tag['manifest']}"}
        return {"status": "not_found", "message": "No Offline Manifest found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_cors_wildcard(url: str) -> Dict[str, Any]:
    """
    Checks if Access-Control-Allow-Origin is set to '*'.
    """
    try:
        res = requests.head(url, timeout=5)
        acao = res.headers.get('Access-Control-Allow-Origin')
        if acao == '*':
            return {"status": "vulnerable", "message": "CORS allows wildcard origin '*' (Insecure)"}
        elif acao:
            return {"status": "safe", "origin": acao, "message": f"CORS Origin: {acao}"}
        return {"status": "info", "message": "CORS header not present"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_geolocation_api(url: str) -> Dict[str, Any]:
    """
    Checks if Geolocation API is used.
    """
    try:
        res = requests.get(url, timeout=5)
        if 'navigator.geolocation' in res.text:
            return {"status": "detected", "message": "Geolocation API usage detected"}
        return {"status": "not_detected", "message": "No obvious Geolocation API usage"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
