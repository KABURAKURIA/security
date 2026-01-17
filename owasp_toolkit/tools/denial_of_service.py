import requests
import time
import socket
import threading

def check_anti_automation(url, form_data):
    """
    Checks if multiple rapid submissions are allowed (lack of rate limiting/CAPTCHA).
    """
    try:
        # Try sending 5 requests rapidly
        responses = []
        for _ in range(5):
            res = requests.post(url, data=form_data, timeout=5)
            responses.append(res.status_code)

        if all(code == 200 for code in responses):
            return "Multiple requests accepted (Potential lack of Rate Limiting/Anti-Automation)"
        elif 429 in responses:
            return "Rate limiting detected (Status 429)"
        else:
            return f"Responses: {responses}"
    except Exception as e:
        return str(e)

def check_slowloris_susceptibility(host, port=80):
    """
    Basic check to see if the server keeps connections open for partial requests.
    This is a non-destructive check that just tests if a partial request is held.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send("GET / HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {host}\r\n".encode("utf-8"))
        s.send("X-a: b\r\n".encode("utf-8")) # Partial header

        # Wait a bit to see if connection is closed
        time.sleep(2)
        try:
            # If we can still send, it might be susceptible, but this is very basic.
            s.send("X-b: c\r\n".encode("utf-8"))
            s.close()
            return "Server kept connection open for partial request (Potential Slowloris susceptibility)"
        except BrokenPipeError:
            return "Server closed connection (Likely not susceptible)"
    except Exception as e:
        return str(e)

def check_sql_wildcard_dos(url, param):
    """
    Checks for SQL Wildcard Denial of Service (e.g. searching for '%').
    """
    try:
        base_time = 0
        # Measure baseline
        start = time.time()
        requests.get(url, timeout=5)
        base_time = time.time() - start

        # Inject Wildcard
        if '?' in url:
            target = f"{url}&{param}=%"
        else:
            target = f"{url}?{param}=%"

        start = time.time()
        requests.get(target, timeout=10)
        dos_time = time.time() - start

        if dos_time > (base_time * 5) and dos_time > 2:
             return f"Response time significantly increased with wildcard (Baseline: {base_time:.2f}s, Wildcard: {dos_time:.2f}s)"
        return "No significant delay detected with wildcard"
    except Exception as e:
        return str(e)

def check_large_payload_handling(url):
    """
    Checks how the server handles large request bodies.
    """
    try:
        large_data = "A" * 100000 # 100KB
        res = requests.post(url, data={"data": large_data}, timeout=10)
        if res.status_code == 413:
            return "Properly handled (413 Payload Too Large)"
        elif res.status_code == 200:
            return "Accepted large payload (Status 200)"
        else:
            return f"Responded with status {res.status_code}"
    except Exception as e:
        return str(e)

def check_xml_bomb_protection(url):
    """
    Checks if XML parser is susceptible to Billion Laughs attack (Basic Check).
    """
    payload = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]>
    <lolz>&lol2;</lolz>
    """
    try:
        # We don't send the full bomb to avoid crashing, just a small nested one to see if it processes.
        # This is risky, so we just check if it accepts XML at all or errors out safely.
        headers = {'Content-Type': 'application/xml'}
        res = requests.post(url, data=payload, headers=headers, timeout=5)
        if res.status_code == 200:
             return "Server accepted XML entity expansion (Potential risk)"
        return f"Server response: {res.status_code}"
    except Exception as e:
        return str(e)
