from owasp_toolkit.decorators import validate_arguments
import requests
import time
import socket
import statistics
import concurrent.futures
from typing import List, Dict, Any
from .utils import replace_or_append_param

@validate_arguments
def check_anti_automation(url: str, form_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks if multiple rapid submissions are allowed (lack of rate limiting/CAPTCHA).
    """
    try:
        responses = []

        def send_request():
            return requests.post(url, data=form_data, timeout=5).status_code

        # Send 10 requests rapidly using threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_request) for _ in range(10)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    responses.append(future.result())
                except:
                    pass

        if not responses:
            return {"status": "error", "message": "Failed to send requests"}

        if all(code == 200 for code in responses):
             return {"status": "vulnerable", "message": "Multiple requests accepted (Potential lack of Rate Limiting/Anti-Automation)", "codes": responses}
        elif 429 in responses:
             return {"status": "safe", "message": "Rate limiting detected (Status 429)"}
        else:
             return {"status": "mixed", "codes": responses}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@validate_arguments
def check_slowloris_susceptibility(host: str, port: int = 80) -> Dict[str, Any]:
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
            return {"status": "vulnerable", "message": "Server kept connection open for partial request (Potential Slowloris susceptibility)"}
        except BrokenPipeError:
            return {"status": "safe", "message": "Server closed connection (Likely not susceptible)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@validate_arguments
def check_sql_wildcard_dos(url: str, param: str) -> Dict[str, Any]:
    """
    Checks for SQL Wildcard Denial of Service (e.g. searching for '%').
    """
    try:
        # Measure baseline (Average of 5 requests)
        times = []
        for _ in range(5):
            start = time.time()
            requests.get(url, timeout=5)
            times.append(time.time() - start)

        base_time = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0

        # Inject Wildcard
        target = replace_or_append_param(url, param, "%")

        start = time.time()
        requests.get(target, timeout=10)
        dos_time = time.time() - start

        # Use a dynamic threshold: Avg + Max(2s, 5 * StDev)
        # This means it must be at least 2 seconds slower AND statistically significant
        threshold = base_time + max(2.0, 5 * stdev)

        if dos_time > threshold:
             return {"status": "vulnerable", "message": f"Response time significantly increased with wildcard (Baseline Avg: {base_time:.2f}s, Wildcard: {dos_time:.2f}s, Threshold: {threshold:.2f}s)"}
        return {"status": "safe", "message": f"No significant delay detected with wildcard (Baseline: {base_time:.2f}s, Wildcard: {dos_time:.2f}s)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@validate_arguments
def check_large_payload_handling(url: str) -> Dict[str, Any]:
    """
    Checks how the server handles large request bodies.
    """
    try:
        large_data = "A" * 100000 # 100KB
        res = requests.post(url, data={"data": large_data}, timeout=10)
        if res.status_code == 413:
            return {"status": "safe", "message": "Properly handled (413 Payload Too Large)"}
        elif res.status_code == 200:
            return {"status": "warning", "message": "Accepted large payload (Status 200)"}
        else:
            return {"status": "info", "message": f"Responded with status {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@validate_arguments
def check_xml_bomb_protection(url: str) -> Dict[str, Any]:
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
             return {"status": "vulnerable", "message": "Server accepted XML entity expansion (Potential risk)"}
        return {"status": "safe", "message": f"Server response: {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
