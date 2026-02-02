import hashlib
import requests
import re
import time
import statistics
import concurrent.futures
from typing import List, Dict, Union, Any
from .utils import replace_or_append_param

def validate_data_integrity(expected_hash: str, data: str = None, url: str = None, algorithm: str = 'sha256') -> Dict[str, Any]:
    """
    Verifies if data (or content from URL) matches the expected hash (integrity check).
    Must provide either 'data' or 'url'.
    """
    try:
        content_bytes = b""

        if url:
            res = requests.get(url, timeout=10)
            if res.status_code != 200:
                return {"status": "error", "message": f"Failed to fetch URL. Status: {res.status_code}"}
            content_bytes = res.content
        elif data is not None:
            content_bytes = data.encode()
        else:
            return {"status": "error", "message": "Must provide either 'data' or 'url'"}

        if algorithm == 'sha256':
            calc_hash = hashlib.sha256(content_bytes).hexdigest()
        elif algorithm == 'md5':
            calc_hash = hashlib.md5(content_bytes).hexdigest()
        else:
             return {"status": "error", "message": "Unsupported algorithm"}

        if calc_hash == expected_hash:
             return {"status": "success", "message": "Integrity verified (Matches)"}
        else:
             return {"status": "failed", "message": f"Integrity check failed. Calculated: {calc_hash}", "calculated_hash": calc_hash}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_sequential_ids(url: str, param: str) -> Dict[str, Any]:
    """
    Checks if a parameter seems to be using sequential IDs, which might indicate predictable resource usage.
    """
    try:
        # Check ID 1, 2, 3
        results = []
        for i in range(1, 4):
            target = replace_or_append_param(url, param, str(i))
            res = requests.head(target, timeout=3)
            if res.status_code == 200:
                results.append(i)

        if len(results) == 3:
             return {"status": "vulnerable", "message": "Sequential IDs found (1, 2, 3) - Predictable Reference Risk"}
        return {"status": "safe", "message": "No obvious sequential IDs found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def analyze_workflow_bypass(steps_urls: List[str]) -> Dict[str, Any]:
    """
    Simulates skipping steps in a workflow.
    Input: list of URLs representing steps [step1, step2, step3]
    """
    try:
        # Try accessing step 3 directly
        if len(steps_urls) < 2:
             return {"status": "error", "message": "Need at least 2 steps"}

        last_step = steps_urls[-1]
        res = requests.get(last_step, timeout=5)

        if res.status_code == 200:
             return {"status": "vulnerable", "message": "Able to access final step directly (Potential Workflow Bypass)"}
        return {"status": "safe", "message": f"Access to final step returned {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_parameter_manipulation(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks if changing parameter values (e.g. price, quantity) works.
    This is a simulation helper.
    """
    # e.g. params = {'price': '10', 'quantity': '1'}
    results = {}
    try:
        # Try negative quantity
        test_params = params.copy()
        if 'quantity' in test_params:
            test_params['quantity'] = '-1'
            res = requests.post(url, data=test_params, timeout=5)
            if res.status_code == 200:
                results['Negative Quantity'] = "Accepted (Check logic)"
            else:
                results['Negative Quantity'] = f"Status {res.status_code}"

        # Try modifying price
        if 'price' in test_params:
            test_params = params.copy()
            test_params['price'] = '0.01'
            res = requests.post(url, data=test_params, timeout=5)
            if res.status_code == 200:
                results['Price Modification'] = "Accepted (Check logic)"
            else:
                results['Price Modification'] = f"Status {res.status_code}"

        if results:
             return {"status": "completed", "results": results}
        return {"status": "info", "message": "No standard business parameters found to test"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_timing_attacks(url: str, username: str) -> Dict[str, Any]:
    """
    Checks if login response time differs significantly for valid vs invalid user (User Enumeration).
    """
    try:
        iterations = 5
        invalid_times = []
        target_times = []

        # Warm-up request
        requests.post(url, data={'username': 'warmup', 'password': 'password'}, timeout=5)

        for _ in range(iterations):
            # Baseline (likely invalid user)
            start = time.time()
            requests.post(url, data={'username': 'invalid_user_12345', 'password': 'password'}, timeout=5)
            invalid_times.append(time.time() - start)

            # Target user
            start = time.time()
            requests.post(url, data={'username': username, 'password': 'password'}, timeout=5)
            target_times.append(time.time() - start)

        avg_invalid = statistics.mean(invalid_times)
        avg_target = statistics.mean(target_times)

        # Calculate standard deviation if enough data points
        if len(invalid_times) > 1:
            stdev_invalid = statistics.stdev(invalid_times)
        else:
            stdev_invalid = 0

        # If target takes significantly longer (e.g., > 3 standard deviations from invalid mean)
        # We use a threshold of 3 sigmas or a static significant difference if stdev is very low
        threshold = max(0.5, 3 * stdev_invalid)

        diff = avg_target - avg_invalid

        if diff > threshold:
             return {"status": "vulnerable", "message": f"Significant timing difference detected (Avg Invalid: {avg_invalid:.3f}s, Avg Target: {avg_target:.3f}s, Diff: {diff:.3f}s > Threshold: {threshold:.3f}s)"}
        return {"status": "safe", "message": f"No significant timing difference (Avg Invalid: {avg_invalid:.3f}s, Avg Target: {avg_target:.3f}s)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_segregation_of_duties(admin_url: str, user_cookie: Dict[str, str]) -> Dict[str, Any]:
    """
    Tests if a low privilege user can access an admin endpoint.
    """
    try:
        res = requests.get(admin_url, cookies=user_cookie, timeout=5)
        if res.status_code == 200 and "login" not in res.text.lower():
             return {"status": "vulnerable", "message": "Low privilege user accessed admin URL"}
        return {"status": "safe", "message": f"Access denied or redirected (Status: {res.status_code})"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_trust_relationships(url: str, trusted_origin: str) -> Dict[str, Any]:
    """
    Checks if the application accepts requests from a trusted origin (CORS/Referer).
    """
    try:
        headers = {"Origin": trusted_origin, "Referer": trusted_origin}
        res = requests.get(url, headers=headers, timeout=5)

        cors_header = res.headers.get("Access-Control-Allow-Origin")
        if cors_header == trusted_origin or cors_header == "*":
             return {"status": "info", "message": f"Accepted Origin: {cors_header}", "cors_header": cors_header}
        return {"status": "safe", "message": "Origin not explicitly reflected in CORS header"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def test_non_repudiation(url: str) -> Dict[str, Any]:
    """
    Checks for headers or tokens that might indicate non-repudiation controls (e.g. strict logging, signatures).
    This is a heuristic check.
    """
    try:
        res = requests.head(url, timeout=5)
        headers = res.headers
        indicators = []
        if "X-Request-ID" in headers or "X-Correlation-ID" in headers:
            indicators.append("Traceability Headers Found")

        # Check if Digital Signature is required (often in custom headers)
        if any("signature" in h.lower() for h in headers.keys()):
            indicators.append("Signature Header Found")

        if indicators:
             return {"status": "info", "indicators": indicators}
        return {"status": "info", "message": "No obvious non-repudiation headers found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_lack_of_input_validation(url: str, param: str) -> Dict[str, Any]:
    """
    Checks if a parameter accepts special characters without error (Generic).
    """
    special_chars = "'\"<>()"
    try:
        target = replace_or_append_param(url, param, special_chars)
        res = requests.get(target, timeout=5)
        if special_chars in res.text:
             return {"status": "warning", "message": "Input reflected without encoding (Potential XSS/Injection)"}
        return {"status": "safe", "message": "Input not reflected verbatim"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_process_timing_issues(url: str) -> Dict[str, Any]:
    """
    Checks if multiple rapid requests cause errors (Race Condition / Concurrency).
    """
    try:
        # Send requests in parallel using ThreadPoolExecutor
        statuses = []

        def fetch(u):
            return requests.get(u, timeout=5).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch, url) for _ in range(10)]
            for future in concurrent.futures.as_completed(futures):
                statuses.append(future.result())

        if len(set(statuses)) > 1:
             return {"status": "warning", "message": "Inconsistent responses received (Race Condition Risk)", "statuses": statuses}
        return {"status": "safe", "message": "Consistent responses"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
