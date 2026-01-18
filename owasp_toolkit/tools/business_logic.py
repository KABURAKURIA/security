import hashlib
import requests
import re
import time
from typing import List, Dict, Union, Any

def validate_data_integrity(data: str, expected_hash: str, algorithm: str = 'sha256') -> Dict[str, Any]:
    """
    Verifies if data matches the expected hash (integrity check).
    """
    try:
        if algorithm == 'sha256':
            calc_hash = hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'md5':
            calc_hash = hashlib.md5(data.encode()).hexdigest()
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
            if '?' in url:
                target = f"{url}&{param}={i}"
            else:
                target = f"{url}?{param}={i}"
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
        # Baseline (likely invalid user)
        start = time.time()
        requests.post(url, data={'username': 'invalid_user_12345', 'password': 'password'}, timeout=5)
        invalid_time = time.time() - start

        # Target user
        start = time.time()
        requests.post(url, data={'username': username, 'password': 'password'}, timeout=5)
        target_time = time.time() - start

        if target_time > (invalid_time * 2) and target_time > 0.5: # 0.5s threshhold to avoid noise
             return {"status": "vulnerable", "message": f"Significant timing difference detected (Invalid: {invalid_time:.2f}s, Target: {target_time:.2f}s)"}
        return {"status": "safe", "message": "No significant timing difference"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
