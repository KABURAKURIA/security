import hashlib
import requests
import re
import time

def validate_data_integrity(data, expected_hash, algorithm='sha256'):
    """
    Verifies if data matches the expected hash (integrity check).
    """
    try:
        if algorithm == 'sha256':
            calc_hash = hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'md5':
            calc_hash = hashlib.md5(data.encode()).hexdigest()
        else:
            return "Unsupported algorithm"

        if calc_hash == expected_hash:
            return "Integrity verified (Matches)"
        else:
            return f"Integrity check failed. Calculated: {calc_hash}"
    except Exception as e:
        return str(e)

def check_sequential_ids(url, param):
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
            return "Sequential IDs found (1, 2, 3) - Predictable Reference Risk"
        return "No obvious sequential IDs found"
    except Exception as e:
        return str(e)

def analyze_workflow_bypass(steps_urls):
    """
    Simulates skipping steps in a workflow.
    Input: list of URLs representing steps [step1, step2, step3]
    """
    try:
        # Try accessing step 3 directly
        if len(steps_urls) < 2: return "Need at least 2 steps"

        last_step = steps_urls[-1]
        res = requests.get(last_step, timeout=5)

        if res.status_code == 200:
            return "Able to access final step directly (Potential Workflow Bypass)"
        return f"Access to final step returned {res.status_code}"
    except Exception as e:
        return str(e)

def check_parameter_manipulation(url: str, params: dict):
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

        return results if results else "No standard business parameters found to test"
    except Exception as e:
        return str(e)

def check_timing_attacks(url, username):
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

        if target_time > (invalid_time * 2):
            return f"Significant timing difference detected (Invalid: {invalid_time:.2f}s, Target: {target_time:.2f}s)"
        return "No significant timing difference"
    except Exception as e:
        return str(e)
