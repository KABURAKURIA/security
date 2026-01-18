import requests
import os
from typing import List, Dict, Union, Any

def check_file_upload_size_limit(url: str, field_name: str) -> Dict[str, Any]:
    """
    Tests if the server enforces file size limits.
    """
    try:
        # Create a large dummy file content
        large_content = "A" * (10 * 1024 * 1024) # 10MB
        files = {field_name: ('large_test.txt', large_content)}

        res = requests.post(url, files=files, timeout=10)

        if res.status_code == 413:
             return {"status": "safe", "message": "Properly rejected large file (413 Payload Too Large)"}
        elif res.status_code == 200:
             return {"status": "warning", "message": "Accepted 10MB file (Check if limit exists)"}
        else:
             return {"status": "info", "message": f"Server responded with {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_malicious_file_extensions(url: str, field_name: str) -> Dict[str, Any]:
    """
    Tests if the server accepts dangerous file extensions.
    """
    extensions = ['.php', '.exe', '.sh', '.jsp', '.py', '.html', '.svg']
    results = {}

    for ext in extensions:
        try:
            filename = f"test_exploit{ext}"
            files = {field_name: (filename, "<?php echo 'HACKED'; ?>")}
            res = requests.post(url, files=files, timeout=5)

            if res.status_code == 200:
                results[ext] = "Accepted (Potential Risk)"
            elif res.status_code == 403 or res.status_code == 415:
                results[ext] = "Rejected (Good)"
            else:
                results[ext] = f"Status {res.status_code}"
        except:
            results[ext] = "Error"

    return {"status": "completed", "results": results}

def check_upload_accessibility(url: str, upload_dir: str = "uploads/") -> Dict[str, Any]:
    """
    Checks if uploaded files are directly accessible in a common directory.
    """
    try:
        test_file = "test_access.txt"
        target = url.rstrip('/') + '/' + upload_dir + test_file
        res = requests.head(target, timeout=5)

        if res.status_code == 200:
             return {"status": "vulnerable", "message": f"Found file at {target} - Directory listing or direct access might be enabled"}
        elif res.status_code == 403:
             return {"status": "safe", "message": "Access Forbidden (Good)"}
        else:
             return {"status": "info", "message": "File not found or protected"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_svg_xss(url: str, field_name: str) -> Dict[str, Any]:
    """
    Tests for SVG XSS upload.
    """
    svg_payload = """<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>"""
    try:
        files = {field_name: ('exploit.svg', svg_payload, 'image/svg+xml')}
        res = requests.post(url, files=files, timeout=5)

        if res.status_code == 200:
            if "alert(1)" in res.text: # If it reflects the content back
                return {"status": "vulnerable", "message": "SVG accepted and content reflected (High Risk of Stored XSS)"}
            return {"status": "warning", "message": "SVG accepted (Check if it's served as image/svg+xml)"}
        return {"status": "safe", "message": f"Rejected with status {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def sanitize_filename_check(filename: str) -> Dict[str, Any]:
    """
    Helper to check if a filename is safe (alphanumeric).
    """
    import re
    if re.match(r'^[\w\-. ]+$', filename):
        return {"status": "safe", "message": "Safe filename"}
    return {"status": "unsafe", "message": "Unsafe characters detected"}
