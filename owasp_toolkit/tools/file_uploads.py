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

def check_file_content_type_validation(url: str, field_name: str) -> Dict[str, Any]:
    """
    Checks if the server validates the Content-Type header independently of the file extension.
    Uploads a benign file (e.g. .jpg) with a mismatched MIME type (e.g. text/plain).
    """
    try:
        # File extension is image, but Content-Type is text
        files = {field_name: ('test_image.jpg', b'fake image content', 'text/plain')}
        res = requests.post(url, files=files, timeout=5)

        if res.status_code == 200:
             return {"status": "warning", "message": "File accepted despite mismatched Content-Type (Possible lack of strict MIME validation)"}
        elif res.status_code in [400, 415, 422]:
             return {"status": "safe", "message": f"File rejected (Status {res.status_code}) - Likely validating Content-Type"}

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

def check_antivirus_scanning(url: str, field_name: str) -> Dict[str, Any]:
    """
    Checks if the server scans uploaded files for viruses using the EICAR test string.
    """
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        files = {field_name: ('eicar_test.txt', eicar_string)}
        res = requests.post(url, files=files, timeout=10)

        # If rejected (4xx/5xx) or specific message
        if res.status_code in [400, 403, 422, 500]:
             return {"status": "safe", "message": f"File rejected (Status {res.status_code}). Potential Antivirus/Validation active."}

        if "virus" in res.text.lower() or "malware" in res.text.lower():
             return {"status": "safe", "message": "Virus detected message found in response."}

        if res.status_code == 200:
             return {"status": "vulnerable", "message": "EICAR test file accepted (Status 200). Antivirus scanning might be missing."}

        return {"status": "info", "message": f"Server responded with {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_magic_bytes_validation(url: str, field_name: str) -> Dict[str, Any]:
    """
    Verifies if the server validates file content against the file extension by uploading a text file with a .jpg extension.
    """
    try:
        # File has .jpg extension but content is plain text (no magic bytes of JPEG)
        filename = "fake_image.jpg"
        content = b"This is just text, not an image."
        files = {field_name: (filename, content, 'image/jpeg')}

        res = requests.post(url, files=files, timeout=5)

        if res.status_code == 200:
             return {"status": "vulnerable", "message": "File accepted despite invalid magic bytes (Extension trusted over Content)"}
        elif res.status_code in [400, 415, 422]:
             return {"status": "safe", "message": "File rejected (Likely validated magic bytes)"}

        return {"status": "info", "message": f"Server responded with {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
