import re
import uuid
import random
import string
import datetime
import json
import xml.dom.minidom
import ipaddress
import socket
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fake_useragent import UserAgent
from typing import List, Dict, Any

def extract_emails(text: str) -> List[str]:
    return list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)))

def extract_ipv4(text: str) -> List[str]:
    return list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)))

def extract_urls(text: str) -> List[str]:
    return list(set(re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", text)))

def generate_random_string(length: int = 12) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_uuid() -> str:
    return str(uuid.uuid4())

def timestamp_to_date(ts: str) -> str:
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return f"Error: {str(e)}"

def json_prettify(json_str: str) -> str:
    try:
        parsed = json.loads(json_str)
        return json.dumps(parsed, indent=4)
    except Exception as e:
        return f"Error: {str(e)}"

def xml_prettify(xml_str: str) -> str:
    try:
        dom = xml.dom.minidom.parseString(xml_str)
        return dom.toprettyxml()
    except Exception as e:
        return f"Error: {str(e)}"

def cidr_to_ips(cidr: str) -> Any:
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except Exception as e:
         return {"status": "error", "message": str(e)}

def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False

def is_valid_ipv6(ip: str) -> bool:
    try:
        ipaddress.IPv6Address(ip)
        return True
    except:
        return False

def get_host_by_name(hostname: str) -> Dict[str, Any]:
    try:
        ip = socket.gethostbyname(hostname)
        return {"status": "success", "ip": ip}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_service_name(port: int, proto: str = 'tcp') -> str:
    try:
        return socket.getservbyport(int(port), proto)
    except:
        return "Unknown"

def generate_random_user_agent() -> str:
    ua = UserAgent()
    return ua.random

def check_string_similarity(s1: str, s2: str) -> float:
    from difflib import SequenceMatcher
    return SequenceMatcher(None, s1, s2).ratio()

def count_words(text: str) -> int:
    return len(text.split())

def count_chars(text: str) -> int:
    return len(text)

def reverse_string(text: str) -> str:
    return text[::-1]

def to_upper(text: str) -> str:
    return text.upper()

def to_lower(text: str) -> str:
    return text.lower()

def remove_whitespace(text: str) -> str:
    return text.replace(" ", "")

def get_current_time() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_port_open(host: str, port: int, timeout: int = 1) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False

def get_base_url(url: str) -> str:
    """Returns the scheme and netloc (e.g., http://example.com/)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"

def replace_or_append_param(url: str, param: str, value: str) -> str:
    """Parses the URL, replaces the parameter value if it exists, or appends it if it doesn't."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
