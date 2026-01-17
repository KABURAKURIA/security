import re
import uuid
import random
import string
import datetime
import json
import xml.dom.minidom
import ipaddress
import socket
from fake_useragent import UserAgent

def extract_emails(text):
    return list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)))

def extract_ipv4(text):
    return list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)))

def extract_urls(text):
    return list(set(re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", text)))

def generate_random_string(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_uuid():
    return str(uuid.uuid4())

def timestamp_to_date(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid Timestamp"

def json_prettify(json_str):
    try:
        parsed = json.loads(json_str)
        return json.dumps(parsed, indent=4)
    except:
        return "Invalid JSON"

def xml_prettify(xml_str):
    try:
        dom = xml.dom.minidom.parseString(xml_str)
        return dom.toprettyxml()
    except:
        return "Invalid XML"

def cidr_to_ips(cidr):
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except:
        return "Invalid CIDR"

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False

def is_valid_ipv6(ip):
    try:
        ipaddress.IPv6Address(ip)
        return True
    except:
        return False

def get_host_by_name(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return "Resolution failed"

def get_service_name(port, proto='tcp'):
    try:
        return socket.getservbyport(int(port), proto)
    except:
        return "Unknown"

def generate_random_user_agent():
    ua = UserAgent()
    return ua.random

def check_string_similarity(s1, s2):
    from difflib import SequenceMatcher
    return SequenceMatcher(None, s1, s2).ratio()

def count_words(text):
    return len(text.split())

def count_chars(text):
    return len(text)

def reverse_string(text):
    return text[::-1]

def to_upper(text):
    return text.upper()

def to_lower(text):
    return text.lower()

def remove_whitespace(text):
    return text.replace(" ", "")

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_port_open(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False
