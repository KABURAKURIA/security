import gradio as gr
from owasp_toolkit.tools import (
    info_gathering,
    config_management,
    secure_transmission,
    authentication,
    data_validation,
    session_management,
    cryptography,
    authorization,
    denial_of_service,
    business_logic,
    file_uploads,
    card_payment,
    html5,
    utils
)

# Wrapper functions for Gradio
def quick_scan(url):
    results = {}
    results['Robots.txt'] = info_gathering.get_robots_txt(url)
    results['Headers'] = info_gathering.get_http_headers(url)
    results['Tech'] = info_gathering.identify_tech_headers(url)
    results['Security Headers'] = {
        'CSP': config_management.check_csp(url),
        'HSTS': config_management.check_hsts(url),
        'X-Frame': config_management.check_x_frame_options(url)
    }
    return str(results)

def crypto_tool(text, operation):
    if operation == "MD5": return cryptography.calculate_hash(text, 'md5')
    if operation == "SHA256": return cryptography.calculate_hash(text, 'sha256')
    if operation == "Base64 Encode": return cryptography.base64_encode(text)
    if operation == "Base64 Decode": return cryptography.base64_decode(text)
    if operation == "URL Encode": return cryptography.url_encode(text)
    if operation == "URL Decode": return cryptography.url_decode(text)
    if operation == "Hex Encode": return cryptography.hex_encode(text)
    if operation == "Hex Decode": return cryptography.hex_decode(text)
    return "Unknown operation"

def network_tool(target, operation):
    if operation == "DNS Lookup": return str(info_gathering.dns_lookup(target))
    if operation == "Whois": return str(info_gathering.whois_lookup(target))
    if operation == "Port Scan (Common)": return str(info_gathering.scan_ports(target))
    if operation == "SSL Info": return str(secure_transmission.get_ssl_certificate_info(target))
    return "Unknown operation"

def password_tool(password):
    strength = authentication.check_password_strength(password)
    entropy = session_management.calculate_entropy(password)
    return f"Strength: {strength}\nEntropy: {entropy}"

def misc_checks(url, check_type):
    if check_type == "CORS Check":
        return html5.check_cors_wildcard(url)
    elif check_type == "Offline Manifest":
        return html5.check_offline_manifest(url)
    elif check_type == "Payment HTTPS":
        return card_payment.check_payment_gateway_https(url)
    elif check_type == "Admin Access":
        return str(authorization.check_admin_access(url))
    elif check_type == "Slowloris Check":
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == 'https' else 80
        if not host:
             # Fallback if no scheme provided
             host = url.split(':')[0] if ':' in url else url
        return denial_of_service.check_slowloris_susceptibility(host, port)
    return "Unknown check"

# Build UI
with gr.Blocks(title="OWASP Security Toolkit") as demo:
    gr.Markdown("# 🛡️ OWASP Security Toolkit (Gradio Edition)")

    with gr.Tab("Quick Scan"):
        gr.Markdown("Run a basic reconnaissance scan on a URL.")
        url_input = gr.Textbox(label="URL", value="http://example.com")
        scan_btn = gr.Button("Scan")
        scan_output = gr.Code(label="Results")
        scan_btn.click(quick_scan, inputs=url_input, outputs=scan_output)

    with gr.Tab("Cryptography & Encoding"):
        gr.Markdown("Hash, Encode, and Decode text.")
        crypto_input = gr.Textbox(label="Input Text")
        crypto_op = gr.Dropdown([
            "MD5", "SHA256",
            "Base64 Encode", "Base64 Decode",
            "URL Encode", "URL Decode",
            "Hex Encode", "Hex Decode"
        ], label="Operation")
        crypto_btn = gr.Button("Process")
        crypto_output = gr.Textbox(label="Output")
        crypto_btn.click(crypto_tool, inputs=[crypto_input, crypto_op], outputs=crypto_output)

    with gr.Tab("Network & SSL"):
        gr.Markdown("DNS, Whois, and SSL checks.")
        net_input = gr.Textbox(label="Domain/IP/URL", value="example.com")
        net_op = gr.Dropdown([
            "DNS Lookup", "Whois", "Port Scan (Common)", "SSL Info"
        ], label="Tool")
        net_btn = gr.Button("Run")
        net_output = gr.Code(label="Output")
        net_btn.click(network_tool, inputs=[net_input, net_op], outputs=net_output)

    with gr.Tab("Password Analysis"):
        gr.Markdown("Check password strength and entropy.")
        pw_input = gr.Textbox(label="Password", type="password")
        pw_btn = gr.Button("Analyze")
        pw_output = gr.Textbox(label="Analysis")
        pw_btn.click(password_tool, inputs=pw_input, outputs=pw_output)

    with gr.Tab("Advanced Checks"):
        gr.Markdown("Run specific vulnerability checks.")
        adv_url = gr.Textbox(label="URL", value="http://example.com")
        adv_op = gr.Dropdown([
            "CORS Check", "Offline Manifest", "Payment HTTPS", "Admin Access", "Slowloris Check"
        ], label="Check Type")
        adv_btn = gr.Button("Run Check")
        adv_output = gr.Textbox(label="Result")
        adv_btn.click(misc_checks, inputs=[adv_url, adv_op], outputs=adv_output)

if __name__ == "__main__":
    demo.launch()
