# 🛡️ OWASP-Aligned Security Assessment Toolkit

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Gradio](https://img.shields.io/badge/Gradio-Interface-orange.svg)](https://gradio.app/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/)

A modular cybersecurity assessment suite and vulnerability testing framework containing **100+ automated tools** aligned with the OWASP Testing Guide and Top 10 vulnerabilities, accessible via CLI, Streamlit, and Gradio interfaces.

---

## 🧱 Toolkit Modules

```
owasp_toolkit/
├── tools/
│   ├── authentication.py       # Password strength, brute force defenses, MFA verification
│   ├── authorization.py        # IDOR detection, privilege escalation, role audits
│   ├── cryptography.py         # Cipher suite analysis, hashing checks, TLS configuration
│   ├── data_validation.py      # SQLi, XSS, command injection, path traversal payloads
│   ├── session_management.py   # Cookie security attributes (SameSite, Secure, HttpOnly), session fixation
│   ├── secure_transmission.py  # HSTS validation, certificate expiry, protocol downgrade checks
│   ├── info_gathering.py       # Subdomain enumeration, header analysis, banner grabbing
│   ├── file_uploads.py         # Malicious MIME-type bypass, double extensions, polyglot checks
│   └── denial_of_service.py    # ReDoS checks, resource exhaustion testing
```

---

## 🚀 Usage & Launching Dashboards

```bash
# Clone the repository
git clone https://github.com/KABURAKURIA/security.git
cd security

# Install dependencies
pip install -r requirements.txt

# Option A: Launch the Streamlit dashboard
streamlit run streamlit_app.py

# Option B: Launch the Gradio web interface
python gradio_app.py

# Option C: Run automated test suite
pytest tests/
```

---

## ⚠️ Disclaimer

This toolkit is developed exclusively for authorized penetration testing, security research, and defensive hardening. Always obtain proper authorization before scanning any target infrastructure.

---

## 📄 License

MIT License.
