# OWASP Security Toolkit

This toolkit contains over 100 web application security tools covering Information Gathering, Configuration Management, Secure Transmission, Authentication, Data Validation, Session Management, and Cryptography.

## Interfaces

There are two ways to use the tools:

### Streamlit (Recommended)
The Streamlit app provides access to all 100+ tools with a dynamic interface.

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

### Gradio
The Gradio app provides a simplified view of selected tools.

```bash
pip install -r requirements.txt
python gradio_app.py
```

## Structure

- `owasp_toolkit/tools/`: Source code for all security checks.
- `streamlit_app.py`: Main dashboard.
- `gradio_app.py`: Alternative interface.
- `tests/`: Unit tests.

## Testing

Run tests with:
```bash
python3 -m unittest discover tests
```
