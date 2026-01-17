import streamlit as st
import inspect
from owasp_toolkit.tools import (
    info_gathering,
    config_management,
    secure_transmission,
    authentication,
    data_validation,
    session_management,
    cryptography,
    utils
)

st.set_page_config(page_title="OWASP Security Toolkit", layout="wide")

st.title("🛡️ OWASP Web Application Security Toolkit")
st.markdown("Over 100 tools for web application security testing and analysis.")

# Sidebar
category = st.sidebar.selectbox("Select Category", [
    "Information Gathering",
    "Configuration Management",
    "Secure Transmission",
    "Authentication",
    "Data Validation",
    "Session Management",
    "Cryptography",
    "Utilities"
])

# Map categories to modules
modules = {
    "Information Gathering": info_gathering,
    "Configuration Management": config_management,
    "Secure Transmission": secure_transmission,
    "Authentication": authentication,
    "Data Validation": data_validation,
    "Session Management": session_management,
    "Cryptography": cryptography,
    "Utilities": utils
}

selected_module = modules[category]

# Get functions
functions = []
for name, obj in inspect.getmembers(selected_module):
    if inspect.isfunction(obj) and obj.__module__ == selected_module.__name__:
        functions.append(name)

tool_name = st.sidebar.selectbox("Select Tool", functions)

# Tool execution logic
if tool_name:
    st.header(f"{category} - {tool_name}")

    func = getattr(selected_module, tool_name)
    doc = inspect.getdoc(func)
    if doc:
        st.info(doc)

    # Introspect arguments
    sig = inspect.signature(func)
    params = sig.parameters

    inputs = {}
    with st.form(key=tool_name):
        for param_name, param in params.items():
            # Basic type inference or default
            label = param_name.replace("_", " ").title()

            if param_name == 'url':
                inputs[param_name] = st.text_input(label, value="http://example.com")
            elif param_name == 'domain':
                inputs[param_name] = st.text_input(label, value="example.com")
            elif param_name == 'hostname':
                inputs[param_name] = st.text_input(label, value="example.com")
            elif 'password' in param_name:
                inputs[param_name] = st.text_input(label, type="password")
            elif param_name == 'port':
                inputs[param_name] = st.number_input(label, value=443, step=1)
            elif param.default != inspect.Parameter.empty:
                 # If default value exists, use it
                 val = param.default
                 if isinstance(val, bool):
                     inputs[param_name] = st.checkbox(label, value=val)
                 elif isinstance(val, int):
                     inputs[param_name] = st.number_input(label, value=val)
                 elif isinstance(val, list):
                      # For lists, maybe a text input converting to list? Or just show it?
                      # For simplicity, if it's a list argument, we might skip or handle specially.
                      # Let's assume list inputs are rare for the user to provide directly in this simple UI,
                      # or treat as string and eval (dangerous) or split by comma.
                      inputs[param_name] = st.text_input(f"{label} (comma separated)", value=", ".join(map(str, val)))
                 else:
                     inputs[param_name] = st.text_input(label, value=str(val))
            else:
                inputs[param_name] = st.text_input(label)

        submitted = st.form_submit_button("Run Tool")

        if submitted:
            try:
                # Pre-process inputs
                final_args = {}
                for k, v in inputs.items():
                    # Handle list conversion
                    if isinstance(params[k].default, list) and isinstance(v, str):
                        try:
                            # Basic comma split, trying to keep types if int
                            items = v.split(',')
                            final_list = []
                            for item in items:
                                item = item.strip()
                                if item.isdigit():
                                    final_list.append(int(item))
                                else:
                                    final_list.append(item)
                            final_args[k] = final_list
                        except:
                            final_args[k] = v
                    else:
                        final_args[k] = v

                with st.spinner("Running..."):
                    result = func(**final_args)

                st.success("Completed!")
                st.write("### Result")
                st.code(str(result) if not isinstance(result, (dict, list)) else result)
                if isinstance(result, (dict, list)):
                    st.json(result)

            except Exception as e:
                st.error(f"Error occurred: {e}")
