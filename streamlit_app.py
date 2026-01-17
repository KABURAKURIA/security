
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
    authorization,
    denial_of_service,
    business_logic,
    file_uploads,
    card_payment,
    html5,
    utils
)

# Set page config
st.set_page_config(page_title="OWASP Security Toolkit", layout="wide", page_icon="🛡️")

# Custom CSS for Nepbrutalism + Glassmorphism
st.markdown("""
<style>
    /* Global Font */
    html, body, [class*="css"]  {
        font-family: 'Courier New', Courier, monospace;
        background-color: #f0f2f5;
        color: #1a1a1a;
    }

    /* Sidebar - Glassmorphism */
    section[data-testid="stSidebar"] {
        background: rgba(255, 255, 255, 0.2);
        backdrop-filter: blur(15px);
        -webkit-backdrop-filter: blur(15px);
        border-right: 1px solid rgba(255, 255, 255, 0.3);
    }

    /* Main Area - Gradient Background */
    .stApp {
        background: linear-gradient(135deg, #e0eafc 0%, #cfdef3 100%);
    }

    /* Headers - Nepbrutalism */
    h1, h2, h3 {
        color: #000;
        text-transform: uppercase;
        font-weight: 900;
        text-shadow: 2px 2px 0px rgba(0,0,0,0.2);
    }

    h1 {
        border: 3px solid #000;
        background-color: #fff;
        padding: 10px 20px;
        box-shadow: 5px 5px 0px #000;
        display: inline-block;
    }

    /* Buttons - Nepbrutalism */
    .stButton > button {
        background-color: #ff9f43 !important;
        color: #000 !important;
        border: 3px solid #000 !important;
        border-radius: 0px !important;
        box-shadow: 4px 4px 0px #000 !important;
        font-weight: bold !important;
        text-transform: uppercase;
        transition: all 0.1s ease;
    }

    .stButton > button:hover {
        transform: translate(2px, 2px);
        box-shadow: 2px 2px 0px #000 !important;
    }

    .stButton > button:active {
        transform: translate(4px, 4px);
        box-shadow: 0px 0px 0px #000 !important;
    }

    /* Inputs - Nepbrutalism + Glassmorphism */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > div {
        background: rgba(255, 255, 255, 0.6) !important;
        border: 2px solid #000 !important;
        border-radius: 0px !important;
        color: #000 !important;
        box-shadow: 3px 3px 0px rgba(0,0,0,0.1) !important;
    }

    /* Info Box / Success / Error - Glass Cards */
    .stAlert {
        background: rgba(255, 255, 255, 0.4);
        backdrop-filter: blur(10px);
        border: 2px solid #000;
        border-radius: 0px;
        box-shadow: 4px 4px 0px #000;
        color: #000;
    }

    /* JSON / Code output */
    code {
        background: #000 !important;
        color: #0f0 !important;
        border: 1px solid #0f0;
        font-family: 'Consolas', monospace;
    }

    /* Expander - Nepbrutalism */
    .streamlit-expanderHeader {
        background-color: #fff !important;
        border: 2px solid #000 !important;
        border-radius: 0px !important;
        box-shadow: 3px 3px 0px #000 !important;
        color: #000 !important;
        font-weight: bold;
    }

    div[data-testid="stExpander"] {
        background-color: transparent;
        border: none;
    }

</style>
""", unsafe_allow_html=True)

st.title("🛡️ OWASP Security Toolkit")
st.markdown("**Nepbrutalist** & **Glassmorphic** Edition")

# Sidebar
st.sidebar.markdown("### 🧰 Toolkit Menu")

# Map categories to modules
modules = {
    "Information Gathering": info_gathering,
    "Configuration Management": config_management,
    "Secure Transmission": secure_transmission,
    "Authentication": authentication,
    "Session Management": session_management,
    "Authorization": authorization,
    "Data Validation": data_validation,
    "Denial of Service": denial_of_service,
    "Business Logic": business_logic,
    "Cryptography": cryptography,
    "File Uploads": file_uploads,
    "Card Payment": card_payment,
    "HTML 5": html5,
    "Utilities": utils
}

category = st.sidebar.selectbox("Select Category", list(modules.keys()))

selected_module = modules[category]

# Get functions
functions = []
for name, obj in inspect.getmembers(selected_module):
    if inspect.isfunction(obj) and obj.__module__ == selected_module.__name__:
        functions.append(name)

tool_name = st.sidebar.selectbox("Select Tool", functions)

# Description in sidebar
if tool_name:
    func = getattr(selected_module, tool_name)
    doc = inspect.getdoc(func)
    if doc:
        st.sidebar.info(doc)

# Main Area - Tool Execution
if tool_name:
    st.markdown(f"## {category} / {tool_name}")

    # Glassmorphic Card for the tool
    with st.container():
        st.markdown('<div style="background: rgba(255,255,255,0.3); backdrop-filter: blur(10px); padding: 20px; border: 2px solid #000; box-shadow: 5px 5px 0px #000; margin-bottom: 20px;">', unsafe_allow_html=True)

        func = getattr(selected_module, tool_name)

        # Introspect arguments
        sig = inspect.signature(func)
        params = sig.parameters

        inputs = {}
        with st.form(key=tool_name):
            cols = st.columns(2)  # Two column layout for inputs

            for i, (param_name, param) in enumerate(params.items()):
                col = cols[i % 2]

                with col:
                    label = param_name.replace("_", " ").title()

                    # Smart defaults based on name
                    default_val = ""
                    if param.default != inspect.Parameter.empty:
                        default_val = param.default

                    if param_name == 'url':
                        inputs[param_name] = st.text_input(label, value="http://example.com")
                    elif param_name == 'domain':
                        inputs[param_name] = st.text_input(label, value="example.com")
                    elif param_name == 'hostname':
                        inputs[param_name] = st.text_input(label, value="example.com")
                    elif 'password' in param_name and 'strength' not in tool_name: # Avoid masking if checking strength of visible input
                         inputs[param_name] = st.text_input(label, type="password")
                    elif param_name == 'port':
                         val = 443
                         if isinstance(default_val, int): val = default_val
                         inputs[param_name] = st.number_input(label, value=val, step=1)
                    elif isinstance(default_val, bool):
                         inputs[param_name] = st.checkbox(label, value=default_val)
                    elif isinstance(default_val, int):
                         inputs[param_name] = st.number_input(label, value=default_val)
                    elif isinstance(default_val, list):
                         inputs[param_name] = st.text_input(f"{label} (comma separated)", value=", ".join(map(str, default_val)))
                    else:
                         inputs[param_name] = st.text_input(label, value=str(default_val) if default_val != "" else "")

            st.markdown("<br>", unsafe_allow_html=True)
            submitted = st.form_submit_button("🚀 EXECUTE")

            if submitted:
                try:
                    # Pre-process inputs
                    final_args = {}
                    for k, v in inputs.items():
                        # Handle list conversion
                        if isinstance(params[k].default, list) and isinstance(v, str):
                            try:
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

                    with st.spinner("Processing..."):
                        result = func(**final_args)

                    st.success("Operation Successful")

                    st.markdown("### Result Output")
                    if isinstance(result, (dict, list)):
                        st.json(result)
                    else:
                        st.code(str(result))

                except Exception as e:
                    st.error(f"Error occurred: {e}")

        st.markdown('</div>', unsafe_allow_html=True)
