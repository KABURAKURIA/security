import gradio as gr
import inspect
import json
import typing
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

# Custom CSS for Nepbrutalism + Glassmorphism
custom_css = """
body {
    background: linear-gradient(135deg, #e0eafc 0%, #cfdef3 100%);
    font-family: 'Courier New', Courier, monospace;
}

.gradio-container {
    background: rgba(255, 255, 255, 0.2) !important;
    backdrop-filter: blur(10px) !important;
    border: 3px solid #000 !important;
    box-shadow: 10px 10px 0px #000 !important;
    border-radius: 0px !important;
}

button {
    background-color: #ff9f43 !important;
    color: #000 !important;
    border: 2px solid #000 !important;
    box-shadow: 3px 3px 0px #000 !important;
    font-weight: bold !important;
    text-transform: uppercase !important;
    border-radius: 0px !important;
}

button:hover {
    transform: translate(1px, 1px);
    box-shadow: 2px 2px 0px #000 !important;
}

.input_box, textarea, input, select {
    background: rgba(255, 255, 255, 0.7) !important;
    border: 2px solid #000 !important;
    border-radius: 0px !important;
    box-shadow: inset 2px 2px 0px rgba(0,0,0,0.1) !important;
}

h1, h2, h3 {
    text-transform: uppercase;
    text-shadow: 2px 2px 0px rgba(255,255,255,0.5);
}

.tabs {
    border-bottom: 2px solid #000;
}

.tabitem {
    border: 1px solid #000 !important;
    margin-right: 5px;
    background: #fff;
    border-radius: 0px !important;
}

.tabitem.selected {
    background: #000 !important;
    color: #fff !important;
}
"""

modules = {
    "Info Gathering": info_gathering,
    "Config": config_management,
    "Secure Trans": secure_transmission,
    "Auth": authentication,
    "Session": session_management,
    "AuthZ": authorization,
    "Validation": data_validation,
    "DoS": denial_of_service,
    "Logic": business_logic,
    "Crypto": cryptography,
    "Uploads": file_uploads,
    "Payments": card_payment,
    "HTML5": html5,
    "Utils": utils
}

def create_interface(func):
    """Generates a Gradio Interface for a given function."""
    sig = inspect.signature(func)
    type_hints = typing.get_type_hints(func)
    inputs = []

    for param_name, param in sig.parameters.items():
        label = param_name.replace("_", " ").title()

        default_val = param.default if param.default != inspect.Parameter.empty else None
        param_type = type_hints.get(param_name)

        if param_type == dict or typing.get_origin(param_type) is dict:
             val = "{}"
             if isinstance(default_val, dict):
                 val = json.dumps(default_val)
             inputs.append(gr.Textbox(label=f"{label} (JSON)", value=val, lines=3))
        elif param_name == 'url':
            inputs.append(gr.Textbox(label=label, value="http://example.com"))
        elif param_name == 'domain':
            inputs.append(gr.Textbox(label=label, value="example.com"))
        elif 'password' in param_name:
             inputs.append(gr.Textbox(label=label, type="password"))
        elif param_name == 'port':
             val = default_val if default_val is not None else 443
             inputs.append(gr.Number(label=label, value=val, precision=0))
        elif type(default_val) is bool or param_type is bool:
             inputs.append(gr.Checkbox(label=label, value=default_val if type(default_val) is bool else False))
        elif type(default_val) is int or param_type is int:
             inputs.append(gr.Number(label=label, value=default_val if type(default_val) is int else 0))
        elif param_type == list or typing.get_origin(param_type) is list or isinstance(default_val, list):
             val = ", ".join(map(str, default_val)) if isinstance(default_val, list) else ""
             inputs.append(gr.Textbox(label=f"{label} (comma separated)", value=val))
        else:
             val = str(default_val) if default_val is not None else ""
             inputs.append(gr.Textbox(label=label, value=val))

    def wrapper(*args):
        # Convert list args back to list if needed (simple approximation)
        final_args = list(args)
        # Re-mapping isn't strictly necessary if order is preserved, which it is.
        # But we need to handle the comma-separated strings for lists.
        # However, `inputs` mapping corresponds to `*args` order.

        converted_args = []
        for i, arg in enumerate(final_args):
            param_name = list(sig.parameters.keys())[i]
            param_default = sig.parameters[param_name].default
            param_type = type_hints.get(param_name)

            if (param_type == dict or typing.get_origin(param_type) is dict) and isinstance(arg, str):
                try:
                    converted_args.append(json.loads(arg))
                except Exception as e:
                    return f"Error parsing JSON for {param_name}: {e}"
                continue

            if (param_type == list or typing.get_origin(param_type) is list or isinstance(param_default, list)) and isinstance(arg, str):
                 try:
                    items = arg.split(',')
                    l = []
                    for item in items:
                        item = item.strip()
                        if item.isdigit(): l.append(int(item))
                        else: l.append(item)
                    converted_args.append(l)
                 except:
                    converted_args.append(arg)
            else:
                converted_args.append(arg)

        try:
            return str(func(*converted_args))
        except Exception as e:
            return f"Error: {e}"

    return gr.Interface(
        fn=wrapper,
        inputs=inputs,
        outputs=gr.Code(label="Result"),
        title=func.__name__.replace("_", " ").title(),
        description=inspect.getdoc(func) or "No description provided."
    )

total_tools = sum([len([name for name, obj in inspect.getmembers(mod) if inspect.isfunction(obj) and obj.__module__ == mod.__name__]) for mod in modules.values()])

with gr.Blocks(css=custom_css, title="OWASP Security Toolkit") as demo:
    gr.Markdown("# 🛡️ OWASP Security Toolkit")
    gr.Markdown(f"### {total_tools} Tools Available | Nepbrutalist x Glassmorphism Style")

    with gr.Tabs():
        for category, module in modules.items():
            with gr.TabItem(category):
                # Get functions
                functions = []
                for name, obj in inspect.getmembers(module):
                    if inspect.isfunction(obj) and obj.__module__ == module.__name__:
                        functions.append(obj)

                if not functions:
                    gr.Markdown("No tools in this category.")
                else:
                    # Create a sub-tab or accordion for each tool
                    # Gradio renders all interfaces at once if we just list them, which might be heavy.
                    # Using Accordion is better.
                    for func in functions:
                        with gr.Accordion(func.__name__.replace("_", " ").title(), open=False):
                            create_interface(func).render()

if __name__ == "__main__":
    demo.launch()
