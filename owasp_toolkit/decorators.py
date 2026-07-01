import functools
import inspect

def validate_arguments(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            for name, value in bound_args.arguments.items():
                param = sig.parameters[name]
                ann = param.annotation
                if value is None:
                    if ann is bool: bound_args.arguments[name] = False
                    elif ann is int: bound_args.arguments[name] = 0
                    elif ann is float: bound_args.arguments[name] = 0.0
                    elif ann is str: bound_args.arguments[name] = ""
                else:
                    if ann is bool:
                        if isinstance(value, str):
                            bound_args.arguments[name] = value.lower() in ('true', '1', 't', 'yes')
                        else:
                            bound_args.arguments[name] = bool(value)
                    elif ann is int:
                        bound_args.arguments[name] = int(value)
                    elif ann is float:
                        bound_args.arguments[name] = float(value)
                    elif ann is str:
                        if not isinstance(value, str):
                            bound_args.arguments[name] = str(value)
        except (TypeError, ValueError) as e:
            return {"status": "error", "message": str(e)}
        return func(*bound_args.args, **bound_args.kwargs)
    return wrapper
