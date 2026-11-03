from pathlib import Path

for filename, route, limit in [
    ("banking.py", "/banking", "10 per minute"),
    ("pin_security.py", "/change-pin", "5 per minute"),
]:
    path = Path(filename)
    code = path.read_text(encoding="utf-8-sig")

    if "from rate_limit import limiter" not in code:
        code = "from rate_limit import limiter\n" + code

    old = f'@' + (
        'banking_bp' if filename == "banking.py" else 'pin_bp'
    ) + f'.route("{route}", methods=["GET", "POST"])'

    new = old + f'\n@limiter.limit("{limit}", methods=["POST"])'

    if new in code:
        print(filename, "already protected.")
    elif old not in code:
        print("ERROR: Route not found in", filename)
    else:
        code = code.replace(old, new, 1)
        path.write_text(code, encoding="utf-8")
        print(filename, "rate limit installed.")
