from pathlib import Path

path = Path("app.py")
code = path.read_text(encoding="utf-8-sig")

if "limiter.init_app(app)" in code:
    print("Rate limiter already installed.")
else:
    marker = "csrf = CSRFProtect(app)"
    addition = (
        "from rate_limit import limiter\n"
        "limiter.init_app(app)\n"
    )

    if marker not in code:
        print("ERROR: CSRF setup not found. No changes made.")
    else:
        code = code.replace(marker, marker + "\n" + addition, 1)
        path.write_text(code, encoding="utf-8")
        print("Rate limiter initialized.")
