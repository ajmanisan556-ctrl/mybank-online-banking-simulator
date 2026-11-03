from pathlib import Path

path = Path("app.py")
code = path.read_text(encoding="utf-8-sig")

old = '''@app.route("/login", methods=["GET", "POST"])
def login():'''

new = '''@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():'''

if new in code:
    print("Login rate limit already installed.")
elif old not in code:
    print("ERROR: Login route not found.")
else:
    code = code.replace(old, new, 1)
    path.write_text(code, encoding="utf-8")
    print("Login rate limit installed.")
