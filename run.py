from app import app

if __name__ == "__main__":
    print("Starting MyBank Banking Simulator...")
    app.run(
        host="127.0.0.1",
        port=5050,
        debug=False
    )
