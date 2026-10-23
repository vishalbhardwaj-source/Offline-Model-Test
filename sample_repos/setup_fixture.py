import os
import subprocess
from pathlib import Path


def init_sample_repo(base_dir: Path):
    repo_dir = base_dir / "sample_repos" / "sample_web_app"
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Git init
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True)
    subprocess.run(["git", "config", "user.email", "offline-dev@test.org"], cwd=str(repo_dir), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Offline Dev"], cwd=str(repo_dir), capture_output=True)

    # 1. Main branch files
    server_py = repo_dir / "server.py"
    server_py.write_text("""
import os
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Offline Demo App")

# Simulated credentials vulnerability
INTERNAL_API_KEY = "AKIA1234567890ABCDEF"

@app.get("/")
def home():
    return {"status": "ok", "service": "catalog"}

@app.get("/api/v1/auth/login")
def login(username: str):
    return {"token": "sample-jwt-token"}

@app.get("/api/v1/products")
def list_products():
    return [{"id": 1, "name": "Offline Engine", "price": 0}]

def check_feature():
    if is_feature_enabled("FEATURE_PAYMENT_V2"):
        return True
    return False
""", encoding="utf-8")

    req_file = repo_dir / "requirements.txt"
    req_file.write_text("fastapi==0.110.0\nuvicorn\npydantic\n", encoding="utf-8")

    test_file = repo_dir / "test_catalog.py"
    test_file.write_text("""
def test_products():
    assert True

def test_feature_payment():
    flag = "FEATURE_PAYMENT_V2"
    assert flag == "FEATURE_PAYMENT_V2"
""", encoding="utf-8")

    html_file = repo_dir / "index.html"
    html_file.write_text("<!DOCTYPE html><html><body><h1>Offline Catalog</h1></body></html>", encoding="utf-8")

    # Commit on main
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit on main"], cwd=str(repo_dir), capture_output=True)

    # Create feature branch with diff
    subprocess.run(["git", "checkout", "-b", "feature/checkout"], cwd=str(repo_dir), capture_output=True)
    
    checkout_py = repo_dir / "checkout.py"
    checkout_py.write_text("""
from server import app

@app.post("/api/v1/checkout")
def checkout_cart(cart_id: str):
    return {"order_id": "ORD-123", "status": "processed"}
""", encoding="utf-8")

    subprocess.run(["git", "add", "checkout.py"], cwd=str(repo_dir), capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add checkout endpoint"], cwd=str(repo_dir), capture_output=True)

    # Switch back to main
    subprocess.run(["git", "checkout", "main"], cwd=str(repo_dir), capture_output=True)


if __name__ == "__main__":
    init_sample_repo(Path("."))
    print("Sample repository initialized at sample_repos/sample_web_app")
