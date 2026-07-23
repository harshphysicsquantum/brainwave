from fastapi import FastAPI
import ssl
import socket
from datetime import datetime
import requests
import re


app = FastAPI()

def check_ssl(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert['notAfter']  # e.g. 'Jun  1 12:00:00 2026 GMT'
        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.utcnow()).days

        findings = []
        if days_left < 0:
            score = 0
            findings.append("Certificate has expired")
        elif days_left < 30:
            score = 50
            findings.append(f"Certificate expires in {days_left} days")
        else:
            score = 100
            findings.append(f"Certificate valid, expires in {days_left} days")

        return {"score": score, "findings": findings}

    except Exception as e:
        return {"score": 0, "findings": [f"Could not check SSL: {str(e)}"]}


def check_headers(domain: str):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        headers = response.headers

        important_headers = {
            "Content-Security-Policy": "Missing Content-Security-Policy",
            "X-Frame-Options": "Missing X-Frame-Options",
            "Strict-Transport-Security": "Missing Strict-Transport-Security (HSTS)",
            "X-Content-Type-Options": "Missing X-Content-Type-Options"
        }

        findings = []
        for header, message in important_headers.items():
            if header not in headers:
                findings.append(message)

        total = len(important_headers)
        missing = len(findings)
        score = int(((total - missing) / total) * 100)

        if not findings:
            findings.append("All key security headers present")

        return {"score": score, "findings": findings}

    except Exception as e:
        return {"score": 0, "findings": [f"Could not check headers: {str(e)}"]}


def check_breach(email: str):
    try:
        response = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=5)
        data = response.json()

        breaches = data.get("breaches", [[]])[0]  # API returns a nested list

        if breaches:
            score = max(0, 100 - (len(breaches) * 20))
            findings = [f"Found in {len(breaches)} breach(es): {', '.join(breaches[:3])}"]
        else:
            score = 100
            findings = ["No breaches found"]

        return {"score": score, "findings": findings}

    except Exception as e:
        return {"score": 50, "findings": [f"Could not check breach status: {str(e)}"]}


def check_subdomains(domain: str):
    common_subs = ["www", "mail", "dev", "staging", "api", "admin", "test", "portal"]
    found = []

    for sub in common_subs:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            found.append(full)
        except socket.gaierror:
            pass

    count = len(found)
    if count == 0:
        score = 100
        findings = ["No common subdomains found"]
    elif count < 4:
        score = 80
        findings = [f"{count} subdomains found: {', '.join(found)}"]
    else:
        score = 60
        findings = [f"{count} subdomains found: {', '.join(found)}"]

    return {"score": score, "findings": findings}


def check_secrets(github_org: str):
    try:
        repos_response = requests.get(f"https://api.github.com/orgs/{github_org}/repos", timeout=3)
        repos = repos_response.json()

        if not isinstance(repos, list):
            repos_response = requests.get(f"https://api.github.com/users/{github_org}/repos", timeout=3)
            repos = repos_response.json()

        if not isinstance(repos, list):
            return {"score": 50, "findings": [f"Could not fetch repos: {repos.get('message', 'unknown error')}"]}

        patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]",
            "Private Key": r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----"
        }

        findings = []
        checked_files = 0

        for repo in repos[:2]:
            repo_name = repo["name"]
            contents_url = f"https://api.github.com/repos/{github_org}/{repo_name}/contents"
            contents_response = requests.get(contents_url, timeout=3)
            files = contents_response.json()

            if not isinstance(files, list):
                continue

            for file in files[:5]:
                if file.get("type") != "file":
                    continue
                if not file["name"].endswith((".py", ".js", ".env", ".json", ".yml", ".txt")):
                    continue

                file_response = requests.get(file["download_url"], timeout=3)
                content = file_response.text
                checked_files += 1

                for label, pattern in patterns.items():
                    if re.search(pattern, content):
                        findings.append(f"{label} found in {repo_name}/{file['name']}")

        if not findings:
            score = 100
            findings = [f"No secrets found in {checked_files} files checked"]
        else:
            score = max(0, 100 - (len(findings) * 30))

        return {"score": score, "findings": findings}

    except Exception as e:
        return {"score": 50, "findings": [f"Could not check secrets: {str(e)}"]}

@app.get("/scan")
def scan(domain: str, email: str = "test@example.com", github_org: str = "github"):
    return {
        "domain": domain,
        "overall_score": 62,
        "categories": {
            "ssl": check_ssl(domain),
            "headers": check_headers(domain),
            "subdomains": check_subdomains(domain),
            "secrets": check_secrets(github_org),
            "breach": check_breach(email)
        }
    }