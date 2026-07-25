from fastapi import FastAPI
import ssl
import socket
from datetime import datetime
import requests
import re
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


FINDING_LOOKUP = {
    "No breaches found": {"weight": 0, "fix": "No immediate action required. Continue using strong passwords and MFA."},
    "No secrets found": {"weight": 0, "fix": "No action required. Continue following secure coding practices."},
    "No common subdomains found": {"weight": 0, "fix": "No action required. Continue monitoring your attack surface."},
    "All key security headers present": {"weight": 0, "fix": "No action needed. Continue following security best practices."},
    "Certificate valid, expires in": {"weight": 0, "fix": "No action needed. Continue renewing the certificate before it expires."},
    "Missing Referrer-Policy": {"weight": 1, "fix": "Configure a Referrer-Policy header that limits shared information."},
    "Missing X-Content-Type-Options": {"weight": 2, "fix": "Add the X-Content-Type-Options header with the value nosniff."},
    "Missing X-Frame-Options": {"weight": 2, "fix": "Add the X-Frame-Options header."},
    "Certificate expires in": {"weight": 3, "fix": "Renew the certificate before it expires to avoid browser warnings."},
    "Missing Strict-Transport-Security": {"weight": 3, "fix": "Enable the Strict-Transport-Security header."},
    "Missing Content-Security-Policy": {"weight": 4, "fix": "Configure a Content-Security-Policy header."},
    "subdomains found": {"weight": 5, "fix": "Review each subdomain and remove or secure any unnecessary ones."},
    "OpenAI API Key": {"weight": 7, "fix": "Revoke the key, generate a new one, and store it securely."},
    "Google API Key": {"weight": 7, "fix": "Restrict the key, rotate it if necessary, and remove it from the repository."},
    "Self-signed certificate": {"weight": 7, "fix": "Replace it with a certificate issued by a trusted Certificate Authority."},
    "Generic API Key": {"weight": 7, "fix": "Remove the key from the repository and rotate it if it is active."},
    "Certificate has expired": {"weight": 8, "fix": "Renew and install a valid SSL/TLS certificate immediately."},
    "Email in one breach": {"weight": 5, "fix": "Change reused passwords, enable multi-factor authentication, and monitor the account."},
    "Email in multiple breaches": {"weight": 8, "fix": "Change passwords, enable MFA, and review account activity."},
    "Firebase Secret": {"weight": 8, "fix": "Rotate the credentials and remove them from the repository."},
    "JWT Secret": {"weight": 9, "fix": "Generate a new signing secret and invalidate previously signed tokens if appropriate."},
    "GitHub Token": {"weight": 9, "fix": "Revoke the token immediately and create a new one with minimum required permissions."},
    "Hardcoded Password": {"weight": 9, "fix": "Remove the password, rotate it immediately, and use a secure secret manager."},
    "AWS Key": {"weight": 10, "fix": "Revoke the key immediately, generate a new one, and remove it from the repository."},
    "Private Key": {"weight": 10, "fix": "Revoke or replace the key immediately and remove it from the repository."}
}

def score_findings(category_result):
    total_weight = 0
    enriched_findings = []

    for finding in category_result["findings"]:
        matched = None
        for key, data in FINDING_LOOKUP.items():
            if key in finding:
                matched = data
                break

        weight = matched["weight"] if matched else 0
        fix = matched["fix"] if matched else "No specific remediation available."
        total_weight += weight

        enriched_findings.append({
            "text": finding,
            "severity_weight": weight,
            "fix": fix
        })

    total_weight = min(total_weight, 10)
    normalized_score = max(0, 100 - (total_weight * 10))

    return normalized_score, enriched_findings

def check_ssl(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert['notAfter']
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

    except ssl.SSLCertVerificationError:
        return {"score": 30, "findings": ["Self-signed certificate"]}
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

        breaches = data.get("breaches", [[]])[0]
        count = len(breaches)

        if count == 0:
            score = 100
            findings = ["No breaches found"]
        elif count == 1:
            score = 60
            findings = [f"Email in one breach: {breaches[0]}"]
        else:
            score = 20
            findings = [f"Email in multiple breaches ({count}): {', '.join(breaches[:3])}"]

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
    "Private Key": r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----",
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{20,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "Firebase Secret": r"(?i)firebase.{0,20}['\"][A-Za-z0-9\-_]{20,}['\"]",
    "JWT Secret": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Hardcoded Password": r"(?i)password['\"]?\s*[:=]\s*['\"][^'\"]{6,}['\"]"
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
    raw_categories = {
        "ssl": check_ssl(domain),
        "headers": check_headers(domain),
        "subdomains": check_subdomains(domain),
        "secrets": check_secrets(github_org),
        "breach": check_breach(email)
    }

    final_categories = {}
    category_scores = []

    for name, result in raw_categories.items():
        score, enriched = score_findings(result)
        final_categories[name] = {"score": score, "findings": enriched}
        category_scores.append(score)

    overall_score = int(sum(category_scores) / len(category_scores))

    return {
        "domain": domain,
        "overall_score": overall_score,
        "categories": final_categories
    }