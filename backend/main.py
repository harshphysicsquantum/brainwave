from fastapi import FastAPI

app = FastAPI()

@app.get("/scan")
def scan(domain: str):
    # fake data for now — real scanning logic comes later
    return {
        "domain": domain,
        "overall_score": 62,
        "categories": {
            "ssl": {
                "score": 80,
                "findings": ["Certificate expires in 12 days"]
            },
            "headers": {
                "score": 40,
                "findings": ["Missing Content-Security-Policy", "Missing X-Frame-Options"]
            },
            "subdomains": {
                "score": 70,
                "findings": ["dev.example.com exposed"]
            },
            "secrets": {
                "score": 30,
                "findings": ["Possible AWS key found in repo: config.py"]
            },
            "breach": {
                "score": 90,
                "findings": []
            }
        }
    }