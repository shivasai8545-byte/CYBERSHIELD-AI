from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_WORDS = {
    "verify", "login", "signin", "account", "update", "secure", "bank",
    "password", "wallet", "payment", "urgent", "claim", "prize", "free"
}

def inspect_url(url):
    candidate = url.strip().rstrip(".,);!?")
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 0

    if not host:
        return {"score": 0, "risk": "Unknown", "reasons": ["Could not identify a valid domain."]}

    if parsed.scheme != "https":
        score += 15
        reasons.append("The link does not use HTTPS.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 25
        reasons.append("The domain uses an internationalized/punycode label.")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 25
        reasons.append("The link uses an IP address instead of a domain name.")

    if host in URL_SHORTENERS:
        score += 20
        reasons.append("The link uses a URL-shortening service.")

    if len(candidate) > 100:
        score += 10
        reasons.append("The URL is unusually long.")

    if host.count("-") >= 2:
        score += 10
        reasons.append("The domain contains several hyphens.")

    if "@" in candidate:
        score += 20
        reasons.append("The URL contains an @ symbol, which can hide the real destination.")

    matched = [word for word in SUSPICIOUS_WORDS if word in candidate.lower()]
    if matched:
        score += min(20, 5 * len(matched))
        reasons.append("It contains suspicious terms: " + ", ".join(sorted(matched)) + ".")

    score = min(score, 100)
    risk = "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    if not reasons:
        reasons.append("No obvious warning signs were detected by these basic checks.")
    return {"score": score, "risk": risk, "reasons": reasons, "host": host}

def extract_urls(text):
    return URL_RE.findall(text or "")

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    submitted_text = ""
    if request.method == "POST":
        submitted_text = request.form.get("message", "").strip()
        urls = extract_urls(submitted_text)
        if urls:
            checks = [inspect_url(url) for url in urls]
            result = {"items": checks, "count": len(checks)}
        else:
            result = {
                "items": [{
                    "score": 0,
                    "risk": "Unknown",
                    "reasons": ["No URL was found. Paste a message containing a link to scan."]
                }],
                "count": 0
            }
    return render_template("index.html", result=result, submitted_text=submitted_text)

@app.route("/health")
def health():
    return {"status": "ok", "app": "CyberShield AI"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
