# CyberShield AI

A beginner-friendly Flask prototype that scans URLs found in suspicious messages and highlights common phishing warning signs.

## Features
- Paste an SMS, email, or URL into the scanner.
- Extracts links from text.
- Checks for common indicators such as non-HTTPS links, IP-address hosts, URL shorteners, suspicious keywords, and unusual URL patterns.
- Shows a simple risk score and findings.
- Includes a `/health` endpoint.

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux/Termux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Important limitation
This project uses simple heuristic checks. It is an educational prototype, not a production-grade AI detector, antivirus, or guarantee of website safety. A low score does not prove a URL is safe. Never submit real passwords, API keys, or private messages.

## GitHub upload
Upload the project files and folders, but never upload `.env` files, passwords, API keys, or personal data.
