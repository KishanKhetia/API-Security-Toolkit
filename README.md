# API Security Toolkit

Professional API security scanning tool written in Python. Features:

- Cloud‑ready (auto-detects AWS/Azure/GCP APIs)
- CVSS 4.0 vulnerability scoring
- Pretty console output using Rich with rounded/double box styles
- Reconnaissance and vulnerability assessment phases
- Proxy support and configurable timeouts
- JWT analysis, IDOR checks, data exposure, rate limiting, security headers
- Cloud provider specific tests (metadata SSRF, public bucket checks)
- JSON and HTML report generation

## Installation

```bash
# create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate    # or `.\.venv\Scripts\Activate.ps1` on Windows

# install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# full scan (recon + VA)
python api-security-toolkit.py -t https://api.example.com

# reconnaissance only
python api-security-toolkit.py -t https://api.example.com --mode recon

# vulnerability assessment using existing recon report
python api-security-toolkit.py -t https://api.example.com --mode va -r recon_report.json

# single endpoint scan with optional JWT
python api-security-toolkit.py -t https://api.example.com --mode va -e GET:/api/v1/users -k <token>

# Example targeting a cloud API (AWS API Gateway)
python api-security-toolkit.py -t https://xxx.execute-api.amazonaws.com/prod
```

Additional options:

```
-o, --output      Output directory for reports (default: .)
--proxy           Proxy URL (e.g. http://127.0.0.1:8080)
--timeout         Request timeout in seconds (default: 10)
```

Cloud detection is automatic; if the target URL or response headers indicate
AWS/Azure/GCP the toolkit will run extra tests against metadata services.

## Development

- Source is in `api-security-toolkit.py`.
- Tests may be added later (none included currently).

