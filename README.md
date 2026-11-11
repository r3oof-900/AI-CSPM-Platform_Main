# AI-CSPM

Cross-layer cloud security posture scanner. It builds a graph across
Kubernetes workload -> ServiceAccount -> IAM role -> IAM policy -> KMS key -> S3 bucket
and finds attack paths that single-layer scanners miss, then proposes least-privilege
Terraform fixes (deterministic offline engine, or Google Gemini).

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # then put your Gemini key in .env (optional)
python -m pytest -q tests
```

## Usage
```bash
python ai_cspm.py --target samples/vulnerable_baseline --offline
python ai_cspm.py --target samples/vulnerable_baseline --html report.html --graph graph.html
python ai_cspm.py --live-demo --offline
python ai_cspm.py --live --aws-profile prod --fail-on high
```

## Configuration
| Variable | Purpose | Default |
|---|---|---|
| `GEMINI_API_KEY` | Enables live LLM remediation | unset = offline engine |
| `GEMINI_MODEL` | Gemini model name | `gemini-flash-lite-latest` |
| `GEMINI_TIMEOUT` | HTTP timeout (seconds) | `25` |

Real environment variables take precedence over `.env`. `.env` is read only from the
current directory or the project root.

## Security notes
- **Never commit `.env`.** It is git-ignored; CI and pre-commit run gitleaks.
- With a Gemini key set, IaC snippets (resource names, ARNs) are sent to Google.
  Use `--offline` to guarantee nothing leaves your machine.
- Review any `--apply-fix` patch before applying it.
