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
# Live LLM remediation requires explicit consent and API key:
python ai_cspm.py --target samples/vulnerable_baseline --allow-external-llm
```

## Configuration
| Variable | Purpose | Default |
|---|---|---|
| `GEMINI_API_KEY` | API key for optional live LLM remediation | unset = offline engine |
| `GEMINI_MODEL` | Gemini model name | `gemini-flash-lite-latest` |
| `GEMINI_TIMEOUT` | HTTP timeout (seconds) | `25` |

Real environment variables take precedence over `.env`. `.env` is read only from the
current directory or the project root.

## Security & Privacy Notes
- **Never commit `.env`.** It is git-ignored; CI and pre-commit run gitleaks.
- **External LLM Consent (`--allow-external-llm`):** By default, AI-CSPM runs in 100% deterministic local offline mode. Sending prompts to Google Gemini requires **both** `GEMINI_API_KEY` and the explicit `--allow-external-llm` CLI flag.
- **Strict Privacy & Targeted Masking:** When external LLM is enabled, AI-CSPM extracts *only* the specific affected resource block (file contents and unrelated resources are withheld). All sensitive tokens, passwords, database connection strings, access keys (`AKIA...`), GitHub PATs, and private keys are scrubbed and replaced with `[REDACTED_BY_AI_CSPM]` before transmission.
- Review any `--apply-fix` patch before applying it.
