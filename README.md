# CipherShare

End-to-end encrypted, leak-traceable file sharing with expiring capability links.
A CS 416 course prototype: the browser encrypts, the server stores only ciphertext,
links expire, and leaked copies can be attributed to the link they came from.

## What it does

- **Private.** AES-256-GCM encryption in the browser with a fresh key and nonce per
  file. The server stores ciphertext plus minimal metadata and never sees a key.
- **Protected.** Optional password split: the file key is XOR-split into a link half
  (URL fragment) and a password half (PBKDF2-HMAC-SHA-256, 600,000 iterations, per
  share salt). A leaked password-protected link alone decrypts nothing.
- **Accountable.** Personalized links carry registered 128-bit tokens; the
  recipient's browser invisibly fingerprints the downloaded copy (image LSB or an
  appended trailer), and `tools/trace.py` attributes a leaked copy to the
  registered link.
- **Expiring.** Server-enforced expiry (1 s to 24 h) and revocation on every
  download: 404 unknown, 410 expired or revoked.

See `ARCHITECTURE.md` for the full design and threat model and `TRACING.md` for
how the fingerprinting works. The course report is submitted separately on Moodle.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload            # http://127.0.0.1:8000
```

Open the URL, pick a file, optionally set a password and recipient names, and
share the generated links. Recipients open a link in any browser, enter the
password if there is one, and download a fingerprinted copy.

## Tests

```bash
python -m pytest tests/ -q          # 53 passed (API, storage, tracer, evaluation)
node --test tests/*.test.mjs        # 23 passed (crypto, marking; Node >= 19)
```

## Tracing a leak

```bash
python tools/trace.py <leaked-file> [--data-dir data] [--legacy] [--share-id <id>]
```

Works on images (LSB fingerprint) and other files (appended `%%CS2:<token>%%`
trailer). Reports the registered recipient link above a calibrated score
threshold, or "no recipient above the accusation threshold".

## Evaluation

```bash
python tools/evaluate.py            # writes report/evidence/13-threshold-evaluation.txt
python tools/benchmark.py           # writes report/evidence/14-performance.txt
```

## Repository layout

```
app.py, storage.py        FastAPI backend and ShareStore (SQLite + ciphertext files)
static/                   index.html, app.js, crypto.js, marking.js, style.css
tools/                    trace.py, fingerprint_mirror.py, evaluate.py, benchmark.py
tests/                    pytest + Node suites, cross-language fingerprint vector
data/                     runtime state (gitignored)
report/evidence/          recorded evidence 01-21 (supporting the report claims)
```

## Status

Coursework prototype, not production-hardened. Client-side marking is deterrence,
not enforcement; the tracing scheme is Tardos-inspired with empirically measured
reliability. The full security boundary and limitations are documented in
`ARCHITECTURE.md` (section 13) and the report (section 6).
