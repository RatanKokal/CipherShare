# Evidence index

Captured on 20 October 2026 for the CS 416 Stage I report.

| File | Contents |
|---|---|
| `01-health-check.txt` | `GET /health` response. |
| `02-encryption-roundtrip.txt` | Three Node round-trip tests (text, binary, empty). |
| `03-api-upload-download.txt` | Abridged curl upload/download transcript and digest comparison. |
| `04-expiry-test.txt` | Expiry status transition (200 before, 410 after). |
| `05-tampering-test.txt` | Data/tag/truncation/nonce tamper and wrong-key rejection. |
| `06-storage-inspection.txt` | Schema/key-absence and ciphertext/plaintext inspection. |
| `07-test-suite.txt` | Current 18-test pytest and 9-test Node transcript. |
| `08-http-trace.txt` | Create/download/404/410 trace plus uvicorn access-log key check. |
| `09-binary-roundtrip.txt` | Real PDF, PNG, and 10 MiB round trips with SHA-256 checks. |

Some historical transcripts reference temporary files under `/tmp/ciphershare-*` that are no longer retained. Those artifacts are evidence of the original run, not a self-contained reproduction. Re-run the commands in the report or the test suite to reproduce the current behavior.
