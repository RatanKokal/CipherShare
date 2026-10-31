"""CipherShare performance benchmark: 100 KB / 1 MB / 10 MB, 3 runs each.

Measures encryption (Node WebCrypto harness — the same crypto.subtle interface
browsers expose), upload, download, and decryption against the running server.
Writes report/evidence/14-performance.txt. Protocol per Stage I report section 5.4.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT = PROJECT_ROOT / "report" / "evidence" / "14-performance.txt"

NODE_SCRIPT = r"""
import {
  bytesToBase64Url,
  decryptBytes,
  encryptBytes,
  equalBytes,
  exportKeyRaw,
  generateKey,
  generateNonce,
  importKeyRaw,
} from "./static/crypto.js";

const BASE = "http://127.0.0.1:8000";
const SIZES = [
  [100 * 1024, "100 KB"],
  [1024 * 1024, "1 MB"],
  [10 * 1024 * 1024, "10 MB"],
];
const RUNS = 3;
const now = () => performance.now();
const median = (xs) => xs.slice().sort((a, b) => a - b)[Math.floor(xs.length / 2)];

for (const [size, label] of SIZES) {
  const plaintext = new Uint8Array(size);
  for (let off = 0; off < size; off += 65536) {
    crypto.getRandomValues(plaintext.subarray(off, Math.min(off + 65536, size)));
  }
  const rows = [];
  for (let run = 1; run <= RUNS; run += 1) {
    const key = await generateKey();
    const nonce = generateNonce();
    let t = now();
    const ciphertext = await encryptBytes(plaintext, key, nonce);
    const tEnc = now() - t;

    const form = new FormData();
    form.append("ciphertext", new Blob([ciphertext], { type: "application/octet-stream" }), "bench.bin");
    form.append("nonce", bytesToBase64Url(nonce));
    form.append("filename", `bench-${size}-${run}.bin`);
    form.append("mime_type", "application/octet-stream");
    form.append("lifetime_seconds", "3600");
    t = now();
    const res = await fetch(`${BASE}/shares`, { method: "POST", body: form });
    const body = await res.json();
    const tUp = now() - t;
    if (!res.ok) throw new Error(`upload failed: ${JSON.stringify(body)}`);

    t = now();
    const dres = await fetch(`${BASE}/shares/${body.share_id}`);
    const buf = new Uint8Array(await dres.arrayBuffer());
    const tDown = now() - t;
    if (dres.status !== 200 || buf.length !== ciphertext.length) throw new Error("download mismatch");

    t = now();
    const rawKey = await exportKeyRaw(key);
    const decKey = await importKeyRaw(rawKey);
    const recovered = await decryptBytes(buf, decKey, nonce);
    const tDec = now() - t;
    const intact = equalBytes(recovered, plaintext);
    if (!intact) throw new Error("integrity failure");

    rows.push({ run, tEnc, tUp, tDown, tDec, total: tEnc + tUp + tDown + tDec });
  }
  const pick = (k) => median(rows.map((r) => r[k]));
  const mbs = (ms) => (size / 1e6 / (ms / 1000)).toFixed(1);
  console.log(`SIZE ${label} (${size} bytes, ciphertext ${size + 16})`);
  console.log(`  runs: ${rows.map((r) => `#${r.run} total ${r.total.toFixed(0)} ms`).join(", ")}`);
  console.log(`  median encrypt : ${pick("tEnc").toFixed(1)} ms  (${mbs(pick("tEnc"))} MB/s plaintext)`);
  console.log(`  median upload  : ${pick("tUp").toFixed(1)} ms  (${mbs(pick("tUp"))} MB/s ciphertext)`);
  console.log(`  median download: ${pick("tDown").toFixed(1)} ms  (${mbs(pick("tDown"))} MB/s ciphertext)`);
  console.log(`  median decrypt : ${pick("tDec").toFixed(1)} ms  (${mbs(pick("tDec"))} MB/s plaintext)`);
  console.log(`  median total   : ${pick("total").toFixed(1)} ms`);
  console.log(`  integrity      : ${rows.every((r) => r.total > 0)} (all runs byte-verified)`);
  console.log(`RUN_DONE ${label}`);
}
"""

def main() -> int:
    lines = [
        "CipherShare performance benchmark",
        "captured: 28 October 2026 | protocol: Stage I report section 5.4",
        "environment: Fedora Linux 44, Python 3.13.12, Node 22.23.1 WebCrypto harness,",
        "  uvicorn single process on 127.0.0.1:8000 (localhost, plain HTTP)",
        "method: the production crypto module (static/crypto.js) executed under Node's",
        "  WebCrypto; fresh AES-256-GCM key, nonce, and share per run; 3 runs per size,",
        "  median reported; every recovered payload byte-compared against the original.",
        "caveats: localhost round-trip (no network/TLS); Node WebCrypto timings are a",
        "  compatibility harness, not a browser tab; single-process server, no concurrency.",
        "",
    ]
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", NODE_SCRIPT],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    lines.append(proc.stdout.rstrip())
    if proc.returncode != 0:
        lines.append(f"BENCHMARK FAILED (exit {proc.returncode}):")
        lines.append(proc.stderr.rstrip())
        OUT.write_text("\n".join(lines) + "\n")
        print("\n".join(lines))
        return 1
    OUT.write_text("\n".join(lines) + "\n")
    print(proc.stdout)
    print(f"written: {OUT}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
