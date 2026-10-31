# Leak Tracing, Explained

*How CipherShare traces a leaked file back to the person who leaked it — the method, the
math, and the reasoning behind every design choice.*

---

## 1. What is this technique called?

Three classic ideas, stacked:

| Layer | Name | Origin |
|---|---|---|
| Hiding bits in pixels | **LSB steganography** | old technique; flip the lowest bit of a color value, image looks identical |
| Different serial number per copy | **Fingerprinting / traitor tracing** | used by banks and the DVD industry against leakers/pirates |
| Surviving collusion | **Tardos codes** | Gábor Tardos, 2003 — collusion-resistant fingerprinting codes |

In industry the whole combo is called **forensic watermarking**; in academia,
**collusion-resistant fingerprinting codes**.

## 2. The problem it solves

End-to-end encryption ends at decryption. Once a recipient has the plaintext, no cipher
stops them from copying and leaking it. Expiry only cuts off *future* downloads. So we
add **accountability**: every copy that leaves the system silently says who downloaded it.

Key design rule: the embedding happens **in the recipient's browser, after decryption**.
The server never touches plaintext, so the E2E guarantee is preserved. (A server-side
watermark would require plaintext on the server and defeat the entire project.)

## 3. End-to-end flow

```
Sender                creates share, registers recipients (Ashwin, Priya, ...)
                      the server issues each recipient a registered 128-bit token;
                      each recipient gets a distinct link:
                        /s/<share_id>#<key-half>:<token>

Recipient (Priya)     browser decrypts the file, THEN embeds a codeword derived
                      from her token (HMAC-SHA-256 keyed by the full token bytes)
                      before saving the download

Leak                  Priya's copy ends up somewhere it shouldn't

Tracer                python tools/trace.py leaked.png
                      reads the hidden bits, scores them against every registered
                      recipient, prints:  accused: Priya (score 489.3, threshold 96)
```

## 4. What exactly gets embedded

Not the name, not the raw identity — a **512-bit codeword** derived from the
recipient's registered token. HMAC-SHA-256 keyed by the token expands the 128-bit
token into 512 uniform values; bit `i` is `1` iff value `i` falls below a fixed
bias `p_i` drawn from `[0.25, 0.75)`. Because the process is deterministic, anyone
holding the token (browser or tracer) can regenerate the codeword — no codebook
storage needed. The token travels only in the URL fragment; the server never
receives it back. The original label-based scheme is retained only as a legacy
path for pre-token evidence.

Each bit is written **3 times** (repetition code) into **1536 unique pixel positions**
chosen by a fixed-seed PRNG from the image's pixels. Only the **least significant
bit** of the red/green/blue byte is touched — invisible to the eye. Positions are
deduplicated (duplicates would corrupt the round trip).

Non-image files get a simpler fallback: an appended `%%CS2:<token>%%` trailer. It works
and is trivially traceable, but it is inspectable in a hex editor — documented weakness,
robust PDF/XMP encoding is future work.

## 5. What the tracer does

Given a leaked image:

1. **Locate** the 1536 positions (same PRNG, same image dimensions → same positions).
2. **Extract** the 1536 LSBs; for each group of 3, take the **majority vote** → a
   512-bit string `y` (the noisy whisper of someone's codeword).
3. **Score every registered recipient.** For candidate codeword `c`:

```
score(c) = sum over the 512 positions of:

  y_i = 1, c_i = 1  →  + sqrt((1 - p_i) / p_i)
  y_i = 0, c_i = 0  →  + sqrt(p_i / (1 - p_i))
  y_i = 1, c_i = 0  →  - sqrt(p_i / (1 - p_i))
  y_i = 0, c_i = 1  →  - sqrt((1 - p_i) / p_i)
```

   Agreement adds a positive term, disagreement a negative one — and the **magnitude
   depends on the bias**: agreeing on a rare bit is stronger evidence than agreeing on a
   50/50 bit.
4. **Decide:** the highest scorer wins, but only if it clears the **threshold (96)**.

## 6. The numbers, concretely

| Who | Score | Why |
|---|---|---|
| The real leaker | **≈ 489** | their codeword agrees with `y` almost everywhere → nearly all 512 terms positive |
| An innocent recipient | **≈ 0 ± 23** | agrees by pure luck on ~half the positions; positives and negatives cancel — a random walk around zero |
| Threshold | **96** | ≈ 4σ above innocent noise, but ~5× below a genuine match |

One-line intuition: *luck nets zero; truth nets 489; the threshold separates them.*

## 7. Why not an exact hash mapping?

A natural alternative: embed `hash(token)`, extract the bits, look the hash up in a
table. It fails because **the extracted bits are never clean** — an exact mapping is
all-or-nothing, and one flipped bit kills the trace. The bits flip for two very
different reasons:

| Noise type | Example | Handled by |
|---|---|---|
| Random / accidental | re-save, single pixel edits, screenshot edge | **repetition code** (3× + majority vote) |
| Adversarial / strategic | two colluders mixing their copies | **Tardos scoring** (fuzzy, weighted nearest-codeword) |

After a 2-person coalition mixes copies, the extracted string disagrees with *each*
colluder's true codeword in ~25% of positions (~128 of 512 bits). No exact lookup
survives that — you must ask which registered codeword the noisy string is most
consistent with. Weighted scoring (not plain Hamming distance) also resists casual
framing: an unweighted nearest-match can be pulled toward an innocent third person.

Our scheme is **Tardos-inspired**: it uses the same probabilistic idea, but its
construction and empirical evaluation do not establish the guarantees of the
classical Tardos scheme. What we can say from measurement is that innocents scored
near zero and the guilty member scored far above threshold in all tested scenarios.

## 8. Attack menu (what works, what doesn't)

| Attack | Result |
|---|---|
| Re-save the PNG in an editor | trace **survives** (PNG is lossless, LSBs preserved) |
| Re-encode as JPEG | trace **fails** — lossy compression scrambles LSBs (documented limitation) |
| Randomly scramble ~1000 pixels | extracted string becomes noise → all scores near 0 → "no recipient above the accusation threshold" |
| Crop / resize | position selection depends on dimensions → mark lost (documented) |
| **Collusion**: 2 recipients diff and mix their copies | Tardos decoder still accuses **one of the two**; innocents stay below threshold |
| **Casual framing** (`?r=` substitution) | **removed** for new-format links: the marking identity is a registered, share-bound token in the fragment, never a caller-supplied label |
| **Framing with stolen token or patched client** | a recipient who obtains another recipient's full link or patches the JavaScript can still frame or suppress marks — a token attests which link produced a mark, assuming the intended code path; it is not server attestation |

## 9. Where the code lives

| File | Role |
|---|---|
| `static/marking.js` | browser-side: HMAC codeword generation, LSB embedding, extraction, scoring (also used by Node tests) |
| `static/app.js` | wires embedding into the recipient download flow |
| `tools/fingerprint_mirror.py` | Python mirror of marking.js (extract/score/embed) — byte-compatible |
| `tools/trace.py` | CLI: `python tools/trace.py <leaked-file> [--data-dir data]` |
| `tests/fingerprint.test.mjs` | Node tests: round trip, accusation, coalition, trailer |
| `tests/test_tracer.py` | pytest incl. **cross-language check** — the JS implementation writes a vector file, Python must reproduce it exactly |
| `report/evidence/11-fingerprint-trace.txt` | captured trace demo |
| `report/evidence/12-collusion-test.txt` | captured coalition result |

## 10. Honest limitations

> **Client-side marking is deterrence, not enforcement.** A recipient who downloads
> without a valid marking identity — or who patches the JavaScript — obtains content
> untraceable **by this fingerprinting mechanism**; other evidence (access logs,
> distribution channel, testimony) may still apply.

- Parameters are tuned for coalitions of 2–3; large coalitions can defeat the mark.
- The collusion guarantee is asserted by our tests, not proven for arbitrary coalitions.
- Lossy re-encoding, cropping, and screenshots-of-screenshots destroy the mark.
- Tracing is **deterrence and attribution, not prevention** — it does not stop copying.
- Framing via a stolen full link or a patched client remains (the mark is not
  server-attested).
- The tracer needs the leaked copy's pixel dimensions to be unchanged from the download.

## 11. Reproduce it yourself

```bash
node --test tests/fingerprint.test.mjs          # writes the cross-language vector
python -m pytest tests/test_tracer.py -q        # incl. real PNG trace via tracer CLI
```

Live demo: share an image to two recipients, download both copies, leak one, run the
tracer, then try the attacks in section 8 and watch the score move.
