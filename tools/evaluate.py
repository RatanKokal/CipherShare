"""CipherShare attribution threshold evaluation harness.

Uses the production algorithms (tools/fingerprint_mirror.py): codeword generation,
pixel-level embedding, slot-level collusion mixing, majority-vote extraction, and a
factorized-but-equivalent scoring routine validated against the production scorer in
the fixture gate. Writes report/evidence/13-threshold-evaluation.txt.
"""

from __future__ import annotations

import base64
import io
import json
import math
import sys
import tempfile
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from fingerprint_mirror import (  # noqa: E402
    ACCUSATION_THRESHOLD,
    CODEWORD_BITS,
    MARK_SLOTS,
    REPETITION,
    accuse,
    bias_basis,
    codeword,
    embed_into_pixels,
    extract_codeword,
    slot_sequence,
    tardos_score,
)
from trace import image_pixels  # noqa: E402

RNG = np.random.default_rng(20261028)
BIAS = np.array(bias_basis(), dtype=np.float64)
G1 = np.sqrt((1.0 - BIAS) / BIAS)
G0 = np.sqrt(BIAS / (1.0 - BIAS))
ALPHA = (G1 - G0) / 2.0
BETA = (G1 + G0) / 2.0
THRESHOLDS = [48, 64, 80, 96, 112, 128, 144, 160]
DET_THRESHOLDS = [80, 96, 112, 128]
FAR_TRIALS = 50_000
DET_TRIALS = 5_000
TRANSFORM_TRIALS = 30
IMAGE_DIM = 512
POPULATIONS = [2, 5, 20, 100, 1000]
REPORT_PATH = PROJECT_ROOT / "report" / "evidence" / "13-threshold-evaluation.txt"
VECTOR_PATH = PROJECT_ROOT / "tests" / "data" / "fingerprint-vector.json"
LINES: list[str] = []


def out(line: str = "") -> None:
    LINES.append(line)
    print(line, flush=True)


def random_codewords(shape) -> np.ndarray:
    return (RNG.random(shape + (CODEWORD_BITS,)) < BIAS).astype(np.int8)


def make_y_from_candidates(member_bits: np.ndarray, strategy: str) -> np.ndarray:
    trials, c = member_bits.shape[0], member_bits.shape[1]
    lsb = np.repeat(member_bits, REPETITION, axis=2)
    if strategy == "single-member":
        mixed = lsb[:, 0, :].copy()
    elif strategy == "random-per-slot":
        pick = RNG.integers(0, c, size=(trials, MARK_SLOTS))
        mixed = np.take_along_axis(lsb, pick[:, None, :], axis=1)[:, 0, :]
    elif strategy == "majority":
        if c == 3:
            summed = lsb.sum(axis=1)
            mixed = (summed * 2 > c).astype(np.int8)
        else:
            mixed = lsb[:, 0, :].copy()
    elif strategy == "anti-majority":
        if c == 3:
            summed = lsb.sum(axis=1)
            mixed = (summed * 2 <= c).astype(np.int8)
        else:
            pick = RNG.integers(0, c, size=(trials, MARK_SLOTS))
            mixed = np.take_along_axis(lsb, pick[:, None, :], axis=1)[:, 0, :]
    elif strategy == "erasure":
        summed_members = lsb.sum(axis=1)
        same = (summed_members == c) | (summed_members == 0)
        mixed = np.where(same, lsb[:, 0, :], RNG.integers(0, 2, size=(trials, MARK_SLOTS)))
    else:
        raise ValueError(strategy)
    summed = mixed.reshape(trials, CODEWORD_BITS, REPETITION).sum(axis=2)
    return (summed * 2 > REPETITION).astype(np.int8)


def apply_ber(bits: np.ndarray, ber: float) -> np.ndarray:
    if ber == 0.0:
        return bits
    return np.bitwise_xor(bits, (RNG.random(bits.shape) < ber).astype(np.int8))


def score_matrix(y_bits: np.ndarray, cand_bits: np.ndarray) -> np.ndarray:
    y_signed = 2.0 * y_bits.astype(np.float64) - 1.0
    c_signed = 2.0 * cand_bits.astype(np.float64) - 1.0
    return (y_signed * BETA) @ c_signed.T + (y_signed * ALPHA).sum(axis=1)[:, None]


def score_against_pertrial_candidates(y_bits, cand_bits, chunk=200):
    trials, n = cand_bits.shape[0], cand_bits.shape[1]
    scores = np.empty((trials, n), dtype=np.float64)
    for start in range(0, trials, chunk):
        stop = min(start + chunk, trials)
        ys = 2.0 * y_bits[start:stop].astype(np.float64) - 1.0
        cs = 2.0 * cand_bits[start:stop].astype(np.float64) - 1.0
        scores[start:stop] = np.einsum("ti,tji->tj", ys * BETA, cs) + (ys * ALPHA).sum(axis=1)[:, None]
    return scores


def detection_trials(trials: int, n_candidates: int, c: int, strategy: str, ber: float):
    member_bits = random_codewords((trials, c))
    y = apply_ber(make_y_from_candidates(member_bits, strategy), ber)
    innocent_bits = random_codewords((trials, n_candidates - c))
    cand = np.concatenate([member_bits, innocent_bits], axis=1)
    return score_against_pertrial_candidates(y, cand), c


def detection_metrics(scores: np.ndarray, c: int, threshold: int) -> dict:
    member = scores[:, :c]
    innocent = scores[:, c:]
    member_max = member.max(axis=1)
    innocent_max = innocent.max(axis=1)
    detected = member_max >= threshold
    miss = float((~detected).mean())
    cfar = float((innocent_max[detected] >= threshold).mean()) if detected.any() else float("nan")
    accused_innocent = (innocent_max > member_max) & (innocent_max >= threshold)
    per_member = [
        float(((member.argmax(axis=1) == m) & detected & ~accused_innocent).mean())
        for m in range(c)
    ]
    return {
        "miss": miss,
        "cfar_any": cfar,
        "fp_accusation": float(accused_innocent.mean()),
        "per_cand_exceeds": float((innocent >= threshold).mean()),
        "per_member": per_member,
    }


def far_run(n_candidates: int, trials: int, ber: float = 0.0):
    exceed = {t: 0 for t in THRESHOLDS}
    family = {t: 0 for t in THRESHOLDS}
    draws = 0
    done = 0
    chunk = max(1, 4_000_000 // (n_candidates * CODEWORD_BITS))
    while done < trials:
        size = min(chunk, trials - done)
        y = apply_ber(random_codewords((size, 1))[:, 0, :], ber)
        ys = 2.0 * y.astype(np.float64) - 1.0
        weighted = ys * BETA
        const = (ys * ALPHA).sum(axis=1)[:, None]
        trial_max = np.full(size, -1e18)
        for j0 in range(0, n_candidates, 256):
            block = random_codewords((size, min(256, n_candidates - j0)))
            cs = 2.0 * block.astype(np.float64) - 1.0
            scores = np.einsum("ti,tji->tj", weighted, cs) + const
            for t in THRESHOLDS:
                exceed[t] += int((scores >= t).sum())
            trial_max = np.maximum(trial_max, scores.max(axis=1))
        for t in THRESHOLDS:
            family[t] += int((trial_max >= t).sum())
        draws += size * n_candidates
        done += size
    return exceed, family, draws


def fixture_gate() -> bool:
    out("1. Fixture validation gate (production code, not the vectorized path)")
    ok = True
    vector = json.loads(VECTOR_PATH.read_text())
    pixels = base64.b64decode(vector["pixels_base64"])
    extracted = extract_codeword(pixels)
    match = extracted == vector["codeword"]
    ok &= match
    out(f"   JS-embedded pixel buffer extracts to the JS codeword: {match}")

    y = np.array(extracted, dtype=np.int8).reshape(1, -1)
    c_bits = np.array(codeword(vector["token"]), dtype=np.int8).reshape(1, -1)
    mirror_score = tardos_score(codeword(vector["token"]), extracted, bias_basis())
    vec_score = float(score_matrix(y, c_bits)[0, 0])
    close = math.isclose(mirror_score, vec_score, rel_tol=0, abs_tol=1e-9)
    ok &= close
    out(f"   factorized scorer == production scorer: {mirror_score:.4f} vs {vec_score:.4f} -> {close}")

    single = random_codewords((1, 1))
    y_single = make_y_from_candidates(single, "single-member")
    same = bool((y_single[0] == single[0, 0]).all())
    ok &= same
    out(f"   single-member strategy reproduces the codeword exactly: {same}")

    pair = random_codewords((1, 2))
    y_mix = make_y_from_candidates(pair, "random-per-slot")[0]
    differs = not bool((y_mix == pair[0, 0]).all()) and not bool((y_mix == pair[0, 1]).all())
    out(f"   per-slot 2-mix y differs from BOTH members' codewords (reviewer's point): {differs}")

    width = 256
    total = width * width * 3
    slots = slot_sequence(total)
    base = RNG.integers(0, 256, size=width * width * 4, dtype=np.uint8)
    base[3::4] = 255
    coal = ["eval-col-a", "eval-col-b"]
    copy_a, copy_b = bytearray(base), bytearray(base)
    embed_into_pixels(copy_a, coal[0])
    embed_into_pixels(copy_b, coal[1])
    attacked = bytearray(base)
    offs = [(s // 3) * 4 + (s % 3) for s in slots]
    for off in offs:
        src = copy_a if RNG.random() < 0.5 else copy_b
        attacked[off] = (attacked[off] & 0xFE) | (src[off] & 1)
    y_pix = extract_codeword(bytes(attacked))
    result = accuse(y_pix, [{"token": label} for label in coal + ["eval-inn-9"]])
    member_hit = result is not None and result["token"] in coal
    ok &= member_hit
    out(f"   pixel-level 2-collusion fixture traced to a coalition member: {member_hit}")
    out(f"   gate result: {'PASS' if ok else 'FAIL'}")
    return ok


def run_far_study():
    out("")
    out("2. Per-candidate false accusation rate (innocent-only trials, BER=0)")
    out("   rule of three: zero events in N draws -> 95% CI upper bound = 3/N")
    results = {}
    half = FAR_TRIALS // 2
    for n in POPULATIONS:
        ev_ex, ev_fam, ev_draws = far_run(n, FAR_TRIALS - half)
        out(f"   n={n:5d}: {ev_draws:,} innocent draws (held-out half)")
        for t in THRESHOLDS:
            rate = ev_ex[t] / ev_draws
            note = f" (0 events, 95% UB {3.0 / ev_draws:.1e})" if ev_ex[t] == 0 else ""
            out(f"     T>={t:3d}: per-candidate FAR {rate:.2e}{note} | family-wise(exceeds) {ev_fam[t] / (FAR_TRIALS - half):.2e}")
        results[n] = (ev_ex, ev_fam, ev_draws)
    out("")
    out("   BER-invariance side-check (n=20, 10k trials per condition):")
    for ber in [0.0, 0.05]:
        ex, _, draws = far_run(20, 10_000, ber=ber)
        out(f"     BER={ber:.2f}: per-candidate FAR at T>=96 = {ex[96] / draws:.2e}")
    return results


def run_detection_study():
    out("")
    out("3. Detection study (slot-level attacks; y built per-slot, then majority-voted)")
    out("   miss = P(no member >= T) | cfar = P(any innocent exceeds | detected) |")
    out("   fp-acc = P(tracer accuses an innocent)")
    bers = [0.0, 0.005, 0.01, 0.02, 0.05, 0.10]
    strategies = {
        1: ["single-member"],
        2: ["random-per-slot", "single-member", "erasure"],
        3: ["random-per-slot", "single-member", "majority", "anti-majority", "erasure"],
    }
    summary = {}
    n = 20
    out(f"   candidate population n={n}; {DET_TRIALS} held-out trials per cell")
    for c in [1, 2, 3]:
        for strategy in strategies[c]:
            for ber in bers:
                scores, _ = detection_trials(DET_TRIALS, n, c, strategy, ber)
                summary[(c, strategy, ber)] = {t: detection_metrics(scores, c, t) for t in DET_THRESHOLDS}
    for c in [1, 2, 3]:
        for strategy in strategies[c]:
            out(f"   c={c} strategy={strategy}")
            out("     BER    " + "".join(f"| T={t} miss / cfar / fp-acc " for t in DET_THRESHOLDS))
            for ber in bers:
                row = summary[(c, strategy, ber)]
                cells = "".join(
                    f"| {row[t]['miss']:.3f} / {row[t]['cfar_any']:.1e} / {row[t]['fp_accusation']:.1e} "
                    for t in DET_THRESHOLDS
                )
                out(f"     {ber:.3f}  " + cells)
    out("")
    out("   per-member attribution at T=96, BER=0 (share of all trials accusing each member):")
    for c in [2, 3]:
        for strategy in ["random-per-slot", "erasure"]:
            metrics = summary[(c, strategy, 0.0)][96]
            shares = ", ".join(f"m{i + 1}={v:.3f}" for i, v in enumerate(metrics["per_member"]))
            out(f"     c={c} {strategy}: {shares}")
    return summary


def run_transform_survival():
    out("")
    out("4. Real-image transform survival (separate axis from synthetic BER)")
    out("   production embed into 512x512 RGBA PNG, transform, production extract+accuse")
    from PIL import Image, ImageDraw

    width = IMAGE_DIM
    results = {}

    def jpeg_q(q):
        def f(data):
            buf = io.BytesIO()
            Image.open(io.BytesIO(data)).convert("RGB").save(buf, format="JPEG", quality=q)
            return buf.getvalue()
        return f

    def resize(f):
        def g(data):
            img = Image.open(io.BytesIO(data))
            buf = io.BytesIO()
            img.resize((int(width * f), int(width * f)), Image.LANCZOS).save(buf, format="PNG")
            return buf.getvalue()
        return g

    def crop(f):
        def g(data):
            img = Image.open(io.BytesIO(data))
            w, h = img.size
            buf = io.BytesIO()
            img.crop((int(w * f), int(h * f), int(w * (1 - f)), int(h * (1 - f)))).save(buf, format="PNG")
            return buf.getvalue()
        return g

    transforms = {
        "re-save PNG (lossless)": lambda d: d,
        "JPEG re-encode q=90": jpeg_q(90),
        "JPEG re-encode q=75": jpeg_q(75),
        "JPEG re-encode q=50": jpeg_q(50),
        "resize 0.9x LANCZOS": resize(0.9),
        "resize 0.5x LANCZOS": resize(0.5),
        "crop 10% borders": crop(0.10),
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir) / "leak.png"
        for name, transform in transforms.items():
            hits = 0
            for trial in range(TRANSFORM_TRIALS):
                img = Image.new("RGB", (width, width))
                draw = ImageDraw.Draw(img)
                for x in range(0, width, 8):
                    draw.line([(x, 0), (x, width)], fill=(x % 256, (x * 3) % 256, (x * 7) % 256))
                buf = bytearray(img.convert("RGBA").tobytes("raw", "RGBA"))
                label = f"transform-leak-{trial}"
                embed_into_pixels(buf, label)
                out_buf = io.BytesIO()
                Image.frombytes("RGBA", (width, width), bytes(buf)).save(out_buf, format="PNG")
                tmp.write_bytes(transform(out_buf.getvalue()))
                pixels = image_pixels(tmp)
                if pixels is None:
                    continue
                raw, _, _ = pixels
                extracted = extract_codeword(raw)
                if extracted is None:
                    continue
                candidates = [
                    {"token": label},
                    {"token": f"inn-{trial}-a"},
                    {"token": f"inn-{trial}-b"},
                ]
                result = accuse(extracted, candidates)
                if result is not None and result["token"] == label:
                    hits += 1
            results[name] = hits
            out(f"   {name:26s}: {hits}/{TRANSFORM_TRIALS} still accused as the leaker")
    return results


def calibration_and_verdict(far_results):
    out("")
    out("5. Threshold calibration (calibration half only) and held-out verdict")
    cal_n = 20
    half = FAR_TRIALS // 2
    cal_ex, _, cal_draws = far_run(cal_n, half)
    chosen = next((t for t in THRESHOLDS if cal_ex[t] / cal_draws <= 1e-4), None)
    out(f"   calibration rule: smallest threshold with per-candidate FAR <= 1e-4 at n={cal_n}")
    out(f"   calibrated threshold T* = {chosen}")
    ev_ex, ev_fam, ev_draws = far_results[cal_n]
    out(f"   held-out per-candidate FAR at T*: {ev_ex[chosen] / ev_draws:.2e}"
        if chosen else "   T* above grid; no threshold on the grid meets the calibration rule")
    out(f"   held-out per-candidate FAR at legacy 96: {ev_ex[96] / ev_draws:.2e}")
    out("")
    out("6. Statistical power statement")
    out(f"   zero-event resolution floor at n={cal_n}: FAR >= {3.0 / ev_draws:.1e} (rule of three)")
    out(f"   draws at n=20: {ev_draws:,}; draws at n=1000: {far_results[1000][2]:,}")
    out("   a per-candidate 1e-6 claim needs >= 3e6 independent innocent draws")
    big_draws = far_results[1000][2]
    big_ex = far_results[1000][0]
    if 3.0 / big_draws <= 1e-6:
        t96 = big_ex[96] / big_draws
        out(f"   n=1000 run resolves 1e-6: measured per-candidate FAR at T>=96 = {t96:.2e}"
            f" -> claim {'SUPPORTED' if t96 <= 1e-6 else 'NOT SUPPORTED'} at that population")
    else:
        out("   verdict: INSUFFICIENT STATISTICAL POWER to substantiate 1e-6 in this run")
    out("")
    out(f"   production threshold constant: {ACCUSATION_THRESHOLD} (any change is a separate commit)")


def provenance() -> None:
    import subprocess

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        ).stdout.strip()
    except Exception:
        commit = "unknown"
    out("CipherShare attribution threshold evaluation")
    out(f"captured: 28 October 2026 | code revision: {commit}")
    out("command: python tools/evaluate.py  (writes this file)")
    out("randomness: numpy default_rng master seed 20261028 (single stream, "
        "deterministic given the code revision); xorshift32 seeds are fixed "
        "constants in fingerprint_mirror.py (positions 0x43533153, biases "
        "0x54415244)")
    out(f"parameters: codeword bits={CODEWORD_BITS}, repetition={REPETITION}, "
        f"slots={MARK_SLOTS}, thresholds={THRESHOLDS}")
    out(f"budgets: FAR_TRIALS={FAR_TRIALS}, DET_TRIALS={DET_TRIALS}, "
        f"TRANSFORM_TRIALS={TRANSFORM_TRIALS}, image dim={IMAGE_DIM}")


def main() -> int:
    provenance()
    out("")
    if not fixture_gate():
        out("GATE FAILED - refusing to evaluate")
        return 1
    far_results = run_far_study()
    run_detection_study()
    run_transform_survival()
    calibration_and_verdict(far_results)
    REPORT_PATH.write_text("\n".join(LINES) + "\n")
    out("")
    out(f"written: {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
