from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from fingerprint_mirror import (  # noqa: E402
    TOKEN_PATTERN,
    accuse,
    bias_basis,
    codeword,
    embed_into_pixels,
    extract_codeword,
    legacy_codeword,
    legacy_embed_into_pixels,
    parse_legacy_trailer,
    parse_trailer,
    slot_sequence,
    tardos_score,
    xorshift32,
)
from storage import ShareStore  # noqa: E402

VECTOR_PATH = PROJECT_ROOT / "tests" / "data" / "fingerprint-vector.json"
RECIPIENTS = ["Ashwin", "Priya", "Rohan"]


def make_pixels(width: int, height: int) -> bytearray:
    random = xorshift32(0xC1D3)
    pixels = bytearray(width * height * 4)
    for index in range(len(pixels)):
        pixels[index] = 255 if index % 4 == 3 else int(next(random) * 256) % 256
    return pixels


@pytest.fixture(scope="module")
def vector() -> dict:
    if not VECTOR_PATH.is_file():
        pytest.fail(
            "fingerprint-vector.json is missing; run "
            "`node --test tests/fingerprint.test.mjs` first to generate it"
        )
    return json.loads(VECTOR_PATH.read_text())


def test_python_matches_javascript_bias_and_codeword(vector):
    bias = bias_basis()
    assert bias == vector["bias"]
    assert codeword(vector["token"]) == vector["codeword"]


def test_python_matches_javascript_slot_sequence(vector):
    assert slot_sequence(vector["total"]) == vector["slots"]


def test_python_extracts_javascript_embedded_mark(vector):
    pixels = base64.b64decode(vector["pixels_base64"])
    extracted = extract_codeword(bytes(pixels))
    assert extracted == vector["codeword"]


def test_python_accuses_javascript_embedded_mark(vector):
    pixels = base64.b64decode(vector["pixels_base64"])
    extracted = extract_codeword(bytes(pixels))
    candidates = [
        {"token": vector["token"], "share_id": "s1", "display_name": "Vector User"},
        {"token": "W3CJbdNXIJYcj0JkTHPiVA", "share_id": "s1", "display_name": "Inno One"},
        {"token": "dK5MP3sGym27qrgwzq1DHw", "share_id": "s1", "display_name": "Inno Two"},
    ]
    accused = accuse(extracted, candidates)
    assert accused is not None
    assert accused["token"] == vector["token"]


def test_embed_extract_round_trip_in_python():
    pixels = make_pixels(256, 256)
    assert embed_into_pixels(pixels, "EKm9T9XGPqFQ2IA3VZMnJQ")
    extracted = extract_codeword(bytes(pixels))
    assert extracted == codeword("EKm9T9XGPqFQ2IA3VZMnJQ")


def test_distinct_tokens_do_not_collapse_to_identical_codewords():
    first = codeword("aaaa1aaaa2aaaa3aaaa4a")
    second = codeword("aaaa1aaaa2aaaa3aaaa4b")
    differences = sum(1 for a, b in zip(first, second) if a != b)
    assert differences > 100
    assert first != second


def test_trailer_round_trip_and_cs2_cs1_separation():
    payload = os.urandom(2048)
    token = "Gu4Qx4OLpa4ORp9V8b6erQ"
    marked = payload + f"%%CS2:{token}%%".encode()
    assert parse_trailer(marked) == token
    assert parse_legacy_trailer(marked) is None
    legacy = os.urandom(512) + b"%%CS1:legacyLbl%%"
    assert parse_trailer(legacy) is None
    assert parse_legacy_trailer(legacy) == "legacyLbl"
    assert parse_trailer(payload) is None


@pytest.fixture()
def demo_env(tmp_path):
    store = ShareStore(tmp_path)
    record = store.create_share(
        ciphertext=os.urandom(128),
        nonce_b64="AAAAAAAAAAAAAAAAAAAAAA",
        filename="poster.png",
        mime_type="image/png",
        lifetime_seconds=600,
    )
    created = store.add_recipients(record["share_id"], RECIPIENTS)
    labels = {item["name"]: item for item in created}
    assert all(TOKEN_PATTERN.fullmatch(item["token"]) for item in created)
    assert len({item["token"] for item in created}) == len(created)
    return store, record, labels


def run_tracer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "tools" / "trace.py"), *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )


def test_tracer_identifies_leaker_from_real_png(demo_env, tmp_path):
    store, record, labels = demo_env
    width, height = 256, 256
    pixels = make_pixels(width, height)
    assert embed_into_pixels(pixels, labels["Priya"]["token"])

    from PIL import Image

    image_path = tmp_path / "leaked.png"
    Image.frombytes("RGBA", (width, height), bytes(pixels)).save(image_path, format="PNG")

    result = run_tracer(str(image_path), "--data-dir", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Priya" in result.stdout
    assert record["share_id"] in result.stdout
    assert "token-registered" in result.stdout


def test_tracer_identifies_leaker_from_cs2_trailer(demo_env, tmp_path):
    store, record, labels = demo_env
    leaked = tmp_path / "leaked.bin"
    leaked.write_bytes(os.urandom(512) + f"%%CS2:{labels['Ashwin']['token']}%%".encode())
    result = run_tracer(str(leaked), "--data-dir", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Ashwin" in result.stdout


def test_unregistered_token_is_rejected(demo_env, tmp_path):
    store, record, labels = demo_env
    pixels = make_pixels(256, 256)
    assert embed_into_pixels(pixels, "ebrtn_PY1fV6RBg7VFS-dw")
    from PIL import Image

    image_path = tmp_path / "unregistered.png"
    Image.frombytes("RGBA", (256, 256), bytes(pixels)).save(image_path, format="PNG")
    result = run_tracer(str(image_path), "--data-dir", str(tmp_path))
    assert result.returncode == 1
    assert "no recipient above the accusation threshold" in result.stdout

    trailer = tmp_path / "unregistered.bin"
    trailer.write_bytes(os.urandom(256) + b"%%CS2:MLvHkBaYVmVDonCBgf9qHg%%")
    result = run_tracer(str(trailer), "--data-dir", str(tmp_path))
    assert result.returncode == 1
    assert "not a registered recipient" in result.stdout


def test_token_is_share_bound(demo_env, tmp_path):
    store, record, labels = demo_env
    other = store.create_share(
        ciphertext=os.urandom(64),
        nonce_b64="AAAAAAAAAAAAAAAAAAAAAA",
        filename="other.png",
        mime_type="image/png",
        lifetime_seconds=600,
    )
    other_recipients = store.add_recipients(other["share_id"], ["SomeoneElse"])

    width, height = 256, 256
    pixels = make_pixels(width, height)
    assert embed_into_pixels(pixels, labels["Priya"]["token"])
    from PIL import Image

    image_path = tmp_path / "cross_share.png"
    Image.frombytes("RGBA", (width, height), bytes(pixels)).save(image_path, format="PNG")
    result = run_tracer(str(image_path), "--data-dir", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert record["share_id"] in result.stdout
    assert other["share_id"] not in result.stdout
    assert "SomeoneElse" not in result.stdout.split("accused")[-1].split("\n")[0]


def test_legacy_image_evidence_requires_explicit_flag(demo_env, tmp_path):
    store, record, labels = demo_env
    width, height = 256, 256
    pixels = make_pixels(width, height)
    assert legacy_embed_into_pixels(pixels, labels["Priya"]["label"])

    from PIL import Image

    image_path = tmp_path / "legacy.png"
    Image.frombytes("RGBA", (width, height), bytes(pixels)).save(image_path, format="PNG")

    without_flag = run_tracer(str(image_path), "--data-dir", str(tmp_path))
    assert without_flag.returncode == 1
    assert "no recipient above the accusation threshold" in without_flag.stdout

    with_flag = run_tracer(str(image_path), "--data-dir", str(tmp_path), "--legacy")
    assert with_flag.returncode == 0, with_flag.stdout + with_flag.stderr
    assert "LEGACY" in with_flag.stdout
    assert "Priya" in with_flag.stdout


def test_legacy_cs1_trailer_is_flagged_and_requires_flag(demo_env, tmp_path):
    store, record, labels = demo_env
    leaked = tmp_path / "legacy.bin"
    leaked.write_bytes(os.urandom(512) + f"%%CS1:{labels['Rohan']['label']}%%".encode())

    without_flag = run_tracer(str(leaked), "--data-dir", str(tmp_path))
    assert without_flag.returncode == 1
    assert "LEGACY" in without_flag.stdout

    with_flag = run_tracer(str(leaked), "--data-dir", str(tmp_path), "--legacy")
    assert with_flag.returncode == 0, with_flag.stdout + with_flag.stderr
    assert "Rohan" in with_flag.stdout
    assert "legacy label" in with_flag.stdout


def test_share_id_flag_restricts_candidates(demo_env, tmp_path):
    store, record, labels = demo_env
    other = store.create_share(
        ciphertext=os.urandom(64),
        nonce_b64="AAAAAAAAAAAAAAAAAAAAAA",
        filename="other.png",
        mime_type="image/png",
        lifetime_seconds=600,
    )
    store.add_recipients(other["share_id"], ["SomeoneElse"])

    width, height = 256, 256
    pixels = make_pixels(width, height)
    assert embed_into_pixels(pixels, labels["Priya"]["token"])
    from PIL import Image

    image_path = tmp_path / "narrowed.png"
    Image.frombytes("RGBA", (width, height), bytes(pixels)).save(image_path, format="PNG")

    result = run_tracer(
        str(image_path), "--data-dir", str(tmp_path), "--share-id", other["share_id"]
    )
    assert result.returncode == 1
    assert "no recipient above the accusation threshold" in result.stdout

    result = run_tracer(
        str(image_path), "--data-dir", str(tmp_path), "--share-id", record["share_id"]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Priya" in result.stdout

    result = run_tracer(
        str(image_path), "--data-dir", str(tmp_path), "--share-id", "nonexistent-share-id"
    )
    assert result.returncode == 2
    assert "no registered recipients" in result.stdout


def test_trailer_checked_before_image_extraction(demo_env, tmp_path):
    store, record, labels = demo_env
    from PIL import Image

    for fmt in ["GIF", "BMP"]:
        img_path = tmp_path / f"poster.{fmt.lower()}"
        Image.new("RGB", (256, 256), (90, 120, 150)).save(img_path, format=fmt)
        leaked = tmp_path / f"leaked_{fmt.lower()}.gif"
        leaked.write_bytes(img_path.read_bytes() + f"%%CS2:{labels['Priya']['token']}%%".encode())
        result = run_tracer(str(leaked), "--data-dir", str(tmp_path))
        assert result.returncode == 0, f"{fmt}: {result.stdout + result.stderr}"
        assert "Priya" in result.stdout

    png_with_trailer = tmp_path / "leaked.png"
    Image.new("RGB", (256, 256), (10, 20, 30)).save(png_with_trailer, format="PNG")
    original = png_with_trailer.read_bytes()
    png_with_trailer.write_bytes(original + f"%%CS2:{labels['Ashwin']['token']}%%".encode())
    result = run_tracer(str(png_with_trailer), "--data-dir", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Ashwin" in result.stdout


def test_tracer_never_accepts_caller_supplied_identity(demo_env, tmp_path):
    result = run_tracer("--help")
    combined = result.stdout + result.stderr
    assert "--label" not in combined
    assert "--token" not in combined
    assert "--r" not in combined.replace("--retry", "")


def test_tracer_reports_no_mark(demo_env, tmp_path):
    leaked = tmp_path / "clean.bin"
    leaked.write_bytes(os.urandom(512))
    result = run_tracer(str(leaked), "--data-dir", str(tmp_path))
    assert result.returncode == 1
    assert "no traceable mark" in result.stdout


def test_tracer_below_threshold_reports_no_match(demo_env, tmp_path):
    store, record, labels = demo_env
    random = xorshift32(0xBEEF)
    pixels = make_pixels(256, 256)
    total = 256 * 256 * 3
    for value in (int(next(random) / 4294967296 * total) for _ in range(1536)):
        offset = (value // 3) * 4 + (value % 3)
        pixels[offset] ^= 1
    from PIL import Image

    image_path = tmp_path / "scrambled.png"
    Image.frombytes("RGBA", (256, 256), bytes(pixels)).save(image_path, format="PNG")
    result = run_tracer(str(image_path), "--data-dir", str(tmp_path))
    assert result.returncode == 1
    assert "no recipient above the accusation threshold" in result.stdout
