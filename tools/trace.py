from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fingerprint_mirror import (  # noqa: E402
    ACCUSATION_THRESHOLD,
    TOKEN_PATTERN,
    accuse,
    accuse_legacy,
    extract_codeword,
    parse_legacy_trailer,
    parse_trailer,
)
from storage import ShareStore


def image_pixels(path: Path) -> tuple[bytes, int, int] | None:
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(path) as image:
            converted = image.convert("RGBA")
            return converted.tobytes("raw", "RGBA"), converted.width, converted.height
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="CipherShare leak tracer")
    parser.add_argument("file", help="leaked file to trace")
    parser.add_argument("--data-dir", default="data", help="CipherShare data directory")
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="score pre-token (label-based) image evidence; never triggered automatically",
    )
    parser.add_argument(
        "--share-id",
        default=None,
        help="restrict candidate scoring to one share's registry (reduces "
        "multiple-testing exposure when the leaking share is known)",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.is_file():
        print(f"error: {path} is not a file")
        return 2

    store = ShareStore(Path(args.data_dir))
    if args.share_id:
        recipients = store.get_recipients(args.share_id)
        if not recipients:
            print(f"share {args.share_id} has no registered recipients")
            return 2
    else:
        recipients = store.list_all_recipients()
    candidates = [
        c for c in recipients if c.get("token") and TOKEN_PATTERN.fullmatch(c["token"])
    ]
    legacy_candidates = recipients
    if not candidates and not legacy_candidates:
        print("no recipients registered in the database")
        return 1

    print(f"CipherShare tracer: {path.name}")
    print(f"candidates: {len(candidates)} registered token(s)")

    data = path.read_bytes()

    token = parse_trailer(data)
    if token is not None:
        print("mark type: appended trailer (CS2)")
        match = next((c for c in candidates if c["token"] == token), None)
        if match is None:
            print("trailer token is not a registered recipient")
            return 1
        print(
            f"accused: {match['display_name']} "
            f"(share {match['share_id']}, token-registered, exact match)"
        )
        return 0

    legacy_label = parse_legacy_trailer(data)
    if legacy_label is not None:
        print("mark type: appended trailer (CS1) — LEGACY pre-token evidence")
        if not args.legacy:
            print(
                "legacy CS1 trailer found; re-run with --legacy to accept legacy"
                " evidence (CS1 is flagged, never treated as token evidence)"
            )
            return 1
        match = next((c for c in legacy_candidates if c["label"] == legacy_label), None)
        if match is None:
            print(f"legacy label {legacy_label} is not a registered recipient")
            return 1
        print(
            f"accused: {match['display_name']} "
            f"(share {match['share_id']}, legacy label {legacy_label}, exact match)"
        )
        return 0

    pixels = image_pixels(path)
    if pixels is None:
        print("no traceable mark found in this file")
        return 1

    raw, width, height = pixels
    print(f"mark type: image LSB ({width}x{height})")
    extracted = extract_codeword(raw)
    if extracted is None:
        print("image mark unreadable (image too small or pixels altered)")
        return 1

    if args.legacy and legacy_candidates:
        accused = accuse_legacy(extracted, legacy_candidates)
        if accused is not None:
            print(
                f"accused (LEGACY): {accused['display_name']} "
                f"(share {accused['share_id']}, label {accused['label']}, "
                f"score {accused['score']:.1f}, threshold {ACCUSATION_THRESHOLD})"
            )
            return 0

    accused = accuse(extracted, candidates)
    if accused is None:
        print("no recipient above the accusation threshold")
        return 1
    print(
        f"accused: {accused['display_name']} "
        f"(share {accused['share_id']}, token-registered, "
        f"score {accused['score']:.1f}, threshold {ACCUSATION_THRESHOLD})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
