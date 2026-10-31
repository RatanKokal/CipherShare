"""Python mirror of static/marking.js.

Used by tools/trace.py to extract marks and by tests to synthesize leaked copies.
Must stay byte-compatible with the browser implementation. The legacy label-based
scheme (FNV-1a seeding) is retained only for pre-token evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import struct

CODEWORD_BITS = 512
REPETITION = 3
MARK_SLOTS = CODEWORD_BITS * REPETITION
ACCUSATION_THRESHOLD = 96
HMAC_BLOCKS = CODEWORD_BITS // 8
SEED_POSITIONS = 0x43533153
SEED_BIAS = 0x54415244
MASK = 0xFFFFFFFF
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")
TRAILER_PATTERN = re.compile(rb"%%CS2:([A-Za-z0-9_-]{22})%%\s*\Z")
LEGACY_TRAILER_PATTERN = re.compile(rb"%%CS1:([A-Za-z0-9_-]{4,64})%%\s*\Z")


def xorshift32(seed: int):
    state = (seed | 1) & MASK
    while True:
        state ^= (state << 13) & MASK
        state ^= state >> 17
        state ^= (state << 5) & MASK
        state &= MASK
        yield state


def draw(seed: int, count: int) -> list[float]:
    generator = xorshift32(seed)
    return [next(generator) / 4294967296 for _ in range(count)]


def fnv1a32(text: str) -> int:
    digest = 0x811C9DC5
    for byte in text.encode("utf-8"):
        digest = ((digest ^ byte) * 0x01000193) & MASK
    return digest & MASK


_BIAS_CACHE: list[float] | None = None


def bias_basis() -> list[float]:
    global _BIAS_CACHE
    if _BIAS_CACHE is None:
        _BIAS_CACHE = [0.25 + 0.5 * value for value in draw(SEED_BIAS, CODEWORD_BITS)]
    return _BIAS_CACHE


def codeword(identity: str) -> list[int]:
    bias = bias_basis()
    key = identity.encode("utf-8")
    bits = []
    for block in range(HMAC_BLOCKS):
        digest = hmac.new(key, block.to_bytes(8, "big"), hashlib.sha256).digest()
        words = struct.unpack(">8I", digest)
        for word in words:
            bits.append(1 if word / 4294967296 < bias[len(bits)] else 0)
    return bits


def legacy_codeword(label: str) -> list[int]:
    bias = bias_basis()
    return [
        1 if value < bias[index] else 0
        for index, value in enumerate(draw(fnv1a32(label), CODEWORD_BITS))
    ]


def slot_sequence(total: int) -> list[int]:
    generator = xorshift32(SEED_POSITIONS)
    slots: list[int] = []
    seen: set[int] = set()
    while len(slots) < MARK_SLOTS:
        slot = int(next(generator) / 4294967296 * total)
        offset = (slot // 3) * 4 + (slot % 3)
        if offset not in seen:
            seen.add(offset)
            slots.append(slot)
    return slots


def byte_offset(slot: int) -> int:
    return (slot // 3) * 4 + (slot % 3)


def embed_into_pixels(pixels: bytearray, identity: str) -> bool:
    return _embed_with(pixels, codeword(identity))


def legacy_embed_into_pixels(pixels: bytearray, label: str) -> bool:
    return _embed_with(pixels, legacy_codeword(label))


def _embed_with(pixels: bytearray, bits: list[int]) -> bool:
    total = (len(pixels) // 4) * 3
    if total < MARK_SLOTS:
        return False
    slots = slot_sequence(total)
    position = 0
    for bit in bits:
        for _ in range(REPETITION):
            offset = byte_offset(slots[position])
            pixels[offset] = (pixels[offset] & 0xFE) | bit
            position += 1
    return True


def extract_codeword(pixels: bytes) -> list[int] | None:
    total = (len(pixels) // 4) * 3
    if total < MARK_SLOTS:
        return None
    slots = slot_sequence(total)
    raw = [pixels[byte_offset(slot)] & 1 for slot in slots]
    bits = []
    for index in range(CODEWORD_BITS):
        ones = sum(raw[index * REPETITION : (index + 1) * REPETITION])
        bits.append(1 if ones * 2 > REPETITION else 0)
    return bits


def tardos_score(codeword_bits: list[int], extracted: list[int], bias: list[float]) -> float:
    score = 0.0
    for index, bit in enumerate(extracted):
        p = bias[index]
        if bit == 1:
            score += (
                math.sqrt((1 - p) / p)
                if codeword_bits[index] == 1
                else -math.sqrt(p / (1 - p))
            )
        else:
            score += (
                math.sqrt(p / (1 - p))
                if codeword_bits[index] == 0
                else -math.sqrt((1 - p) / p)
            )
    return score


def accuse(extracted: list[int], candidates: list[dict]) -> dict | None:
    bias = bias_basis()
    best = None
    for candidate in candidates:
        score = tardos_score(codeword(candidate["token"]), extracted, bias)
        if best is None or score > best["score"]:
            best = {**candidate, "score": score}
    if best is None or best["score"] < ACCUSATION_THRESHOLD:
        return None
    return best


def accuse_legacy(extracted: list[int], candidates: list[dict]) -> dict | None:
    bias = bias_basis()
    best = None
    for candidate in candidates:
        score = tardos_score(legacy_codeword(candidate["label"]), extracted, bias)
        if best is None or score > best["score"]:
            best = {**candidate, "score": score}
    if best is None or best["score"] < ACCUSATION_THRESHOLD:
        return None
    return best


def parse_trailer(data: bytes) -> str | None:
    match = TRAILER_PATTERN.search(data[-4096:])
    return match.group(1).decode("ascii") if match else None


def parse_legacy_trailer(data: bytes) -> str | None:
    match = LEGACY_TRAILER_PATTERN.search(data[-4096:])
    return match.group(1).decode("ascii") if match else None
