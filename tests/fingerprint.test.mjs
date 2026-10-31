import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACCUSATION_THRESHOLD,
  CODEWORD_BITS,
  MARK_SLOTS,
  TOKEN_PATTERN,
  accuse,
  appendTrailer,
  biasBasis,
  codeword,
  embedIntoPixels,
  equalCodewordBits,
  extractCodeword,
  parseLegacyTrailer,
  parseMarkingFragment,
  parseTrailer,
  slotSequence,
  tardosScore,
  xorshift32,
} from "../static/marking.js";

const here = dirname(fileURLToPath(import.meta.url));

function makePixels(width, height) {
  const random = xorshift32(0xc1d3);
  const pixels = new Uint8Array(width * height * 4);
  for (let index = 0; index < pixels.length; index += 1) {
    pixels[index] = index % 4 === 3 ? 255 : Math.floor(random() * 256);
  }
  return pixels;
}

test("bias basis is deterministic; tokens are 22-char urlsafe", () => {
  const bias = biasBasis();
  assert.equal(bias.length, CODEWORD_BITS);
  for (const value of bias) {
    assert.ok(value >= 0.25 && value < 0.75);
  }
  assert.equal(TOKEN_PATTERN.test("rH86AxOULd2M9sigXKCnZA"), true);
  assert.equal(TOKEN_PATTERN.test("short"), false);
});

test("codewords are deterministic per token and distinct across tokens", async () => {
  const a = await codeword("rH86AxOULd2M9sigXKCnZA");
  const a2 = await codeword("rH86AxOULd2M9sigXKCnZA");
  const b = await codeword("mUb93LYhjUC36FGiFRVPeg");
  assert.deepEqual(Array.from(a), Array.from(a2));
  assert.notDeepEqual(Array.from(a), Array.from(b));
});

test("HMAC stream uses the full token (not a reduced seed)", async () => {
  const long1 = await codeword("aaaa1aaaa2aaaa3aaaa4a");
  const long2 = await codeword("aaaa1aaaa2aaaa3aaaa4b");
  let differences = 0;
  for (let i = 0; i < CODEWORD_BITS; i += 1) {
    if (long1[i] !== long2[i]) differences += 1;
  }
  assert.ok(differences > 100, `tokens differ in only ${differences} bits`);
});

test("embed and extract round trip recovers the codeword", async () => {
  const pixels = makePixels(128, 128);
  assert.equal(await embedIntoPixels(pixels, "0BuVtU8GtPiyIkRX4cyHTQ"), true);
  const extracted = extractCodeword(pixels);
  assert.ok(equalCodewordBits(extracted, await codeword("0BuVtU8GtPiyIkRX4cyHTQ")));
});

test("image too small for marking is rejected", async () => {
  const pixels = makePixels(16, 16);
  assert.equal(await embedIntoPixels(pixels, "tiny"), false);
  assert.equal(extractCodeword(pixels), null);
});

test("accusation identifies the leaker among innocents", async () => {
  const leaker = "7wTFWePT-AuVJouX4JaHZQ";
  const innocents = ["W3CJbdNXIJYcj0JkTHPiVA", "dK5MP3sGym27qrgwzq1DHw", "mmQ-9n9XowpswubGNPNV2Q"];
  const pixels = makePixels(256, 256);
  await embedIntoPixels(pixels, leaker);
  const extracted = extractCodeword(pixels);
  const result = await accuse(
    extracted,
    [{ token: leaker }, ...innocents.map((token) => ({ token }))]
  );
  assert.ok(result);
  assert.equal(result.token, leaker);
  assert.ok(result.score >= ACCUSATION_THRESHOLD);
  const bias = biasBasis();
  for (const innocent of innocents) {
    const score = tardosScore(await codeword(innocent), extracted, bias);
    assert.ok(score < ACCUSATION_THRESHOLD, `innocent scored ${score}`);
  }
});

test("two-member coalition is still traced to a guilty member", async () => {
  const width = 256;
  const height = 256;
  const total = width * height * 3;
  const alice = "7F0WyaBDa8WW_Rmi5A57-Q";
  const bob = "YsHj-t0FRe1143Fd26jvvQ";
  const innocent = "AONu4rBbiiIy_7aFMI9_nQ";

  const base = makePixels(width, height);
  const copyA = base.slice();
  const copyB = base.slice();
  await embedIntoPixels(copyA, alice);
  await embedIntoPixels(copyB, bob);

  const slots = slotSequence(total);
  const random = xorshift32(0xfeed);
  const attacked = base.slice();
  for (const slot of slots) {
    const offset = Math.floor(slot / 3) * 4 + (slot % 3);
    const source = random() < 0.5 ? copyA : copyB;
    attacked[offset] = (attacked[offset] & 0xfe) | (source[offset] & 1);
  }

  const extracted = extractCodeword(attacked);
  assert.ok(extracted);
  assert.ok(!equalCodewordBits(extracted, await codeword(alice)));
  const result = await accuse(extracted, [
    { token: alice },
    { token: bob },
    { token: innocent },
  ]);
  assert.ok(result);
  assert.ok(
    result.token === alice || result.token === bob,
    `accused ${result.token} is not in the coalition`
  );
  const innocentScore = tardosScore(await codeword(innocent), extracted, biasBasis());
  assert.ok(innocentScore < ACCUSATION_THRESHOLD);
});

test("CS2 trailer marks round trip; CS1 parses only as legacy", () => {
  const payload = new Uint8Array(2048);
  for (let index = 0; index < payload.length; index += 1) payload[index] = index % 251;
  const token = "Gu4Qx4OLpa4ORp9V8b6erQ";
  const marked = appendTrailer(payload, token);
  assert.equal(parseTrailer(marked), token);
  assert.equal(parseTrailer(payload), null);
  assert.equal(parseLegacyTrailer(marked), null);
  const legacy = new Uint8Array(4096 - 14).fill(0x41);
  const legacyMarked = appendTrailer(legacy, "legacyLbl");
  assert.equal(parseTrailer(legacyMarked), null);
});

test("fragment parser separates link half from token; ?r= is never an identity", () => {
  const linkHalf = "AbC123xyz_Qrs456tuv";
  const token = "rH86AxOULd2M9sigXKCnZA";
  const withToken = parseMarkingFragment(`${linkHalf}:${token}`);
  assert.equal(withToken.linkHalf, linkHalf);
  assert.equal(withToken.token, token);

  const plain = parseMarkingFragment(linkHalf);
  assert.equal(plain.linkHalf, linkHalf);
  assert.equal(plain.token, null);

  const tampered = parseMarkingFragment(`${linkHalf}:not-a-valid-token`);
  assert.equal(tampered.linkHalf, linkHalf);
  assert.equal(tampered.token, null);

  assert.equal(parseMarkingFragment(`${linkHalf}:${token}`).token, token);
  assert.equal(parseMarkingFragment(`?r=${token}`).token, null);
});

test("cross-language vector file is written for the Python tracer", async () => {
  const width = 64;
  const height = 64;
  const token = "rH86AxOULd2M9sigXKCnZA";
  const total = width * height * 3;
  const pixels = makePixels(width, height);
  await embedIntoPixels(pixels, token);
  const slots = slotSequence(total);
  const bias = biasBasis();
  const bits = await codeword(token);

  const vector = {
    token,
    width,
    height,
    total,
    slots: Array.from(slots),
    bias,
    codeword: Array.from(bits),
    pixels_base64: Buffer.from(pixels).toString("base64"),
    extracted_matches_codeword: equalCodewordBits(extractCodeword(pixels), bits),
  };
  assert.ok(vector.extracted_matches_codeword);
  assert.equal(vector.slots.length, MARK_SLOTS);

  const dataDir = join(here, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "fingerprint-vector.json"), JSON.stringify(vector));
});
