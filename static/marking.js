export const CODEWORD_BITS = 512;
export const REPETITION = 3;
export const MARK_SLOTS = CODEWORD_BITS * REPETITION;
export const ACCUSATION_THRESHOLD = 96;
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]{22}$/;
const SEED_POSITIONS = 0x43533153;
const SEED_BIAS = 0x54415244;
const HMAC_BLOCKS = CODEWORD_BITS / 8;
const MASK = 0xffffffff;

export function xorshift32(seed) {
  let state = (seed | 1) >>> 0;
  return function () {
    state = (state ^ ((state << 13) & MASK)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ ((state << 5) & MASK)) >>> 0;
    return state / 4294967296;
  };
}

let biasCache = null;

export function biasBasis() {
  if (!biasCache) {
    const random = xorshift32(SEED_BIAS);
    biasCache = [];
    for (let index = 0; index < CODEWORD_BITS; index += 1) {
      biasCache.push(0.25 + 0.5 * random());
    }
  }
  return biasCache;
}

export async function hmacStream(identity, blocks) {
  const keyBytes = new TextEncoder().encode(identity);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const words = new Float64Array(blocks * 8);
  for (let block = 0; block < blocks; block += 1) {
    const counter = new ArrayBuffer(8);
    new DataView(counter).setBigUint64(0, BigInt(block), false);
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
    const view = new DataView(digest.buffer);
    for (let word = 0; word < 8; word += 1) {
      words[block * 8 + word] = view.getUint32(word * 4, false) / 4294967296;
    }
  }
  return words;
}

export async function codeword(identity) {
  const bias = biasBasis();
  const stream = await hmacStream(identity, HMAC_BLOCKS);
  const bits = new Uint8Array(CODEWORD_BITS);
  for (let index = 0; index < CODEWORD_BITS; index += 1) {
    bits[index] = stream[index] < bias[index] ? 1 : 0;
  }
  return bits;
}

export function slotSequence(total) {
  const random = xorshift32(SEED_POSITIONS);
  const slots = new Uint32Array(MARK_SLOTS);
  const seen = new Set();
  let count = 0;
  while (count < MARK_SLOTS) {
    const slot = Math.floor(random() * total);
    const offset = Math.floor(slot / 3) * 4 + (slot % 3);
    if (!seen.has(offset)) {
      seen.add(offset);
      slots[count] = slot;
      count += 1;
    }
  }
  return slots;
}

function byteOffset(slot) {
  const pixel = Math.floor(slot / 3);
  return pixel * 4 + (slot % 3);
}

export async function embedIntoPixels(pixels, identity) {
  const total = (pixels.length / 4) * 3;
  if (total < MARK_SLOTS) return false;
  const bits = await codeword(identity);
  const slots = slotSequence(total);
  for (let bit = 0; bit < CODEWORD_BITS; bit += 1) {
    for (let copy = 0; copy < REPETITION; copy += 1) {
      const offset = byteOffset(slots[bit * REPETITION + copy]);
      pixels[offset] = (pixels[offset] & 0xfe) | bits[bit];
    }
  }
  return true;
}

export function extractCodeword(pixels) {
  const total = (pixels.length / 4) * 3;
  if (total < MARK_SLOTS) return null;
  const slots = slotSequence(total);
  const raw = new Uint8Array(MARK_SLOTS);
  for (let position = 0; position < MARK_SLOTS; position += 1) {
    raw[position] = pixels[byteOffset(slots[position])] & 1;
  }
  const bits = new Uint8Array(CODEWORD_BITS);
  for (let bit = 0; bit < CODEWORD_BITS; bit += 1) {
    let ones = 0;
    for (let copy = 0; copy < REPETITION; copy += 1) {
      ones += raw[bit * REPETITION + copy];
    }
    bits[bit] = ones * 2 > REPETITION ? 1 : 0;
  }
  return bits;
}

export function equalCodewordBits(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function tardosScore(codewordBits, extracted, bias) {
  let score = 0;
  for (let index = 0; index < CODEWORD_BITS; index += 1) {
    const p = bias[index];
    if (extracted[index] === 1) {
      score += codewordBits[index] === 1 ? Math.sqrt((1 - p) / p) : -Math.sqrt(p / (1 - p));
    } else {
      score += codewordBits[index] === 0 ? Math.sqrt(p / (1 - p)) : -Math.sqrt((1 - p) / p);
    }
  }
  return score;
}

export async function accuse(extracted, candidates) {
  const bias = biasBasis();
  let best = null;
  for (const candidate of candidates) {
    const bits = await codeword(candidate.token);
    const score = tardosScore(bits, extracted, bias);
    if (!best || score > best.score) best = { ...candidate, score };
  }
  if (!best || best.score < ACCUSATION_THRESHOLD) return null;
  return best;
}

export function appendTrailer(bytes, token) {
  const marker = new TextEncoder().encode(`%%CS2:${token}%%`);
  const out = new Uint8Array(bytes.length + marker.length);
  out.set(bytes);
  out.set(marker, bytes.length);
  return out;
}

export function parseTrailer(bytes) {
  const tail = new TextDecoder("latin1").decode(bytes.slice(-4096));
  const match = /%%CS2:([A-Za-z0-9_-]{22})%%\s*$/.exec(tail);
  return match ? match[1] : null;
}

export function parseLegacyTrailer(bytes) {
  const tail = new TextDecoder("latin1").decode(bytes.slice(-4096));
  const match = /%%CS1:([A-Za-z0-9_-]{4,64})%%\s*$/.exec(tail);
  return match ? match[1] : null;
}

export function parseMarkingFragment(fragment) {
  const parts = fragment.split(":");
  if (parts.length === 1) return { linkHalf: parts[0], token: null };
  if (parts.length === 2 && TOKEN_PATTERN.test(parts[1])) {
    return { linkHalf: parts[0], token: parts[1] };
  }
  return { linkHalf: parts[0], token: null };
}

export async function fingerprintImage(blob, identity) {
  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(bitmap, 0, 0);
  const image = context.getImageData(0, 0, canvas.width, canvas.height);
  if (!(await embedIntoPixels(image.data, identity))) return null;
  context.putImageData(image, 0, 0);
  return new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
}
