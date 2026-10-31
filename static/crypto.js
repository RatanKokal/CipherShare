const AES_GCM = { name: "AES-GCM", length: 256 };
const IV_BYTES = 12;
const TAG_BITS = 128;

export async function generateKey() {
  return crypto.subtle.generateKey(AES_GCM, true, ["encrypt", "decrypt"]);
}

export async function exportKeyRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function importKeyRaw(rawBytes) {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
}

export function generateNonce() {
  return crypto.getRandomValues(new Uint8Array(IV_BYTES));
}

export async function derivePasswordHalf(password, salt, iterations) {
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

export function xorBytes(left, right) {
  if (left.length !== right.length) {
    throw new Error("xorBytes length mismatch");
  }
  const result = new Uint8Array(left.length);
  for (let index = 0; index < left.length; index += 1) {
    result[index] = left[index] ^ right[index];
  }
  return result;
}

export async function encryptBytes(plaintext, key, nonce) {
  const bytes = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const result = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS },
    key,
    bytes
  );
  return new Uint8Array(result);
}

export async function decryptBytes(ciphertext, key, nonce) {
  const result = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS },
    key,
    ciphertext
  );
  return new Uint8Array(result);
}

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlToBytes(text) {
  const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
