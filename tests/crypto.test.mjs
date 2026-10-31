import test from "node:test";
import assert from "node:assert/strict";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  decryptBytes,
  derivePasswordHalf,
  encryptBytes,
  equalBytes,
  exportKeyRaw,
  generateKey,
  generateNonce,
  importKeyRaw,
  xorBytes,
} from "../static/crypto.js";

async function makeShare(plaintext) {
  const key = await generateKey();
  const nonce = generateNonce();
  const ciphertext = await encryptBytes(plaintext, key, nonce);
  const rawKey = await exportKeyRaw(key);
  return { ciphertext, nonce, rawKey };
}

test("text file round trip preserves exact bytes", async () => {
  const plaintext = new TextEncoder().encode("CipherShare test document\nLine two.\n");
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const recovered = await decryptBytes(ciphertext, await importKeyRaw(rawKey), nonce);
  assert.ok(equalBytes(plaintext, recovered));
});

test("binary file round trip preserves exact bytes", async () => {
  const plaintext = new Uint8Array(256);
  for (let index = 0; index < plaintext.length; index += 1) {
    plaintext[index] = index;
  }
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const recovered = await decryptBytes(ciphertext, await importKeyRaw(rawKey), nonce);
  assert.ok(equalBytes(plaintext, recovered));
});

test("empty file round trip preserves zero length", async () => {
  const plaintext = new Uint8Array(0);
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  assert.equal(ciphertext.length, 16);
  const recovered = await decryptBytes(ciphertext, await importKeyRaw(rawKey), nonce);
  assert.equal(recovered.length, 0);
});

test("tampered ciphertext is rejected", async () => {
  const plaintext = new TextEncoder().encode("integrity matters");
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const tampered = ciphertext.slice();
  tampered[0] ^= 0x01;
  await assert.rejects(
    decryptBytes(tampered, await importKeyRaw(rawKey), nonce),
    /OperationError|The operation failed/
  );
});

test("tampered tag is rejected", async () => {
  const plaintext = new TextEncoder().encode("integrity matters");
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const tampered = ciphertext.slice();
  tampered[tampered.length - 1] ^= 0x01;
  await assert.rejects(
    decryptBytes(tampered, await importKeyRaw(rawKey), nonce),
    /OperationError|The operation failed/
  );
});

test("truncated ciphertext is rejected", async () => {
  const plaintext = new TextEncoder().encode("integrity matters");
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const truncated = ciphertext.slice(0, -1);
  await assert.rejects(
    decryptBytes(truncated, await importKeyRaw(rawKey), nonce),
    /OperationError|The operation failed/
  );
});

test("modified nonce is rejected", async () => {
  const plaintext = new TextEncoder().encode("integrity matters");
  const { ciphertext, nonce, rawKey } = await makeShare(plaintext);
  const modifiedNonce = nonce.slice();
  modifiedNonce[0] ^= 0x01;
  await assert.rejects(
    decryptBytes(ciphertext, await importKeyRaw(rawKey), modifiedNonce),
    /OperationError|The operation failed/
  );
});

test("wrong key is rejected", async () => {
  const plaintext = new TextEncoder().encode("confidential");
  const { ciphertext, nonce } = await makeShare(plaintext);
  const wrongKey = await generateKey();
  await assert.rejects(
    decryptBytes(ciphertext, wrongKey, nonce),
    /OperationError|The operation failed/
  );
});

test("base64url encoding round trips key bytes", async () => {
  const key = await generateKey();
  const rawKey = await exportKeyRaw(key);
  const encoded = bytesToBase64Url(rawKey);
  assert.equal(encoded.includes("+"), false);
  assert.equal(encoded.includes("/"), false);
  assert.equal(encoded.includes("="), false);
  assert.ok(equalBytes(rawKey, base64UrlToBytes(encoded)));
});

test("password split and recombination recover the exact key", async () => {
  const rawKey = new Uint8Array(await crypto.subtle.exportKey(
    "raw",
    await generateKey()
  ));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const linkHalf = xorBytes(rawKey, await derivePasswordHalf("correct horse", salt, 1000));
  assert.ok(!equalBytes(linkHalf, rawKey));
  const rebuilt = xorBytes(linkHalf, await derivePasswordHalf("correct horse", salt, 1000));
  assert.ok(equalBytes(rawKey, rebuilt));
});

test("link half alone does not reveal the key", async () => {
  const rawKey = await exportKeyRaw(await generateKey());
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const linkHalf = xorBytes(rawKey, await derivePasswordHalf("satoshi", salt, 1000));
  assert.equal(linkHalf.length, rawKey.length);
  assert.ok(!equalBytes(linkHalf, rawKey));
});

test("wrong password recombination fails decryption", async () => {
  const plaintext = new TextEncoder().encode("hostel minutes");
  const key = await generateKey();
  const nonce = generateNonce();
  const ciphertext = await encryptBytes(plaintext, key, nonce);
  const rawKey = await exportKeyRaw(key);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const linkHalf = xorBytes(rawKey, await derivePasswordHalf("right", salt, 1000));
  const wrongRebuild = xorBytes(linkHalf, await derivePasswordHalf("wrong", salt, 1000));
  await assert.rejects(
    decryptBytes(ciphertext, await importKeyRaw(wrongRebuild), nonce)
  );
});

test("full password-split flow decrypts end to end", async () => {
  const plaintext = new TextEncoder().encode("mess menu week 12");
  const key = await generateKey();
  const nonce = generateNonce();
  const ciphertext = await encryptBytes(plaintext, key, nonce);
  const rawKey = await exportKeyRaw(key);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 1000;
  const passwordHalf = await derivePasswordHalf("wing4", salt, iterations);
  const linkHalf = xorBytes(rawKey, passwordHalf);

  const recipientHalf = await derivePasswordHalf("wing4", salt, iterations);
  const rebuiltKey = await importKeyRaw(xorBytes(linkHalf, recipientHalf));
  const recovered = await decryptBytes(ciphertext, rebuiltKey, nonce);
  assert.ok(equalBytes(plaintext, recovered));
});
