import { readFile, writeFile } from "node:fs/promises";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  decryptBytes,
  encryptBytes,
  exportKeyRaw,
  generateKey,
  generateNonce,
  importKeyRaw,
} from "../static/crypto.js";

const [mode, inputPath, payloadPath, metaPath] = process.argv.slice(2);

if (!mode || !inputPath || !payloadPath || !metaPath) {
  console.error("usage: node fixture.mjs <encrypt|decrypt> <input> <payload> <meta>");
  process.exit(2);
}

if (mode === "encrypt") {
  const plaintext = new Uint8Array(await readFile(inputPath));
  const key = await generateKey();
  const nonce = generateNonce();
  const ciphertext = await encryptBytes(plaintext, key, nonce);
  const rawKey = await exportKeyRaw(key);
  await writeFile(payloadPath, ciphertext);
  await writeFile(
    metaPath,
    JSON.stringify(
      {
        nonce: bytesToBase64Url(nonce),
        key: bytesToBase64Url(rawKey),
        plaintext_bytes: plaintext.length,
        ciphertext_bytes: ciphertext.length,
      },
      null,
      2
    )
  );
  console.log(`encrypted ${plaintext.length} bytes -> ${ciphertext.length} bytes`);
} else if (mode === "decrypt") {
  const ciphertext = new Uint8Array(await readFile(inputPath));
  const meta = JSON.parse(await readFile(metaPath, "utf8"));
  const key = await importKeyRaw(base64UrlToBytes(meta.key));
  const plaintext = await decryptBytes(ciphertext, key, base64UrlToBytes(meta.nonce));
  await writeFile(payloadPath, plaintext);
  console.log(`decrypted ${ciphertext.length} bytes -> ${plaintext.length} bytes`);
} else {
  console.error("mode must be encrypt or decrypt");
  process.exit(2);
}
