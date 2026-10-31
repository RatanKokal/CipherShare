import {
  base64UrlToBytes,
  bytesToBase64Url,
  decryptBytes,
  encryptBytes,
  exportKeyRaw,
  generateKey,
  generateNonce,
  importKeyRaw,
  derivePasswordHalf,
  xorBytes,
} from "./crypto.js";
import {
  appendTrailer,
  fingerprintImage,
  parseMarkingFragment,
  TOKEN_PATTERN,
} from "./marking.js";

const MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024;
const KDF_ITERATIONS = 600000;
const SHARE_ID_PATTERN = /^\/s\/([A-Za-z0-9_-]{16,64})\/?$/;

const shareButton = document.getElementById("share-button");
const fileInput = document.getElementById("file-input");
const passwordInput = document.getElementById("password-input");
const lifetimeInput = document.getElementById("lifetime-input");
const recipientsInput = document.getElementById("recipients-input");
const shareStatus = document.getElementById("share-status");
const shareResult = document.getElementById("share-result");
const genericLinkBlock = document.getElementById("generic-link-block");
const recipientLinks = document.getElementById("recipient-links");
const shareLinkInput = document.getElementById("share-link");
const copyButton = document.getElementById("copy-button");
const shareWarning = document.getElementById("share-warning");

const recipientPanel = document.getElementById("recipient-panel");
const recipientShareId = document.getElementById("recipient-share-id");
const recipientPasswordField = document.getElementById("recipient-password-field");
const recipientPasswordInput = document.getElementById("recipient-password");
const downloadButton = document.getElementById("download-button");
const recipientStatus = document.getElementById("recipient-status");

function setStatus(element, message, kind) {
  element.textContent = message;
  element.className = `status ${kind ?? "info"}`;
  element.hidden = false;
}

function clearStatus(element) {
  element.hidden = true;
  element.textContent = "";
}

function shareIdFromPath() {
  const match = SHARE_ID_PATTERN.exec(location.pathname);
  return match ? match[1] : null;
}

async function detailOf(response) {
  try {
    const body = await response.json();
    if (body && typeof body.detail === "string") return body.detail;
  } catch (error) {
    return response.statusText;
  }
  return response.statusText;
}

async function shareFile() {
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    setStatus(shareStatus, "Choose a file first.", "error");
    return;
  }
  if (file.size > MAX_PLAINTEXT_BYTES) {
    setStatus(shareStatus, "File exceeds the 10 MB limit.", "error");
    return;
  }

  shareButton.disabled = true;
  clearStatus(shareStatus);
  shareResult.hidden = true;

  try {
    setStatus(shareStatus, "Encrypting in your browser…");
    const plaintext = new Uint8Array(await file.arrayBuffer());
    const key = await generateKey();
    const nonce = generateNonce();
    const ciphertext = await encryptBytes(plaintext, key, nonce);

    const password = passwordInput.value;
    let linkKey = await exportKeyRaw(key);
    const form = new FormData();
    form.append(
      "ciphertext",
      new Blob([ciphertext], { type: "application/octet-stream" }),
      "payload.bin"
    );
    form.append("nonce", bytesToBase64Url(nonce));
    form.append("filename", file.name);
    form.append("mime_type", file.type || "application/octet-stream");
    form.append("lifetime_seconds", lifetimeInput.value);

    if (password) {
      setStatus(shareStatus, "Deriving password half…");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passwordHalf = await derivePasswordHalf(password, salt, KDF_ITERATIONS);
      linkKey = xorBytes(linkKey, passwordHalf);
      form.append("salt", bytesToBase64Url(salt));
      form.append("kdf_iterations", String(KDF_ITERATIONS));
    }
    if (recipientsInput.value.trim()) {
      form.append("recipients", recipientsInput.value);
    }

    setStatus(shareStatus, "Uploading ciphertext…");
    const response = await fetch("/shares", { method: "POST", body: form });
    if (!response.ok) {
      throw new Error(await detailOf(response));
    }
    const body = await response.json();
    const fragment = bytesToBase64Url(linkKey);
    const recipients = body.recipients ?? [];

    genericLinkBlock.hidden = recipients.length > 0;
    recipientLinks.innerHTML = "";
    if (recipients.length) {
      const title = document.createElement("span");
      title.className = "recipient-links-title";
      title.textContent = "Personalized links (one per recipient):";
      recipientLinks.appendChild(title);
      for (const recipient of recipients) {
        recipientLinks.appendChild(buildRecipientRow(body.share_id, recipient, fragment));
      }
      shareWarning.textContent =
        "Each recipient's link carries their registered marking token in the fragment; their downloaded copy is invisibly marked and a leak can be traced to that link. Send each link only to its recipient.";
    } else {
      shareLinkInput.value = `${location.origin}/s/${body.share_id}#${fragment}`;
      shareWarning.textContent = password
        ? "Anyone with this link AND the password can decrypt before expiry. Send them through different channels. The password is never uploaded."
        : "Anyone with this link can decrypt before expiry. Set a password to split the key.";
    }
    shareResult.hidden = false;
    setStatus(
      shareStatus,
      body.password_protected
        ? "Encrypted share created (password-protected)."
        : "Encrypted share created.",
      "success"
    );
  } catch (error) {
    setStatus(shareStatus, `Share failed: ${error.message}`, "error");
  } finally {
    shareButton.disabled = false;
  }
}

async function downloadShare() {
  const shareId = shareIdFromPath();
  if (!shareId) {
    setStatus(recipientStatus, "This page does not contain a share ID.", "error");
    return;
  }
  const parsedFragment = parseMarkingFragment(location.hash.replace(/^#/, ""));
  const fragment = parsedFragment.linkHalf;
  if (!fragment) {
    setStatus(recipientStatus, "This link is missing its key fragment.", "error");
    return;
  }

  downloadButton.disabled = true;
  clearStatus(recipientStatus);

  try {
    setStatus(recipientStatus, "Downloading ciphertext…");
    const response = await fetch(`/shares/${shareId}`);
    if (response.status === 404) {
      setStatus(recipientStatus, "Share not found. Check the link.", "error");
      return;
    }
    if (response.status === 410) {
      setStatus(recipientStatus, "This link has expired or was revoked.", "error");
      return;
    }
    if (!response.ok) {
      throw new Error(await detailOf(response));
    }

    const saltB64 = response.headers.get("X-Salt");
    const nonce = base64UrlToBytes(response.headers.get("X-Nonce"));
    const ciphertext = new Uint8Array(await response.arrayBuffer());

    let rawKey = base64UrlToBytes(fragment);
    if (saltB64) {
      const password = recipientPasswordInput.value;
      if (!password) {
        setStatus(
          recipientStatus,
          "This share is password-protected. Enter the password and try again.",
          "error"
        );
        recipientPasswordInput.focus();
        return;
      }
      setStatus(recipientStatus, "Deriving password half…");
      const salt = base64UrlToBytes(saltB64);
      const iterations = Number(response.headers.get("X-Kdf-Iterations"));
      const passwordHalf = await derivePasswordHalf(password, salt, iterations);
      rawKey = xorBytes(rawKey, passwordHalf);
    }

    setStatus(recipientStatus, "Decrypting locally…");
    const key = await importKeyRaw(rawKey);
    let plaintext;
    try {
      plaintext = await decryptBytes(ciphertext, key, nonce);
    } catch (error) {
      setStatus(
        recipientStatus,
        saltB64
          ? "Decryption failed: wrong password, or the file was modified in transit."
          : "Decryption failed: the key fragment does not match, or the file was modified in transit.",
        "error"
      );
      return;
    }

    const filename = decodeURIComponent(
      response.headers.get("X-Filename") || "download.bin"
    );
    const mime = response.headers.get("X-Mime-Type") || "application/octet-stream";
    const parsed = parseMarkingFragment(location.hash.replace(/^#/, ""));
    const token = parsed.token && TOKEN_PATTERN.test(parsed.token) ? parsed.token : null;
    const marked = token ? await markCopy(plaintext, mime, token, filename) : null;
    const outputBytes = marked ? marked.bytes : plaintext;
    const outputName = marked ? marked.name : filename;
    const outputMime = marked ? marked.mime : mime;

    const blob = new Blob([outputBytes], { type: outputMime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = outputName;
    anchor.click();
    URL.revokeObjectURL(url);
    setStatus(
      recipientStatus,
      marked
        ? `Decrypted and saved “${outputName}”. This copy is fingerprinted with this link's marking identity.`
        : `Decrypted and saved “${outputName}”. This download is not marked (no marking token in this link).`,
      marked ? "success" : "info"
    );
  } catch (error) {
    setStatus(recipientStatus, `Download failed: ${error.message}`, "error");
  } finally {
    downloadButton.disabled = false;
  }
}

async function markCopy(plaintext, mime, label, filename) {
  const isRasterImage = /^image\/(png|jpe?g)$/i.test(mime);
  if (isRasterImage) {
    try {
      const markedBlob = await fingerprintImage(
        new Blob([plaintext], { type: mime }),
        label
      );
      if (markedBlob) {
        return {
          bytes: new Uint8Array(await markedBlob.arrayBuffer()),
          name: filename.replace(/\.(jpe?g)$/i, ".png"),
          mime: "image/png",
        };
      }
    } catch (error) {
      return { bytes: appendTrailer(plaintext, label), name: filename, mime };
    }
    return null;
  }
  return { bytes: appendTrailer(plaintext, label), name: filename, mime };
}

function buildRecipientRow(shareId, recipient, fragment) {
  const row = document.createElement("div");
  row.className = "recipient-link-row";

  const name = document.createElement("span");
  name.className = "recipient-name";
  name.textContent = recipient.name;

  const input = document.createElement("input");
  input.readOnly = true;
  input.value = `${location.origin}/s/${shareId}#${fragment}:${recipient.token}`;

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(input.value);
      button.textContent = "Copied";
    } catch (error) {
      input.select();
      button.textContent = "Select & copy";
    }
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1500);
  });

  row.appendChild(name);
  row.appendChild(input);
  row.appendChild(button);
  return row;
}

async function copyLink() {
  try {
    await navigator.clipboard.writeText(shareLinkInput.value);
    copyButton.textContent = "Copied";
  } catch (error) {
    shareLinkInput.select();
    copyButton.textContent = "Select & copy";
  }
  setTimeout(() => {
    copyButton.textContent = "Copy";
  }, 1500);
}

const shareId = shareIdFromPath();
if (shareId) {
  recipientPanel.hidden = false;
  recipientShareId.textContent = `Share ID: ${shareId}`;
} else {
  document.getElementById("sender-panel").hidden = false;
}

shareButton.addEventListener("click", shareFile);
downloadButton.addEventListener("click", downloadShare);
copyButton.addEventListener("click", copyLink);
recipientPasswordInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") downloadShare();
});
