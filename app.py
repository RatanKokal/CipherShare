from __future__ import annotations

import base64
import binascii
import os
import re
import time
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from storage import ShareStore

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DEFAULT_DATA_DIR = Path(os.environ.get("CIPHERSHARE_DATA_DIR", BASE_DIR / "data"))

MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024
GCM_TAG_BYTES = 16
MAX_UPLOAD_BYTES = MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES
MIN_LIFETIME_SECONDS = 1
MAX_LIFETIME_SECONDS = 24 * 60 * 60
MAX_RECIPIENTS = 20
MAX_RECIPIENT_NAME_BYTES = 40
SHARE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16}$")
SALT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")
MIME_PATTERN = re.compile(r"^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$")
MIN_KDF_ITERATIONS = 100_000
MAX_KDF_ITERATIONS = 5_000_000


def decode_nonce(value: str) -> bytes:
    if not NONCE_PATTERN.fullmatch(value):
        raise ValueError("nonce must be 16 base64url characters")
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as error:
        raise ValueError("nonce must be base64url") from error


def decode_salt(value: str) -> bytes:
    if not SALT_PATTERN.fullmatch(value):
        raise ValueError("salt must be 22 base64url characters")
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as error:
        raise ValueError("salt must be base64url") from error


def sanitize_filename(value: str) -> str:
    name = Path(value).name
    name = "".join(
        character
        for character in name
        if character.isprintable() and character not in '\\/:*?"<>|'
    ).strip()
    return (name or "download.bin")[:120]


def sanitize_mime(value: str) -> str:
    return value if MIME_PATTERN.fullmatch(value) else "application/octet-stream"


def sanitize_recipient_names(value: str) -> list[str]:
    names = []
    for part in re.split(r"[\n,;]+", value):
        name = "".join(
            character
            for character in part
            if character.isprintable() and character not in "\t\x0b\x0c\r\n"
        )
        name = re.sub(r"\s+", " ", name).strip()[:MAX_RECIPIENT_NAME_BYTES]
        if name and name not in names:
            names.append(name)
    return names


def create_app(data_dir: Path | None = None, max_upload_bytes: int = MAX_UPLOAD_BYTES) -> FastAPI:
    app = FastAPI(
        title="CipherShare",
        version="0.1.0",
        description="Ciphertext-only file sharing with expiring links.",
    )
    store = ShareStore(Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR)
    app.state.store = store
    app.state.max_upload_bytes = int(max_upload_bytes)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def no_static_caching(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "ciphershare", "version": "0.1.0"}

    @app.post("/shares", status_code=201)
    async def create_share(
        ciphertext: Annotated[UploadFile, File()],
        nonce: Annotated[str, Form()],
        filename: Annotated[str, Form()] = "download.bin",
        mime_type: Annotated[str, Form()] = "application/octet-stream",
        lifetime_seconds: Annotated[int, Form()] = 600,
        salt: Annotated[str, Form()] = "",
        kdf_iterations: Annotated[int, Form()] = 0,
        recipients: Annotated[str, Form()] = "",
    ) -> dict:
        try:
            nonce_bytes = decode_nonce(nonce)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        if len(nonce_bytes) != 12:
            raise HTTPException(status_code=400, detail="nonce must be exactly 12 bytes")

        salt_bytes = None
        iterations = None
        if salt or kdf_iterations:
            if not salt or not kdf_iterations:
                raise HTTPException(
                    status_code=400,
                    detail="salt and kdf_iterations must be provided together",
                )
            try:
                salt_bytes = decode_salt(salt)
            except ValueError as error:
                raise HTTPException(status_code=400, detail=str(error)) from error
            if len(salt_bytes) != 16:
                raise HTTPException(status_code=400, detail="salt must be 16 bytes")
            if not MIN_KDF_ITERATIONS <= kdf_iterations <= MAX_KDF_ITERATIONS:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "kdf_iterations must be between "
                        f"{MIN_KDF_ITERATIONS} and {MAX_KDF_ITERATIONS}"
                    ),
                )
            iterations = int(kdf_iterations)

        recipient_names = sanitize_recipient_names(recipients)
        if len(recipient_names) > MAX_RECIPIENTS:
            raise HTTPException(
                status_code=400,
                detail=f"at most {MAX_RECIPIENTS} recipients are allowed",
            )

        if not MIN_LIFETIME_SECONDS <= lifetime_seconds <= MAX_LIFETIME_SECONDS:
            raise HTTPException(
                status_code=400,
                detail=f"lifetime_seconds must be between {MIN_LIFETIME_SECONDS} and {MAX_LIFETIME_SECONDS}",
            )

        payload = await ciphertext.read(app.state.max_upload_bytes + 1)
        if len(payload) > app.state.max_upload_bytes:
            raise HTTPException(status_code=413, detail="encrypted payload is too large")
        if len(payload) < 16:
            raise HTTPException(
                status_code=400,
                detail="encrypted payload must contain ciphertext and an AES-GCM tag",
            )

        record = store.create_share(
            ciphertext=payload,
            nonce_b64=nonce,
            filename=sanitize_filename(filename),
            mime_type=sanitize_mime(mime_type),
            lifetime_seconds=lifetime_seconds,
            salt_b64=salt if salt_bytes is not None else None,
            kdf_iterations=iterations,
        )
        recipients_created = (
            store.add_recipients(record["share_id"], recipient_names)
            if recipient_names
            else []
        )
        for recipient in recipients_created:
            recipient.pop("label", None)
        return {
            "share_id": record["share_id"],
            "expires_at": record["expires_at"],
            "password_protected": salt_bytes is not None,
            "recipients": recipients_created,
        }

    @app.get("/shares/{share_id}")
    def download_share(share_id: str) -> Response:
        if not SHARE_ID_PATTERN.fullmatch(share_id):
            raise HTTPException(status_code=400, detail="invalid share id", headers={"Cache-Control": "no-store"})

        share = store.get_share(share_id)
        if share is None:
            raise HTTPException(status_code=404, detail="share not found", headers={"Cache-Control": "no-store"})
        if share["revoked"] or share["expires_at"] <= int(time.time()):
            raise HTTPException(status_code=410, detail="share expired or revoked", headers={"Cache-Control": "no-store"})

        ciphertext = store.read_ciphertext(share)
        if ciphertext is None:
            raise HTTPException(status_code=500, detail="stored ciphertext is unavailable", headers={"Cache-Control": "no-store"})

        filename = sanitize_filename(share["original_filename"])
        ascii_name = filename.encode("ascii", "ignore").decode("ascii") or "download.bin"
        headers = {
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_name}\"; "
                f"filename*=UTF-8''{quote(filename, safe='')}"
            ),
            "X-Nonce": share["nonce_b64"],
            "X-Expires-At": str(share["expires_at"]),
            "X-Filename": quote(filename, safe=""),
            "X-Mime-Type": share["mime_type"],
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        }
        if share["salt_b64"]:
            headers["X-Salt"] = share["salt_b64"]
            headers["X-Kdf-Iterations"] = str(share["kdf_iterations"])
        return Response(
            content=ciphertext,
            media_type="application/octet-stream",
            headers=headers,
        )

    def index_response() -> FileResponse:
        index = STATIC_DIR / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=404, detail="frontend not built")
        return FileResponse(
            index,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return index_response()

    @app.get("/s/{share_id}", include_in_schema=False)
    def share_page(share_id: str) -> FileResponse:
        return index_response()

    return app


app = create_app()
