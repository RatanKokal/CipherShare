from __future__ import annotations

import base64
import os
import re
import sqlite3
import time
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app import create_app
from storage import ShareStore


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def nonce() -> str:
    return b64url(os.urandom(12))


@pytest.fixture()
def app(tmp_path):
    return create_app(tmp_path)


@pytest.fixture()
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def post_share(client, payload: bytes | None = None, **overrides):
    data = {
        "nonce": nonce(),
        "filename": "notes.txt",
        "mime_type": "text/plain",
        "lifetime_seconds": "600",
    }
    data.update(overrides)
    body = payload if payload is not None else os.urandom(512)
    return client.post(
        "/shares",
        files={"ciphertext": ("payload.bin", body, "application/octet-stream")},
        data=data,
    )


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_and_download_round_trip(client):
    payload = os.urandom(2048)
    created = post_share(client, payload)
    assert created.status_code == 201
    body = created.json()
    assert body["share_id"]
    assert body["expires_at"] > int(time.time())
    assert body["password_protected"] is False
    assert "key" not in body

    downloaded = client.get(f"/shares/{body['share_id']}")
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["x-nonce"]
    assert downloaded.headers["cache-control"] == "no-store"
    assert "attachment" in downloaded.headers["content-disposition"]


def test_unknown_share_returns_404(client):
    response = client.get("/shares/" + "A" * 32)
    assert response.status_code == 404


def test_expired_share_returns_410(app, client):
    record = app.state.store.create_share(
        ciphertext=os.urandom(64),
        nonce_b64=nonce(),
        filename="old.txt",
        mime_type="text/plain",
        lifetime_seconds=60,
        now=int(time.time()) - 120,
    )
    response = client.get(f"/shares/{record['share_id']}")
    assert response.status_code == 410


def test_revoked_share_returns_410(app, client):
    created = post_share(client)
    share_id = created.json()["share_id"]
    assert app.state.store.revoke_share(share_id)
    assert client.get(f"/shares/{share_id}").status_code == 410


def test_malformed_share_id_returns_400(client):
    assert client.get("/shares/short").status_code == 400
    assert client.get("/shares/" + "!" * 32).status_code == 400


def test_missing_nonce_returns_422(client):
    response = client.post(
        "/shares",
        files={"ciphertext": ("payload.bin", os.urandom(64), "application/octet-stream")},
        data={"filename": "x.bin"},
    )
    assert response.status_code == 422


def test_malformed_nonce_returns_400(client):
    response = post_share(client, nonce="not-base64!")
    assert response.status_code == 400


@pytest.mark.parametrize("bad_nonce", ["AAAAAAAAAAAAAAAA!!!!", "AAAAAAAAAAAAAAAA\r\n"])
def test_noncanonical_nonce_returns_400(client, bad_nonce):
    assert post_share(client, nonce=bad_nonce).status_code == 400


def test_short_payload_returns_400(client):
    assert post_share(client, b"short").status_code == 400


def test_empty_plaintext_ciphertext_is_accepted(client):
    created = post_share(client, b"\x00" * 16)
    assert created.status_code == 201
    downloaded = client.get(f"/shares/{created.json()['share_id']}")
    assert downloaded.status_code == 200
    assert downloaded.content == b"\x00" * 16


def test_oversized_upload_is_rejected(tmp_path):
    small_app = create_app(tmp_path, max_upload_bytes=1024)
    with TestClient(small_app) as small_client:
        response = post_share(small_client, os.urandom(2048))
    assert response.status_code == 413


def test_ciphertext_at_ten_mib_plaintext_limit_is_accepted(client):
    payload = os.urandom(10 * 1024 * 1024 + 16)
    created = post_share(client, payload)
    assert created.status_code == 201
    downloaded = client.get(f"/shares/{created.json()['share_id']}")
    assert downloaded.status_code == 200
    assert downloaded.content == payload


def test_password_split_share_round_trip(client):
    payload = os.urandom(1024)
    salt = b64url(os.urandom(16))
    created = post_share(
        client, payload, salt=salt, kdf_iterations="600000"
    )
    assert created.status_code == 201
    assert created.json()["password_protected"] is True

    share_id = created.json()["share_id"]
    downloaded = client.get(f"/shares/{share_id}")
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["x-salt"] == salt
    assert downloaded.headers["x-kdf-iterations"] == "600000"


def test_plain_share_has_no_kdf_headers(client):
    created = post_share(client)
    downloaded = client.get(f"/shares/{created.json()['share_id']}")
    assert "x-salt" not in downloaded.headers
    assert "x-kdf-iterations" not in downloaded.headers


def test_salt_without_iterations_is_rejected(client):
    assert post_share(client, salt=b64url(os.urandom(16))).status_code == 400


def test_iterations_without_salt_is_rejected(client):
    assert post_share(client, kdf_iterations="600000").status_code == 400


@pytest.mark.parametrize("bad_salt", ["short", "!" * 22, "A" * 21])
def test_malformed_salt_is_rejected(client, bad_salt):
    response = post_share(client, salt=bad_salt, kdf_iterations="600000")
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("iterations", "expected"),
    [("99999", 400), ("5000001", 400), ("zero", 422)],
)
def test_kdf_iterations_out_of_range_is_rejected(client, iterations, expected):
    response = post_share(
        client, salt=b64url(os.urandom(16)), kdf_iterations=iterations
    )
    assert response.status_code == expected


def test_share_with_recipients_round_trip(client):
    created = post_share(client, recipients="Ashwin\nPriya, Rohan")
    assert created.status_code == 201
    recipients = created.json()["recipients"]
    assert [r["name"] for r in recipients] == ["Ashwin", "Priya", "Rohan"]
    for recipient in recipients:
        assert re.fullmatch(r"[A-Za-z0-9_-]{22}", recipient["token"])
        assert "label" not in recipient
    assert len({r["token"] for r in recipients}) == 3

    share_id = created.json()["share_id"]
    with sqlite3.connect(client.app.state.store.db_path) as connection:
        rows = connection.execute(
            "SELECT display_name, token FROM recipients WHERE share_id = ?", (share_id,)
        ).fetchall()
    assert sorted(row[0] for row in rows) == ["Ashwin", "Priya", "Rohan"]
    assert all(row[1] for row in rows)


def test_tokens_are_globally_unique_across_shares(client):
    first = post_share(client, recipients="Same Name").json()["recipients"][0]["token"]
    second = post_share(client, recipients="Same Name").json()["recipients"][0]["token"]
    assert first != second


def test_download_response_contains_no_token_material(client):
    created = post_share(client, recipients="Priya")
    share_id = created.json()["share_id"]
    token = created.json()["recipients"][0]["token"]
    downloaded = client.get(f"/shares/{share_id}")
    assert downloaded.status_code == 200
    assert token not in downloaded.text
    assert not any("token" in header.lower() for header in downloaded.headers)


def test_recipient_names_are_sanitized(client):
    created = post_share(client, recipients="  spaced   name \n\n, ,\n\x01ctrl")
    assert created.status_code == 201
    recipients = created.json()["recipients"]
    assert [r["name"] for r in recipients] == ["spaced name", "ctrl"]


def test_duplicate_recipient_names_are_deduplicated(client):
    created = post_share(client, recipients="Ashwin\nAshwin")
    assert created.status_code == 201
    assert len(created.json()["recipients"]) == 1


def test_too_many_recipients_rejected(client):
    created = post_share(client, recipients="\n".join(f"user{i}" for i in range(21)))
    assert created.status_code == 400


def test_plain_share_has_empty_recipients(client):
    created = post_share(client)
    assert created.json()["recipients"] == []


def test_filename_is_sanitized(client):
    created = post_share(client, filename="../../hostel/minutes.txt")
    share_id = created.json()["share_id"]
    downloaded = client.get(f"/shares/{share_id}")
    assert downloaded.headers["x-filename"] == "minutes.txt"
    assert "minutes.txt" in downloaded.headers["content-disposition"]

    unicode_name = "परिपत्र.txt"
    created = post_share(client, filename=unicode_name)
    share_id = created.json()["share_id"]
    downloaded = client.get(f"/shares/{share_id}")
    encoded = quote(unicode_name, safe="")
    assert downloaded.headers["x-filename"] == encoded
    assert f"filename*=UTF-8''{encoded}" in downloaded.headers["content-disposition"]


def test_database_contains_no_key_column(app):
    with sqlite3.connect(app.state.store.db_path) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(shares)")]
    assert not any("key" in column.lower() for column in columns)
    assert "nonce_b64" in columns
    assert "expires_at" in columns


def test_share_persists_across_app_restart(tmp_path):
    first_app = create_app(tmp_path)
    with TestClient(first_app) as first_client:
        payload = os.urandom(256)
        created = post_share(first_client, payload)
        share_id = created.json()["share_id"]

    second_app = create_app(tmp_path)
    with TestClient(second_app) as second_client:
        downloaded = second_client.get(f"/shares/{share_id}")
    assert downloaded.status_code == 200
    assert downloaded.content == payload


def test_store_persists_ciphertext_after_reload(tmp_path):
    store = ShareStore(tmp_path)
    record = store.create_share(
        ciphertext=os.urandom(128),
        nonce_b64=nonce(),
        filename="report.pdf",
        mime_type="application/pdf",
        lifetime_seconds=600,
    )
    reloaded = ShareStore(tmp_path).get_share(record["share_id"])
    assert reloaded is not None
    assert reloaded["original_filename"] == "report.pdf"
