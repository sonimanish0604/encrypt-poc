import secrets
import time
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, EmailStr, Field

from config import get_settings
from crypto_utils import aes_gcm_encrypt, vault_decrypt_key, vault_encrypt_key
from db import get_connection, init_schema

app = FastAPI(title="Encryption PoC")

settings = get_settings()
VAULT_ADDR = settings.vault_addr
VAULT_TOKEN = settings.vault_token
VAULT_TRANSIT_KEY = settings.vault_transit_key
LOGICAL_NAME = "contact_pii"
KEK_ID = "vault-transit:pii-master"


class ContactForm(BaseModel):
    first_name: str = Field(min_length=1, max_length=128)
    middle_name: Optional[str] = Field(default=None, max_length=128)
    last_name: str = Field(min_length=1, max_length=128)
    phone: str = Field(min_length=5, max_length=32)
    email: EmailStr
    phone_dnc: bool
    email_dnc: bool


@app.on_event("startup")
def startup_event():
    _wait_for_vault()
    _bootstrap_vault_transit()
    _wait_for_mysql()
    init_schema()
    _ensure_active_dek()


def _bootstrap_vault_transit():
    import requests

    headers = {"X-Vault-Token": VAULT_TOKEN}
    mounts_resp = requests.get(f"{VAULT_ADDR}/v1/sys/mounts", headers=headers, timeout=5)
    mounts_resp.raise_for_status()
    mounts = mounts_resp.json().get("data", {})

    if "transit/" not in mounts:
        resp = requests.post(
            f"{VAULT_ADDR}/v1/sys/mounts/transit",
            headers=headers,
            json={"type": "transit"},
            timeout=5,
        )
        resp.raise_for_status()

    key_resp = requests.get(f"{VAULT_ADDR}/v1/transit/keys/{VAULT_TRANSIT_KEY}", headers=headers, timeout=5)
    if key_resp.status_code == 404:
        resp = requests.post(
            f"{VAULT_ADDR}/v1/transit/keys/{VAULT_TRANSIT_KEY}",
            headers=headers,
            json={},
            timeout=5,
        )
        resp.raise_for_status()


def _wait_for_vault(max_attempts: int = 15, delay: float = 2.0) -> None:
    import requests

    health_url = f"{VAULT_ADDR}/v1/sys/health"
    for _ in range(max_attempts):
        try:
            resp = requests.get(health_url, timeout=3)
            if resp.status_code in {200, 429, 472, 473, 499}:
                return
        except requests.RequestException:
            pass
        time.sleep(delay)
    raise RuntimeError("Vault not ready; check enc_vault logs.")


def _wait_for_mysql(max_attempts: int = 20, delay: float = 2.0) -> None:
    for _ in range(max_attempts):
        try:
            conn = get_connection()
            conn.close()
            return
        except Exception:
            time.sleep(delay)
    raise RuntimeError("MySQL not ready; check enc_mysql logs.")


def _ensure_active_dek():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id FROM encryption_keys
        WHERE logical_name = %s AND status = 'active'
        LIMIT 1
        """,
        (LOGICAL_NAME,),
    )
    row = cur.fetchone()

    if not row:
        dek_plain = secrets.token_bytes(32)
        dek_wrapped = vault_encrypt_key(VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY, dek_plain)
        cur.execute(
            """
            INSERT INTO encryption_keys (logical_name, dek_wrapped, kek_id, status)
            VALUES (%s, %s, %s, 'active')
            """,
            (LOGICAL_NAME, dek_wrapped, KEK_ID),
        )
        conn.commit()

    cur.close()
    conn.close()


def _get_active_dek():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, dek_wrapped FROM encryption_keys
        WHERE logical_name = %s AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (LOGICAL_NAME,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    key_id, dek_wrapped = row
    dek_plain = vault_decrypt_key(VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY, dek_wrapped)
    return key_id, dek_plain


@app.post("/submit")
def submit_form(form: ContactForm):
    key_id, dek_plain = _get_active_dek()

    def encrypt_field(value: Optional[str], label: str) -> Optional[bytes]:
        if value is None:
            return None
        return aes_gcm_encrypt(dek_plain, value.encode("utf-8"), label.encode("utf-8"))

    f_enc = encrypt_field(form.first_name, "first_name")
    m_enc = encrypt_field(form.middle_name, "middle_name")
    l_enc = encrypt_field(form.last_name, "last_name")
    p_enc = encrypt_field(form.phone, "phone")
    e_enc = encrypt_field(form.email, "email")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO contact_form (
            first_name_enc,
            middle_name_enc,
            last_name_enc,
            phone_enc,
            email_enc,
            phone_dnc,
            email_dnc,
            key_id
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (f_enc, m_enc, l_enc, p_enc, e_enc, form.phone_dnc, form.email_dnc, key_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "Encryption PoC is running. POST /submit with form data."}
