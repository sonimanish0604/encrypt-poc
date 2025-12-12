from typing import List, Optional

from config import get_settings
from crypto_utils import aes_gcm_decrypt, vault_decrypt_key
from db import get_connection


def _decrypt_field(dek: bytes, blob: Optional[bytes], label: str) -> Optional[str]:
    if blob is None:
        return None
    plaintext = aes_gcm_decrypt(dek, blob, label.encode("utf-8"))
    return plaintext.decode("utf-8")


def decrypt_records() -> List[dict]:
    """Return decrypted contact form rows for API and CLI consumption."""
    settings = get_settings()
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT
            dp.id,
            dp.first_name_enc,
            dp.middle_name_enc,
            dp.last_name_enc,
            dp.phone_enc,
            dp.email_enc,
            dp.phone_dnc,
            dp.email_dnc,
            dp.created_at,
            ek.dek_wrapped
        FROM contact_form dp
        JOIN encryption_keys ek ON dp.key_id = ek.id
        ORDER BY dp.id
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    records: List[dict] = []
    for row in rows:
        dek_wrapped = row["dek_wrapped"]
        if isinstance(dek_wrapped, (bytes, bytearray)):
            dek_wrapped = dek_wrapped.decode("utf-8")
        dek_plain = vault_decrypt_key(
            settings.vault_addr,
            settings.vault_token,
            settings.vault_transit_key,
            dek_wrapped,
        )
        records.append(
            {
                "id": row["id"],
                "first_name": _decrypt_field(dek_plain, row["first_name_enc"], "first_name"),
                "middle_name": _decrypt_field(dek_plain, row["middle_name_enc"], "middle_name"),
                "last_name": _decrypt_field(dek_plain, row["last_name_enc"], "last_name"),
                "phone": _decrypt_field(dek_plain, row["phone_enc"], "phone"),
                "email": _decrypt_field(dek_plain, row["email_enc"], "email"),
                "phone_dnc": bool(row["phone_dnc"]),
                "email_dnc": bool(row["email_dnc"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            }
        )
    return records


def run_etl() -> None:
    records = decrypt_records()
    if not records:
        print("No rows found.")
        return

    for rec in records:
        print(f"Row {rec['id']}:")
        print(f"  First Name: {rec['first_name']}")
        print(f"  Middle Name: {rec['middle_name'] or '-'}")
        print(f"  Last Name: {rec['last_name']}")
        print(f"  Phone: {rec['phone']}")
        print(f"  Email: {rec['email']}")
        print(f"  Flags: phone_dnc={rec['phone_dnc']} email_dnc={rec['email_dnc']}")
        print("")


if __name__ == "__main__":
    run_etl()
