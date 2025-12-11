import base64
import os
from typing import Optional

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    """Encrypt bytes using AES-256-GCM (nonce + ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: Optional[bytes] = None) -> bytes:
    """Decrypt bytes produced by aes_gcm_encrypt."""
    aesgcm = AESGCM(key)
    nonce, ciphertext = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, aad)


def vault_encrypt_key(vault_addr: str, token: str, transit_key: str, dek_plain: bytes) -> str:
    """Encrypt a DEK using Vault Transit and return wrapped ciphertext."""
    url = f"{vault_addr}/v1/transit/encrypt/{transit_key}"
    payload = {"plaintext": base64.b64encode(dek_plain).decode("utf-8")}
    headers = {"X-Vault-Token": token}
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()["data"]["ciphertext"]


def vault_decrypt_key(vault_addr: str, token: str, transit_key: str, dek_wrapped: str) -> bytes:
    """Unwrap the DEK through Vault Transit."""
    url = f"{vault_addr}/v1/transit/decrypt/{transit_key}"
    headers = {"X-Vault-Token": token}
    payload = {"ciphertext": dek_wrapped}
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
    plaintext_b64 = resp.json()["data"]["plaintext"]
    return base64.b64decode(plaintext_b64)
