"""Vault API — lightweight encrypted key-value secret store.

Secrets are persisted to ``vault_data.json`` (next to the backend root) and
encrypted with Fernet (AES-128-CBC + HMAC-SHA256).  The encryption key is
derived from the ``LOCAL_AUTH_TOKEN`` setting so no extra secrets are required.

Routes (all require authentication):
    GET  /vault/list    — list stored secret keys (values are never returned in bulk)
    POST /vault/set     — upsert a key-value pair
    POST /vault/delete  — delete a key by name
    GET  /vault/{key}   — fetch the decrypted value for a single key (agents use this)
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import require_user_auth
from app.core.auth import AuthContext
from app.core.config import BACKEND_ROOT, settings
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/vault", tags=["vault"])

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

_VAULT_FILE = BACKEND_ROOT / "vault_data.json"


def _derive_fernet_key() -> bytes:
    """Derive a 32-byte key from LOCAL_AUTH_TOKEN and base64-url-encode it for Fernet."""
    import base64

    seed = settings.local_auth_token.encode() if settings.local_auth_token else b"mission-control-default-vault-key"
    digest = hashlib.sha256(seed).digest()  # always 32 bytes
    return base64.urlsafe_b64encode(digest)  # Fernet requires exactly 32 raw bytes → 44 b64 chars


def _get_fernet() -> Any:
    try:
        from cryptography.fernet import Fernet  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "The 'cryptography' package is required for the vault. "
            "Install it with: uv add cryptography"
        ) from exc
    return Fernet(_derive_fernet_key())


def _load_vault() -> dict[str, str]:
    """Load and decrypt the vault store from disk."""
    if not _VAULT_FILE.exists():
        return {}
    try:
        raw: dict[str, str] = json.loads(_VAULT_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("vault.load_failed path=%s", _VAULT_FILE)
        return {}

    fernet = _get_fernet()
    decrypted: dict[str, str] = {}
    for k, v in raw.items():
        try:
            decrypted[k] = fernet.decrypt(v.encode()).decode()
        except Exception:  # noqa: BLE001
            # Skip corrupted entries rather than crash.
            logger.warning("vault.decrypt_failed key=%s", k)
    return decrypted


def _save_vault(data: dict[str, str]) -> None:
    """Encrypt and persist the vault store to disk."""
    fernet = _get_fernet()
    encrypted = {k: fernet.encrypt(v.encode()).decode() for k, v in data.items()}
    _VAULT_FILE.write_text(json.dumps(encrypted, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class VaultItem(BaseModel):
    key: str
    updated_at: str | None = None


class VaultListResponse(BaseModel):
    items: list[VaultItem]


class VaultSetRequest(BaseModel):
    key: str
    value: str


class VaultSetResponse(BaseModel):
    ok: bool
    key: str


class VaultDeleteRequest(BaseModel):
    key: str


class VaultDeleteResponse(BaseModel):
    ok: bool
    key: str


class VaultGetResponse(BaseModel):
    key: str
    value: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

AUTH_DEP = Depends(require_user_auth)


@router.get("/list", response_model=VaultListResponse)
def list_vault_keys(_auth: AuthContext = AUTH_DEP) -> VaultListResponse:
    """Return all stored secret key names.  Values are never exposed in bulk."""
    data = _load_vault()
    return VaultListResponse(items=[VaultItem(key=k) for k in sorted(data.keys())])


@router.post("/set", response_model=VaultSetResponse)
def set_vault_key(payload: VaultSetRequest, _auth: AuthContext = AUTH_DEP) -> VaultSetResponse:
    """Upsert a key-value pair in the vault."""
    if not payload.key.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="key must not be blank")
    if not payload.value.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="value must not be blank")
    data = _load_vault()
    data[payload.key.strip()] = payload.value.strip()
    _save_vault(data)
    logger.info("vault.set key=%s", payload.key)
    return VaultSetResponse(ok=True, key=payload.key.strip())


@router.post("/delete", response_model=VaultDeleteResponse)
def delete_vault_key(payload: VaultDeleteRequest, _auth: AuthContext = AUTH_DEP) -> VaultDeleteResponse:
    """Delete a key from the vault."""
    data = _load_vault()
    if payload.key not in data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Key '{payload.key}' not found")
    del data[payload.key]
    _save_vault(data)
    logger.info("vault.delete key=%s", payload.key)
    return VaultDeleteResponse(ok=True, key=payload.key)


@router.get("/{key}", response_model=VaultGetResponse)
def get_vault_key(key: str, _auth: AuthContext = AUTH_DEP) -> VaultGetResponse:
    """Fetch the decrypted value for a single key.  Used by agents at runtime."""
    data = _load_vault()
    if key not in data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Key '{key}' not found")
    return VaultGetResponse(key=key, value=data[key])
