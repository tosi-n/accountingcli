from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.fernet import Fernet


def _as_fernet_key(key: str) -> bytes:
    b = key.encode("utf-8")
    base64.urlsafe_b64decode(b)
    return b


class TokenCipher:
    def __init__(self, fernet_key: str):
        self._fernet = Fernet(_as_fernet_key(fernet_key))

    def encrypt_json(self, obj: Any) -> str:
        payload = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return self._fernet.encrypt(payload).decode("utf-8")

    def decrypt_json(self, token: str) -> Any:
        raw = self._fernet.decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))

