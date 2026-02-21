from __future__ import annotations

import os

os.environ.setdefault("ACCOUNTINGCLI_INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY", "test-token-key")

from app.worker import _normalize_sync_types, _to_float, _token_expires_at


def test_normalize_sync_types_defaults_to_bank_transactions() -> None:
    assert _normalize_sync_types(None) == {"bank-transactions"}


def test_normalize_sync_types_maps_bills_to_invoices() -> None:
    assert _normalize_sync_types(["bills", "bank-transactions"]) == {"bank-transactions", "invoices"}


def test_to_float_handles_invalid_values() -> None:
    assert _to_float("12.34") == 12.34
    assert _to_float(None) is None
    assert _to_float("not-a-number") is None


def test_token_expires_at_accepts_numeric_strings() -> None:
    assert _token_expires_at({"expires_at": 123}) == 123
    assert _token_expires_at({"expires_at": "456"}) == 456
    assert _token_expires_at({}) == 0
