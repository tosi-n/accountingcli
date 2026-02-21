from __future__ import annotations

import os

os.environ.setdefault("ACCOUNTINGCLI_INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY", "test-token-key")

from app import providers


def test_quickbooks_base_url_uses_production_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(providers.settings, "QUICKBOOKS_ENV", "production")
    monkeypatch.setattr(providers.settings, "QUICKBOOKS_BASE_URL", "https://sandbox-quickbooks.api.intuit.com")
    assert providers._quickbooks_base_url() == "https://quickbooks.api.intuit.com"


def test_quickbooks_base_url_uses_config_for_non_production(monkeypatch) -> None:
    monkeypatch.setattr(providers.settings, "QUICKBOOKS_ENV", "sandbox")
    monkeypatch.setattr(providers.settings, "QUICKBOOKS_BASE_URL", "https://sandbox-quickbooks.api.intuit.com")
    assert providers._quickbooks_base_url() == "https://sandbox-quickbooks.api.intuit.com"
