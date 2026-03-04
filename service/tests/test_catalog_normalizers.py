from __future__ import annotations

import os

os.environ.setdefault("ACCOUNTINGCLI_INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY", "test-token-key")

from app import main


def test_normalize_xero_tax_codes_parses_display_rate() -> None:
    rows = [
        {
            "TaxType": "OUTPUT2",
            "Name": "20% VAT on Income",
            "DisplayTaxRate": "20.0",
            "TaxTypeID": "abc",
        }
    ]
    normalized = main._normalize_xero_tax_codes(rows)
    assert len(normalized) == 1
    assert normalized[0]["code"] == "OUTPUT2"
    assert normalized[0]["name"] == "20% VAT on Income"
    assert normalized[0]["rate"] == 20.0
    assert normalized[0]["platform_record_id"] == "abc"


def test_normalize_quickbooks_account_codes_prefers_acct_num() -> None:
    rows = [
        {
            "Id": "92",
            "AcctNum": "400",
            "Name": "Advertising",
            "AccountType": "Expense",
            "Active": True,
        }
    ]
    normalized = main._normalize_quickbooks_account_codes(rows)
    assert len(normalized) == 1
    assert normalized[0]["code"] == "400"
    assert normalized[0]["platform_record_id"] == "92"
    assert normalized[0]["type"] == "Expense"
    assert normalized[0]["status"] == "ACTIVE"


def test_normalize_free_agent_tax_codes_deduplicates_rates() -> None:
    rows = [
        {"auto_sales_tax_rate": "20.0"},
        {"auto_sales_tax_rate": "20.0"},
        {"auto_sales_tax_rate": "0.0"},
    ]
    normalized = main._normalize_free_agent_tax_codes(rows)
    assert len(normalized) == 2
    rates = sorted(item["rate"] for item in normalized if item["rate"] is not None)
    assert rates == [0.0, 20.0]


def test_normalize_quickbooks_tax_codes_uses_tax_rate_lookup() -> None:
    tax_rate_index = main._quickbooks_tax_rate_index([{"Id": "7", "RateValue": "20"}])
    rows = [
        {
            "Id": "4",
            "Name": "VAT",
            "SalesTaxRateList": {"TaxRateDetail": [{"TaxRateRef": {"value": "7"}}]},
            "Active": True,
        }
    ]
    normalized = main._normalize_quickbooks_tax_codes(rows, tax_rate_by_id=tax_rate_index)
    assert len(normalized) == 1
    assert normalized[0]["code"] == "VAT"
    assert normalized[0]["rate"] == 20.0
