from __future__ import annotations

import base64
import hashlib
import hmac
import os

os.environ.setdefault("ACCOUNTINGCLI_INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY", "test-token-key")

from app import main


def _signed(secret: str, payload: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def test_verify_xero_webhook_signature(monkeypatch) -> None:
    payload = b'{"events":[{"tenantId":"tenant-123"}]}'
    monkeypatch.setattr(main.settings, "XERO_WEBHOOK_SIGNING_KEY", "xero-secret")

    assert main._verify_xero_webhook_signature(payload, _signed("xero-secret", payload)) is True
    assert main._verify_xero_webhook_signature(payload, "invalid") is False


def test_verify_quickbooks_webhook_signature(monkeypatch) -> None:
    payload = b'{"eventNotifications":[{"realmId":"123"}]}'
    monkeypatch.setattr(main.settings, "QUICKBOOKS_WEBHOOK_VERIFIER_TOKEN", "qbo-secret")

    assert main._verify_quickbooks_webhook_signature(payload, _signed("qbo-secret", payload)) is True
    assert main._verify_quickbooks_webhook_signature(payload, "invalid") is False


def test_build_xero_forward_events_normalizes_invoice_event() -> None:
    payload = {
        "events": [
            {
                "tenantId": "tenant-123",
                "resourceId": "invoice-1",
                "resourceUrl": "https://api.xero.com/api.xro/2.0/Invoices/invoice-1",
                "eventCategory": "INVOICE",
                "eventType": "CREATE",
                "eventDateUtc": "2026-03-12T09:30:00Z",
            }
        ],
        "firstEventSequence": 76,
        "lastEventSequence": 76,
    }

    events = main._build_xero_forward_events(payload, True, {"x-xero-signature": "sig"})

    assert len(events) == 1
    assert events[0]["provider"] == "xero"
    assert events[0]["provider_account_id"] == "tenant-123"
    assert events[0]["object_type"] == "invoice"
    assert events[0]["external_id"] == "invoice-1"
    assert events[0]["auto_create_proposal"] is True


def test_build_quickbooks_forward_events_normalizes_entity_change() -> None:
    payload = {
        "eventNotifications": [
            {
                "realmId": "realm-456",
                "dataChangeEvent": {
                    "entities": [
                        {
                            "name": "Bill",
                            "id": "42",
                            "operation": "Update",
                            "lastUpdated": "2026-03-12T09:30:00Z",
                        }
                    ]
                },
            }
        ]
    }

    events = main._build_quickbooks_forward_events(payload, True, {"intuit-signature": "sig"})

    assert len(events) == 1
    assert events[0]["provider"] == "quickbooks"
    assert events[0]["provider_account_id"] == "realm-456"
    assert events[0]["object_type"] == "bill"
    assert events[0]["external_id"] == "42"
    assert events[0]["auto_create_proposal"] is True
