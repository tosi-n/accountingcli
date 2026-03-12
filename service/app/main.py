from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
from typing import Any
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.choreo_runtime import choreo
from app.crypto import TokenCipher
from app.db import AccountingConnection, BankTransaction, Invoice, OAuthState, SyncRun, WebhookReceipt, init_db, session_scope
from app.internal_auth import require_internal_api_key
from app.providers import (
    build_authorize_url,
    exchange_code,
    free_agent_create_bill,
    free_agent_create_bank_transaction_explanation,
    free_agent_get_bank_accounts,
    free_agent_get_bank_transactions,
    free_agent_get_categories,
    free_agent_get_clients,
    quickbooks_create_bill,
    quickbooks_create_bill_payment,
    quickbooks_get_accounts,
    quickbooks_upload_attachment,
    quickbooks_get_vendors,
    quickbooks_get_tax_codes,
    quickbooks_get_tax_rates,
    refresh_token as provider_refresh_token,
    xero_create_payments,
    xero_create_invoices,
    xero_get_accounts,
    xero_get_connections,
    xero_get_tax_rates,
    xero_upload_invoice_attachment,
)
from app.settings import settings


app = FastAPI(title="accountingcli", version="0.1.0")
SUPPORTED_PROVIDERS = {"xero", "quickbooks", "sage", "free_agent"}


@app.on_event("startup")
async def _startup() -> None:
    os.makedirs("/data", exist_ok=True)
    await init_db()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class AuthorizeUrlIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID
    referrer_url: str | None = None


class ExchangeIn(BaseModel):
    callback_url: str


class DisconnectIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID


class SyncIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID
    sync_types: list[str] = ["bank-transactions"]


class PublishIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID
    payload: dict[str, Any]
    idempotency_key: str | None = None


class PaymentIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID
    provider_record_id: str
    payload: dict[str, Any]
    idempotency_key: str | None = None


class OAuthStatusOut(BaseModel):
    status: str
    tenant_id: str | None = None
    tenant_name: str | None = None


def _cipher() -> TokenCipher:
    return TokenCipher(settings.ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY)


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _payload_sha256(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def _headers_to_dict(request: Request) -> dict[str, str]:
    return {str(key): str(value) for key, value in request.headers.items()}


def _verify_xero_webhook_signature(payload_bytes: bytes, signature: str | None) -> bool:
    secret = str(settings.XERO_WEBHOOK_SIGNING_KEY or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="XERO_WEBHOOK_SIGNING_KEY not configured")
    if not signature:
        return False
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature)


def _verify_quickbooks_webhook_signature(payload_bytes: bytes, signature: str | None) -> bool:
    secret = str(settings.QUICKBOOKS_WEBHOOK_VERIFIER_TOKEN or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="QUICKBOOKS_WEBHOOK_VERIFIER_TOKEN not configured")
    if not signature:
        return False
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature)


def _normalize_payload_json(payload_bytes: bytes) -> dict[str, Any]:
    if not payload_bytes:
        return {}
    try:
        value = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")
    return value


async def _find_connections_for_provider_account(
    db: AsyncSession,
    *,
    provider: str,
    provider_account_id: str,
) -> list[AccountingConnection]:
    if not provider_account_id:
        return []
    rows = (
        await db.execute(
            select(AccountingConnection).where(
                AccountingConnection.provider == provider,
            )
        )
    ).scalars().all()
    matches: list[AccountingConnection] = []
    for row in rows:
        metadata = dict(row.metadata_ or {})
        candidate_ids = {
            str(row.tenant_id or "").strip(),
            str(metadata.get("realm_id") or "").strip(),
            str(metadata.get("tenant_id") or "").strip(),
            str(metadata.get("tenantId") or "").strip(),
        }
        candidate_ids.discard("")
        if provider_account_id in candidate_ids:
            matches.append(row)
    return matches


async def _forward_ledger_event(payload: dict[str, Any]) -> None:
    base = str(settings.BACKEND_PUBLIC_ORIGIN or "").strip().rstrip("/")
    if not base:
        raise HTTPException(status_code=500, detail="BACKEND_PUBLIC_ORIGIN not configured")
    path = str(settings.BACKEND_LEDGER_INGEST_PATH or "").strip() or "/api/v1/internal/ledger/provider-events"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{base}{path}",
            headers={"X-Internal-API-Key": settings.ACCOUNTINGCLI_INTERNAL_API_KEY},
            json=payload,
        )
        response.raise_for_status()


async def _upsert_webhook_receipt(
    db: AsyncSession,
    *,
    provider: str,
    provider_account_id: str | None,
    idempotency_key: str,
    signature_verified: bool,
    request: Request,
    payload_json: dict[str, Any],
    payload_bytes: bytes,
) -> tuple[WebhookReceipt, bool]:
    existing = (
        await db.execute(
            select(WebhookReceipt).where(
                WebhookReceipt.provider == provider,
                WebhookReceipt.idempotency_key == idempotency_key,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False

    receipt = WebhookReceipt(
        provider=provider,
        provider_account_id=provider_account_id,
        idempotency_key=idempotency_key,
        signature_verified=signature_verified,
        payload_sha256=_payload_sha256(payload_bytes),
        headers=_headers_to_dict(request),
        payload=payload_json,
        status="received",
    )
    db.add(receipt)
    await db.flush()
    return receipt, True


def _token_expires_at(token: dict[str, Any]) -> int:
    value = token.get("expires_at")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


async def _maybe_refresh_connection_token(db: AsyncSession, conn: AccountingConnection) -> dict[str, Any]:
    token = _cipher().decrypt_json(conn.token_encrypted)
    if _token_expires_at(token) > int(time.time()) + 60:
        return token
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        return token
    refreshed = await provider_refresh_token(conn.provider, str(refresh_token))
    conn.token_encrypted = _cipher().encrypt_json(refreshed)
    conn.updated_at = dt.datetime.now(dt.UTC)
    await db.commit()
    await db.refresh(conn)
    return refreshed


async def _persist_connection_metadata(
    db: AsyncSession,
    conn: AccountingConnection,
    *,
    tenant_id: str | None = None,
    tenant_name: str | None = None,
    metadata_patch: dict[str, Any] | None = None,
) -> None:
    changed = False
    if tenant_id is not None and tenant_id != conn.tenant_id:
        conn.tenant_id = tenant_id
        changed = True
    if tenant_name is not None and tenant_name != conn.tenant_name:
        conn.tenant_name = tenant_name
        changed = True
    if metadata_patch:
        merged = dict(conn.metadata_ or {})
        merged.update(metadata_patch)
        if merged != dict(conn.metadata_ or {}):
            conn.metadata_ = merged
            changed = True
    if changed:
        conn.updated_at = dt.datetime.now(dt.UTC)
        await db.commit()
        await db.refresh(conn)


async def _resolve_xero_tenant_id(
    db: AsyncSession,
    conn: AccountingConnection,
    token: dict[str, Any],
) -> str | None:
    if conn.tenant_id:
        return conn.tenant_id
    try:
        connections = await xero_get_connections(token)
    except Exception:
        return None
    if not connections:
        return None
    tenant_id = str(connections[0].get("tenantId") or "")
    tenant_name = str(connections[0].get("tenantName") or "") or None
    if not tenant_id:
        return None
    await _persist_connection_metadata(db, conn, tenant_id=tenant_id, tenant_name=tenant_name)
    return tenant_id


def _resolve_quickbooks_realm_id(conn: AccountingConnection, token: dict[str, Any]) -> str | None:
    metadata = dict(conn.metadata_ or {})
    realm_id = conn.tenant_id or metadata.get("realm_id") or token.get("realm_id")
    return str(realm_id) if realm_id else None


async def _resolve_free_agent_subdomain(
    db: AsyncSession,
    conn: AccountingConnection,
    token: dict[str, Any],
) -> str | None:
    subdomain = conn.tenant_id or token.get("business_id") or token.get("businessId")
    tenant_name = conn.tenant_name or token.get("business_name") or token.get("businessName")
    metadata_patch: dict[str, Any] = {}

    if not subdomain:
        try:
            clients = await free_agent_get_clients(token)
            items = clients.get("clients") or []
            if items:
                subdomain = items[0].get("subdomain")
                tenant_name = items[0].get("name")
                metadata_patch["available_clients"] = items[:20]
        except Exception:
            subdomain = None

    if subdomain:
        await _persist_connection_metadata(
            db,
            conn,
            tenant_id=str(subdomain),
            tenant_name=str(tenant_name) if tenant_name else None,
            metadata_patch=metadata_patch or None,
        )
    return str(subdomain) if subdomain else None


def _normalize_xero_account_codes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "code": row.get("Code") or None,
                "name": row.get("Name") or None,
                "platform_record_id": row.get("AccountID") or None,
                "type": row.get("Type") or None,
                "status": row.get("Status") or None,
                "raw": row,
            }
        )
    return out


def _normalize_xero_tax_codes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "code": row.get("TaxType") or None,
                "name": row.get("Name") or None,
                "rate": _to_float(row.get("DisplayTaxRate") or row.get("EffectiveRate")),
                "platform_record_id": row.get("TaxTypeID") or None,
                "status": row.get("Status") or None,
                "raw": row,
            }
        )
    return out


def _normalize_quickbooks_account_codes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "code": row.get("AcctNum") or row.get("Id") or None,
                "name": row.get("Name") or row.get("FullyQualifiedName") or None,
                "platform_record_id": row.get("Id") or None,
                "type": row.get("AccountType") or row.get("Classification") or None,
                "status": "ACTIVE" if row.get("Active", True) else "INACTIVE",
                "raw": row,
            }
        )
    return out


def _quickbooks_tax_rate_index(rows: list[dict[str, Any]]) -> dict[str, float]:
    out: dict[str, float] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        rate_id = row.get("Id")
        rate_value = _to_float(row.get("RateValue"))
        if rate_id and rate_value is not None:
            out[str(rate_id)] = rate_value
    return out


def _normalize_quickbooks_tax_codes(
    rows: list[dict[str, Any]],
    *,
    tax_rate_by_id: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    tax_rate_by_id = tax_rate_by_id or {}
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rate: float | None = None
        detail_groups = [
            (row.get("SalesTaxRateList") or {}).get("TaxRateDetail"),
            (row.get("PurchaseTaxRateList") or {}).get("TaxRateDetail"),
        ]
        for details in detail_groups:
            if not isinstance(details, list):
                continue
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                ref = detail.get("TaxRateRef") or {}
                ref_id = str(ref.get("value") or "")
                if ref_id and ref_id in tax_rate_by_id:
                    rate = tax_rate_by_id[ref_id]
                    break
            if rate is not None:
                break

        out.append(
            {
                "code": row.get("Name") or row.get("Id") or None,
                "name": row.get("Name") or None,
                "rate": rate,
                "platform_record_id": row.get("Id") or None,
                "status": "ACTIVE" if row.get("Active", True) else "INACTIVE",
                "raw": row,
            }
        )
    return out


def _normalize_free_agent_account_codes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "code": row.get("nominal_code") or row.get("code") or row.get("url") or None,
                "name": row.get("description") or row.get("category") or row.get("name") or None,
                "platform_record_id": row.get("url") or row.get("id") or None,
                "type": row.get("category") or None,
                "status": "ACTIVE",
                "raw": row,
            }
        )
    return out


def _normalize_free_agent_tax_codes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_rate = row.get("auto_sales_tax_rate")
        rate = _to_float(raw_rate)
        code = str(raw_rate) if raw_rate is not None else None
        key = f"{code}|{rate}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "code": code,
                "name": f"{code}%" if code else None,
                "rate": rate,
                "platform_record_id": None,
                "status": "ACTIVE",
                "raw": {"auto_sales_tax_rate": raw_rate},
            }
        )
    return out


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_date(value: Any) -> str | None:
    text = _as_text(value)
    if not text:
        return None
    if "T" in text:
        text = text.split("T", 1)[0]
    if " " in text:
        text = text.split(" ", 1)[0]
    return text or None


def _normalize_token(value: Any) -> str:
    text = _as_text(value).lower()
    if not text:
        return ""
    return re.sub(r"[^a-z0-9]+", "", text)


def _coalesce_text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _as_text(payload.get(key))
        if value:
            return value
    return None


def _coalesce_float(payload: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = _to_float(payload.get(key))
        if value is not None:
            return value
    return None


def _coalesce_bool(payload: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, bool):
            return value
        text = _as_text(value).lower()
        if text in {"true", "1", "yes", "y"}:
            return True
        if text in {"false", "0", "no", "n"}:
            return False
    return None


def _extract_attachments(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("attachments")
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for row in raw:
        if not isinstance(row, dict):
            continue
        url = _coalesce_text(row, "url", "access_url", "signed_url", "download_url")
        filename = _coalesce_text(row, "filename", "name", "storage_key")
        if filename:
            filename = os.path.basename(filename)
        content_type = _coalesce_text(row, "content_type", "mime_type") or "application/octet-stream"
        if not url or not filename:
            continue
        out.append(
            {
                "document_id": _coalesce_text(row, "document_id"),
                "url": url,
                "filename": filename,
                "content_type": content_type,
                "kind": _coalesce_text(row, "kind", "document_kind"),
                "content_base64": _coalesce_text(row, "content_base64"),
            }
        )
    return out


def _extract_payment_request(payload: dict[str, Any]) -> dict[str, Any] | None:
    raw = payload.get("payment")
    payment = dict(raw) if isinstance(raw, dict) else {}
    mark_paid = _coalesce_bool(payment, "mark_paid")
    if mark_paid is None:
        mark_paid = _coalesce_bool(payload, "mark_paid")
    if not mark_paid:
        return None
    amount = _coalesce_float(payment, "amount") or _coalesce_float(payload, "amount", "total")
    payment_date = _normalize_date(_coalesce_text(payment, "payment_date", "date") or _coalesce_text(payload, "payment_date", "date", "invoice_date"))
    bank_account = _coalesce_text(payment, "bank_account_name", "bank_account") or _coalesce_text(payload, "bank_account")
    bank_account_id = _coalesce_text(payment, "bank_account_id", "account_id")
    reference = _coalesce_text(payment, "reference") or _coalesce_text(payload, "reference", "invoice_number")
    return {
        "mark_paid": True,
        "amount": amount,
        "payment_date": payment_date,
        "bank_account": bank_account,
        "bank_account_id": bank_account_id,
        "reference": reference,
    }


async def _download_attachment_entry(entry: dict[str, Any]) -> tuple[bytes, str]:
    url = _coalesce_text(entry, "url")
    if not url:
        raise RuntimeError("Attachment entry is missing url")
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        content_type = response.headers.get("content-type") or _coalesce_text(entry, "content_type") or "application/octet-stream"
        return response.content, content_type.split(";", 1)[0].strip() or "application/octet-stream"


def _extract_publish_line_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_items = payload.get("line_items")
    out: list[dict[str, Any]] = []
    if isinstance(raw_items, list):
        for row in raw_items:
            if not isinstance(row, dict):
                continue
            amount = _coalesce_float(row, "amount", "line_amount", "line_total", "total")
            quantity = _coalesce_float(row, "quantity", "qty")
            unit_amount = _coalesce_float(row, "unit_amount", "unit_price", "price")
            description = _coalesce_text(row, "description", "name")
            if amount is None and quantity is not None and unit_amount is not None:
                amount = quantity * unit_amount
            out.append(
                {
                    "description": description,
                    "amount": amount,
                    "quantity": quantity,
                    "unit_amount": unit_amount,
                    "account_code": _coalesce_text(row, "account_code", "account_category"),
                    "tax_code": _coalesce_text(row, "tax_code", "tax_type"),
                    "tax": _coalesce_float(row, "tax"),
                }
            )
    if out:
        return out

    amount = _coalesce_float(payload, "amount", "total")
    return [
        {
            "description": _coalesce_text(payload, "description", "summary", "vendor"),
            "amount": amount,
            "quantity": 1.0 if amount is not None else None,
            "unit_amount": amount,
            "account_code": _coalesce_text(payload, "account_code"),
            "tax_code": _coalesce_text(payload, "tax_code"),
            "tax": _coalesce_float(payload, "tax"),
        }
    ]


async def _resolve_quickbooks_account_ref(
    token: dict[str, Any],
    realm_id: str,
    payload: dict[str, Any],
) -> str | None:
    direct = _coalesce_text(payload, "account_platform_record_id", "account_id")
    if direct:
        return direct

    candidates = [
        _coalesce_text(payload, "account_code"),
        _coalesce_text(payload, "account_name"),
        _coalesce_text(payload, "category"),
    ]
    candidate_tokens = {_normalize_token(v) for v in candidates if v}
    if not candidate_tokens:
        return None

    page_size = 200
    max_pages = 20
    for page in range(1, max_pages + 1):
        start_position = ((page - 1) * page_size) + 1
        response = await quickbooks_get_accounts(
            token,
            realm_id,
            start_position=start_position,
            max_results=page_size,
        )
        rows = (response.get("QueryResponse") or {}).get("Account") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            probe_tokens = {
                _normalize_token(row.get("Id")),
                _normalize_token(row.get("AcctNum")),
                _normalize_token(row.get("Name")),
                _normalize_token(row.get("FullyQualifiedName")),
            }
            if candidate_tokens.intersection({t for t in probe_tokens if t}):
                resolved = _as_text(row.get("Id"))
                if resolved:
                    return resolved
        if len(rows) < page_size:
            break
    return None


async def _resolve_quickbooks_bank_account_ref(
    token: dict[str, Any],
    realm_id: str,
    payload: dict[str, Any],
) -> str | None:
    direct = _coalesce_text(payload, "bank_account_id")
    if direct:
        return direct

    candidate = _coalesce_text(payload, "bank_account")
    if not candidate:
        return None
    candidate_token = _normalize_token(candidate)
    if not candidate_token:
        return None

    page_size = 200
    max_pages = 20
    for page in range(1, max_pages + 1):
        start_position = ((page - 1) * page_size) + 1
        response = await quickbooks_get_accounts(
            token,
            realm_id,
            start_position=start_position,
            max_results=page_size,
        )
        rows = (response.get("QueryResponse") or {}).get("Account") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            account_type = _normalize_token(row.get("AccountType"))
            if account_type not in {"bank", "creditcard"}:
                continue
            probe_tokens = {
                _normalize_token(row.get("Id")),
                _normalize_token(row.get("AcctNum")),
                _normalize_token(row.get("Name")),
                _normalize_token(row.get("FullyQualifiedName")),
            }
            if candidate_token in {t for t in probe_tokens if t}:
                resolved = _as_text(row.get("Id"))
                if resolved:
                    return resolved
        if len(rows) < page_size:
            break
    return None


async def _resolve_quickbooks_tax_code_ref(
    token: dict[str, Any],
    realm_id: str,
    payload: dict[str, Any],
) -> str | None:
    direct = _coalesce_text(payload, "tax_platform_record_id", "tax_code_id")
    if direct:
        return direct

    candidate = _coalesce_text(payload, "tax_code")
    if not candidate:
        return None
    candidate_token = _normalize_token(candidate)
    if not candidate_token:
        return None

    page_size = 200
    max_pages = 20
    for page in range(1, max_pages + 1):
        start_position = ((page - 1) * page_size) + 1
        response = await quickbooks_get_tax_codes(
            token,
            realm_id,
            start_position=start_position,
            max_results=page_size,
        )
        rows = (response.get("QueryResponse") or {}).get("TaxCode") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            probe_tokens = {
                _normalize_token(row.get("Id")),
                _normalize_token(row.get("Name")),
                _normalize_token(row.get("Code")),
            }
            if candidate_token in {t for t in probe_tokens if t}:
                resolved = _as_text(row.get("Id"))
                if resolved:
                    return resolved
        if len(rows) < page_size:
            break
    return None


async def _resolve_quickbooks_vendor_ref(
    token: dict[str, Any],
    realm_id: str,
    payload: dict[str, Any],
) -> str | None:
    direct = _coalesce_text(payload, "contact_id", "vendor_id", "vendor_platform_record_id")
    if direct:
        return direct

    vendor_name = _coalesce_text(payload, "vendor", "contact_name")
    if not vendor_name:
        return None
    vendor_token = _normalize_token(vendor_name)
    if not vendor_token:
        return None

    page_size = 200
    max_pages = 20
    for page in range(1, max_pages + 1):
        start_position = ((page - 1) * page_size) + 1
        response = await quickbooks_get_vendors(
            token,
            realm_id,
            start_position=start_position,
            max_results=page_size,
        )
        rows = (response.get("QueryResponse") or {}).get("Vendor") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            probe_tokens = {
                _normalize_token(row.get("Id")),
                _normalize_token(row.get("DisplayName")),
                _normalize_token(row.get("CompanyName")),
                _normalize_token(row.get("PrintOnCheckName")),
            }
            if vendor_token in {t for t in probe_tokens if t}:
                resolved = _as_text(row.get("Id"))
                if resolved:
                    return resolved
        if len(rows) < page_size:
            break
    return None


async def _resolve_free_agent_contact_url(
    token: dict[str, Any],
    subdomain: str,
    payload: dict[str, Any],
) -> str | None:
    direct = _coalesce_text(payload, "contact_url", "contact_id")
    if direct and direct.startswith("http"):
        return direct

    candidate_values = [
        _coalesce_text(payload, "contact_id"),
        _coalesce_text(payload, "vendor"),
        _coalesce_text(payload, "contact_name"),
    ]
    candidate_tokens = {_normalize_token(v) for v in candidate_values if v}
    if not candidate_tokens:
        return None

    page_size = 100
    max_pages = 20
    for page in range(1, max_pages + 1):
        response = await free_agent_get_clients(
            token,
            page=page,
            per_page=page_size,
        )
        rows = response.get("clients") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            probe_tokens = {
                _normalize_token(row.get("url")),
                _normalize_token(row.get("id")),
                _normalize_token(row.get("subdomain")),
                _normalize_token(row.get("organisation_name")),
                _normalize_token(row.get("company_name")),
                _normalize_token(row.get("name")),
            }
            if candidate_tokens.intersection({t for t in probe_tokens if t}):
                url_value = _as_text(row.get("url"))
                if url_value:
                    return url_value
        if len(rows) < page_size:
            break
    return None


async def _resolve_free_agent_category(
    token: dict[str, Any],
    subdomain: str,
    payload: dict[str, Any],
) -> tuple[str | None, dict[str, Any] | None]:
    direct = _coalesce_text(payload, "account_platform_record_id")
    if direct and direct.startswith("http"):
        return direct, None

    categories_payload = await free_agent_get_categories(token, subdomain)
    rows = categories_payload.get("categories") or []

    candidates = [
        _coalesce_text(payload, "account_code"),
        _coalesce_text(payload, "account_name"),
        _coalesce_text(payload, "category"),
        _coalesce_text(payload, "account_platform_record_id"),
    ]
    candidate_tokens = {_normalize_token(v) for v in candidates if v}

    for row in rows:
        if not isinstance(row, dict):
            continue
        row_url = _as_text(row.get("url"))
        probe_tokens = {
            _normalize_token(row_url),
            _normalize_token(row.get("id")),
            _normalize_token(row.get("nominal_code")),
            _normalize_token(row.get("code")),
            _normalize_token(row.get("category")),
            _normalize_token(row.get("description")),
            _normalize_token(row.get("name")),
        }
        if candidate_tokens and candidate_tokens.intersection({t for t in probe_tokens if t}):
            return row_url or None, row

    if rows:
        first = rows[0] if isinstance(rows[0], dict) else {}
        return _as_text(first.get("url")) or None, first if isinstance(first, dict) else None
    return None, None


async def _resolve_xero_bank_account(
    token: dict[str, Any],
    tenant_id: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    direct = _coalesce_text(payload, "bank_account_id")
    candidate_values = [direct, _coalesce_text(payload, "bank_account")]
    candidate_tokens = {_normalize_token(v) for v in candidate_values if v}
    if not candidate_tokens:
        return None

    response = await xero_get_accounts(token, tenant_id)
    rows = response.get("Accounts") or []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if _normalize_token(row.get("Type")) != "bank":
            continue
        probe_tokens = {
            _normalize_token(row.get("AccountID")),
            _normalize_token(row.get("Code")),
            _normalize_token(row.get("Name")),
        }
        if candidate_tokens.intersection({t for t in probe_tokens if t}):
            return row
    return None


async def _resolve_free_agent_bank_account(
    token: dict[str, Any],
    subdomain: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    direct = _coalesce_text(payload, "bank_account_id")
    candidate = _coalesce_text(payload, "bank_account")
    candidate_tokens = {_normalize_token(v) for v in (direct, candidate) if v}
    if not candidate_tokens:
        return None

    page_size = 100
    max_pages = 20
    for page in range(1, max_pages + 1):
        response = await free_agent_get_bank_accounts(token, subdomain, page=page, per_page=page_size)
        rows = response.get("bank_accounts") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            probe_tokens = {
                _normalize_token(row.get("url")),
                _normalize_token(row.get("id")),
                _normalize_token(row.get("name")),
                _normalize_token(row.get("bank_name")),
            }
            if candidate_tokens.intersection({t for t in probe_tokens if t}):
                return row
        if len(rows) < page_size:
            break
    return None


async def _resolve_free_agent_bank_transaction_url(
    token: dict[str, Any],
    subdomain: str,
    *,
    bank_account: dict[str, Any],
    payment_amount: float | None,
    payment_date: str | None,
) -> str | None:
    bank_account_url = _as_text(bank_account.get("url"))
    if not bank_account_url:
        return None

    page_size = 100
    max_pages = 20
    normalized_amount = round(float(payment_amount or 0.0), 2) if payment_amount is not None else None
    for page in range(1, max_pages + 1):
        response = await free_agent_get_bank_transactions(token, subdomain, page=page, per_page=page_size)
        rows = response.get("bank_transactions") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _as_text((row.get("bank_account") or {}).get("url")) != bank_account_url and _as_text(row.get("bank_account")) != bank_account_url:
                continue
            if payment_date:
                row_date = _normalize_date(row.get("dated_on") or row.get("date"))
                if row_date != payment_date:
                    continue
            if normalized_amount is not None:
                candidate_amount = _to_float(row.get("amount") or row.get("gross_value") or row.get("value"))
                if candidate_amount is None or round(candidate_amount, 2) != normalized_amount:
                    continue
            url_value = _as_text(row.get("url"))
            if url_value:
                return url_value
        if len(rows) < page_size:
            break
    return None


def _build_xero_invoice_payload(payload: dict[str, Any]) -> dict[str, Any]:
    vendor = _coalesce_text(payload, "vendor", "contact_name") or "Unknown vendor"
    contact_id = _coalesce_text(payload, "contact_id")
    contact: dict[str, Any] = {}
    if contact_id and re.fullmatch(r"[0-9a-fA-F-]{32,36}", contact_id):
        contact["ContactID"] = contact_id
    else:
        contact["Name"] = vendor

    line_items: list[dict[str, Any]] = []
    for item in _extract_publish_line_items(payload):
        row: dict[str, Any] = {}
        if item.get("description"):
            row["Description"] = item["description"]
        if item.get("quantity") is not None:
            row["Quantity"] = item["quantity"]
        if item.get("unit_amount") is not None:
            row["UnitAmount"] = item["unit_amount"]
        if item.get("amount") is not None:
            row["LineAmount"] = item["amount"]
        account_code = _coalesce_text(item, "account_code") or _coalesce_text(payload, "account_code")
        if account_code:
            row["AccountCode"] = account_code
        if row:
            line_items.append(row)

    xero_status = "DRAFT"
    requested_status = _coalesce_text(payload, "publish_status", "status")
    if _coalesce_bool(payload, "mark_paid") or _coalesce_bool(payload.get("payment") if isinstance(payload.get("payment"), dict) else {}, "mark_paid"):
        xero_status = "AUTHORISED"
    elif requested_status:
        normalized_status = requested_status.strip().upper()
        if normalized_status in {"DRAFT", "AUTHORISED", "SUBMITTED"}:
            xero_status = normalized_status

    invoice: dict[str, Any] = {
        "Type": "ACCPAY",
        "Status": xero_status,
        "LineAmountTypes": "Exclusive",
        "Contact": contact,
        "LineItems": line_items or [{"Description": _coalesce_text(payload, "description", "summary") or vendor, "Quantity": 1}],
    }
    invoice_date = _normalize_date(_coalesce_text(payload, "invoice_date", "date"))
    due_on = _normalize_date(_coalesce_text(payload, "due_on", "due_date")) or invoice_date
    invoice_number = _coalesce_text(payload, "invoice_number")
    reference = _coalesce_text(payload, "reference")
    currency = _coalesce_text(payload, "currency")
    if invoice_date:
        invoice["Date"] = invoice_date
    if due_on:
        invoice["DueDate"] = due_on
    if invoice_number:
        invoice["InvoiceNumber"] = invoice_number
    if reference:
        invoice["Reference"] = reference
    if currency:
        invoice["CurrencyCode"] = currency.upper()
    return invoice


def _build_quickbooks_bill_payload(
    payload: dict[str, Any],
    *,
    vendor_ref: str,
    account_ref: str,
    tax_code_ref: str | None,
) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    for item in _extract_publish_line_items(payload):
        amount = _to_float(item.get("amount"))
        if amount is None:
            continue
        detail: dict[str, Any] = {"AccountRef": {"value": account_ref}}
        if tax_code_ref:
            detail["TaxCodeRef"] = {"value": tax_code_ref}
        row: dict[str, Any] = {
            "Amount": amount,
            "DetailType": "AccountBasedExpenseLineDetail",
            "AccountBasedExpenseLineDetail": detail,
        }
        description = _as_text(item.get("description"))
        if description:
            row["Description"] = description
        lines.append(row)

    if not lines:
        fallback_amount = _coalesce_float(payload, "amount", "total")
        if fallback_amount is not None:
            lines.append(
                {
                    "Amount": fallback_amount,
                    "DetailType": "AccountBasedExpenseLineDetail",
                    "AccountBasedExpenseLineDetail": {"AccountRef": {"value": account_ref}},
                    "Description": _coalesce_text(payload, "description", "summary") or "",
                }
            )

    bill: dict[str, Any] = {
        "VendorRef": {"value": vendor_ref},
        "Line": lines,
    }
    invoice_date = _normalize_date(_coalesce_text(payload, "invoice_date", "date"))
    due_on = _normalize_date(_coalesce_text(payload, "due_on", "due_date"))
    invoice_number = _coalesce_text(payload, "invoice_number")
    description = _coalesce_text(payload, "description")
    currency = _coalesce_text(payload, "currency")
    if invoice_date:
        bill["TxnDate"] = invoice_date
    if due_on:
        bill["DueDate"] = due_on
    if invoice_number:
        bill["DocNumber"] = invoice_number
    if description:
        bill["PrivateNote"] = description
    if currency:
        bill["CurrencyRef"] = {"value": currency.upper()}
    return bill


def _build_free_agent_bill_payload(
    payload: dict[str, Any],
    *,
    contact_url: str,
    category_url: str,
    default_tax_rate: float | None = None,
) -> dict[str, Any]:
    bill_items: list[dict[str, Any]] = []
    for item in _extract_publish_line_items(payload):
        amount = _to_float(item.get("amount"))
        if amount is None:
            continue
        row: dict[str, Any] = {
            "category": category_url,
            "total_value": f"{amount:.2f}",
        }
        description = _as_text(item.get("description"))
        if description:
            row["description"] = description
        tax_rate = _to_float(item.get("tax"))
        if tax_rate is None:
            tax_rate = default_tax_rate
        if tax_rate is not None:
            row["sales_tax_rate"] = tax_rate
        bill_items.append(row)

    if not bill_items:
        amount = _coalesce_float(payload, "amount", "total")
        if amount is not None:
            fallback: dict[str, Any] = {
                "category": category_url,
                "total_value": f"{amount:.2f}",
            }
            description = _coalesce_text(payload, "description", "summary")
            if description:
                fallback["description"] = description
            if default_tax_rate is not None:
                fallback["sales_tax_rate"] = default_tax_rate
            bill_items.append(fallback)

    bill: dict[str, Any] = {
        "contact": contact_url,
        "bill_items": bill_items,
    }
    dated_on = _normalize_date(_coalesce_text(payload, "invoice_date", "date"))
    due_on = _normalize_date(_coalesce_text(payload, "due_on", "due_date"))
    reference = _coalesce_text(payload, "invoice_number", "reference")
    currency = _coalesce_text(payload, "currency")
    if dated_on:
        bill["dated_on"] = dated_on
    if due_on:
        bill["due_on"] = due_on
    if reference:
        bill["reference"] = reference
    if currency:
        bill["currency"] = currency.upper()
    attachments = _extract_attachments(payload)
    if attachments:
        attachment = attachments[0]
        encoded_content = _coalesce_text(attachment, "content_base64")
        if encoded_content:
            bill["attachment_name"] = _coalesce_text(attachment, "filename")
            bill["attachment_data"] = encoded_content
    return bill


async def _upload_xero_attachments(
    token: dict[str, Any],
    tenant_id: str,
    invoice_id: str,
    attachments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for entry in attachments:
        filename = _coalesce_text(entry, "filename") or "attachment"
        try:
            content, content_type = await _download_attachment_entry(entry)
            response = await xero_upload_invoice_attachment(
                token,
                tenant_id,
                invoice_id,
                filename=filename,
                content=content,
                content_type=content_type,
            )
            results.append(
                {
                    "document_id": _coalesce_text(entry, "document_id") or None,
                    "filename": filename,
                    "status": "uploaded",
                    "raw": response,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "document_id": _coalesce_text(entry, "document_id") or None,
                    "filename": filename,
                    "status": "failed",
                    "error": str(exc),
                }
            )
    return results


async def _upload_quickbooks_attachments(
    token: dict[str, Any],
    realm_id: str,
    bill_id: str,
    attachments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for entry in attachments:
        filename = _coalesce_text(entry, "filename") or "attachment"
        try:
            content, content_type = await _download_attachment_entry(entry)
            response = await quickbooks_upload_attachment(
                token,
                realm_id,
                entity_type="Bill",
                entity_id=bill_id,
                filename=filename,
                content=content,
                content_type=content_type,
                note=_coalesce_text(entry, "kind") or None,
            )
            results.append(
                {
                    "document_id": _coalesce_text(entry, "document_id") or None,
                    "filename": filename,
                    "status": "uploaded",
                    "raw": response,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "document_id": _coalesce_text(entry, "document_id") or None,
                    "filename": filename,
                    "status": "failed",
                    "error": str(exc),
                }
            )
    return results


async def _resolve_quickbooks_bill_vendor_ref(
    token: dict[str, Any],
    realm_id: str,
    provider_record_id: str,
) -> str | None:
    page_size = 200
    max_pages = 20
    target_token = _normalize_token(provider_record_id)
    if not target_token:
        return None

    for page in range(1, max_pages + 1):
        start_position = ((page - 1) * page_size) + 1
        response = await quickbooks_get_bills(
            token,
            realm_id,
            start_position=start_position,
            max_results=page_size,
        )
        rows = (response.get("QueryResponse") or {}).get("Bill") or []
        if not rows:
            break
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _normalize_token(row.get("Id")) != target_token:
                continue
            vendor_ref = row.get("VendorRef") or {}
            resolved = _as_text(vendor_ref.get("value"))
            if resolved:
                return resolved
        if len(rows) < page_size:
            break
    return None


async def _apply_xero_payment(
    token: dict[str, Any],
    tenant_id: str,
    *,
    provider_record_id: str,
    payment_request: dict[str, Any],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bank_account = await _resolve_xero_bank_account(token, tenant_id, payment_request)
    if not isinstance(bank_account, dict):
        raise RuntimeError("Unable to resolve Xero bank account for payment")
    amount = _to_float(payment_request.get("amount"))
    if amount is None:
        raise RuntimeError("Missing payment amount")
    payment_payload: dict[str, Any] = {
        "Invoice": {"InvoiceID": provider_record_id},
        "Account": {"AccountID": _as_text(bank_account.get("AccountID"))},
        "Amount": amount,
    }
    payment_date = _normalize_date(payment_request.get("payment_date")) or _normalize_date(
        (payload or {}).get("invoice_date")
    )
    if payment_date:
        payment_payload["Date"] = payment_date
    reference = _coalesce_text(payment_request, "reference")
    if reference:
        payment_payload["Reference"] = reference
    payment_response = await xero_create_payments(token, tenant_id, [payment_payload])
    payment_rows = payment_response.get("Payments") or []
    first_payment = payment_rows[0] if payment_rows and isinstance(payment_rows[0], dict) else {}
    return {
        "attempted": True,
        "status": "paid",
        "provider_record_id": _as_text(first_payment.get("PaymentID")) or None,
        "raw": first_payment if first_payment else payment_response,
    }


async def _apply_quickbooks_payment(
    token: dict[str, Any],
    realm_id: str,
    *,
    provider_record_id: str,
    payment_request: dict[str, Any],
    vendor_ref: str | None = None,
) -> dict[str, Any]:
    vendor_ref = vendor_ref or await _resolve_quickbooks_bill_vendor_ref(token, realm_id, provider_record_id)
    if not vendor_ref:
        raise RuntimeError("Unable to resolve QuickBooks vendor reference for payment")
    bank_account_ref = await _resolve_quickbooks_bank_account_ref(token, realm_id, payment_request)
    if not bank_account_ref:
        raise RuntimeError("Unable to resolve QuickBooks bank account for payment")
    amount = _to_float(payment_request.get("amount"))
    if amount is None:
        raise RuntimeError("Missing payment amount")
    payment_payload: dict[str, Any] = {
        "VendorRef": {"value": vendor_ref},
        "PayType": "Check",
        "CheckPayment": {"BankAccountRef": {"value": bank_account_ref}},
        "TotalAmt": amount,
        "Line": [
            {
                "Amount": amount,
                "LinkedTxn": [{"TxnId": provider_record_id, "TxnType": "Bill"}],
            }
        ],
    }
    payment_date = _normalize_date(payment_request.get("payment_date"))
    if payment_date:
        payment_payload["TxnDate"] = payment_date
    reference = _coalesce_text(payment_request, "reference")
    if reference:
        payment_payload["PrivateNote"] = reference
    payment_response = await quickbooks_create_bill_payment(token, realm_id, payment_payload)
    payment = payment_response.get("BillPayment") if isinstance(payment_response, dict) else {}
    if not isinstance(payment, dict):
        payment = {}
    return {
        "attempted": True,
        "status": "paid",
        "provider_record_id": _as_text(payment.get("Id")) or None,
        "raw": payment if payment else payment_response,
    }


async def _apply_free_agent_payment(
    token: dict[str, Any],
    subdomain: str,
    *,
    provider_record_id: str,
    payment_request: dict[str, Any],
) -> dict[str, Any]:
    bank_account = await _resolve_free_agent_bank_account(token, subdomain, payment_request)
    if not isinstance(bank_account, dict):
        raise RuntimeError("Unable to resolve FreeAgent bank account for payment")
    amount = _to_float(payment_request.get("amount"))
    if amount is None:
        raise RuntimeError("Missing payment amount")
    payment_date = _normalize_date(payment_request.get("payment_date"))
    bank_txn_url = await _resolve_free_agent_bank_transaction_url(
        token,
        subdomain,
        bank_account=bank_account,
        payment_amount=amount,
        payment_date=payment_date,
    )
    if not bank_txn_url:
        raise RuntimeError("Unable to resolve FreeAgent bank transaction for payment")
    explanation_payload: dict[str, Any] = {
        "bank_transaction": bank_txn_url,
        "bill": provider_record_id,
        "gross_value": f"{amount:.2f}",
    }
    if payment_date:
        explanation_payload["dated_on"] = payment_date
    bank_account_url = _as_text(bank_account.get("url"))
    if bank_account_url:
        explanation_payload["bank_account"] = bank_account_url
    payment_response = await free_agent_create_bank_transaction_explanation(
        token,
        subdomain,
        explanation_payload,
    )
    explanation = payment_response.get("bank_transaction_explanation") if isinstance(payment_response, dict) else {}
    if not isinstance(explanation, dict):
        explanation = {}
    return {
        "attempted": True,
        "status": "paid",
        "provider_record_id": _as_text(explanation.get("url") or explanation.get("id")) or None,
        "raw": explanation if explanation else payment_response,
    }


async def _create_oauth_state(
    db: AsyncSession,
    provider: str,
    payload: dict[str, Any],
    ttl_seconds: int = 900,
) -> str:
    state = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8").rstrip("=")
    expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=ttl_seconds)
    db.add(OAuthState(state=state, provider=provider, payload=payload, expires_at=expires_at))
    await db.commit()
    return state


async def _consume_oauth_state(db: AsyncSession, provider: str, state: str) -> dict[str, Any]:
    res = await db.execute(select(OAuthState).where(OAuthState.state == state, OAuthState.provider == provider))
    row = res.scalars().first()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    if row.expires_at < dt.datetime.now(dt.UTC):
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        raise HTTPException(status_code=400, detail="Expired OAuth state")
    payload = dict(row.payload or {})
    await db.execute(delete(OAuthState).where(OAuthState.state == state))
    await db.commit()
    return payload


def _parse_callback_url(callback_url: str) -> dict[str, str]:
    bits = urllib.parse.urlparse(callback_url)
    q = urllib.parse.parse_qs(bits.query)
    code = (q.get("code") or [None])[0]
    state = (q.get("state") or [None])[0]
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    out: dict[str, str] = {"code": str(code), "state": str(state)}
    realm_id = (q.get("realmId") or [None])[0]
    if realm_id:
        out["realmId"] = str(realm_id)
    return out


async def _upsert_connection(
    db: AsyncSession,
    *,
    business_profile_id: UUID,
    user_id: UUID,
    provider: str,
    token: dict[str, Any],
    tenant_id: str | None = None,
    tenant_name: str | None = None,
    metadata_patch: dict[str, Any] | None = None,
) -> AccountingConnection:
    enc = _cipher().encrypt_json(token)
    now = dt.datetime.now(dt.UTC)
    res = await db.execute(
        select(AccountingConnection).where(
            AccountingConnection.business_profile_id == str(business_profile_id),
            AccountingConnection.provider == provider,
            AccountingConnection.user_id == str(user_id),
        )
    )
    existing = res.scalars().first()
    if existing:
        meta = dict(existing.metadata_ or {})
        if metadata_patch:
            meta.update(metadata_patch)
        await db.execute(
            update(AccountingConnection)
            .where(AccountingConnection.id == existing.id)
            .values(
                user_id=str(user_id),
                token_encrypted=enc,
                tenant_id=tenant_id or existing.tenant_id,
                tenant_name=tenant_name or existing.tenant_name,
                metadata_=meta,
                updated_at=now,
            )
        )
        await db.commit()
        await db.refresh(existing)
        return existing

    conn = AccountingConnection(
        business_profile_id=str(business_profile_id),
        user_id=str(user_id),
        provider=provider,
        token_encrypted=enc,
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        metadata_=metadata_patch or {},
        created_at=now,
        updated_at=now,
    )
    db.add(conn)
    await db.commit()
    await db.refresh(conn)
    return conn


async def _get_connection(
    db: AsyncSession,
    business_profile_id: UUID,
    provider: str,
    user_id: UUID,
) -> AccountingConnection | None:
    res = await db.execute(
        select(AccountingConnection).where(
            AccountingConnection.business_profile_id == str(business_profile_id),
            AccountingConnection.provider == provider,
            AccountingConnection.user_id == str(user_id),
        )
    )
    return res.scalars().first()


@app.post("/internal/oauth/{provider}/authorize-url", dependencies=[Depends(require_internal_api_key)])
async def authorize_url(provider: str, body: AuthorizeUrlIn) -> dict[str, str]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        state = await _create_oauth_state(
            db,
            provider,
            {
                "business_profile_id": str(body.business_profile_id),
                "user_id": str(body.user_id),
                "referrer_url": body.referrer_url or "",
            },
        )
        return {"authorization_url": build_authorize_url(provider, state)}


@app.post("/internal/oauth/{provider}/exchange", dependencies=[Depends(require_internal_api_key)])
async def exchange(provider: str, body: ExchangeIn) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    bits = _parse_callback_url(body.callback_url)
    async for db in session_scope():
        state_payload = await _consume_oauth_state(db, provider, bits["state"])
        bp_id = UUID(state_payload["business_profile_id"])
        user_id = UUID(state_payload["user_id"])

        token = await exchange_code(provider, bits["code"])

        tenant_id = None
        tenant_name = None
        metadata_patch: dict[str, Any] = {}

        if provider == "xero":
            try:
                connections = await xero_get_connections(token)
                if connections:
                    tenant_id = connections[0].get("tenantId")
                    tenant_name = connections[0].get("tenantName")
            except Exception:
                tenant_id = None
                tenant_name = None

        if provider == "free_agent":
            # FreeAgent is multi-tenant by client subdomain; attempt to pick the first available client.
            tenant_id = token.get("business_id") or token.get("businessId")
            tenant_name = token.get("business_name") or token.get("businessName")
            if not tenant_id:
                try:
                    clients = await free_agent_get_clients(token)
                    items = clients.get("clients") or []
                    if items:
                        tenant_id = items[0].get("subdomain")
                        tenant_name = items[0].get("name")
                        metadata_patch["available_clients"] = items[:20]
                except Exception:
                    tenant_id = None
                    tenant_name = None

        if provider == "quickbooks" and "realmId" in bits:
            metadata_patch["realm_id"] = bits["realmId"]
            tenant_id = bits["realmId"]

        await _upsert_connection(
            db,
            business_profile_id=bp_id,
            user_id=user_id,
            provider=provider,
            token=token,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            metadata_patch=metadata_patch,
        )

        return {
            "connected": True,
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "business_profile_id": str(bp_id),
        }


@app.get(
    "/internal/oauth/{provider}/status",
    dependencies=[Depends(require_internal_api_key)],
    response_model=OAuthStatusOut,
)
async def status(provider: str, business_profile_id: UUID, user_id: UUID) -> OAuthStatusOut:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider, user_id)
        if not conn:
            return OAuthStatusOut(status="not_connected")
        return OAuthStatusOut(status="connected", tenant_id=conn.tenant_id, tenant_name=conn.tenant_name)


@app.post("/internal/oauth/{provider}/disconnect", dependencies=[Depends(require_internal_api_key)])
async def disconnect(provider: str, body: DisconnectIn) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        await db.execute(
            delete(AccountingConnection).where(
                AccountingConnection.business_profile_id == str(body.business_profile_id),
                AccountingConnection.provider == provider,
                AccountingConnection.user_id == str(body.user_id),
            )
        )
        await db.commit()
    return {"disconnected": True}


@app.post("/internal/sync/{provider}", dependencies=[Depends(require_internal_api_key)])
async def trigger_sync(provider: str, body: SyncIn) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider == "sage":
        raise HTTPException(status_code=400, detail="Sage sync is unsupported in this release")

    allowed_sync_types = {"bank-transactions", "invoices"}
    normalized_sync_types: list[str] = []
    for t in body.sync_types or []:
        tt = str(t).strip()
        if tt == "bills":
            tt = "invoices"
        if tt not in allowed_sync_types:
            raise HTTPException(status_code=400, detail=f"Unsupported sync_type: {tt}")
        normalized_sync_types.append(tt)
    if not normalized_sync_types:
        normalized_sync_types = ["bank-transactions"]

    # Send choreo event; return first run_id
    event_name = f"accounting.sync.{provider}"
    event = await choreo.send(
        event_name,
        {
            "business_profile_id": str(body.business_profile_id),
            "user_id": str(body.user_id),
            "provider": provider,
            "sync_types": normalized_sync_types,
        },
        idempotency_key=(
            "accountingcli:"
            f"{provider}:"
            f"{body.business_profile_id}:"
            f"{body.user_id}:"
            f"{','.join(sorted(normalized_sync_types))}"
        ),
        user_id=str(body.user_id),
    )
    run_ids = event.get("run_ids") or []
    choreo_run_id = str(run_ids[0]) if run_ids else None

    async for db in session_scope():
        sync_run = SyncRun(
            business_profile_id=str(body.business_profile_id),
            user_id=str(body.user_id),
            provider=provider,
            status="queued",
            choreo_run_id=choreo_run_id,
        )
        db.add(sync_run)
        await db.commit()

    return {"choreo_run_id": choreo_run_id}


@app.post("/internal/publish/{provider}", dependencies=[Depends(require_internal_api_key)])
async def publish_bill(provider: str, body: PublishIn) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider == "sage":
        raise HTTPException(status_code=400, detail="Sage publish is unsupported in this release")

    payload = dict(body.payload or {})
    attachments = _extract_attachments(payload)
    payment_request = _extract_payment_request(payload)

    async for db in session_scope():
        conn = await _get_connection(db, body.business_profile_id, provider, body.user_id)
        if not conn:
            raise HTTPException(status_code=404, detail=f"No {provider} connection for this user/profile")

        try:
            token = await _maybe_refresh_connection_token(db, conn)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to refresh {provider} token: {exc}") from exc

        if provider == "xero":
            tenant_id = await _resolve_xero_tenant_id(db, conn, token)
            if not tenant_id:
                raise HTTPException(status_code=422, detail="Missing Xero tenant_id")
            publish_payload = dict(payload)
            if payment_request:
                publish_payload["payment"] = payment_request
                publish_payload["mark_paid"] = True
            invoice = _build_xero_invoice_payload(publish_payload)
            response = await xero_create_invoices(token, tenant_id, [invoice])
            rows = response.get("Invoices") or []
            first = rows[0] if rows and isinstance(rows[0], dict) else {}
            provider_record_id = _as_text(first.get("InvoiceID")) or None
            attachment_results: list[dict[str, Any]] = []
            if provider_record_id and attachments:
                attachment_results = await _upload_xero_attachments(token, tenant_id, provider_record_id, attachments)
            payment_result: dict[str, Any] | None = None
            if provider_record_id and payment_request:
                payment_result = {"attempted": True, "status": "failed"}
                try:
                    payment_result = await _apply_xero_payment(
                        token,
                        tenant_id,
                        provider_record_id=provider_record_id,
                        payment_request=payment_request,
                        payload=payload,
                    )
                except Exception as exc:
                    payment_result = {"attempted": True, "status": "failed", "error": str(exc)}
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(first.get("InvoiceNumber") or first.get("Reference")) or None,
                "idempotency_key": body.idempotency_key,
                "attachments": attachment_results,
                "payment": payment_result,
                "raw": first if first else response,
            }

        if provider == "quickbooks":
            realm_id = _resolve_quickbooks_realm_id(conn, token)
            if not realm_id:
                raise HTTPException(status_code=422, detail="Missing QuickBooks realm_id")
            vendor_ref = await _resolve_quickbooks_vendor_ref(token, realm_id, payload)
            if not vendor_ref:
                raise HTTPException(status_code=422, detail="Unable to resolve QuickBooks vendor reference")
            account_ref = await _resolve_quickbooks_account_ref(token, realm_id, payload)
            if not account_ref:
                raise HTTPException(status_code=422, detail="Unable to resolve QuickBooks account reference")
            tax_code_ref = await _resolve_quickbooks_tax_code_ref(token, realm_id, payload)
            bill_payload = _build_quickbooks_bill_payload(
                payload,
                vendor_ref=vendor_ref,
                account_ref=account_ref,
                tax_code_ref=tax_code_ref,
            )
            response = await quickbooks_create_bill(token, realm_id, bill_payload)
            bill = response.get("Bill") if isinstance(response, dict) else {}
            if not isinstance(bill, dict):
                bill = {}
            provider_record_id = _as_text(bill.get("Id")) or None
            attachment_results: list[dict[str, Any]] = []
            if provider_record_id and attachments:
                attachment_results = await _upload_quickbooks_attachments(token, realm_id, provider_record_id, attachments)
            payment_result: dict[str, Any] | None = None
            if provider_record_id and payment_request:
                payment_result = {"attempted": True, "status": "failed"}
                try:
                    payment_result = await _apply_quickbooks_payment(
                        token,
                        realm_id,
                        provider_record_id=provider_record_id,
                        payment_request=payment_request,
                        vendor_ref=vendor_ref,
                    )
                except Exception as exc:
                    payment_result = {"attempted": True, "status": "failed", "error": str(exc)}
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(bill.get("DocNumber")) or None,
                "idempotency_key": body.idempotency_key,
                "attachments": attachment_results,
                "payment": payment_result,
                "raw": bill if bill else response,
            }

        if provider == "free_agent":
            subdomain = await _resolve_free_agent_subdomain(db, conn, token)
            if not subdomain:
                raise HTTPException(status_code=422, detail="Missing FreeAgent subdomain")
            contact_url = await _resolve_free_agent_contact_url(token, subdomain, payload)
            if not contact_url:
                raise HTTPException(status_code=422, detail="Unable to resolve FreeAgent contact URL")
            category_url, category_row = await _resolve_free_agent_category(token, subdomain, payload)
            if not category_url:
                raise HTTPException(status_code=422, detail="Unable to resolve FreeAgent category URL")
            default_tax_rate = _to_float(payload.get("tax"))
            if default_tax_rate is None and isinstance(category_row, dict):
                default_tax_rate = _to_float(category_row.get("auto_sales_tax_rate"))
            publish_payload = dict(payload)
            attachment_results: list[dict[str, Any]] = []
            if attachments:
                first_attachment = attachments[0]
                try:
                    content, _content_type = await _download_attachment_entry(first_attachment)
                    encoded_content = base64.b64encode(content).decode("ascii")
                    publish_payload["attachments"] = [{**first_attachment, "content_base64": encoded_content}]
                    attachment_results.append(
                        {
                            "document_id": _coalesce_text(first_attachment, "document_id") or None,
                            "filename": _coalesce_text(first_attachment, "filename") or None,
                            "status": "uploaded",
                        }
                    )
                except Exception as exc:
                    attachment_results.append(
                        {
                            "document_id": _coalesce_text(first_attachment, "document_id") or None,
                            "filename": _coalesce_text(first_attachment, "filename") or None,
                            "status": "failed",
                            "error": str(exc),
                        }
                    )
            bill_payload = _build_free_agent_bill_payload(
                publish_payload,
                contact_url=contact_url,
                category_url=category_url,
                default_tax_rate=default_tax_rate,
            )
            response = await free_agent_create_bill(token, subdomain, bill_payload)
            bill = response.get("bill") if isinstance(response, dict) else {}
            if not isinstance(bill, dict):
                bill = {}
            provider_record_id = _as_text(bill.get("url") or bill.get("id")) or None
            payment_result: dict[str, Any] | None = None
            if provider_record_id and payment_request:
                payment_result = {"attempted": True, "status": "failed"}
                try:
                    payment_result = await _apply_free_agent_payment(
                        token,
                        subdomain,
                        provider_record_id=provider_record_id,
                        payment_request=payment_request,
                    )
                except Exception as exc:
                    payment_result = {"attempted": True, "status": "failed", "error": str(exc)}
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(bill.get("reference")) or None,
                "idempotency_key": body.idempotency_key,
                "attachments": attachment_results,
                "payment": payment_result,
                "raw": bill if bill else response,
            }

        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")


@app.post("/internal/pay/{provider}", dependencies=[Depends(require_internal_api_key)])
async def apply_payment(provider: str, body: PaymentIn) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider == "sage":
        raise HTTPException(status_code=400, detail="Sage payment is unsupported in this release")

    payment_request = dict(body.payload or {})
    if not payment_request:
        raise HTTPException(status_code=400, detail="Missing payment payload")

    async for db in session_scope():
        conn = await _get_connection(db, body.business_profile_id, provider, body.user_id)
        if not conn:
            raise HTTPException(status_code=404, detail=f"No {provider} connection for this user/profile")

        try:
            token = await _maybe_refresh_connection_token(db, conn)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to refresh {provider} token: {exc}") from exc

        try:
            if provider == "xero":
                tenant_id = await _resolve_xero_tenant_id(db, conn, token)
                if not tenant_id:
                    raise HTTPException(status_code=422, detail="Missing Xero tenant_id")
                payment_result = await _apply_xero_payment(
                    token,
                    tenant_id,
                    provider_record_id=body.provider_record_id,
                    payment_request=payment_request,
                )
            elif provider == "quickbooks":
                realm_id = _resolve_quickbooks_realm_id(conn, token)
                if not realm_id:
                    raise HTTPException(status_code=422, detail="Missing QuickBooks realm_id")
                payment_result = await _apply_quickbooks_payment(
                    token,
                    realm_id,
                    provider_record_id=body.provider_record_id,
                    payment_request=payment_request,
                )
            elif provider == "free_agent":
                subdomain = await _resolve_free_agent_subdomain(db, conn, token)
                if not subdomain:
                    raise HTTPException(status_code=422, detail="Missing FreeAgent subdomain")
                payment_result = await _apply_free_agent_payment(
                    token,
                    subdomain,
                    provider_record_id=body.provider_record_id,
                    payment_request=payment_request,
                )
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        return {
            "provider": provider,
            "provider_record_id": body.provider_record_id,
            "idempotency_key": body.idempotency_key,
            **payment_result,
        }


@app.get("/internal/data/bank-transactions", dependencies=[Depends(require_internal_api_key)])
async def list_bank_transactions(
    business_profile_id: UUID,
    provider: str,
    user_id: UUID,
    since: str | None = None,
) -> list[dict[str, Any]]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider, user_id)
        if not conn:
            return []
        q = select(BankTransaction).where(
            BankTransaction.business_profile_id == str(business_profile_id),
            BankTransaction.provider == provider,
        )
        if since:
            # v1: string compare; consumers can filter more precisely later
            q = q.where(BankTransaction.transaction_date >= since)
        res = await db.execute(q)
        rows = res.scalars().all()
        return [
            {
                "id": r.id,
                "business_profile_id": r.business_profile_id,
                "provider": r.provider,
                "provider_transaction_id": r.provider_transaction_id,
                "transaction_date": r.transaction_date,
                "amount": r.amount,
                "currency": r.currency,
                "description": r.description,
                "raw": r.raw,
            }
            for r in rows
        ]


@app.get("/internal/data/invoices", dependencies=[Depends(require_internal_api_key)])
async def list_invoices(
    business_profile_id: UUID,
    provider: str,
    user_id: UUID,
    since: str | None = None,
) -> list[dict[str, Any]]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider, user_id)
        if not conn:
            return []
        q = select(Invoice).where(
            Invoice.business_profile_id == str(business_profile_id),
            Invoice.provider == provider,
        )
        if since:
            q = q.where(Invoice.invoice_date >= since)
        res = await db.execute(q)
        rows = res.scalars().all()
        return [
            {
                "id": r.id,
                "business_profile_id": r.business_profile_id,
                "provider": r.provider,
                "provider_invoice_id": r.provider_invoice_id,
                "invoice_type": r.invoice_type,
                "status": r.status,
                "invoice_date": r.invoice_date,
                "due_date": r.due_date,
                "total": r.total,
                "currency": r.currency,
                "reference": r.reference,
                "contact_id": r.contact_id,
                "contact_name": r.contact_name,
                "raw": r.raw,
            }
            for r in rows
        ]


@app.get("/internal/data/account-codes", dependencies=[Depends(require_internal_api_key)])
async def list_account_codes(
    business_profile_id: UUID,
    provider: str,
    user_id: UUID,
) -> list[dict[str, Any]]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider == "sage":
        return []

    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider, user_id)
        if not conn:
            return []

        try:
            token = await _maybe_refresh_connection_token(db, conn)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to refresh {provider} token: {exc}") from exc

        if provider == "xero":
            tenant_id = await _resolve_xero_tenant_id(db, conn, token)
            if not tenant_id:
                return []
            payload = await xero_get_accounts(token, tenant_id)
            rows = payload.get("Accounts") or []
            return _normalize_xero_account_codes(rows)

        if provider == "quickbooks":
            realm_id = _resolve_quickbooks_realm_id(conn, token)
            if not realm_id:
                return []
            rows: list[dict[str, Any]] = []
            page_size = 200
            max_pages = 20
            for page in range(1, max_pages + 1):
                start_position = ((page - 1) * page_size) + 1
                payload = await quickbooks_get_accounts(
                    token,
                    realm_id,
                    start_position=start_position,
                    max_results=page_size,
                )
                page_rows = (payload.get("QueryResponse") or {}).get("Account") or []
                if not page_rows:
                    break
                rows.extend([r for r in page_rows if isinstance(r, dict)])
                if len(page_rows) < page_size:
                    break
            return _normalize_quickbooks_account_codes(rows)

        if provider == "free_agent":
            subdomain = await _resolve_free_agent_subdomain(db, conn, token)
            if not subdomain:
                return []
            payload = await free_agent_get_categories(token, subdomain)
            rows = payload.get("categories") or []
            return _normalize_free_agent_account_codes(rows)

        return []


@app.get("/internal/data/tax-codes", dependencies=[Depends(require_internal_api_key)])
async def list_tax_codes(
    business_profile_id: UUID,
    provider: str,
    user_id: UUID,
) -> list[dict[str, Any]]:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider == "sage":
        return []

    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider, user_id)
        if not conn:
            return []

        try:
            token = await _maybe_refresh_connection_token(db, conn)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to refresh {provider} token: {exc}") from exc

        if provider == "xero":
            tenant_id = await _resolve_xero_tenant_id(db, conn, token)
            if not tenant_id:
                return []
            payload = await xero_get_tax_rates(token, tenant_id)
            rows = payload.get("TaxRates") or []
            return _normalize_xero_tax_codes(rows)

        if provider == "quickbooks":
            realm_id = _resolve_quickbooks_realm_id(conn, token)
            if not realm_id:
                return []
            rows: list[dict[str, Any]] = []
            tax_rate_rows: list[dict[str, Any]] = []
            page_size = 200
            max_pages = 20
            for page in range(1, max_pages + 1):
                start_position = ((page - 1) * page_size) + 1
                payload = await quickbooks_get_tax_codes(
                    token,
                    realm_id,
                    start_position=start_position,
                    max_results=page_size,
                )
                page_rows = (payload.get("QueryResponse") or {}).get("TaxCode") or []
                if not page_rows:
                    break
                rows.extend([r for r in page_rows if isinstance(r, dict)])
                if len(page_rows) < page_size:
                    break
            for page in range(1, max_pages + 1):
                start_position = ((page - 1) * page_size) + 1
                payload = await quickbooks_get_tax_rates(
                    token,
                    realm_id,
                    start_position=start_position,
                    max_results=page_size,
                )
                page_rows = (payload.get("QueryResponse") or {}).get("TaxRate") or []
                if not page_rows:
                    break
                tax_rate_rows.extend([r for r in page_rows if isinstance(r, dict)])
                if len(page_rows) < page_size:
                    break
            return _normalize_quickbooks_tax_codes(
                rows,
                tax_rate_by_id=_quickbooks_tax_rate_index(tax_rate_rows),
            )

        if provider == "free_agent":
            subdomain = await _resolve_free_agent_subdomain(db, conn, token)
            if not subdomain:
                return []
            payload = await free_agent_get_categories(token, subdomain)
            rows = payload.get("categories") or []
            return _normalize_free_agent_tax_codes(rows)

        return []


def _normalize_object_type(raw: str) -> str:
    token = str(raw or "").strip().lower().replace(" ", "_")
    token = token.replace("banktransaction", "bank_transaction")
    token = token.replace("manualjournal", "manual_journal")
    return token


def _build_xero_forward_events(payload_json: dict[str, Any], signature_verified: bool, headers: dict[str, str]) -> list[dict[str, Any]]:
    events = payload_json.get("events") or []
    if not isinstance(events, list):
        return []
    out: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        tenant_id = str(event.get("tenantId") or "").strip()
        resource_id = str(event.get("resourceId") or event.get("resourceUrl") or "").strip()
        category = str(event.get("eventCategory") or "event").strip().lower()
        operation = str(event.get("eventType") or "update").strip().lower()
        event_time = event.get("eventDateUtc") or payload_json.get("lastEventSequence") or payload_json.get("firstEventSequence")
        object_type = _normalize_object_type(category)
        out.append(
            {
                "provider": "xero",
                "provider_account_id": tenant_id,
                "idempotency_key": f"xero:{tenant_id}:{object_type}:{resource_id or index}:{operation}:{event_time}",
                "source": f"connector.xero.tenant/{tenant_id or 'unknown'}",
                "type": f"xero.{object_type}.{operation}.v1",
                "subject": resource_id or event.get("resourceUrl"),
                "time": event.get("eventDateUtc"),
                "headers": headers,
                "data": event,
                "signature_verified": signature_verified,
                "object_type": object_type,
                "external_id": resource_id or str(index),
                "provider_updated_at": event.get("eventDateUtc"),
                "auto_create_proposal": object_type in {"invoice", "bank_transaction", "manual_journal"},
            }
        )
    return out


def _build_quickbooks_forward_events(payload_json: dict[str, Any], signature_verified: bool, headers: dict[str, str]) -> list[dict[str, Any]]:
    notifications = payload_json.get("eventNotifications") or []
    if not isinstance(notifications, list):
        return []
    out: list[dict[str, Any]] = []
    for notification in notifications:
        if not isinstance(notification, dict):
            continue
        realm_id = str(notification.get("realmId") or "").strip()
        data_change = notification.get("dataChangeEvent") or {}
        entities = data_change.get("entities") or []
        if not isinstance(entities, list):
            entities = []
        for index, entity in enumerate(entities):
            if not isinstance(entity, dict):
                continue
            object_type = _normalize_object_type(str(entity.get("name") or "entity"))
            operation = str(entity.get("operation") or "update").strip().lower()
            entity_id = str(entity.get("id") or "").strip()
            updated_at = entity.get("lastUpdated")
            out.append(
                {
                    "provider": "quickbooks",
                    "provider_account_id": realm_id,
                    "idempotency_key": f"qbo:{realm_id}:{object_type}:{entity_id or index}:{operation}:{updated_at}",
                    "source": f"connector.quickbooks.realm/{realm_id or 'unknown'}",
                    "type": f"qbo.{object_type}.{operation}.v1",
                    "subject": entity_id or object_type,
                    "time": updated_at,
                    "headers": headers,
                    "data": {**entity, "realmId": realm_id},
                    "signature_verified": signature_verified,
                    "object_type": object_type,
                    "external_id": entity_id or str(index),
                    "provider_updated_at": updated_at,
                    "auto_create_proposal": object_type in {"invoice", "bill", "purchase", "journalentry"},
                }
            )
    return out


async def _forward_webhook_events(
    db: AsyncSession,
    *,
    provider: str,
    provider_events: list[dict[str, Any]],
    receipt: WebhookReceipt,
) -> int:
    forwarded = 0
    seen_profiles: set[tuple[str, str]] = set()
    for event in provider_events:
        provider_account_id = str(event.get("provider_account_id") or "").strip()
        if not provider_account_id:
            continue
        matches = await _find_connections_for_provider_account(
            db,
            provider=provider,
            provider_account_id=provider_account_id,
        )
        for conn in matches:
            dedupe_key = (str(conn.business_profile_id), str(event["idempotency_key"]))
            if dedupe_key in seen_profiles:
                continue
            seen_profiles.add(dedupe_key)
            payload = dict(event)
            payload["business_profile_id"] = str(conn.business_profile_id)
            await _forward_ledger_event(payload)
            forwarded += 1

    receipt.status = "forwarded" if forwarded else "ignored"
    receipt.forwarded_at = dt.datetime.now(dt.UTC)
    await db.flush()
    return forwarded


@app.post("/webhooks/xero")
async def xero_webhook(request: Request) -> dict[str, Any]:
    payload_bytes = await request.body()
    payload_json = _normalize_payload_json(payload_bytes)
    signature = request.headers.get("x-xero-signature")
    signature_verified = _verify_xero_webhook_signature(payload_bytes, signature)
    if not signature_verified:
        raise HTTPException(status_code=401, detail="Invalid Xero webhook signature")

    provider_events = _build_xero_forward_events(payload_json, signature_verified, _headers_to_dict(request))
    provider_account_id = str(((payload_json.get("events") or [{}])[0] or {}).get("tenantId") or "").strip()
    idempotency_key = f"xero:{_payload_sha256(payload_bytes)}"

    async for db in session_scope():
        receipt, created = await _upsert_webhook_receipt(
            db,
            provider="xero",
            provider_account_id=provider_account_id or None,
            idempotency_key=idempotency_key,
            signature_verified=signature_verified,
            request=request,
            payload_json=payload_json,
            payload_bytes=payload_bytes,
        )
        if not created:
            return {"status": "duplicate", "forwarded": 0}
        try:
            forwarded = await _forward_webhook_events(
                db,
                provider="xero",
                provider_events=provider_events,
                receipt=receipt,
            )
            await db.commit()
            return {"status": "accepted", "forwarded": forwarded}
        except Exception as exc:
            receipt.status = "failed"
            receipt.error = str(exc)
            await db.commit()
            raise HTTPException(status_code=502, detail=f"Failed forwarding Xero webhook: {exc}") from exc

    return {"status": "accepted", "forwarded": 0}


@app.post("/webhooks/quickbooks")
async def quickbooks_webhook(request: Request) -> dict[str, Any]:
    payload_bytes = await request.body()
    payload_json = _normalize_payload_json(payload_bytes)
    signature = request.headers.get("intuit-signature")
    signature_verified = _verify_quickbooks_webhook_signature(payload_bytes, signature)
    if not signature_verified:
        raise HTTPException(status_code=401, detail="Invalid QuickBooks webhook signature")

    provider_events = _build_quickbooks_forward_events(payload_json, signature_verified, _headers_to_dict(request))
    notifications = payload_json.get("eventNotifications") or []
    provider_account_id = str(((notifications[0] if notifications else {}) or {}).get("realmId") or "").strip()
    idempotency_key = f"quickbooks:{_payload_sha256(payload_bytes)}"

    async for db in session_scope():
        receipt, created = await _upsert_webhook_receipt(
            db,
            provider="quickbooks",
            provider_account_id=provider_account_id or None,
            idempotency_key=idempotency_key,
            signature_verified=signature_verified,
            request=request,
            payload_json=payload_json,
            payload_bytes=payload_bytes,
        )
        if not created:
            return {"status": "duplicate", "forwarded": 0}
        try:
            forwarded = await _forward_webhook_events(
                db,
                provider="quickbooks",
                provider_events=provider_events,
                receipt=receipt,
            )
            await db.commit()
            return {"status": "accepted", "forwarded": forwarded}
        except Exception as exc:
            receipt.status = "failed"
            receipt.error = str(exc)
            await db.commit()
            raise HTTPException(status_code=502, detail=f"Failed forwarding QuickBooks webhook: {exc}") from exc

    return {"status": "accepted", "forwarded": 0}
