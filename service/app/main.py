from __future__ import annotations

import base64
import datetime as dt
import os
import re
import time
import urllib.parse
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.choreo_runtime import choreo
from app.crypto import TokenCipher
from app.db import AccountingConnection, BankTransaction, Invoice, OAuthState, SyncRun, init_db, session_scope
from app.internal_auth import require_internal_api_key
from app.providers import (
    build_authorize_url,
    exchange_code,
    free_agent_create_bill,
    free_agent_get_categories,
    free_agent_get_clients,
    quickbooks_create_bill,
    quickbooks_get_accounts,
    quickbooks_get_vendors,
    quickbooks_get_tax_codes,
    quickbooks_get_tax_rates,
    refresh_token as provider_refresh_token,
    xero_create_invoices,
    xero_get_accounts,
    xero_get_connections,
    xero_get_tax_rates,
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
        tax_code = _coalesce_text(item, "tax_code") or _coalesce_text(payload, "tax_code")
        if tax_code:
            row["TaxType"] = tax_code
        if row:
            line_items.append(row)

    invoice: dict[str, Any] = {
        "Type": "ACCPAY",
        "Status": "DRAFT",
        "LineAmountTypes": "Exclusive",
        "Contact": contact,
        "LineItems": line_items or [{"Description": _coalesce_text(payload, "description", "summary") or vendor, "Quantity": 1}],
    }
    invoice_date = _normalize_date(_coalesce_text(payload, "invoice_date", "date"))
    due_on = _normalize_date(_coalesce_text(payload, "due_on", "due_date"))
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
    return bill


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
            invoice = _build_xero_invoice_payload(payload)
            response = await xero_create_invoices(token, tenant_id, [invoice])
            rows = response.get("Invoices") or []
            first = rows[0] if rows and isinstance(rows[0], dict) else {}
            provider_record_id = _as_text(first.get("InvoiceID")) or None
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(first.get("InvoiceNumber") or first.get("Reference")) or None,
                "idempotency_key": body.idempotency_key,
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
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(bill.get("DocNumber")) or None,
                "idempotency_key": body.idempotency_key,
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
            bill_payload = _build_free_agent_bill_payload(
                payload,
                contact_url=contact_url,
                category_url=category_url,
                default_tax_rate=default_tax_rate,
            )
            response = await free_agent_create_bill(token, subdomain, bill_payload)
            bill = response.get("bill") if isinstance(response, dict) else {}
            if not isinstance(bill, dict):
                bill = {}
            provider_record_id = _as_text(bill.get("url") or bill.get("id")) or None
            return {
                "published": True,
                "provider": provider,
                "provider_record_id": provider_record_id,
                "reference": _as_text(bill.get("reference")) or None,
                "idempotency_key": body.idempotency_key,
                "raw": bill if bill else response,
            }

        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")


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
