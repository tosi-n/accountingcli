from __future__ import annotations

import asyncio
import datetime as dt
import time
from typing import Any

from sqlalchemy import select, update

from app.choreo_runtime import choreo
from app.crypto import TokenCipher
from app.db import AccountingConnection, BankTransaction, Invoice, init_db, session_scope
from app.providers import (
    free_agent_get_bank_transactions,
    free_agent_get_bills,
    free_agent_get_clients,
    quickbooks_get_bills,
    quickbooks_get_company_info,
    quickbooks_get_purchases,
    refresh_token as provider_refresh_token,
    xero_get_bank_transactions,
    xero_get_connections,
    xero_get_invoices,
)
from app.settings import settings


def _cipher() -> TokenCipher:
    return TokenCipher(settings.ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY)


def _token_expires_at(token: dict[str, Any]) -> int:
    v = token.get("expires_at")
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return 0


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


async def _maybe_refresh(provider: str, token: dict[str, Any]) -> dict[str, Any]:
    if _token_expires_at(token) > int(time.time()) + 60:
        return token
    rt = token.get("refresh_token")
    if not rt:
        return token
    return await provider_refresh_token(provider, str(rt))


async def _load_connection(business_profile_id: str, provider: str) -> AccountingConnection | None:
    async for db in session_scope():
        res = await db.execute(
            select(AccountingConnection).where(
                AccountingConnection.business_profile_id == business_profile_id,
                AccountingConnection.provider == provider,
            )
        )
        return res.scalars().first()
    return None


def _normalize_sync_types(raw: Any) -> set[str]:
    allowed = {"bank-transactions", "invoices"}
    out: set[str] = set()
    if isinstance(raw, list):
        items = raw
    elif raw is None:
        items = []
    else:
        items = [raw]
    for t in items:
        tt = str(t).strip()
        if tt == "bills":
            tt = "invoices"
        if tt in allowed:
            out.add(tt)
    # Keep backward-compatible behavior if callers don't pass any sync types.
    if not out:
        out.add("bank-transactions")
    return out


async def _persist_connection_updates(
    *,
    business_profile_id: str,
    provider: str,
    token: dict[str, Any] | None = None,
    tenant_id: str | None = None,
    tenant_name: str | None = None,
) -> None:
    patch: dict[str, Any] = {"updated_at": dt.datetime.now(dt.UTC)}
    if token is not None:
        patch["token_encrypted"] = _cipher().encrypt_json(token)
    if tenant_id is not None:
        patch["tenant_id"] = tenant_id
    if tenant_name is not None:
        patch["tenant_name"] = tenant_name
    if len(patch) == 1:
        return
    async for db in session_scope():
        await db.execute(
            update(AccountingConnection)
            .where(
                AccountingConnection.business_profile_id == business_profile_id,
                AccountingConnection.provider == provider,
            )
            .values(**patch)
        )
        await db.commit()


@choreo.function("accounting-sync-xero", trigger="accounting.sync.xero", retries=3, timeout=900)
async def sync_xero(ctx, step):
    bp_id = str(ctx.data.get("business_profile_id") or "")
    if not bp_id:
        return {"outcome": "skipped", "reason": "missing_business_profile_id"}

    sync_types = _normalize_sync_types(ctx.data.get("sync_types"))

    conn = await step.run("load-connection", lambda: _load_connection(bp_id, "xero"))
    if not conn:
        return {"outcome": "skipped", "reason": "no_connection"}

    token = _cipher().decrypt_json(conn.token_encrypted)
    token = await step.run("refresh-token", lambda: _maybe_refresh("xero", token))
    await step.run("persist-token", lambda: _persist_connection_updates(business_profile_id=bp_id, provider="xero", token=token))

    tenant_id = conn.tenant_id
    tenant_name = conn.tenant_name
    if not tenant_id:
        connections = await step.run("fetch-tenant", lambda: xero_get_connections(token))
        if connections:
            tenant_id = connections[0].get("tenantId")
            tenant_name = connections[0].get("tenantName")
            await step.run(
                "persist-tenant",
                lambda: _persist_connection_updates(
                    business_profile_id=bp_id,
                    provider="xero",
                    tenant_id=str(tenant_id) if tenant_id else None,
                    tenant_name=str(tenant_name) if tenant_name else None,
                ),
            )
    if not tenant_id:
        return {"outcome": "failed", "reason": "missing_tenant_id"}

    outcome: dict[str, Any] = {"outcome": "ok", "provider": "xero"}

    if "bank-transactions" in sync_types:
        data = await step.run("fetch-bank-transactions", lambda: xero_get_bank_transactions(token, str(tenant_id)))
        items = data.get("BankTransactions") or []

        async for db in session_scope():
            for it in items:
                tx_id = it.get("BankTransactionID")
                if not tx_id:
                    continue
                tx = BankTransaction(
                    business_profile_id=bp_id,
                    provider="xero",
                    provider_transaction_id=str(tx_id),
                    transaction_date=str(it.get("Date") or ""),
                    amount=float(it.get("Total") or 0.0) if it.get("Total") is not None else None,
                    currency=str(it.get("CurrencyCode") or "") if it.get("CurrencyCode") else None,
                    description=str(it.get("Reference") or "") if it.get("Reference") else None,
                    raw=it,
                )
                db.add(tx)
            try:
                await db.commit()
            except Exception:
                # Best-effort: ignore unique constraint races; v1 keeps it simple.
                await db.rollback()

        outcome["bank_transactions"] = len(items)

    if "invoices" in sync_types:
        page_size = 100
        max_pages = 20
        invoices: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload = await step.run(
                f"fetch-invoices-page-{page}",
                lambda p=page: xero_get_invoices(token, str(tenant_id), page=p, page_size=page_size),
            )
            page_items = payload.get("Invoices") or []
            if not page_items:
                break
            invoices.extend(page_items)
            if len(page_items) < page_size:
                break

        # Keep invoice semantics aligned: bills are represented as invoices.
        # Xero exposes bills as Invoices with Type=ACCPAY.
        bill_types = {"ACCPAY", "ACCPAYCREDIT"}
        invoices = [i for i in invoices if (i.get("Type") or "") in bill_types]

        async for db in session_scope():
            existing = await db.execute(
                select(Invoice.provider_invoice_id).where(
                    Invoice.business_profile_id == bp_id,
                    Invoice.provider == "xero",
                )
            )
            existing_ids = {str(x) for x in existing.scalars().all()}

            for inv in invoices:
                inv_id = inv.get("InvoiceID")
                if not inv_id:
                    continue
                inv_id_s = str(inv_id)
                if inv_id_s in existing_ids:
                    continue
                contact = inv.get("Contact") or {}
                db.add(
                    Invoice(
                        business_profile_id=bp_id,
                        provider="xero",
                        provider_invoice_id=inv_id_s,
                        invoice_type=str(inv.get("Type") or "") or None,
                        status=str(inv.get("Status") or "") or None,
                        invoice_date=str(inv.get("DateString") or inv.get("Date") or "") or None,
                        due_date=str(inv.get("DueDateString") or inv.get("DueDate") or "") or None,
                        total=float(inv.get("Total")) if inv.get("Total") is not None else None,
                        currency=str(inv.get("CurrencyCode") or "") or None,
                        reference=str(inv.get("InvoiceNumber") or inv.get("Reference") or "") or None,
                        contact_id=str(contact.get("ContactID") or "") or None,
                        contact_name=str(contact.get("Name") or "") or None,
                        raw=inv,
                    )
                )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

        outcome["invoices"] = len(invoices)

    return outcome


@choreo.function("accounting-sync-quickbooks", trigger="accounting.sync.quickbooks", retries=3, timeout=900)
async def sync_quickbooks(ctx, step):
    bp_id = str(ctx.data.get("business_profile_id") or "")
    if not bp_id:
        return {"outcome": "skipped", "reason": "missing_business_profile_id"}

    sync_types = _normalize_sync_types(ctx.data.get("sync_types"))

    conn = await step.run("load-connection", lambda: _load_connection(bp_id, "quickbooks"))
    if not conn:
        return {"outcome": "skipped", "reason": "no_connection"}

    token = _cipher().decrypt_json(conn.token_encrypted)
    token = await step.run("refresh-token", lambda: _maybe_refresh("quickbooks", token))
    await step.run(
        "persist-token",
        lambda: _persist_connection_updates(business_profile_id=bp_id, provider="quickbooks", token=token),
    )

    metadata = dict(conn.metadata_ or {})
    realm_id = conn.tenant_id or metadata.get("realm_id") or token.get("realm_id")
    tenant_name = conn.tenant_name
    if realm_id and not tenant_name:
        try:
            company = await step.run(
                "fetch-company-info",
                lambda: quickbooks_get_company_info(token, str(realm_id)),
            )
            tenant_name = (company.get("CompanyInfo") or {}).get("CompanyName")
        except Exception:
            tenant_name = conn.tenant_name

    if not realm_id:
        return {"outcome": "failed", "provider": "quickbooks", "reason": "missing_realm_id"}

    if str(realm_id) != str(conn.tenant_id or "") or (tenant_name and tenant_name != conn.tenant_name):
        await step.run(
            "persist-tenant",
            lambda: _persist_connection_updates(
                business_profile_id=bp_id,
                provider="quickbooks",
                tenant_id=str(realm_id),
                tenant_name=str(tenant_name) if tenant_name else None,
            ),
        )

    outcome: dict[str, Any] = {"outcome": "ok", "provider": "quickbooks"}

    if "bank-transactions" in sync_types:
        page_size = 200
        max_pages = 20
        purchases: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            start_position = ((page - 1) * page_size) + 1
            payload = await step.run(
                f"fetch-purchases-page-{page}",
                lambda sp=start_position: quickbooks_get_purchases(
                    token,
                    str(realm_id),
                    start_position=sp,
                    max_results=page_size,
                ),
            )
            page_items = (payload.get("QueryResponse") or {}).get("Purchase") or []
            if not page_items:
                break
            purchases.extend(page_items)
            if len(page_items) < page_size:
                break

        async for db in session_scope():
            existing = await db.execute(
                select(BankTransaction.provider_transaction_id).where(
                    BankTransaction.business_profile_id == bp_id,
                    BankTransaction.provider == "quickbooks",
                )
            )
            existing_ids = {str(x) for x in existing.scalars().all()}

            for p in purchases:
                tx_id = p.get("Id")
                if not tx_id:
                    continue
                tx_id_s = str(tx_id)
                if tx_id_s in existing_ids:
                    continue
                currency_ref = p.get("CurrencyRef") or {}
                description = (
                    str(p.get("PrivateNote") or p.get("PaymentType") or p.get("DocNumber") or "")
                    or None
                )
                db.add(
                    BankTransaction(
                        business_profile_id=bp_id,
                        provider="quickbooks",
                        provider_transaction_id=tx_id_s,
                        transaction_date=str(p.get("TxnDate") or "") or None,
                        amount=_to_float(p.get("TotalAmt")),
                        currency=str(currency_ref.get("value") or currency_ref.get("name") or "") or None,
                        description=description,
                        raw=p,
                    )
                )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

        outcome["bank_transactions"] = len(purchases)

    if "invoices" in sync_types:
        page_size = 200
        max_pages = 20
        bills: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            start_position = ((page - 1) * page_size) + 1
            payload = await step.run(
                f"fetch-bills-page-{page}",
                lambda sp=start_position: quickbooks_get_bills(
                    token,
                    str(realm_id),
                    start_position=sp,
                    max_results=page_size,
                ),
            )
            page_items = (payload.get("QueryResponse") or {}).get("Bill") or []
            if not page_items:
                break
            bills.extend(page_items)
            if len(page_items) < page_size:
                break

        async for db in session_scope():
            existing = await db.execute(
                select(Invoice.provider_invoice_id).where(
                    Invoice.business_profile_id == bp_id,
                    Invoice.provider == "quickbooks",
                )
            )
            existing_ids = {str(x) for x in existing.scalars().all()}

            for b in bills:
                inv_id = b.get("Id")
                if not inv_id:
                    continue
                inv_id_s = str(inv_id)
                if inv_id_s in existing_ids:
                    continue
                vendor_ref = b.get("VendorRef") or {}
                balance = _to_float(b.get("Balance"))
                db.add(
                    Invoice(
                        business_profile_id=bp_id,
                        provider="quickbooks",
                        provider_invoice_id=inv_id_s,
                        invoice_type="bill",
                        status="PAID" if balance == 0 else "OPEN",
                        invoice_date=str(b.get("TxnDate") or "") or None,
                        due_date=str(b.get("DueDate") or "") or None,
                        total=_to_float(b.get("TotalAmt")),
                        currency=str((b.get("CurrencyRef") or {}).get("value") or "") or None,
                        reference=str(b.get("DocNumber") or b.get("PrivateNote") or "") or None,
                        contact_id=str(vendor_ref.get("value") or "") or None,
                        contact_name=str(vendor_ref.get("name") or "") or None,
                        raw=b,
                    )
                )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

        outcome["invoices"] = len(bills)

    return outcome


@choreo.function("accounting-sync-sage", trigger="accounting.sync.sage", retries=3, timeout=900)
async def sync_sage(ctx, step):  # noqa: ARG001
    return {
        "outcome": "failed",
        "provider": "sage",
        "reason": "unsupported_provider",
        "message": "Sage sync is not supported in this release",
    }


@choreo.function("accounting-sync-free-agent", trigger="accounting.sync.free_agent", retries=3, timeout=900)
async def sync_free_agent(ctx, step):
    bp_id = str(ctx.data.get("business_profile_id") or "")
    if not bp_id:
        return {"outcome": "skipped", "reason": "missing_business_profile_id"}

    sync_types = _normalize_sync_types(ctx.data.get("sync_types"))

    conn = await step.run("load-connection", lambda: _load_connection(bp_id, "free_agent"))
    if not conn:
        return {"outcome": "skipped", "reason": "no_connection"}

    token = _cipher().decrypt_json(conn.token_encrypted)
    token = await step.run("refresh-token", lambda: _maybe_refresh("free_agent", token))
    await step.run(
        "persist-token",
        lambda: _persist_connection_updates(business_profile_id=bp_id, provider="free_agent", token=token),
    )

    # FreeAgent requires X-Subdomain for most endpoints (multi-tenant by client subdomain).
    subdomain = conn.tenant_id or token.get("business_id")
    tenant_name = conn.tenant_name or token.get("business_name")
    if not subdomain:
        clients = await step.run("fetch-clients", lambda: free_agent_get_clients(token))
        items = clients.get("clients") or []
        if items:
            subdomain = items[0].get("subdomain")
            tenant_name = items[0].get("name")
    if subdomain:
        await step.run(
            "persist-tenant",
            lambda: _persist_connection_updates(
                business_profile_id=bp_id,
                provider="free_agent",
                tenant_id=str(subdomain),
                tenant_name=str(tenant_name) if tenant_name else None,
            ),
        )

    outcome: dict[str, Any] = {"outcome": "ok", "provider": "free_agent"}

    if "bank-transactions" in sync_types:
        if not subdomain:
            return {"outcome": "failed", "reason": "missing_subdomain"}

        page_size = 100
        max_pages = 20
        transactions: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload = await step.run(
                f"fetch-bank-transactions-page-{page}",
                lambda p=page: free_agent_get_bank_transactions(
                    token,
                    str(subdomain),
                    page=p,
                    per_page=page_size,
                ),
            )
            page_items = payload.get("bank_transactions") or []
            if not page_items:
                break
            transactions.extend(page_items)
            if len(page_items) < page_size:
                break

        async for db in session_scope():
            existing = await db.execute(
                select(BankTransaction.provider_transaction_id).where(
                    BankTransaction.business_profile_id == bp_id,
                    BankTransaction.provider == "free_agent",
                )
            )
            existing_ids = {str(x) for x in existing.scalars().all()}

            for tx in transactions:
                tx_id = tx.get("url") or tx.get("id")
                if not tx_id:
                    continue
                tx_id_s = str(tx_id)
                if tx_id_s in existing_ids:
                    continue

                amount = _to_float(tx.get("gross_value"))
                if amount is None:
                    amount = _to_float(tx.get("amount"))
                description = (
                    str(tx.get("description") or tx.get("explanation") or tx.get("bank_account") or "")
                    or None
                )
                db.add(
                    BankTransaction(
                        business_profile_id=bp_id,
                        provider="free_agent",
                        provider_transaction_id=tx_id_s,
                        transaction_date=str(tx.get("dated_on") or tx.get("date") or "") or None,
                        amount=amount,
                        currency=str(tx.get("currency") or "") or None,
                        description=description,
                        raw=tx,
                    )
                )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

        outcome["bank_transactions"] = len(transactions)

    if "invoices" in sync_types:
        if not subdomain:
            return {"outcome": "failed", "reason": "missing_subdomain"}

        page_size = 100
        max_pages = 20
        bills: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload = await step.run(
                f"fetch-bills-page-{page}",
                lambda p=page: free_agent_get_bills(token, str(subdomain), page=p, per_page=page_size),
            )
            page_items = payload.get("bills") or []
            if not page_items:
                break
            bills.extend(page_items)
            if len(page_items) < page_size:
                break

        async for db in session_scope():
            existing = await db.execute(
                select(Invoice.provider_invoice_id).where(
                    Invoice.business_profile_id == bp_id,
                    Invoice.provider == "free_agent",
                )
            )
            existing_ids = {str(x) for x in existing.scalars().all()}

            for b in bills:
                inv_id = b.get("url") or b.get("id")
                if not inv_id:
                    continue
                inv_id_s = str(inv_id)
                if inv_id_s in existing_ids:
                    continue
                total_raw = b.get("total_value")
                try:
                    total_val = float(total_raw) if total_raw is not None else None
                except Exception:
                    total_val = None

                db.add(
                    Invoice(
                        business_profile_id=bp_id,
                        provider="free_agent",
                        provider_invoice_id=inv_id_s,
                        invoice_type="bill",
                        status=str(b.get("status") or "") or None,
                        invoice_date=str(b.get("dated_on") or "") or None,
                        due_date=str(b.get("due_on") or "") or None,
                        total=total_val,
                        currency=str(b.get("currency") or "") or None,
                        reference=str(b.get("reference") or "") or None,
                        contact_id=str(b.get("contact") or "") or None,
                        contact_name=str(b.get("contact_name") or "") or None,
                        raw=b,
                    )
                )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

        outcome["invoices"] = len(bills)

    return outcome


async def main() -> None:
    await init_db()
    await choreo.start_worker()


if __name__ == "__main__":
    asyncio.run(main())
