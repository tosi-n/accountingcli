from __future__ import annotations

import base64
import datetime as dt
import os
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
    free_agent_get_clients,
    refresh_token as provider_refresh_token,
    xero_get_connections,
)
from app.settings import settings


app = FastAPI(title="accountingcli", version="0.1.0")


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


class OAuthStatusOut(BaseModel):
    status: str
    tenant_id: str | None = None
    tenant_name: str | None = None


def _cipher() -> TokenCipher:
    return TokenCipher(settings.ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY)


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


async def _get_connection(db: AsyncSession, business_profile_id: UUID, provider: str) -> AccountingConnection | None:
    res = await db.execute(
        select(AccountingConnection).where(
            AccountingConnection.business_profile_id == str(business_profile_id),
            AccountingConnection.provider == provider,
        )
    )
    return res.scalars().first()


@app.post("/internal/oauth/{provider}/authorize-url", dependencies=[Depends(require_internal_api_key)])
async def authorize_url(provider: str, body: AuthorizeUrlIn) -> dict[str, str]:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
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
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
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
async def status(provider: str, business_profile_id: UUID) -> OAuthStatusOut:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        conn = await _get_connection(db, business_profile_id, provider)
        if not conn:
            return OAuthStatusOut(status="not_connected")
        return OAuthStatusOut(status="connected", tenant_id=conn.tenant_id, tenant_name=conn.tenant_name)


@app.post("/internal/oauth/{provider}/disconnect", dependencies=[Depends(require_internal_api_key)])
async def disconnect(provider: str, body: DisconnectIn) -> dict[str, Any]:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        await db.execute(
            delete(AccountingConnection).where(
                AccountingConnection.business_profile_id == str(body.business_profile_id),
                AccountingConnection.provider == provider,
            )
        )
        await db.commit()
    return {"disconnected": True}


@app.post("/internal/sync/{provider}", dependencies=[Depends(require_internal_api_key)])
async def trigger_sync(provider: str, body: SyncIn) -> dict[str, Any]:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
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
        idempotency_key=f"accountingcli:{provider}:{body.business_profile_id}:{','.join(sorted(normalized_sync_types))}",
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


@app.get("/internal/data/bank-transactions", dependencies=[Depends(require_internal_api_key)])
async def list_bank_transactions(
    business_profile_id: UUID,
    provider: str,
    since: str | None = None,
) -> list[dict[str, Any]]:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
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
    since: str | None = None,
) -> list[dict[str, Any]]:
    if provider not in {"xero", "quickbooks", "sage", "free_agent"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
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
