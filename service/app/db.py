from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, AsyncIterator, Optional

from sqlalchemy import JSON, DateTime, Float, String, Text, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.settings import settings


class Base(DeclarativeBase):
    pass


class OAuthState(Base):
    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))


class AccountingConnection(Base):
    __tablename__ = "accounting_connections"
    __table_args__ = (
        UniqueConstraint("business_profile_id", "provider", name="uq_accounting_connection_bp_provider"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    business_profile_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # xero|quickbooks|sage|free_agent
    token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tenant_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), onupdate=lambda: dt.datetime.now(dt.UTC))


class BankTransaction(Base):
    __tablename__ = "bank_transactions"
    __table_args__ = (
        UniqueConstraint("business_profile_id", "provider", "provider_transaction_id", name="uq_bank_tx_provider_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    business_profile_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_transaction_id: Mapped[str] = mapped_column(String(128), nullable=False)
    transaction_date: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    amount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    currency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))


class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = (
        UniqueConstraint("business_profile_id", "provider", "provider_invoice_id", name="uq_invoice_provider_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    business_profile_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_invoice_id: Mapped[str] = mapped_column(String(256), nullable=False)

    invoice_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    invoice_date: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    due_date: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    total: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    currency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    contact_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    contact_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    raw: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    business_profile_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    choreo_run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), onupdate=lambda: dt.datetime.now(dt.UTC))


_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.ACCOUNTINGCLI_DATABASE_URL, future=True, echo=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def session_scope() -> AsyncIterator[AsyncSession]:
    Session = get_sessionmaker()
    async with Session() as session:
        yield session
