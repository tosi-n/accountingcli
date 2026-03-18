from __future__ import annotations

from pydantic import model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Internal auth
    ACCOUNTINGCLI_INTERNAL_API_KEY: str

    # Token encryption (Fernet base64 key; 32 bytes)
    ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY: str

    # DB
    # Precedence:
    # 1. ACCOUNTINGCLI_DATABASE_URL (tool-specific override)
    # 2. TOOL_DATABASE_URL (shared embedded-tool database)
    # 3. DATABASE_URL (reuse host/backend database)
    # 4. local SQLite fallback
    ACCOUNTINGCLI_DATABASE_URL: str = ""
    TOOL_DATABASE_URL: str = ""
    DATABASE_URL: str = ""

    # Choreo
    CHOREO_SERVER_URL: str = "http://choreo:8080"

    # Public origin used for OAuth redirect URI (Stimulir backend)
    BACKEND_PUBLIC_ORIGIN: str = "http://localhost:8000"
    BACKEND_LEDGER_INGEST_PATH: str = "/api/v1/internal/ledger/provider-events"

    # Xero
    XERO_CLIENT_ID: str = ""
    XERO_CLIENT_SECRET: str = ""
    XERO_SCOPE: str = "openid profile email offline_access accounting.invoices accounting.invoices.read accounting.payments accounting.payments.read accounting.banktransactions accounting.banktransactions.read accounting.settings accounting.settings.read accounting.contacts accounting.contacts.read accounting.attachments accounting.attachments.read"
    XERO_AUTHORIZATION_URL: str = "https://login.xero.com/identity/connect/authorize"
    XERO_TOKEN_URL: str = "https://identity.xero.com/connect/token"
    XERO_REVOKE_TOKEN_URL: str = ""
    XERO_BASE_URL: str = "https://api.xero.com"
    XERO_WEBHOOK_SIGNING_KEY: str = ""

    # QuickBooks
    QUICKBOOKS_CLIENT_ID: str = ""
    QUICKBOOKS_CLIENT_SECRET: str = ""
    QUICKBOOKS_SCOPE: str = "com.intuit.quickbooks.accounting"
    QUICKBOOKS_AUTHORIZATION_URL: str = "https://appcenter.intuit.com/connect/oauth2"
    QUICKBOOKS_TOKEN_URL: str = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
    QUICKBOOKS_BASE_URL: str = "https://sandbox-quickbooks.api.intuit.com"
    QUICKBOOKS_ENV: str = "sandbox"
    QUICKBOOKS_WEBHOOK_VERIFIER_TOKEN: str = ""

    # Sage
    SAGE_CLIENT_ID: str = ""
    SAGE_CLIENT_SECRET: str = ""
    SAGE_SCOPE: str = "full_access"
    SAGE_AUTHORIZATION_URL: str = "https://central.uk.sageone.com/oauth2/auth"
    SAGE_TOKEN_URL: str = "https://oauth.accounting.sage.com/token"
    SAGE_REVOKE_TOKEN_URL: str = ""
    SAGE_BASE_URL: str = "https://api.accounting.sage.com"

    # FreeAgent
    FREE_AGENT_CLIENT_ID: str = ""
    FREE_AGENT_CLIENT_SECRET: str = ""
    FREE_AGENT_AUTHORIZATION_URL: str = "https://api.sandbox.freeagent.com/v2/approve_app"
    FREE_AGENT_TOKEN_URL: str = "https://api.sandbox.freeagent.com/v2/token_endpoint"
    FREE_AGENT_REVOKE_TOKEN_URL: str = ""
    FREE_AGENT_BASE_URL: str = "https://api.sandbox.freeagent.com"

    # Proactive token refresh
    ACCOUNTINGCLI_TOKEN_REFRESH_INTERVAL_HOURS: int = 12
    ACCOUNTINGCLI_ACCESS_TOKEN_REFRESH_BUFFER_HOURS: int = 1
    ACCOUNTINGCLI_REFRESH_TOKEN_STALENESS_DAYS: int = 30

    @model_validator(mode="after")
    def resolve_database_urls(self) -> "Settings":
        explicit = (self.ACCOUNTINGCLI_DATABASE_URL or "").strip()
        if explicit:
            self.ACCOUNTINGCLI_DATABASE_URL = explicit
            return self

        shared_tool_db = (self.TOOL_DATABASE_URL or "").strip()
        if shared_tool_db:
            self.ACCOUNTINGCLI_DATABASE_URL = shared_tool_db
            return self

        host_db = (self.DATABASE_URL or "").strip()
        if host_db:
            self.ACCOUNTINGCLI_DATABASE_URL = host_db
            return self

        self.ACCOUNTINGCLI_DATABASE_URL = "sqlite+aiosqlite:////data/accountingcli.db"
        return self


settings = Settings()
