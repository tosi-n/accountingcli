from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Internal auth
    ACCOUNTINGCLI_INTERNAL_API_KEY: str

    # Token encryption (Fernet base64 key; 32 bytes)
    ACCOUNTINGCLI_TOKEN_ENCRYPTION_KEY: str

    # DB
    ACCOUNTINGCLI_DATABASE_URL: str = "sqlite+aiosqlite:////data/accountingcli.db"

    # Choreo
    CHOREO_SERVER_URL: str = "http://choreo:8080"

    # Public origin used for OAuth redirect URI (Stimulir backend)
    BACKEND_PUBLIC_ORIGIN: str = "http://localhost:8000"

    # Xero
    XERO_CLIENT_ID: str = ""
    XERO_CLIENT_SECRET: str = ""
    XERO_SCOPE: str = "offline_access"
    XERO_AUTHORIZATION_URL: str = "https://login.xero.com/identity/connect/authorize"
    XERO_TOKEN_URL: str = "https://identity.xero.com/connect/token"
    XERO_REVOKE_TOKEN_URL: str = ""
    XERO_BASE_URL: str = "https://api.xero.com"

    # QuickBooks
    QUICKBOOKS_CLIENT_ID: str = ""
    QUICKBOOKS_CLIENT_SECRET: str = ""
    QUICKBOOKS_SCOPE: str = "com.intuit.quickbooks.accounting"
    QUICKBOOKS_AUTHORIZATION_URL: str = "https://appcenter.intuit.com/connect/oauth2"
    QUICKBOOKS_TOKEN_URL: str = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
    QUICKBOOKS_BASE_URL: str = "https://sandbox-quickbooks.api.intuit.com"
    QUICKBOOKS_ENV: str = "sandbox"

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


settings = Settings()

