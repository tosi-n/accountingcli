from __future__ import annotations

import base64
import json
import time
import urllib.parse
from typing import Any

import httpx

from app.settings import settings


def _now_ts() -> int:
    return int(time.time())


def _calc_expires_at(token: dict[str, Any]) -> dict[str, Any]:
    if "expires_in" in token and "expires_at" not in token:
        token["expires_at"] = _now_ts() + int(token["expires_in"])
    return token


def _preserve_refresh_token(token: dict[str, Any], previous_refresh_token: str) -> dict[str, Any]:
    if not str(token.get("refresh_token") or "").strip():
        token["refresh_token"] = previous_refresh_token
    return _calc_expires_at(token)


def build_redirect_uri(provider: str) -> str:
    base = settings.BACKEND_PUBLIC_ORIGIN.rstrip("/")
    return f"{base}/api/v1/tool-accounting/oauth/callback/{provider}"


def build_authorize_url(provider: str, state: str) -> str:
    if provider == "xero":
        params = {
            "response_type": "code",
            "client_id": settings.XERO_CLIENT_ID,
            "redirect_uri": build_redirect_uri("xero"),
            "scope": settings.XERO_SCOPE,
            "state": state,
        }
        return f"{settings.XERO_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    if provider == "quickbooks":
        params = {
            "client_id": settings.QUICKBOOKS_CLIENT_ID,
            "response_type": "code",
            "scope": settings.QUICKBOOKS_SCOPE,
            "redirect_uri": build_redirect_uri("quickbooks"),
            "state": state,
        }
        return f"{settings.QUICKBOOKS_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    if provider == "sage":
        params = {
            "response_type": "code",
            "client_id": settings.SAGE_CLIENT_ID,
            "redirect_uri": build_redirect_uri("sage"),
            "scope": settings.SAGE_SCOPE,
            "state": state,
        }
        return f"{settings.SAGE_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    if provider == "free_agent":
        params = {
            "response_type": "code",
            "client_id": settings.FREE_AGENT_CLIENT_ID,
            "redirect_uri": build_redirect_uri("free_agent"),
            "state": state,
        }
        return f"{settings.FREE_AGENT_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    raise ValueError(f"unknown provider: {provider}")


async def exchange_code(provider: str, code: str) -> dict[str, Any]:
    if provider == "xero":
        basic = base64.b64encode(f"{settings.XERO_CLIENT_ID}:{settings.XERO_CLIENT_SECRET}".encode("utf-8")).decode("utf-8")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": build_redirect_uri("xero"),
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                settings.XERO_TOKEN_URL,
                data=data,
                headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return _calc_expires_at(resp.json())

    if provider == "quickbooks":
        basic = base64.b64encode(f"{settings.QUICKBOOKS_CLIENT_ID}:{settings.QUICKBOOKS_CLIENT_SECRET}".encode("utf-8")).decode("utf-8")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": build_redirect_uri("quickbooks"),
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                settings.QUICKBOOKS_TOKEN_URL,
                data=data,
                headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return _calc_expires_at(resp.json())

    if provider == "sage":
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": build_redirect_uri("sage"),
            "client_id": settings.SAGE_CLIENT_ID,
            "client_secret": settings.SAGE_CLIENT_SECRET,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(settings.SAGE_TOKEN_URL, data=data)
            resp.raise_for_status()
            return _calc_expires_at(resp.json())

    if provider == "free_agent":
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": build_redirect_uri("free_agent"),
            "client_id": settings.FREE_AGENT_CLIENT_ID,
            "client_secret": settings.FREE_AGENT_CLIENT_SECRET,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(settings.FREE_AGENT_TOKEN_URL, data=data)
            resp.raise_for_status()
            return _calc_expires_at(resp.json())

    raise ValueError(f"unknown provider: {provider}")


async def refresh_token(provider: str, refresh_token_value: str) -> dict[str, Any]:
    if provider == "xero":
        basic = base64.b64encode(f"{settings.XERO_CLIENT_ID}:{settings.XERO_CLIENT_SECRET}".encode("utf-8")).decode("utf-8")
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token_value}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                settings.XERO_TOKEN_URL,
                data=data,
                headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return _preserve_refresh_token(resp.json(), refresh_token_value)

    if provider == "quickbooks":
        basic = base64.b64encode(f"{settings.QUICKBOOKS_CLIENT_ID}:{settings.QUICKBOOKS_CLIENT_SECRET}".encode("utf-8")).decode("utf-8")
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token_value}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                settings.QUICKBOOKS_TOKEN_URL,
                data=data,
                headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return _preserve_refresh_token(resp.json(), refresh_token_value)

    if provider == "sage":
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_value,
            "client_id": settings.SAGE_CLIENT_ID,
            "client_secret": settings.SAGE_CLIENT_SECRET,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(settings.SAGE_TOKEN_URL, data=data)
            resp.raise_for_status()
            return _preserve_refresh_token(resp.json(), refresh_token_value)

    if provider == "free_agent":
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_value,
            "client_id": settings.FREE_AGENT_CLIENT_ID,
            "client_secret": settings.FREE_AGENT_CLIENT_SECRET,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(settings.FREE_AGENT_TOKEN_URL, data=data)
            resp.raise_for_status()
            return _preserve_refresh_token(resp.json(), refresh_token_value)

    raise ValueError(f"unknown provider: {provider}")


async def xero_get_connections(token: dict[str, Any]) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/connections"),
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        resp.raise_for_status()
        return resp.json()


async def xero_get_bank_transactions(token: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "xero-tenant-id": tenant_id,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/BankTransactions"),
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_get_invoices(
    token: dict[str, Any],
    tenant_id: str,
    *,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "xero-tenant-id": tenant_id,
    }
    params = {"page": page, "pageSize": page_size}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/Invoices"),
            headers=headers,
            params=params,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_get_accounts(token: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "xero-tenant-id": tenant_id,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/Accounts"),
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_get_tax_rates(token: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "xero-tenant-id": tenant_id,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/TaxRates"),
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def free_agent_api_get(
    path: str,
    token: dict[str, Any],
    *,
    subdomain: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.FREE_AGENT_BASE_URL, path)
    headers: dict[str, str] = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
    }
    if subdomain:
        headers["X-Subdomain"] = subdomain
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()


async def free_agent_get_clients(token: dict[str, Any], *, page: int = 1, per_page: int = 100) -> dict[str, Any]:
    return await free_agent_api_get(
        "/v2/clients",
        token,
        params={"page": page, "per_page": per_page},
    )


async def free_agent_get_bills(
    token: dict[str, Any],
    subdomain: str,
    *,
    page: int = 1,
    per_page: int = 100,
    nested_bill_items: bool = True,
) -> dict[str, Any]:
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    if nested_bill_items:
        params["nested_bill_items"] = True
    return await free_agent_api_get("/v2/bills", token, subdomain=subdomain, params=params)


async def free_agent_get_bank_transactions(
    token: dict[str, Any],
    subdomain: str,
    *,
    page: int = 1,
    per_page: int = 100,
) -> dict[str, Any]:
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    return await free_agent_api_get("/v2/bank_transactions", token, subdomain=subdomain, params=params)


async def free_agent_get_categories(
    token: dict[str, Any],
    subdomain: str,
) -> dict[str, Any]:
    return await free_agent_api_get("/v2/categories", token, subdomain=subdomain)


async def free_agent_get_bank_accounts(
    token: dict[str, Any],
    subdomain: str,
    *,
    page: int = 1,
    per_page: int = 100,
) -> dict[str, Any]:
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    return await free_agent_api_get("/v2/bank_accounts", token, subdomain=subdomain, params=params)


def _quickbooks_base_url() -> str:
    env = (settings.QUICKBOOKS_ENV or "").strip().lower()
    if env == "production":
        return "https://quickbooks.api.intuit.com"
    return settings.QUICKBOOKS_BASE_URL


async def quickbooks_query(
    token: dict[str, Any],
    realm_id: str,
    query: str,
    *,
    minorversion: int = 70,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(_quickbooks_base_url(), f"/v3/company/{realm_id}/query")
    params = {
        "query": query,
        "minorversion": minorversion,
    }
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()


async def quickbooks_get_company_info(token: dict[str, Any], realm_id: str) -> dict[str, Any]:
    url = urllib.parse.urljoin(
        _quickbooks_base_url(),
        f"/v3/company/{realm_id}/companyinfo/{realm_id}",
    )
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url, headers=headers, params={"minorversion": 70})
        resp.raise_for_status()
        return resp.json()


async def quickbooks_get_purchases(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from Purchase startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def quickbooks_get_bills(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from Bill startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def quickbooks_get_accounts(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from Account startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def quickbooks_get_tax_codes(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from TaxCode startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def quickbooks_get_tax_rates(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from TaxRate startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def xero_create_invoices(
    token: dict[str, Any],
    tenant_id: str,
    invoices: list[dict[str, Any]],
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "xero-tenant-id": tenant_id,
    }
    payload = {"Invoices": invoices}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.put(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/Invoices"),
            headers=headers,
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_upload_invoice_attachment(
    token: dict[str, Any],
    tenant_id: str,
    invoice_id: str,
    *,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
    include_online: bool = False,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": content_type or "application/octet-stream",
        "xero-tenant-id": tenant_id,
    }
    encoded_filename = urllib.parse.quote(filename, safe="")
    params = {"IncludeOnline": str(bool(include_online)).lower()}
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            urllib.parse.urljoin(
                settings.XERO_BASE_URL,
                f"/api.xro/2.0/Invoices/{invoice_id}/Attachments/{encoded_filename}",
            ),
            headers=headers,
            params=params,
            content=content,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_get_payment(
    token: dict[str, Any],
    tenant_id: str,
    payment_id: str,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "xero-tenant-id": tenant_id,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(
            urllib.parse.urljoin(settings.XERO_BASE_URL, f"/api.xro/2.0/Payments/{payment_id}"),
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def xero_create_payments(
    token: dict[str, Any],
    tenant_id: str,
    payments: list[dict[str, Any]],
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "xero-tenant-id": tenant_id,
    }
    payload = {"Payments": payments}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.put(
            urllib.parse.urljoin(settings.XERO_BASE_URL, "/api.xro/2.0/Payments"),
            headers=headers,
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()


async def quickbooks_get_vendors(
    token: dict[str, Any],
    realm_id: str,
    *,
    start_position: int = 1,
    max_results: int = 200,
) -> dict[str, Any]:
    q = f"select * from Vendor startposition {int(start_position)} maxresults {int(max_results)}"  # nosec
    return await quickbooks_query(token, realm_id, q)


async def quickbooks_create_bill(
    token: dict[str, Any],
    realm_id: str,
    bill: dict[str, Any],
    *,
    minorversion: int = 70,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(_quickbooks_base_url(), f"/v3/company/{realm_id}/bill")
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    params = {"minorversion": minorversion}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, headers=headers, params=params, json=bill)
        resp.raise_for_status()
        return resp.json()


async def quickbooks_upload_attachment(
    token: dict[str, Any],
    realm_id: str,
    *,
    entity_type: str,
    entity_id: str,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
    note: str | None = None,
    minorversion: int = 70,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(_quickbooks_base_url(), f"/v3/company/{realm_id}/upload")
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
    }
    params = {"minorversion": minorversion}
    metadata: dict[str, Any] = {
        "AttachableRef": [
            {
                "EntityRef": {
                    "type": entity_type,
                    "value": entity_id,
                }
            }
        ],
        "FileName": filename,
    }
    if note:
        metadata["Note"] = note
    files = {
        "file_metadata_01": (None, json.dumps({"Attachable": metadata}), "application/json"),
        "file_content_01": (filename, content, content_type or "application/octet-stream"),
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, headers=headers, params=params, files=files)
        resp.raise_for_status()
        return resp.json()


async def quickbooks_create_bill_payment(
    token: dict[str, Any],
    realm_id: str,
    payment: dict[str, Any],
    *,
    minorversion: int = 70,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(_quickbooks_base_url(), f"/v3/company/{realm_id}/billpayment")
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    params = {"minorversion": minorversion}
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, headers=headers, params=params, json=payment)
        resp.raise_for_status()
        return resp.json()


async def free_agent_api_post(
    path: str,
    token: dict[str, Any],
    *,
    subdomain: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.FREE_AGENT_BASE_URL, path)
    headers: dict[str, str] = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if subdomain:
        headers["X-Subdomain"] = subdomain
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, headers=headers, json=payload or {})
        resp.raise_for_status()
        return resp.json()


async def free_agent_create_bill(
    token: dict[str, Any],
    subdomain: str,
    bill: dict[str, Any],
) -> dict[str, Any]:
    return await free_agent_api_post("/v2/bills", token, subdomain=subdomain, payload={"bill": bill})


async def free_agent_create_bank_transaction_explanation(
    token: dict[str, Any],
    subdomain: str,
    explanation: dict[str, Any],
) -> dict[str, Any]:
    return await free_agent_api_post(
        "/v2/bank_transaction_explanations",
        token,
        subdomain=subdomain,
        payload={"bank_transaction_explanation": explanation},
    )
