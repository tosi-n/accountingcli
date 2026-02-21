# accountingcli

Internal tool-service (FastAPI) for accounting integrations used by `stimulir-console`.

Scope (v1):
- OAuth broker for: Xero, QuickBooks, Sage, FreeAgent
- Sync surface for normalized bank transactions (worker via Choreo)

This repo **copies** upstream behavior from `jack-2` into `vendor/jack2/...` as the
source-of-truth reference. We do not move or delete anything from `jack-2`.

## Run (local)

API:
```bash
docker build -t accountingcli:dev -f service/Dockerfile .
docker run --rm -p 8000:8000 --env-file .env accountingcli:dev
```

Worker:
```bash
docker build -t accountingcli-worker:dev -f worker/Dockerfile .
docker run --rm --env-file .env accountingcli-worker:dev
```

## Internal API (called by stimulir backend)
- `POST /internal/oauth/{provider}/authorize-url`
- `POST /internal/oauth/{provider}/exchange`
- `GET /internal/oauth/{provider}/status?business_profile_id=...`
- `POST /internal/oauth/{provider}/disconnect`
- `POST /internal/sync/{provider}`
- `GET /internal/data/bank-transactions?business_profile_id=...&provider=...&since=...`
- `GET /internal/data/invoices?business_profile_id=...&provider=...&since=...`

All internal endpoints require `X-Internal-API-Key: $ACCOUNTINGCLI_INTERNAL_API_KEY`.
