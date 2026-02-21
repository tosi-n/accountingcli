# Upstream Mapping (jack-2)

This repo vendors selected source-of-truth integration code from:

- `/Users/tosi-n/Documents/Dev/Jenesys/jack-2`

Status at time of initial sync:

- `jack-2` git: **no commits yet** (no `HEAD` SHA available)
- `jack-2` branch (from `git status -sb`): `feature/billing-system-latest`
- Synced at: `2026-02-17`

## Files Vendored

Copied into `vendor/jack2/...`:

- `backend/app/core/accounting/integrations/base.py`
- `backend/app/core/accounting/integrations/xero.py`
- `backend/app/core/accounting/integrations/quickbooks.py`
- `backend/app/core/accounting/integrations/sage.py`
- `backend/app/core/accounting/integrations/free_agent.py`
- `backend/app/core/services/oauth/base.py`
- `backend/app/core/services/oauth/exceptions.py`

## Sync Policy

1. Change integration behavior in `jack-2` first.
2. Re-sync this repo with `./scripts/sync_from_jack2.sh`.
3. Keep new code here limited to glue (HTTP surface, durable worker plumbing, normalization).

