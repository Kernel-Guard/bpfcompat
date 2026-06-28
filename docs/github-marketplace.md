# GitHub Marketplace webhook

The API server exposes a webhook endpoint for the bpfcompat GitHub Marketplace
listing. It receives `marketplace_purchase` events (purchase, change, cancel,
free-trial) and appends each verified delivery to a durable ledger for later
reconciliation and provisioning.

## Endpoint

```
POST https://api.kernelguard.net/github/marketplace/webhook
```

- **Authentication:** the delivery's HMAC-SHA256 signature
  (`X-Hub-Signature-256`) — *not* an API key. GitHub cannot present the API
  key/JWT used by the rest of the write surface, so the signature is the sole
  authenticator.
- **Content type:** `application/json` (the signature is computed over the raw
  JSON body; the `application/x-www-form-urlencoded` form is not supported).

## Configuration

Set the shared secret on the server to the exact value configured on the
listing's webhook:

```
BPFCOMPAT_GITHUB_MARKETPLACE_WEBHOOK_SECRET=<the listing webhook secret>
```

When this is unset the endpoint returns **503** and records nothing — it never
runs open.

On the GitHub side (listing → *Webhook*):
- **Payload URL:** `https://api.kernelguard.net/github/marketplace/webhook`
- **Secret:** the same value as the env var above
- **SSL verification:** enabled

## Response contract

| Status | When |
|---|---|
| `200` | ping, a recorded `marketplace_purchase`, or an acknowledged non-purchase event |
| `400` | malformed payload, or missing `X-GitHub-Event` header |
| `401` | missing or invalid signature |
| `405` | non-POST method |
| `413` | body exceeds 1 MiB |
| `500` | failed to persist the event — GitHub will redeliver |
| `503` | webhook secret not configured |

A `500` on persistence is deliberate: GitHub retries failed deliveries, so a
transient disk error doesn't silently drop a paid purchase event.

## Ledger

Verified events are appended as JSON Lines to:

```
<workdir>/marketplace/events.jsonl
```

The file is `0600` (the raw payload can include an organization billing email).
Each line carries a flat summary (action, account, plan, billing cycle) plus the
raw payload under `raw` so nothing is lost.

## What this does *not* do (yet)

This endpoint **ingests and records** purchase events. Turning a purchase into
an entitlement (granting access, emailing the buyer, updating a plan) is a
separate step that consumes the ledger — intentionally decoupled so ingestion
stays simple, idempotent-friendly, and independently testable.
