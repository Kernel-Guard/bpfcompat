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

## Hosting via Cloudflare Tunnel

The webhook is pure ingestion and does **not** need the KVM/QEMU demo host — it
can run on any always-on Linux box. Because `kernelguard.net` is already on
Cloudflare, the lowest-friction way to publish `api.kernelguard.net` is a
Cloudflare Tunnel: the box dials *out* to Cloudflare, so there are no inbound
ports to open, no public IP, and no Let's Encrypt on the box (TLS terminates at
the Cloudflare edge).

On the box that runs `bpfcompat serve` (bound to `127.0.0.1:8080`):

```bash
# 1. Make sure the server is up with the secret set:
#    /etc/bpfcompat/serve.env -> BPFCOMPAT_GITHUB_MARKETPLACE_WEBHOOK_SECRET=<value>
#    sudo systemctl restart bpfcompat-serve

# 2. Install cloudflared, then run the helper (interactive browser login):
./scripts/cloudflared-setup.sh
```

`scripts/cloudflared-setup.sh` logs in, creates a `bpfcompat-api` tunnel, routes
`api.kernelguard.net` to it (creating the proxied CNAME in Cloudflare DNS),
writes `/etc/cloudflared/config.yml` from
`packaging/cloudflared/config.yml.example`, and installs the `cloudflared`
system service. After it finishes:

```bash
curl -i https://api.kernelguard.net/livez                      # 200 = tunnel + server up
curl -i -X POST https://api.kernelguard.net/github/marketplace/webhook  # 401 = webhook live & verifying
```

Then on the GitHub listing webhook page → **Recent Deliveries → Redeliver** the
ping; expect a `200`.

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
