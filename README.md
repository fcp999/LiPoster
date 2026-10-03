# LinkedIn Publisher

A small, single-user LinkedIn text-post scheduler. It publishes directly through LinkedIn's API, stores the returned post ID and public URL, retries transient failures, and preserves the exact provider error when a post fails.

## Features

- Immediate and scheduled text posts
- LinkedIn OAuth 2.0
- Automatic `#NetScout` suffix
- SQLite audit trail
- Duplicate-safe failure handling for ambiguous POST results
- Browser interface and bearer-token REST API
- Docker deployment behind HAProxy
- No third-party Python packages

## LinkedIn application setup

1. Create an application at <https://www.linkedin.com/developers/apps>.
2. Enable **Share on LinkedIn** and **Sign In with LinkedIn using OpenID Connect**.
3. Add `https://linkedin.fcp3.me/auth/linkedin/callback` as an authorized redirect URL.
4. Copy `.env.example` to `.env` and enter the Client ID and Client Secret.
5. Generate both local secrets:

```bash
openssl rand -hex 32
openssl rand -hex 32
```

## Run

```bash
cp .env.example .env
# Edit .env. Never commit it.
docker compose up -d --build
docker compose logs -f
```

Open `https://linkedin.fcp3.me/connect` and approve LinkedIn access. The browser interface then appears at `https://linkedin.fcp3.me/`.

## REST API

Queue an immediate post:

```bash
curl -X POST https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"TCP does not retransmit because a packet is slow. It retransmits because the sender lacks timely evidence of delivery."}'
```

Queue a scheduled post using an ISO 8601 time:

```bash
curl -X POST https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"Scheduled packet-analysis post","scheduled_at":"2026-10-05T14:00:00-04:00"}'
```

Read status and the public LinkedIn URL:

```bash
curl https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY"
```

## Tests

```bash
python -m unittest -v
```

## Security notes

- Keep `.env` and `/data/linkedin.db` private. The database contains the LinkedIn access token.
- Expose the service only through HTTPS.
- The API requires a random bearer key. The browser UI uses an HTTP-only, secure, signed cookie.
- OAuth state values expire after ten minutes and are single-use.
- The container runs as a non-root user with a read-only filesystem.
- Publish calls are not blindly retried. A network timeout may occur after LinkedIn accepted a post, so an automatic retry could create a duplicate. The exact error is retained for review.

## Current scope

Version 1 publishes personal-profile text posts. Image upload, article cards, deletion, and organization-page posting should be added only after the basic OAuth and text-post path is confirmed against the LinkedIn application.
