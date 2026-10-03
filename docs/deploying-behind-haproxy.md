# A LinkedIn Publisher Behind HAProxy: OAuth, a Loader Hijack, and Three Wrong Turns

*Notes on deploying a single-user LinkedIn post scheduler to a lab Docker host — and on what the LinkedIn OAuth API actually grants you in 2026.*

---

## The goal

I wanted a scheduler for LinkedIn text posts. Not a SaaS integration, not a browser extension — something that ran on my own hardware, queued posts on my own clock, and could be driven by `curl`.

The result is [LiPoster](https://github.com/fcp999/LiPoster): a single-file Python service with no third-party dependencies, deployed in a container behind the HAProxy that fronts my lab, reachable at `https://linkedin.fcp3.me`.

This is the write-up: the architecture, the LinkedIn OAuth problems that consumed most of an afternoon, and the deployment mistakes worth not repeating.

---

## Architecture

```
Internet
   │
   ▼
HAProxy  (192.168.0.204:443)          TLS termination, host-based routing
   │  linkedin.fcp3.me → 192.168.0.209:8085
   ▼
Docker host (192.168.0.209)           Rocky Linux 8.10
   │
   ▼
linkedin-publisher container          python:3.13-alpine, non-root, read-only rootfs
   ├── HTTP server + scheduler thread
   └── SQLite volume (/data/linkedin.db)
```

Four design choices carried most of the weight.

**One file, standard library only.** No Flask, no requests, no scheduler library. `http.server.ThreadingHTTPServer` for the API, a daemon thread for the publish loop, `urllib` for outbound calls, `sqlite3` for state. That means no dependency tree to audit and no surface beyond the one file.

**The database *is* the queue.** Posts live in a `posts` table with a `status` column — `queued`, `publishing`, `published`, `failed` — and the scheduler polls for rows whose `scheduled_at` has passed. No broker, no external queue, and an audit trail for free. The token lives in an `oauth` table in the same file.

**Scopes as configuration.** `OAUTH_SCOPE` is an environment variable rather than a string literal in the code. This turned out to be essential, not merely tidy — the entire afternoon was a sequence of changing which scopes to request.

**Identity from the token, not from an API call.** Explained below; this was the fix that made everything work.

---

## The OAuth problem

LinkedIn's 2026 OAuth surface is a maze of independently-gated capabilities. The failure mode is nasty because **each gate rejects at a different stage**, and the errors don't distinguish between them.

The app requests three scopes:

```
openid  profile  w_member_social
```

`w_member_social` is the one that actually posts. `openid` and `profile` come from a *different product* in the LinkedIn developer portal — **Sign In with LinkedIn using OpenID Connect** — which is separate from **Share on LinkedIn**. You can have one and not the other.

### Gate 1: the scope isn't authorized

With only Share on LinkedIn enabled, authorization failed before a code was ever issued:

```
error=unauthorized_scope_error
error_description=Scope "openid" is not authorized for your application
```

LinkedIn rejects the *whole request*. You don't get a partial grant with the scopes it likes — you get nothing.

The app's original code reported this as `"Invalid or expired OAuth state"`, because it checked `if not row or not code:` and treated *any* callback without a code as a state mismatch. This sent debugging down the wrong path: the state was valid, and the state was never the problem. **A callback can arrive carrying `error=` instead of `code=`, and that distinction has to be surfaced.**

I patched the callback handler to report provider errors verbatim and to report state validity separately:

```python
provider_error = args.get("error", [""])[0]
provider_desc = args.get("error_description", [""])[0]
if provider_error:
    self.send_json(400, {"error": provider_error,
                         "error_description": provider_desc,
                         "state_valid": bool(row)})
    return
```

From then on the browser told the truth:

```json
{
  "error": "unauthorized_scope_error",
  "error_description": "Scope \"openid\" is not authorized for your application",
  "state_valid": true
}
```

### Gate 2: the fallback scope is also dead

Before adding the OIDC product, I tried the pre-OIDC route: request `r_liteprofile` alongside `w_member_social`, and resolve the person ID from the legacy `/v2/me` endpoint. That scope was rejected too:

```
Scope "r_liteprofile" is not authorized for your application
```

This is worth knowing: **`r_liteprofile` is being retired.** On newer applications LinkedIn won't authorize it at all. The old tutorials that reach for it no longer apply.

### Gate 3: a valid token, and still no identity

Once the OIDC product was granted, the scope check passed and the callback received a real `code`. The token exchange succeeded. Then the next step failed:

```
LinkedIn HTTP 403: {"status":403,"serviceErrorCode":100,"code":"ACCESS_DENIED",
                    "message":"Not enough permissions to access: userinfo.GET.NO_VERSION"}
```

**This is the confusing one.** `openid` was authorized enough to issue a token, but `/v2/userinfo` — the endpoint `openid` exists to unlock — was still denied. Granting the product and permitting that endpoint are evidently two separate gates.

Meanwhile `/v2/me` was denied as well, because `r_liteprofile` wasn't granted. So both identity endpoints were unreachable while the token itself was perfectly good.

### The fix: read the `id_token`

The access token response includes an **`id_token`** — a signed JWT. Its `sub` claim *is* the LinkedIn person id. It's already in your hands at that point in the flow, produced by an exchange that succeeded. You don't call anything; you decode a local base64 payload.

```python
def person_id_from_token(token: dict) -> str | None:
    """Read the LinkedIn person id from the OIDC id_token, when one was issued."""
    id_token = token.get("id_token")
    if not id_token:
        return None
    try:
        payload_b64 = id_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, json.JSONDecodeError):
        return None
    sub = claims.get("sub")
    return sub.removeprefix("urn:li:person:") if sub else None
```

The callback then tries the `id_token` first and falls back to the API endpoints only if it's absent:

```python
person_id = person_id_from_token(token) or fetch_person_id(token["access_token"])
```

**No endpoint can deny a claim you already hold.** Every prior failure was LinkedIn refusing to *tell us who the user was*. The `id_token` sidesteps the question entirely.

### The scope ladder

Everything above reduces to a table. Testing each rung against a live application:

| Scope set | Result |
| --- | --- |
| `w_member_social` | Authorized — but cannot resolve the person id |
| `w_member_social r_liteprofile` | `unauthorized_scope_error` (scope retired) |
| `openid profile w_member_social` | Authorized; `/v2/userinfo` may still be denied |

`w_member_social` alone can *post*, but it cannot *identify*. Every LinkedIn UGC post needs `urn:li:person:{id}` up front, so a posting-only token is useless on its own. That's the trap: the scope you need to publish is not the scope you need to address the publish.

The third row is the working configuration, and only with the `id_token` path.

---

## Deployment

### The application

```bash
cd /docker/linkedin/app
sudo docker compose build --no-cache
sudo docker compose up -d --force-recreate
```

### The reverse proxy

HAProxy on a separate host needed a frontend rule and a backend:

```
use_backend linkedin_backend   if { hdr(host) -i linkedin.fcp3.me }

backend linkedin_backend
    option httpchk GET /healthz
    http-check expect status 200
    server publisher 192.168.0.209:8085 check inter 10s
```

Validate before reloading — this catches syntax errors before they take down every other site behind the same frontend:

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
```

### Configuration

`.env`, mode `600`, never committed (`.gitignore` covers it):

```
BASE_URL=https://linkedin.fcp3.me
LINKEDIN_CLIENT_ID=...
LINKEDIN_CLIENT_SECRET=...
OAUTH_SCOPE=openid profile w_member_social
APP_API_KEY=<openssl rand -hex 32>
SESSION_SECRET=<openssl rand -hex 32>
DEFAULT_HASHTAGS=#NetScout
DB_PATH=/data/linkedin.db
PORT=8080
POLL_SECONDS=30
USER_TIMEZONE=America/New_York
```

`APP_API_KEY` and `SESSION_SECRET` are generated locally with `openssl rand -hex 32` and must each be at least 32 characters — the app refuses to start otherwise.

---

## Five mistakes worth avoiding

**1. `docker compose up -d` does not rebuild the image.**

This cost the most time of anything in the project. I patched `app.py` on disk, ran `--force-recreate`, and spent a build cycle convinced my fix hadn't worked — because the container was running the *previous* image. `--force-recreate` recreates the container; it does not rebuild from source.

The tell is a hash comparison:

```bash
sudo docker exec linkedin-publisher md5sum /app/app.py
sudo md5sum /docker/linkedin/app/app.py
```

Mismatched hashes mean a stale build. Fix:

```bash
sudo docker compose build --no-cache && sudo docker compose up -d --force-recreate
```

Always verify the running code, not just that the container is up.

**2. `docker restart` won't reload `.env`.**

Container environment is frozen at creation. Editing `.env` and restarting reuses the old values. You need `up -d --force-recreate`.

**3. A `sed` can delete a line instead of replacing it.**

Substituting a secret, I wrote a command that matched the key and dropped the line entirely. The app then crashed on `validate_config()` — which was the *good* outcome, because a missing required variable fails loudly. The bad outcome would have been a silent empty credential. Prefer rewriting the file from a parsed dict over `sed` for secrets:

```python
d = dict(l.split("=", 1) for l in open(p) if "=" in l)
d["LINKEDIN_CLIENT_SECRET"] = secret
open(p, "w").write("\n".join(f"{k}={v}" for k, v in d.items()) + "\n")
```

**4. Read the raw callback URL.**

Three times I was told "Invalid or expired OAuth state" when the state was fine. The truth was in the query string, which the app discarded. If you're debugging OAuth, log the full callback. Better: surface the provider's `error` and `error_description` to the user in the first place.

**5. A loopback bind breaks a remote reverse proxy.**

The app's default compose file binds `127.0.0.1:8080:8080`. That's good security hygiene if the proxy is on the same host — and completely useless if it isn't. HAProxy on `.204` couldn't reach `.209`'s loopback. Symptom: `haproxy` reports the backend `DOWN, Connection refused`, and every request returns 503 while the app is provably healthy.

I changed the bind to `8085:8080`. Note this *is* a real trade-off: the service is now reachable from anywhere on the LAN, unencrypted. The better answer is binding to the proxy's specific IP, or fronting it with TLS on the Docker host itself.

I also moved off port 8080 because Dashy already owned it on that host — `bind: address already in use`, caught immediately by the port publish.

---

## Verification

A container that starts is not a working service. The chain to check, in order:

```bash
# 1. Container is healthy
sudo docker ps --filter name=linkedin-publisher

# 2. App answers locally
curl -s http://127.0.0.1:8085/healthz

# 3. Proxy can reach it
curl -s http://192.168.0.209:8085/healthz          # from the proxy host

# 4. Full path through the proxy
curl -sk -o /dev/null -w "%{http_code}\n" https://linkedin.fcp3.me/healthz

# 5. HAProxy backends are UP
journalctl -u haproxy --since "5 min ago" | grep linkedin
```

Step 3 is the one that catches the loopback-bind problem, and it's easy to skip because steps 1 and 2 both look perfect.

**End to end:** two posts published, first attempt each.

```
{'id': 1, 'status': 'published', 'attempts': 1,
 'public_url': 'https://www.linkedin.com/feed/update/urn:li:share:7512214654446661633'}
{'id': 2, 'status': 'published', 'attempts': 1,
 'public_url': 'https://www.linkedin.com/feed/update/urn:li:share:7512216042174210049'}
```

The unit tests pass too, though they only cover the post-queueing and session-signing logic — they never touch OAuth, which is exactly where all the problems were. Worth noting for anyone extending this: the untested path was the broken path.

---

## Publishing

Through the browser form, or the REST API:

```bash
curl -X POST https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"Post text here"}'
```

Scheduled posts take an ISO 8601 time:

```bash
-d '{"text":"...","scheduled_at":"2026-10-05T14:00:00-04:00"}'
```

`#NetScout` is appended automatically unless the text already contains it.

---

## What I'd do differently

**Verify the running code, always.** The stale-image problem wasted more time than any LinkedIn API issue. A hash comparison takes five seconds.

**Surface provider errors at the boundary.** The generic "Invalid or expired OAuth state" message was wrong three separate times. Error messages that guess are worse than no message at all, because they send you somewhere specific and wrong.

**Expect the API to change under you.** Every 2026 LinkedIn guide I found recommended scopes that no longer work. The durable insight isn't a scope list — it's that the `id_token` carries the identity you need, independent of which endpoints are currently permitted. That will survive the next round of deprecations.

**The token is the credential.** `/data/linkedin.db` holds a live LinkedIn access token valid for 60 days. It's a secret on the same footing as the client secret, and the app's own security notes say so.

---

## Repository

- **App:** https://github.com/fcp999/LiPoster
- **This fix:** branch `oauth-id-token-fix`, commit `41c3055` — *Resolve OAuth identity without the userinfo endpoint*
- **Changes:** 2 files, 57 insertions, 6 deletions

The branch makes the OAuth flow complete on an application without the OIDC product's full entitlements, makes the requested scopes configurable, and stops collapsing distinct OAuth failures into one misleading message. The scope ladder above is documented in the commit message, so the next person doesn't spend an afternoon rediscovering it.
