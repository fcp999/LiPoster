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

Five design choices carried most of the weight.

**One file, standard library only.** No Flask, no requests, no scheduler library. `http.server.ThreadingHTTPServer` for the API, a daemon thread for the publish loop, `urllib` for outbound calls, `sqlite3` for state. That means no dependency tree to audit and no surface beyond the one file.

**The database *is* the queue.** Posts live in a `posts` table with a `status` column — `queued`, `publishing`, `published`, `failed` — and the scheduler polls for rows whose `scheduled_at` has passed. No broker, no external queue, and an audit trail for free. The token lives in an `oauth` table in the same file.

**Scopes as configuration.** `OAUTH_SCOPE` is an environment variable rather than a string literal in the code. This turned out to be essential, not merely tidy — the entire afternoon was a sequence of changing which scopes to request.

**Identity from the token, not from an API call.** Explained below; this was the fix that made everything work.

**Stories from curated feeds, not search.** The generator reads RSS and Atom feeds from sources with editorial standards. Every item in a feed is an article by construction, so there is no ranking problem and no way for a vendor landing page to enter the queue. Web search remains a fallback. This replaced a search-ranking approach that produced navigation menus and product pages, and the replacement is the single most important design decision in the project.

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

### Where everything lives

```
/docker/linkedin/app/                 deployment directory (source + config)
├── app.py                            the service (single file)
├── compose.yaml                      container definition
├── Dockerfile                        python:3.13-alpine build
├── .env                              secrets, mode 600, never committed
└── .env.example                      template, committed

/docker/docker/volumes/app_linkedin-data/_data/linkedin.db
                                      SQLite volume — holds the live token
```

The volume is the important one. It is **not** in the deployment directory and it is **not** recreated by a rebuild, so a `build --no-cache` cannot destroy it. That separation is the whole reason a schema change or a bad deploy is recoverable: the container is disposable, the data is not.

**Back up before touching anything.** The volume is the only copy of a 60-day access token:

```bash
sudo docker run --rm \
  -v app_linkedin-data:/data \
  -v /tmp:/backup alpine \
  tar czf /backup/linkedin-$(date +%Y%m%d).tgz -C /data .
```

Restoring is the same command with `xzf` instead of `czf`, against a stopped container.

### Container hardening

The `compose.yaml` in this deployment does more than the upstream default:

```yaml
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

Confirmed in the running container:

```
readonly=true   user=publisher   privileged=false
```

`read_only: true` is why `docker cp` into the container fails with *"container rootfs is marked read-only"* — that error is the hardening working, not a bug. `/tmp` is a tmpfs so anything that needs scratch space still has it.

The process runs as `publisher`, not root, so a compromise starts with no privileges to escalate from.

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

`OAUTH_SCOPE` is deliberately a variable rather than a literal. Being able to change the requested scopes without editing code is what made the OAuth debugging above tractable.

**Changing `.env` requires recreating the container, not restarting it.** The environment is frozen at container creation:

```bash
sudo docker compose up -d --force-recreate     # picks up new .env values
sudo docker restart linkedin-publisher         # does NOT
```

Verify the value actually landed inside the running container before trusting it:

```bash
sudo docker exec linkedin-publisher env | grep DEFAULT_HASHTAGS
```

This matters more than it sounds. The app appends `#NetScout` at *queue* time based on this variable, so checking it on disk is not enough — it has to be checked in the process that will read it.

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

`#NetScout` is appended automatically unless the text already contains it — and only if `DEFAULT_HASHTAGS` is set. Set it to an empty value to disable the tag entirely:

```
DEFAULT_HASHTAGS=
```

Then recreate the container, since the variable is read at queue time from the frozen environment.

### Posting long text

LinkedIn caps a post at 3,000 characters. Build the payload with a tool rather than hand-escaping newlines — JSON escaping by hand is where multi-paragraph posts break:

```bash
python3 -c "import json; print(json.dumps({'text': open('post.txt').read().strip()}))" > /tmp/post.json
```

Then send the file:

```bash
curl -X POST https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/post.json
```

### Reading state

The API is the only interface that reports outcomes. The browser UI shows the same rows, but the API is scriptable:

```bash
curl -s https://linkedin.fcp3.me/api/posts \
  -H "Authorization: Bearer $APP_API_KEY"
```

Each row carries `status`, `attempts`, `public_url`, and `last_error`. A healthy post is `status: published`, `attempts: 1`, `last_error: null`. Anything with `attempts > 1` deserves a look, and `last_error` holds the verbatim provider response.

Querying the database directly is also fine, and is the fastest way to confirm a publish landed:

```bash
sudo docker exec linkedin-publisher python3 -c "
import sqlite3
c = sqlite3.connect('/data/linkedin.db')
for r in c.execute('SELECT id, status, attempts, public_url, last_error FROM posts ORDER BY id DESC LIMIT 5'):
    print(r)
"
```

### Publishing failures are not retried

This is deliberate, and it is the single most important behaviour to understand. The scheduler marks a failed publish as `failed` and **does not** queue an automatic retry.

A network timeout on the POST is ambiguous. LinkedIn may have accepted the post before the connection dropped. Retrying automatically would publish a duplicate. The app's own comment says so:

> A timed-out POST may have reached LinkedIn. Automatic retries can create duplicates, so ambiguous publish failures require review.

The `last_error` column preserves the exact provider response for that review.

---

## Operating it

### The publish loop

The scheduler thread wakes every `POLL_SECONDS` (30 by default) and processes due rows. There is no cron entry, no systemd timer, and no external trigger — the loop lives inside the container. That means:

- Stopping the container stops publishing.
- `restart: unless-stopped` brings it back after a host reboot.
- A backlog drains on the next tick once the container is back.

### Restarting cleanly

```bash
cd /docker/linkedin/app

# Code changed — rebuild, then recreate
sudo docker compose build --no-cache && sudo docker compose up -d --force-recreate

# Only .env changed — recreate is enough
sudo docker compose up -d --force-recreate

# Nothing changed, just want it bounced
sudo docker compose restart
```

### When the healthcheck fails

The Dockerfile defines a healthcheck against `/healthz` with a 30-second interval and 5-second start period. If `docker ps` shows `(unhealthy)`, the app is not answering on its internal port:

```bash
sudo docker inspect linkedin-publisher --format '{{.State.Health.Status}} restarts={{.RestartCount}}'
sudo docker logs --tail 50 linkedin-publisher
```

A crashed app writes the traceback to the container log — the process prints to stdout, so `docker logs` is the only place it appears. There is no log file on disk.

---

## The daily generator

A second job runs in the same scheduler thread: once per day it selects a story, queues it, and lets the normal publish loop handle delivery. No cron, no systemd timer, no external trigger.

### Schedule

```
DAILY_HOUR_WEEKDAY=10     weekdays, America/New_York
DAILY_HOUR_WEEKEND=7      weekends
```

The story is queued immediately and published by the scheduler, so the post goes out at the configured hour. A `story_log` table records one row per day, which both prevents a second post on the same day and keeps a history of what was published from where.

### Topic rotation

A `generator_state` table holds a cursor. Each day advances through the configured categories in order, so every topic is attempted before any repeats. If a category has no unseen story, the next one is tried rather than skipping the day silently.

```
packet analysis → network security → networking → security research
→ security tooling → ai tooling → quantum computing
```

### Why feeds rather than search

The first version ranked search results. It failed in a specific and instructive way: the highest-scoring candidates were vendor landing pages, category indexes, and homepages.

```
[50] fortinet.com        "What Is Network Traffic?"     — vendor glossary
[60] darkreading.com     "Vulnerabilities & Threats"    — category index
[52] thehackernews.com  "The Hacker News"              — homepage
```

No amount of scoring fixes this, because the problem is the source, not the ranking. Search returns pages *about* a topic; a feed returns that publication's articles, in order, with dates.

Two source shapes deserve specific mention as traps:

**`releases.atom` feeds look like content but are not.** A project's release feed yields build numbers and changelog dumps — `b11382` with a 7 KB HTML blob as its summary. Every item is a release by definition, so scoring cannot promote an article that does not exist. These were dropped.

**A single-source category will go dry.** "security tooling" began with one Suricata feed and one candidate. Within days it would fall through to the search fallback, which is exactly where the bad picks lived.

### Source file

Feeds live in `feeds.txt`, not in `.env`, because `.env` cannot hold a multi-line value without quoting. The file is mounted read-only into the container:

```yaml
volumes:
  - linkedin-data:/data
  - ./feeds.txt:/data/feeds.txt:ro
```

Format is one `category|url` per line:

```
packet analysis|https://zeek.org/feed/
network security|https://feeds.feedburner.com/feedburner/Talos
quantum computing|https://arxiv.org/rss/quant-ph
```

Every URL in the shipped list was fetched and confirmed to return parseable RSS or Atom. Two findings worth keeping: Talos publishes no working feed at `blog.talosintelligence.com/rss/` — it returns an HTML error page — but syndicates correctly through `feeds.feedburner.com/feedburner/Talos`. And `arxiv.org/rss/quant-ph` declares `<skipDays>Saturday, Sunday</skipDays>`, so an empty weekend result is correct behaviour, not a broken source.

### Summary extraction

Feed bodies arrive in inconsistent shapes, and two ordering mistakes cost real debugging time:

```python
text = html.unescape(html.unescape(value))          # unescape FIRST
text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
text = re.sub(r"(?s)<[^>]+>", " ", text)            # then strip
text = html.unescape(text)                           # catch double-encoding
text = re.sub(r"\s+", " ", text).strip()
```

Unescaping must precede stripping. Many feeds deliver the body entity-encoded, so `<p>` arrives as `&lt;p&gt;`. A strip pass running first matches nothing, and the later `unescape` then materialises literal tags into the published post.

Selection also matters: a feed often pairs a one-line `<description>` with the full `<content:encoded>`. Taking the first non-empty field yields a tagline; taking the longest yields the article.

### Opinion posts

Feeds interleave culture and opinion writing with reporting, and sorting by date will happily put a wellness column above a threat advisory. A title filter drops the obvious cases — wellness, hiring, newsletters, podcasts, event promotion — plus any title under four words. It is a heuristic, not a classifier, and it is deliberately narrow.

---

## What I'd do differently

**Prove the output before enabling the schedule.** The first unattended run published a navigation menu, because the extractor had never been tested against a real page. A dry-run that prints what *would* be published takes a minute and catches exactly this. Build the dry-run first, then arm the schedule.

**Verify the running code, always.** The stale-image problem wasted more time than any LinkedIn API issue. A hash comparison takes five seconds.

**Surface provider errors at the boundary.** The generic "Invalid or expired OAuth state" message was wrong three separate times. Error messages that guess are worse than no message at all, because they send you somewhere specific and wrong.

**Expect the API to change under you.** Every 2026 LinkedIn guide I found recommended scopes that no longer work. The durable insight isn't a scope list — it's that the `id_token` carries the identity you need, independent of which endpoints are currently permitted. That will survive the next round of deprecations.

**The token is the credential.** `/data/linkedin.db` holds a live LinkedIn access token valid for 60 days. It's a secret on the same footing as the client secret, and the app's own security notes say so.

---

## Repository

- **App:** https://github.com/fcp999/LiPoster
- **OAuth fix:** commit `41c3055` — *Resolve OAuth identity without the userinfo endpoint* (2 files, 57 insertions, 6 deletions), also merged to `main`
- **This document:** `docs/deploying-behind-haproxy.md`

The fix makes the OAuth flow complete on an application without the OIDC product's full entitlements, makes the requested scopes configurable, and stops collapsing distinct OAuth failures into one misleading message. The scope ladder above is in the commit message, so the next person doesn't spend an afternoon rediscovering it.

### Verifying the public tree is clean

The repo is public, so the source is readable by anyone. Nothing sensitive is in it, and that is worth being able to prove rather than assume. Check that `.env` was never tracked in any commit on any branch:

```bash
git log --all --oneline -- .env          # expect no output
```

Scan every commit for a known secret value:

```bash
git grep -I -n -E '<value>' $(git rev-list --all)
```

And confirm the file is ignored going forward:

```bash
git check-ignore -v .env
```

Repeat this after any commit that touches configuration. A secret committed once is in the history permanently, and removing it requires rewriting every commit after it — which breaks every clone. Prevention is the only cheap option.

### What the repository deliberately does not contain

| Not in the repo | Where it lives instead |
| --- | --- |
| `.env` with real values | `/docker/linkedin/app/.env`, mode 600 |
| The LinkedIn access token | `linkedin.db`, inside the Docker volume |
| Client ID and secret | The `.env` above |
| `APP_API_KEY`, `SESSION_SECRET` | The `.env` above |
| `feeds.txt` | `/docker/linkedin/app/feeds.txt`, mounted read-only |

The `.env.example` file *is* committed, and it contains placeholder strings that look like credentials. They are fake — the format examples in it are keyboard-mash, not real values. Worth knowing so the next person auditing the repo doesn't panic at the sight of them.
