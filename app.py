#!/usr/bin/env python3
"""Single-user LinkedIn post scheduler using only the Python standard library."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo


DB_PATH = os.getenv("DB_PATH", "/data/linkedin.db")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080").rstrip("/")
CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
API_KEY = os.getenv("APP_API_KEY", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
DEFAULT_HASHTAGS = os.getenv("DEFAULT_HASHTAGS", "#NetScout").strip()
PORT = int(os.getenv("PORT", "8080"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
USER_TIMEZONE = os.getenv("USER_TIMEZONE", "America/New_York")


SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  access_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  person_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT NOT NULL,
  scheduled_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  linkedin_id TEXT,
  public_url TEXT,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_due ON posts(status, scheduled_at);
"""


def now() -> int:
    return int(time.time())


def db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)


def linkedin_request(method: str, url: str, token: str | None = None,
                     data: dict | None = None, form: dict | None = None) -> tuple[int, dict, dict]:
    headers = {"User-Agent": "fcp-linkedin-publisher/1.0"}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
        headers["X-Restli-Protocol-Version"] = "2.0.0"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode() or "{}"
            return response.status, json.loads(raw), dict(response.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"message": raw}
        raise RuntimeError(f"LinkedIn HTTP {exc.code}: {json.dumps(payload, separators=(',', ':'))}") from exc


def current_oauth() -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM oauth WHERE singleton=1").fetchone()


def normalized_text(text: str) -> str:
    text = text.strip()
    if DEFAULT_HASHTAGS and DEFAULT_HASHTAGS.lower() not in text.lower():
        text = f"{text}\n\n{DEFAULT_HASHTAGS}"
    if not text or len(text) > 3000:
        raise ValueError("Post text must contain 1 to 3,000 characters after hashtags are added")
    return text


def create_linkedin_post(text: str) -> tuple[str, str]:
    auth = current_oauth()
    if not auth:
        raise RuntimeError("LinkedIn is not connected")
    if auth["expires_at"] <= now():
        raise RuntimeError("LinkedIn access token expired; reconnect the account")
    author = f"urn:li:person:{auth['person_id']}"
    payload = {
        "author": author,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
    _, response, headers = linkedin_request(
        "POST", "https://api.linkedin.com/v2/ugcPosts", auth["access_token"], data=payload
    )
    post_id = headers.get("X-RestLi-Id") or headers.get("x-restli-id") or response.get("id")
    if not post_id:
        raise RuntimeError("LinkedIn returned success without a post identifier")
    return post_id, f"https://www.linkedin.com/feed/update/{post_id}"


def process_due_posts() -> None:
    with db() as conn:
        due = conn.execute(
            "SELECT * FROM posts WHERE status IN ('queued','retry') AND scheduled_at<=? ORDER BY id LIMIT 10",
            (now(),),
        ).fetchall()
    for post in due:
        with db() as conn:
            changed = conn.execute(
                "UPDATE posts SET status='publishing', attempts=attempts+1, updated_at=? "
                "WHERE id=? AND status IN ('queued','retry')", (now(), post["id"])
            ).rowcount
        if not changed:
            continue
        try:
            post_id, public_url = create_linkedin_post(post["text"])
            with db() as conn:
                conn.execute(
                    "UPDATE posts SET status='published',linkedin_id=?,public_url=?,last_error=NULL,updated_at=? WHERE id=?",
                    (post_id, public_url, now(), post["id"]),
                )
        except Exception as exc:
            # A timed-out POST may have reached LinkedIn. Automatic retries can
            # create duplicates, so ambiguous publish failures require review.
            status = "failed"
            delay = 0
            with db() as conn:
                conn.execute(
                    "UPDATE posts SET status=?,scheduled_at=?,last_error=?,updated_at=? WHERE id=?",
                    (status, now() + delay, str(exc)[:2000], now(), post["id"]),
                )


def scheduler() -> None:
    while True:
        try:
            process_due_posts()
        except Exception as exc:
            print(f"scheduler error: {exc}", flush=True)
        time.sleep(POLL_SECONDS)


def signed_session() -> str:
    stamp = str(now())
    sig = hmac.new(SESSION_SECRET.encode(), stamp.encode(), hashlib.sha256).hexdigest()
    return f"{stamp}.{sig}"


def valid_session(value: str) -> bool:
    try:
        stamp, sig = value.split(".", 1)
        if now() - int(stamp) > 86400 * 30:
            return False
        expected = hmac.new(SESSION_SECRET.encode(), stamp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except (ValueError, TypeError):
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "FCPLinkedIn/1.0"

    def send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def read_json(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        if size > 100_000:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(size) or b"{}")

    def api_authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(API_KEY) and hmac.compare_digest(supplied, API_KEY)

    def browser_authorized(self) -> bool:
        cookie = SimpleCookie(self.headers.get("Cookie"))
        value = cookie.get("session")
        return bool(value and SESSION_SECRET and valid_session(value.value))

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_json(200, {"status": "ok"})
            return
        if parsed.path == "/connect":
            state = secrets.token_urlsafe(32)
            with db() as conn:
                conn.execute("DELETE FROM oauth_states WHERE expires_at<?", (now(),))
                conn.execute("INSERT INTO oauth_states(state,expires_at) VALUES(?,?)", (state, now() + 600))
            query = urllib.parse.urlencode({
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": f"{BASE_URL}/auth/linkedin/callback",
                "state": state,
                "scope": "openid profile w_member_social",
            })
            self.redirect(f"https://www.linkedin.com/oauth/v2/authorization?{query}")
            return
        if parsed.path == "/auth/linkedin/callback":
            args = urllib.parse.parse_qs(parsed.query)
            state = args.get("state", [""])[0]
            code = args.get("code", [""])[0]
            with db() as conn:
                row = conn.execute("SELECT * FROM oauth_states WHERE state=? AND expires_at>=?", (state, now())).fetchone()
                conn.execute("DELETE FROM oauth_states WHERE state=?", (state,))
            if not row or not code:
                self.send_json(400, {"error": "Invalid or expired OAuth state"})
                return
            try:
                _, token, _ = linkedin_request("POST", "https://www.linkedin.com/oauth/v2/accessToken", form={
                    "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET, "redirect_uri": f"{BASE_URL}/auth/linkedin/callback",
                })
                _, profile, _ = linkedin_request("GET", "https://api.linkedin.com/v2/userinfo", token["access_token"])
                with db() as conn:
                    conn.execute(
                        "INSERT INTO oauth(singleton,access_token,expires_at,person_id,updated_at) VALUES(1,?,?,?,?) "
                        "ON CONFLICT(singleton) DO UPDATE SET access_token=excluded.access_token,expires_at=excluded.expires_at,person_id=excluded.person_id,updated_at=excluded.updated_at",
                        (token["access_token"], now() + int(token["expires_in"]), profile["sub"], now()),
                    )
                self.redirect("/", f"session={signed_session()}; Path=/; HttpOnly; Secure; SameSite=Lax")
            except Exception as exc:
                self.send_json(502, {"error": str(exc)})
            return
        if parsed.path == "/api/posts":
            if not self.api_authorized():
                self.send_json(401, {"error": "Unauthorized"})
                return
            with db() as conn:
                rows = conn.execute("SELECT * FROM posts ORDER BY id DESC LIMIT 100").fetchall()
            self.send_json(200, [dict(row) for row in rows])
            return
        if parsed.path == "/":
            if not self.browser_authorized():
                self.redirect("/connect")
                return
            auth = current_oauth()
            with db() as conn:
                rows = conn.execute("SELECT * FROM posts ORDER BY id DESC LIMIT 50").fetchall()
            expiry = datetime.fromtimestamp(auth["expires_at"], timezone.utc).isoformat() if auth else "not connected"
            table = "".join(
                f"<tr><td>{r['id']}</td><td>{html.escape(r['status'])}</td><td>{html.escape(r['text'])}</td>"
                f"<td>{html.escape(r['public_url'] or '')}</td><td>{html.escape(r['last_error'] or '')}</td></tr>" for r in rows
            )
            page = f"""<!doctype html><html><head><meta charset=utf-8><title>LinkedIn Publisher</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;background:#111;color:#eee}}textarea,input{{width:100%;padding:10px;margin:6px 0;background:#222;color:#fff;border:1px solid #555}}button{{padding:12px 22px;background:#0a66c2;color:white;border:0}}table{{width:100%;border-collapse:collapse;margin-top:24px}}td,th{{padding:8px;border-bottom:1px solid #444;vertical-align:top}}.muted{{color:#aaa}}</style></head>
<body><h1>LinkedIn Publisher</h1><p class=muted>Token expires: {html.escape(expiry)}</p>
<form method=post action=/web/posts><textarea name=text rows=8 maxlength=2950 required placeholder="Post text"></textarea>
<label>Publish at (blank means now)</label><input type=datetime-local name=scheduled_at><button>Queue post</button></form>
<table><tr><th>ID</th><th>Status</th><th>Text</th><th>URL</th><th>Error</th></tr>{table}</table></body></html>"""
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/posts":
            if not self.api_authorized():
                self.send_json(401, {"error": "Unauthorized"})
                return
            try:
                data = self.read_json()
                post_id = queue_post(data.get("text", ""), data.get("scheduled_at"))
                self.send_json(202, {"id": post_id, "status": "queued"})
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if parsed.path == "/web/posts":
            if not self.browser_authorized():
                self.send_json(401, {"error": "Unauthorized"})
                return
            size = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(size).decode())
            try:
                raw_time = form.get("scheduled_at", [""])[0]
                schedule = datetime.fromisoformat(raw_time).replace(tzinfo=ZoneInfo(USER_TIMEZONE)).timestamp() if raw_time else None
                queue_post(form.get("text", [""])[0], schedule)
                self.redirect("/")
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "Not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.client_address[0]} {fmt % args}", flush=True)


def queue_post(text: str, scheduled_at: int | float | str | None = None) -> int:
    text = normalized_text(text)
    if scheduled_at in (None, ""):
        scheduled = now()
    elif isinstance(scheduled_at, str) and not scheduled_at.isdigit():
        scheduled = int(datetime.fromisoformat(scheduled_at.replace("Z", "+00:00")).timestamp())
    else:
        scheduled = int(scheduled_at)
    stamp = now()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO posts(text,scheduled_at,status,created_at,updated_at) VALUES(?,?,'queued',?,?)",
            (text, scheduled, stamp, stamp),
        )
        return int(cur.lastrowid)


def validate_config() -> None:
    missing = [name for name, value in {
        "LINKEDIN_CLIENT_ID": CLIENT_ID, "LINKEDIN_CLIENT_SECRET": CLIENT_SECRET,
        "APP_API_KEY": API_KEY, "SESSION_SECRET": SESSION_SECRET,
    }.items() if not value]
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")
    if len(API_KEY) < 32 or len(SESSION_SECRET) < 32:
        raise SystemExit("APP_API_KEY and SESSION_SECRET must each contain at least 32 characters")


if __name__ == "__main__":
    validate_config()
    init_db()
    threading.Thread(target=scheduler, daemon=True).start()
    print(f"listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
