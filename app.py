#!/usr/bin/env python3
"""Single-user LinkedIn post scheduler using only the Python standard library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
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
# OpenID Connect scopes (openid/profile) require the "Sign In with LinkedIn using
# OpenID Connect" product. When unavailable, fall back to w_member_social only and
# resolve the person URN through the legacy /v2/me endpoint.
OAUTH_SCOPE = os.getenv("OAUTH_SCOPE", "openid profile w_member_social")
# Story search runs against a local SearXNG instance. It must answer the
# JSON API, which is a non-default setting in SearXNG's settings.yml.
SEARXNG_URL = os.getenv("SEARXNG_URL", "http://192.168.0.209:8082").rstrip("/")
# Hour of the local day at which a story is fetched and queued. The story is
# queued immediately and published by the normal scheduler, so the post goes
# out at this hour.
DAILY_HOUR_WEEKDAY = int(os.getenv("DAILY_HOUR_WEEKDAY", "10"))
DAILY_HOUR_WEEKEND = int(os.getenv("DAILY_HOUR_WEEKEND", "7"))
# Curated RSS/Atom feeds, one per line as "Category|URL". These are preferred
# over search: they have editorial standards, and a feed item is an article by
# construction, so there is no ranking problem to solve.
# Feed sources live in a file, not an environment variable: .env cannot hold a
# multi-line value without quoting, and a quoted block is fragile to edit.
FEED_SOURCES_FILE = os.getenv("FEED_SOURCES_FILE", "/data/feeds.txt")


def load_feed_sources() -> list[tuple[str, str]]:
    """Read "Category|URL" lines from the feed file. Missing file is not fatal."""
    sources: list[tuple[str, str]] = []
    try:
        with open(FEED_SOURCES_FILE, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        print(f"feed source file unreadable ({FEED_SOURCES_FILE}): {exc}", flush=True)
        return sources
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        cat, url = line.split("|", 1)
        cat, url = cat.strip().lower(), url.strip()
        if not url.startswith("http") or url in seen:
            continue
        seen.add(url)
        sources.append((cat, url))
    return sources


FEED_SOURCES: list[tuple[str, str]] = load_feed_sources()
# Topic rotation used only for search fallback when feeds are dry.
TOPICS = [t.strip() for t in os.getenv("TOPICS", "").split(",") if t.strip()]
# How many feed categories to accept in one day. One post per accepted item.
FEEDS_ENABLED = os.getenv("FEEDS_ENABLED", "1").strip() not in ("", "0", "false", "no")
# Kill switch. Set GENERATOR_ENABLED=0 to stop new posts being generated while
# leaving the publish queue and the API running. Existing queued posts still
# publish; only generation stops.
GENERATOR_ENABLED = os.getenv("GENERATOR_ENABLED", "1").strip() not in ("", "0", "false", "no")
# How far back a story may be, in days.
STORY_MAX_AGE_DAYS = int(os.getenv("STORY_MAX_AGE_DAYS", "7"))



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
CREATE TABLE IF NOT EXISTS story_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER,
  topic TEXT NOT NULL,
  day TEXT NOT NULL,
  title TEXT,
  url TEXT NOT NULL,
  domain TEXT,
  query TEXT,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_story_url ON story_log(url);
CREATE UNIQUE INDEX IF NOT EXISTS idx_story_day ON story_log(day);
CREATE TABLE IF NOT EXISTS generator_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  topic_cursor INTEGER NOT NULL DEFAULT 0,
  last_day TEXT,
  last_status TEXT,
  last_error TEXT,
  updated_at INTEGER NOT NULL
);
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


def person_id_from_token(token: dict) -> str | None:
    """Read the LinkedIn person id from the OIDC id_token, when one was issued.

    The id_token is a signed JWT whose sub claim is the person id. Reading it
    locally avoids calling /v2/userinfo, which LinkedIn may deny independently of
    the granted scopes.
    """
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


def fetch_person_id(token: str) -> str:
    """Return the LinkedIn person id from whichever identity endpoint is permitted."""
    if "openid" in OAUTH_SCOPE:
        _, profile, _ = linkedin_request("GET", "https://api.linkedin.com/v2/userinfo", token)
        return profile["sub"]
    if "r_liteprofile" in OAUTH_SCOPE or "r_basicprofile" in OAUTH_SCOPE:
        _, me, _ = linkedin_request("GET", "https://api.linkedin.com/v2/me", token)
        return me["id"]
    raise RuntimeError(
        "Cannot resolve the LinkedIn person id: token has no identity scope. Add "
        "r_liteprofile (Share on LinkedIn) or openid (Sign In with LinkedIn using "
        "OpenID Connect) to OAUTH_SCOPE."
    )


def current_oauth() -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM oauth WHERE singleton=1").fetchone()


def local_now() -> datetime:
    return datetime.now(ZoneInfo(USER_TIMEZONE))


def day_key(moment: datetime | None = None) -> str:
    return (moment or local_now()).strftime("%Y-%m-%d")


def due_hour(moment: datetime | None = None) -> int:
    """Weekends publish at 07:00, weekdays at 10:00, in the user's timezone."""
    moment = moment or local_now()
    return DAILY_HOUR_WEEKEND if moment.weekday() >= 5 else DAILY_HOUR_WEEKDAY


# Feeds emit several stacked layers of entity encoding. The worst observed
# form encodes an apostrophe as "&&#x23&#x3b;x26&#x3b;&#x23&#x3b;39&#x3b;":
# the hex-digit marker "x" and the separator ";" have themselves been encoded.
# A plain html.unescape() stalls on these, so the common shapes are decoded by
# hand first. The key detail is that a value after an "x" is hexadecimal, not
# decimal -- the previous implementation treated x26 as decimal 26 and
# produced the wrong character.


def _decode_codepoint(value: str, is_hex: bool) -> str:
    try:
        n = int(value, 16 if is_hex else 10)
        return chr(n) if 0 < n < 0x110000 else " "
    except ValueError:
        return " "


def repair_entities(value: str) -> str:
    """Normalise malformed numeric entities, then decode standard ones."""
    if not value:
        return value
    text = value
    # Repeatedly unescape until stable: handles the standard multi-layer case.
    for _ in range(4):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    # Handle hex and decimal codepoints with a stray "&#;" prefix.
    text = re.sub(r"&#;x([0-9a-fA-F]{2,6});", lambda m: _decode_codepoint(m.group(1), True), text)
    text = re.sub(r"&#;([0-9]{2,5});", lambda m: _decode_codepoint(m.group(1), False), text)
    # Handle the same shapes without the "&" prefix.
    text = re.sub(r"#;x([0-9a-fA-F]{2,6});", lambda m: _decode_codepoint(m.group(1), True), text)
    text = re.sub(r"#;([0-9]{2,5});", lambda m: _decode_codepoint(m.group(1), False), text)
    text = html.unescape(text)
    # Remove residual entity debris so it never reaches the post.
    text = re.sub(r"&#?;?x?[0-9a-fA-F]{0,6};?", " ", text)
    return text


def parse_feed(xml_text: str) -> list[dict]:
    """Parse an RSS 2.0 or Atom feed into {title,url,published,summary} dicts.

    Uses regex rather than an XML parser: feed markup is inconsistent, and a
    malformed namespace should not abort a whole source.
    """
    items: list[dict] = []
    blocks = re.findall(r"(?is)<item[\s>].*?</item>", xml_text)
    if not blocks:
        blocks = re.findall(r"(?is)<entry[\s>].*?</entry>", xml_text)

    def pick(block: str, *names: str) -> str:
        for name in names:
            match = re.search(rf"(?is)<{name}[^>]*>(.*?)</{name}>", block)
            if match:
                value = match.group(1).strip()
                value = re.sub(r"(?is)^<!\[CDATA\[(.*?)\]\]>$", r"\1", value).strip()
                if value:
                    return value
        return ""

    def clean(value: str, limit: int = 1400) -> str:
        """Unescape, strip markup, and collapse whitespace.

        Unescaping must happen before stripping: feeds commonly deliver the
        body entity-encoded, so &lt;p&gt; has to become <p> before the tag
        regex can see it. A second unescape catches double-encoded entities
        that the first pass exposed.

        Some feeds also emit mangled numeric entities, for example
        "&#;x26;#;39;" which should have been an apostrophe. html.unescape()
        ignores those because "&#;" is not a valid opener, so the debris
        survives into the post. repair_entities() normalises the common
        shapes first.
        """
        text = repair_entities(value)
        text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = repair_entities(text)
        text = re.sub(r"\s+", " ", text).strip()
        # WordPress feeds append "The post <title> appeared first on <site>."
        # to the description. Strip that footer so it does not count toward
        # the post length or appear in the published text.
        text = re.sub(r"(?i)\s*the post .*? appeared first on [^.]+\.?\s*$", "", text).strip()
        if len(text) <= limit:
            return text
        # Cut at a sentence boundary rather than mid-word. A body that stops
        # mid-sentence ("...is not only high-") reads as broken on the feed.
        cut = text[: limit + 1]
        boundary = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
        if boundary >= limit * 0.5:
            return cut[: boundary + 1].strip()
        space = text[:limit].rfind(" ")
        return text[:space].strip() if space >= limit * 0.5 else text[:limit]

    for block in blocks:
        title = clean(pick(block, "title"), 300)
        url = pick(block, "link")
        if not url:
            href = re.search(r'(?is)<link[^>]+href=["\']([^"\']+)["\']', block)
            url = href.group(1) if href else ""
        if not url:
            guid = pick(block, "guid")
            url = guid if guid.startswith("http") else ""
        published = pick(block, "pubDate", "published", "updated", "dc:date")
        # Take the longest of the candidate body fields rather than the first:
        # a feed often pairs a one-line <description> with the full
        # <content:encoded>, and the tagline is not the article.
        candidates = [
            clean(pick(block, name))
            for name in ("content:encoded", "content", "description", "summary")
        ]
        summary = max(candidates, key=len) if candidates else ""
        if len(summary) < 40:
            summary = ""
        if title and url.startswith("http"):
            items.append({"title": title, "url": url, "published": published, "summary": summary})
    return items


def parse_published(value: str) -> float | None:
    """Best-effort parse of RSS/Atom date strings into an epoch."""
    if not value:
        return None
    value = value.strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%a, %d %b %Y %H:%M %z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def fetch_feed(url: str, limit: int = 12) -> list[dict]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "fcp-linkedin-publisher/1.0 (+feed reader)",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        raw = response.read(400_000).decode(errors="replace")
    return parse_feed(raw)[:limit]


# Title patterns that mark a post as opinion, culture, or housekeeping rather
# than reporting or technical writing. Applied to feeds only, where a
# company-culture post sits alongside threat research in the same stream.
# Per-category keywords used to rank stories by relevance. A title or summary
# containing these terms ranks above a same-feed item that is only loosely
# related (for example, a SANS diary entry about an Apple patch in the
# "packet analysis" category). Keys must match the category names in feeds.txt.
CATEGORY_KEYWORDS = {
    "packet analysis": (
        "packet", "pcap", "wireshark", "tshark", "zeek", "suricata", "snort",
        "network traffic", "traffic analysis", "capture", "tap", "tcp",
        "udp", "protocol", "flow", "forensics", "packet analysis", "ids",
        "ips", "intrusion", "signature", "bro", "deep packet", "dpi",
    ),
    "network security": (
        "vulnerability", "cve", "exploit", "zero-day", "zero day", "ransomware",
        "malware", "threat", "adversary", "apt", "backdoor", "phishing",
        "breach", "compromise", "campaign", "attack", "botnet", "rat",
        "remote access", "defender", "incident", "security advisory", "patch",
    ),
    "networking": (
        "bgp", "dns", "routing", "ipv6", "internet", "protocol", "latency",
        "network", "tcp", "udp", "tls", "quic", "congestion", "anycast",
        "cdns", "peering", "asn", "prefix", "packet", "outage",
    ),
    "security research": (
        "research", "analysis", "reverse engineering", "vulnerability", "cve",
        "exploit", "firmware", "hardware", "side-channel", "side channel",
        "fuzzing", "rootkit", "bootkit", "supply chain", "disclosure",
        "proof of concept", "poc", "0day", "zero-day",
    ),
    "security tooling": (
        "tool", "scanner", "detection", "open source", "open-source", "framework",
        "library", "release", "released", "introducing", "new feature",
        "plugin", "engine", "signature", "rule", "ids", "yara", "sandbox",
        "automation", "pipeline", "cli", "api",
    ),
    "ai tooling": (
        "llm", "model", "inference", "training", "agent", "rag", "embedding",
        "fine-tun", "finetun", "transformer", "neural", "gpu", "token",
        "prompt", "generative", "open source", "open-source", "benchmark",
        "framework", "library", "release", "vllm", "llama", "diffusion",
    ),
    "quantum computing": (
        "quantum", "qubit", "qiskit", "superposition", "entanglement",
        "error correction", "fault-tolerant", "fault tolerant", "annealing",
        "quantum computer", "quantum computing", "circuit", "algorithm",
    ),
}


def normalized_title(title: str) -> str:
    """Collapse a title to a comparable key: lowercased, punctuation and
    whitespace folded. Two form letters that differ only in a trailing date or
    ordinal become the same key."""
    text = title.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# Titles that are boilerplate advisories rather than reporting. These are
# technically on-topic but are form letters: a KEV-catalog addition is not a
# story. They are de-ranked so real analysis rises above them.
BOILERPLATE_PATTERNS = (
    "cisa adds one known exploited", "cisa adds two known exploited",
    "known exploited vulnerabilities to catalog", "known exploited vulnerability to catalog",
    "ics advisory", "icsa-", "security advisory for",
    "industrial control systems", "ics medical advisory", "icsa-26",
)


def is_boilerplate(title: str, url: str = "") -> bool:
    """True when an item is a boilerplate advisory rather than reporting.

    Checks both the title and the URL: ICS-advisory form letters carry their
    marker in the path (/ics-advisories/), not in a generic vendor title.
    """
    low = (title + " " + url).lower()
    return any(pattern in low for pattern in BOILERPLATE_PATTERNS)


def relevance_score(category: str, title: str, summary: str) -> int:
    """Count how many category keywords appear in the title and summary."""
    keywords = CATEGORY_KEYWORDS.get(category)
    if not keywords:
        return 0
    text = f"{title} {summary}".lower()
    score = 0
    for kw in keywords:
        if kw in text:
            # Longer, more specific keywords count more than short fragments.
            score += 2 if len(kw) >= 6 else 1
    return score


OPINION_PATTERNS = (
    "give yourself room", "take a break", "well-being", "wellbeing",
    "burnout", "work-life", "work life", "mental health", "self-care",
    "reflections on", "reflecting on", "lessons learned", "what i learned",
    "why i ", "my journey", "we are hiring", "join our team", "meet the team",
    "welcome to the team", "employee spotlight", "company culture",
    "happy holidays", "thank you", "anniversary", "celebrating",
    "sponsors-only", "sponsors only", "newsletter", "podcast", "stormcast",
    "photo exhibition", "webinar", "register now", "save the date",
)
# A title this short is almost never a real article headline.
MIN_TITLE_WORDS = 4


def is_opinion_post(title: str) -> bool:
    """True when a feed item is culture, opinion, or housekeeping, not reporting."""
    low = title.lower().strip()
    if len(low.split()) < MIN_TITLE_WORDS:
        return True
    return any(pattern in low for pattern in OPINION_PATTERNS)


def feed_candidates(category: str, include_opinion: bool = False) -> list[dict]:
    """Collect fresh, unseen items across the feeds for one category.

    Opinion and culture posts are filtered out by default: feeds interleave
    them with reporting, and sorting by date would otherwise surface a
    wellness column over a threat advisory.
    """
    seen = seen_urls()
    floor = now() - STORY_MAX_AGE_DAYS * 86400
    found: list[dict] = []
    for cat, url in FEED_SOURCES:
        if cat != category:
            continue
        try:
            items = fetch_feed(url)
        except Exception as exc:
            print(f"feed failed: {url}: {exc}", flush=True)
            continue
        for item in items:
            if item["url"] in seen:
                continue
            if not include_opinion and is_opinion_post(item.get("title", "")):
                continue
            if is_boilerplate(item.get("title", ""), item.get("url", "")):
                continue
            stamp = parse_published(item.get("published", ""))
            if stamp is not None and stamp < floor:
                continue
            item["_published_ts"] = stamp or 0.0
            item["_source"] = url
            found.append(item)
    # De-duplicate by normalized title: near-identical form letters across a
    # feed (for example, repeated "CISA Adds One KEV" entries) collapse to one.
    deduped: list[dict] = []
    seen_titles: set[str] = set()
    for item in found:
        key = normalized_title(item.get("title", ""))
        if not key or key in seen_titles:
            continue
        seen_titles.add(key)
        deduped.append(item)
    return deduped


def searxng_search(query: str, time_range: str = "week") -> list[dict]:
    params = urllib.parse.urlencode({"q": query, "format": "json", "time_range": time_range})
    req = urllib.request.Request(
        f"{SEARXNG_URL}/search?{params}",
        headers={"User-Agent": "fcp-linkedin-publisher/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode() or "{}")
    return payload.get("results", [])


# Sources that produce listicles, storefronts, or paywalled stubs rather than
# reporting. Dropped before ranking so a daily post never lands on one.
STORY_DENY = {
    "msn.com", "facebook.com", "instagram.com", "pinterest.com", "x.com",
    "twitter.com", "reddit.com", "quora.com", "youtube.com", "tiktok.com",
    "wikipedia.org", "fandom.com", "edx.org", "coursera.org", "udemy.com",
    "amazon.com", "ebay.com", "etsy.com", "alibaba.com", "temu.com",
    "ycombinator.com", "producthunt.com", "gumroad.com", "patreon.com",
    "medium.com", "substack.com", "blogspot.com", "wordpress.com",
}
# Sources that count as reporting for the topics in play.
STORY_PREFER = {
    "theregister.com", "arstechnica.com", "bleepingcomputer.com",
    "thehackernews.com", "krebsonsecurity.com", "securityweek.com",
    "darkreading.com", "schneier.com", "phys.org", "nature.com",
    "sciencemag.org", "sciencedaily.com", "quantamagazine.org",
    "thequantuminsider.com", "quantumzeitgeist.com", "ieee.org",
    "spectrum.ieee.org", "github.blog", "github.com", "apnews.com",
    "reuters.com", "bbc.com", "bbc.co.uk", "npr.org", "wired.com",
    "technologynetworks.com", "lwn.net", "phoronix.com", "hackaday.com",
    "rtl-sdr.com", "ars-technica.com", "cnn.com", "theverge.com",
    "cisa.gov", "nist.gov", "cdc.gov", "who.int", "nih.gov",
}


# Reachable but not article-shaped: topic lists, aggregators, and index pages.
STORY_RANK_LOW = {
    "github.com", "gitlab.com", "sourceforge.net", "stackoverflow.com",
    "news.google.com", "finance.yahoo.com", "bloomberg.com", "marketscreener.com",
    "prnewswire.com", "globenewswire.com", "businesswire.com", "accesswire.com",
}


def story_domain(url: str) -> str:
    host = urllib.parse.urlparse(url).netloc.lower()
    return host[4:] if host.startswith("www.") else host


def domain_matches(domain: str, table: set[str]) -> bool:
    return any(domain == entry or domain.endswith("." + entry) for entry in table)


def seen_urls() -> set[str]:
    with db() as conn:
        return {r["url"] for r in conn.execute("SELECT url FROM story_log")}


def topic_cursor() -> int:
    with db() as conn:
        row = conn.execute("SELECT topic_cursor FROM generator_state WHERE singleton=1").fetchone()
    return row["topic_cursor"] if row else 0


def set_generator_state(cursor: int, day: str, status: str, error: str | None) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO generator_state(singleton,topic_cursor,last_day,last_status,last_error,updated_at) "
            "VALUES(1,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET "
            "topic_cursor=excluded.topic_cursor,last_day=excluded.last_day,"
            "last_status=excluded.last_status,last_error=excluded.last_error,updated_at=excluded.updated_at",
            (cursor, day, status, error, now()),
        )


# Phrases that appear on product, pricing, and landing pages. A page heavy in
# these is selling something, not reporting it.
COMMERCIAL_MARKERS = (
    "free trial", "pricing", "request a demo", "book a demo", "contact sales",
    "sign up free", "our platform", "our solution", "trusted by", "get started",
    "free for", "private plans", "on-prem for", "plans and pricing",
    "start your free", "schedule a demo", "talk to sales", "buy now",
    "add to cart", "subscribe now", "download the", "case study", "whitepaper",
)

# Path segments that mark a page as not-an-article.
NON_ARTICLE_PATHS = (
    "/pricing", "/product", "/products", "/solutions", "/platform", "/demo",
    "/contact", "/about", "/careers", "/jobs", "/partners", "/customers",
    "/trial", "/signup", "/register", "/login", "/cart", "/shop", "/store",
    "/tags/", "/category/", "/author/", "/page/", "/search",
)

# Domains that are editorial: they publish reporting, not sales copy.
EDITORIAL = {
    "theregister.com", "arstechnica.com", "bleepingcomputer.com",
    "thehackernews.com", "krebsonsecurity.com", "securityweek.com",
    "darkreading.com", "schneier.com", "phys.org", "nature.com",
    "sciencemag.org", "sciencedaily.com", "quantamagazine.org",
    "thequantuminsider.com", "quantumzeitgeist.com", "spectrum.ieee.org",
    "ieee.org", "github.blog", "apnews.com", "reuters.com", "bbc.com",
    "bbc.co.uk", "npr.org", "wired.com", "technologynetworks.com",
    "lwn.net", "phoronix.com", "hackaday.com", "rtl-sdr.com",
    "cnn.com", "theverge.com", "cisa.gov", "nist.gov", "cdc.gov",
    "who.int", "nih.gov", "helpnetsecurity.com", "csoonline.com",
    "infoworld.com", "zdnet.com", "thenextweb.com", "techcrunch.com",
    "venturebeat.com", "tomshardware.com", "anandtech.com", "theregister.co.uk",
    "sciencealert.com", "livescience.com", "space.com", "newscientist.com",
    "arstechnica.co.uk", "gizmodo.com", "engadget.com", "slashdot.org",
    "cve.org", "nvd.nist.gov", "unit42.paloaltonetworks.com",
    "fortinet.com", "crowdstrike.com", "mandiant.com", "securelist.com",
    "welivesecurity.com", "tripwire.com", "qualys.com", "tenable.com",
}


def looks_commercial(url: str, title: str, snippet: str) -> bool:
    """True when a candidate reads like a product page rather than reporting."""
    path = urllib.parse.urlparse(url).path.lower()
    if any(path.startswith(seg) or path == seg.rstrip("/") for seg in NON_ARTICLE_PATHS):
        return True
    low = f"{title} {snippet}".lower()
    hits = sum(1 for marker in COMMERCIAL_MARKERS if marker in low)
    return hits >= 2


def story_score(result: dict, topic: str) -> int:
    """Rank candidates. Higher is better; negative means unusable."""
    url = (result.get("url") or "").strip()
    title = (result.get("title") or "").strip()
    snippet = (result.get("content") or "").strip()
    if not url.startswith("http") or len(title) < 15:
        return -100
    domain = story_domain(url)
    if not domain or domain_matches(domain, STORY_DENY):
        return -100
    if domain_matches(domain, STORY_RANK_LOW):
        return -100
    if looks_commercial(url, title, snippet):
        return -100

    score = 0
    # The strongest signal: this outlet publishes journalism.
    if domain_matches(domain, EDITORIAL):
        score += 40
    # A publication date means it is a dated article, not a standing page.
    if result.get("publishedDate"):
        score += 15
    if domain_matches(domain, STORY_PREFER):
        score += 10
    # Longer snippets tend to be article summaries rather than taglines.
    if len(snippet) >= 160:
        score += 8
    elif len(snippet) < 60:
        score -= 10
    low = f"{title} {snippet}".lower()
    if any(word in low for word in topic.lower().split()):
        score += 2
    return score


def pick_story(topic: str) -> dict | None:
    """Return the best unseen result for a topic, or None if the topic is dry."""
    seen = seen_urls()
    candidates: list[tuple[int, dict]] = []
    for query in (topic, f"{topic} news"):
        try:
            results = searxng_search(query)
        except Exception as exc:
            print(f"search failed for {query!r}: {exc}", flush=True)
            continue
        for result in results:
            url = (result.get("url") or "").strip()
            if not url or url in seen:
                continue
            score = story_score(result, topic)
            if score < 0:
                continue
            candidates.append((score, result))
        if candidates:
            break
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1]


# A post shorter than this is a changelog line or a tagline, not an article
# summary. Publishing one looks like a mistake, so the generator skips the day
# instead.
MIN_POST_CHARS = int(os.getenv("MIN_POST_CHARS", "350"))


def build_post(title: str, url: str, domain: str, summary: str) -> str:
    parts = [summary.strip() or title.strip()]
    parts.append(url)
    text = "\n\n".join(p for p in parts if p)
    if DEFAULT_HASHTAGS and DEFAULT_HASHTAGS.lower() not in text.lower():
        text = f"{text}\n\n{DEFAULT_HASHTAGS}"
    return text[:2970]


def post_is_substantial(text: str, url: str) -> bool:
    """True when a candidate has enough body text to be worth publishing.

    The URL and any hashtag are excluded from the count: they are boilerplate
    and would let a one-line entry clear the bar.
    """
    body = text
    for boilerplate in (url, DEFAULT_HASHTAGS):
        if boilerplate:
            body = body.replace(boilerplate, " ")
    return len(body.strip()) >= MIN_POST_CHARS


def html_to_text(raw: str) -> str:
    """Strip tags and collapse whitespace."""
    text = re.sub(r"(?is)<(script|style|noscript|svg|head|nav|footer|form)[^>]*>.*?</\1>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"[\s\u00a0]+", " ", text).strip()


def extract_article(raw: str) -> str:
    """Pull the article body out of a page, avoiding nav and boilerplate.

    Tries, in order: og:description, JSON-LD articleBody, the densest <p>
    cluster, then the whole document as a last resort. The paragraph route is
    what keeps menu items and breadcrumbs out of the post.
    """
    meta = re.search(
        r'<meta[^>]+(?:property|name)=["\']og:description["\'][^>]*content=["\']([^"\']+)',
        raw, re.I,
    )
    if not meta:
        meta = re.search(
            r'<meta[^>]+content=["\']([^"\']{80,})["\'][^>]*(?:property|name)=["\']og:description',
            raw, re.I,
        )
    if meta:
        candidate = html.unescape(meta.group(1)).strip()
        if len(candidate) >= 80:
            return candidate

    for block in re.findall(r'(?is)<script[^>]+application/ld\+json[^>]*>(.*?)</script>', raw):
        try:
            data = json.loads(html.unescape(block).strip())
        except (json.JSONDecodeError, ValueError):
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                body = node.get("articleBody")
                if isinstance(body, str) and len(body) >= 120:
                    return re.sub(r"\s+", " ", body).strip()
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

    paragraphs = []
    for match in re.finditer(r"(?is)<p[^>]*>(.*?)</p>", raw):
        text = html_to_text(match.group(1))
        if len(text) >= 70:
            paragraphs.append(text)
        if sum(len(p) for p in paragraphs) >= 900:
            break
    if paragraphs:
        return " ".join(paragraphs)

    return html_to_text(raw)


def summarize(url: str) -> str:
    """Fetch a story and return a short readable extract.

    Raises on failure so the caller can fall back to the search snippet.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        raw = response.read(600_000).decode(errors="replace")
    return extract_article(raw)[:900]


def generate_daily_post() -> None:
    """Queue one story for today, at most once per day, in topic rotation."""
    if not GENERATOR_ENABLED:
        return
    if not TOPICS:
        return
    moment = local_now()
    day = day_key(moment)
    with db() as conn:
        already = conn.execute("SELECT 1 FROM story_log WHERE day=?", (day,)).fetchone()
    if already:
        return
    if moment.hour < due_hour(moment):
        return
    categories = []
    for cat, _url in FEED_SOURCES:
        if cat not in categories:
            categories.append(cat)
    if not categories:
        categories = [t.lower() for t in TOPICS]

    cursor = topic_cursor() % max(1, len(categories))
    attempts = len(categories)
    for offset in range(attempts):
        index = (cursor + offset) % len(categories)
        category = categories[index]
        items = []
        if FEEDS_ENABLED:
            try:
                items = feed_candidates(category)
            except Exception as exc:
                print(f"feed collect failed for {category!r}: {exc}", flush=True)
        if not items:
            continue
        # Rank by relevance first, recency second. An on-topic engineering
        # article should beat a newer but loosely-related item in the same feed.
        def rank(item: dict) -> tuple:
            title = (item.get("title") or "").strip()
            summary = (item.get("summary") or "").strip()
            rel = relevance_score(category, title, summary)
            ts = item.get("_published_ts") or 0.0
            # Bucket by relevance so recency only breaks ties within a bucket.
            return (rel, ts)
        items.sort(key=rank, reverse=True)
        story = items[0]
        url = story["url"].strip()
        domain = story_domain(url)
        title = (story.get("title") or "").strip()
        body = (story.get("summary") or "").strip()
        if not body:
            try:
                body = summarize(url)
            except Exception as exc:
                print(f"summary fetch failed for {url}: {exc}", flush=True)
                body = title
        text = build_post(title, url, domain, body)
        if not post_is_substantial(text, url):
            print(f"skipping {url}: only {len(text)} chars, below MIN_POST_CHARS={MIN_POST_CHARS}", flush=True)
            continue
        scheduled = moment.replace(hour=due_hour(moment), minute=0, second=0, microsecond=0)
        post_id = queue_post(text, int(scheduled.timestamp()))
        with db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO story_log(post_id,topic,day,title,url,domain,query,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (post_id, category, day, title, url, domain, story.get("_source", ""), now()),
            )
        set_generator_state((index + 1) % len(categories), day, "queued", None)
        print(f"daily post queued: {category} -> {url}", flush=True)
        return

    print("daily post: feeds dry, falling back to search", flush=True)
    for offset in range(attempts):
        index = (cursor + offset) % len(TOPICS)
        topic = TOPICS[index]
        try:
            story = pick_story(topic)
        except Exception as exc:
            print(f"story lookup failed for {topic!r}: {exc}", flush=True)
            continue
        if not story:
            continue
        url = story["url"].strip()
        domain = story_domain(url)
        title = (story.get("title") or "").strip()
        try:
            body = summarize(url)
        except Exception as exc:
            body = (story.get("content") or "").strip()
            print(f"summary fetch failed for {url}: {exc}; using search snippet", flush=True)
        if not body:
            body = title
        text = build_post(title, url, domain, body)
        if not post_is_substantial(text, url):
            print(f"skipping {url}: only {len(text)} chars, below MIN_POST_CHARS={MIN_POST_CHARS}", flush=True)
            continue
        scheduled = moment.replace(hour=due_hour(moment), minute=0, second=0, microsecond=0)
        post_id = queue_post(text, int(scheduled.timestamp()))
        with db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO story_log(post_id,topic,day,title,url,domain,query,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (post_id, topic, day, title, url, domain, topic, now()),
            )
        set_generator_state((index + 1) % len(TOPICS), day, "queued", None)
        print(f"daily post queued: {topic} -> {url}", flush=True)
        return
    set_generator_state(cursor, day, "no_story", "no unseen story for any topic")
    print("daily post: no unseen story found", flush=True)


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
            generate_daily_post()
        except Exception as exc:
            print(f"daily generator error: {exc}", flush=True)
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
                "scope": OAUTH_SCOPE,
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
            provider_error = args.get("error", [""])[0]
            provider_desc = args.get("error_description", [""])[0]
            if provider_error:
                self.send_json(400, {"error": provider_error, "error_description": provider_desc,
                                     "state_valid": bool(row)})
                return
            if not row:
                self.send_json(400, {"error": "invalid_or_expired_state",
                                     "error_description": "OAuth state was not found or has expired"})
                return
            if not code:
                self.send_json(400, {"error": "missing_code",
                                     "error_description": "Callback arrived without an authorization code"})
                return
            try:
                _, token, _ = linkedin_request("POST", "https://www.linkedin.com/oauth/v2/accessToken", form={
                    "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET, "redirect_uri": f"{BASE_URL}/auth/linkedin/callback",
                })
                person_id = person_id_from_token(token) or fetch_person_id(token["access_token"])
                with db() as conn:
                    conn.execute(
                        "INSERT INTO oauth(singleton,access_token,expires_at,person_id,updated_at) VALUES(1,?,?,?,?) "
                        "ON CONFLICT(singleton) DO UPDATE SET access_token=excluded.access_token,expires_at=excluded.expires_at,person_id=excluded.person_id,updated_at=excluded.updated_at",
                        (token["access_token"], now() + int(token["expires_in"]), person_id, now()),
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
            def action_cell(r):
                if r["status"] == "draft":
                    return (
                        f"<td><form method=post action=/web/drafts/{r['id']}/promote style='display:inline'>"
                        f"<button>Publish</button></form> "
                        f"<form method=post action=/web/drafts/{r['id']}/reject style='display:inline'>"
                        f"<button>Reject</button></form></td>"
                    )
                return "<td></td>"
            table = "".join(
                f"<tr><td>{r['id']}</td><td>{html.escape(r['status'])}</td><td>{html.escape(r['text'])}</td>"
                f"<td>{html.escape(r['public_url'] or '')}</td><td>{html.escape(r['last_error'] or '')}</td>"
                f"{action_cell(r)}</tr>" for r in rows
            )
            page = f"""<!doctype html><html><head><meta charset=utf-8><title>LinkedIn Publisher</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;background:#111;color:#eee}}textarea,input{{width:100%;padding:10px;margin:6px 0;background:#222;color:#fff;border:1px solid #555}}button{{padding:12px 22px;background:#0a66c2;color:white;border:0}}table{{width:100%;border-collapse:collapse;margin-top:24px}}td,th{{padding:8px;border-bottom:1px solid #444;vertical-align:top}}.muted{{color:#aaa}}</style></head>
<body><h1>LinkedIn Publisher</h1><p class=muted>Token expires: {html.escape(expiry)}</p>
<form method=post action=/web/posts><textarea name=text rows=8 maxlength=2950 required placeholder="Post text"></textarea>
<label>Publish at (blank means now)</label><input type=datetime-local name=scheduled_at><button>Queue post</button></form>
<table><tr><th>ID</th><th>Status</th><th>Text</th><th>URL</th><th>Error</th><th></th></tr>{table}</table></body></html>"""
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
        match = re.match(r"^/api/posts/(\d+)/(promote|reject)$", parsed.path)
        if match:
            if not self.api_authorized():
                self.send_json(401, {"error": "Unauthorized"})
                return
            post_id = int(match.group(1))
            action = match.group(2)
            ok = promote_post(post_id) if action == "promote" else reject_post(post_id)
            if not ok:
                self.send_json(404, {"error": "draft not found or not in draft state"})
            else:
                new_status = "queued" if action == "promote" else "rejected"
                self.send_json(200, {"id": post_id, "status": new_status})
            return
        match = re.match(r"^/web/drafts/(\d+)/(promote|reject)$", parsed.path)
        if match:
            if not self.browser_authorized():
                self.send_json(401, {"error": "Unauthorized"})
                return
            post_id = int(match.group(1))
            action = match.group(2)
            ok = promote_post(post_id) if action == "promote" else reject_post(post_id)
            self.redirect("/")
            return
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


def draft_post(text: str, scheduled_at: int | float | str | None = None) -> int:
    """Insert a post in 'draft' state. It is never published by the scheduler;
    only an explicit promote moves it to the queue.

    The generator uses this path. The publish loop selects only
    status IN ('queued','retry'), so a draft cannot reach LinkedIn on its own.
    """
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
            "INSERT INTO posts(text,scheduled_at,status,created_at,updated_at) VALUES(?,?,'draft',?,?)",
            (text, scheduled, stamp, stamp),
        )
        return int(cur.lastrowid)


def promote_post(post_id: int) -> bool:
    """Move a draft into the queue, scheduled for now. Returns success."""
    with db() as conn:
        changed = conn.execute(
            "UPDATE posts SET status='queued', scheduled_at=?, updated_at=? WHERE id=? AND status='draft'",
            (now(), now(), post_id),
        ).rowcount
    return bool(changed)


def reject_post(post_id: int) -> bool:
    """Mark a draft rejected so it is no longer a candidate. Returns success."""
    with db() as conn:
        changed = conn.execute(
            "UPDATE posts SET status='rejected', updated_at=? WHERE id=? AND status='draft'",
            (now(), post_id),
        ).rowcount
    return bool(changed)


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
    print(f"feed sources loaded: {len(FEED_SOURCES)}", flush=True)
    print(f"generator enabled: {GENERATOR_ENABLED}", flush=True)
    threading.Thread(target=scheduler, daemon=True).start()
    print(f"listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
