#!/usr/bin/env python3
"""
crawlGTM - Google Tag Manager OSINT & Reconnaissance Tool
Collects GTM IDs from X.com posts and analyzes container contents.

Usage:
    python3 crawl_gtm.py --login                              # Setup X.com session
    python3 crawl_gtm.py --bw-login                           # Setup BuiltWith session
    python3 crawl_gtm.py --search "magecart GTM"              # Search X.com
    python3 crawl_gtm.py --xuser sdcyberresearch              # User timeline
    python3 crawl_gtm.py --gtm GTM-XXXXXXX --deep             # Analyze GTM IDs
    python3 crawl_gtm.py --scan-url https://example.com        # Scan a website
    python3 crawl_gtm.py --fofa 'domain="example.com"' --deep # Search FOFA for GTMs
    python3 crawl_gtm.py --gtm GTM-XXXXXXX --reverse-lookup   # Find sites using GTM
    python3 crawl_gtm.py --xuser USER --deep --reverse-lookup  # Full flow

    # Background scheduler:
    python3 crawl_gtm.py --xuser USER --deep --reverse-lookup --hours 1   # Every 1h
    python3 crawl_gtm.py --xuser USER --deep --reverse-lookup --days 1    # Every 1 day
    python3 crawl_gtm.py --stop                                           # Stop scheduler
    python3 crawl_gtm.py --scheduler-status                               # Check status
    python3 crawl_gtm.py --clear-history                                  # Reset history
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import signal
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import urllib3
import aiohttp
import requests
from bs4 import BeautifulSoup

# Suppress SSL warnings for FOFA host scanning (verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.tree import Tree
from rich import box

console = Console()

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

GTM_JS_URL = "https://www.googletagmanager.com/gtm.js?id={gtm_id}"
GTM_ID_PATTERN = re.compile(r"GTM-[A-Z0-9]{4,12}", re.IGNORECASE)
GA_ID_PATTERN = re.compile(r"G-[A-Z0-9]{6,12}", re.IGNORECASE)
UA_ID_PATTERN = re.compile(r"UA-\d{4,12}-\d{1,4}", re.IGNORECASE)
AW_ID_PATTERN = re.compile(r"AW-\d{6,12}", re.IGNORECASE)

VALID_TLDS = {
    "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "br", "ru",
    "cn", "jp", "in", "au", "ca", "it", "es", "nl", "se", "no", "fi",
    "pl", "cz", "at", "ch", "be", "dk", "pt", "ie", "nz", "za", "mx",
    "ar", "cl", "kr", "tw", "hk", "sg", "my", "th", "ph", "id", "vn",
    "tr", "il", "ae", "sa", "eg", "ng", "ke", "gh", "info", "biz", "xyz",
    "online", "site", "tech", "app", "dev", "cloud", "ai", "me", "tv",
    "cc", "edu", "gov", "mil", "int", "pro", "museum", "aero", "coop",
    "travel", "jobs", "mobi", "cat", "asia", "tel", "name", "ly",
    "gg", "sh", "ms", "to", "fm", "am", "la", "rs", "is", "lt", "lv",
    "ee", "hr", "bg", "ro", "sk", "si", "hu", "ua", "by", "kz", "ge",
    "md", "az", "am", "uz", "tm", "kg", "tj",
    # Common multi-part TLDs
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.id",
    "com.br", "com.au", "com.cn", "com.mx", "com.ar", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.ph", "com.my", "com.vn", "com.eg", "com.ng",
    "com.ua", "com.co",
    "org.uk", "org.au", "org.br",
    "net.au", "net.br",
    "ac.uk", "ac.jp", "ac.kr",
}

URL_PATTERN = re.compile(r'https?://[^\s\'"<>{}|\\^`\[\]]+')

NITTER_INSTANCES = [
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
    "https://nitter.woodland.cafe",
    "https://nitter.1d4.us",
]

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Known GTM-related third-party services for categorization
SERVICE_SIGNATURES = {
    "google-analytics": ["google-analytics.com", "analytics.google.com", "www.googletagmanager.com"],
    "google-ads": ["googleads.g.doubleclick.net", "googleadservices.com", "googlesyndication.com"],
    "facebook-pixel": ["connect.facebook.net", "facebook.com/tr", "www.facebook.com"],
    "hotjar": ["static.hotjar.com", "hotjar.com", "vars.hotjar.com"],
    "linkedin-insight": ["snap.licdn.com", "linkedin.com"],
    "tiktok-pixel": ["analytics.tiktok.com", "tiktok.com"],
    "pinterest-tag": ["s.pinimg.com", "ct.pinterest.com"],
    "bing-ads": ["bat.bing.com", "bing.com"],
    "twitter-pixel": ["static.ads-twitter.com", "analytics.twitter.com", "t.co"],
    "clarity": ["clarity.ms", "www.clarity.ms"],
    "hubspot": ["js.hs-scripts.com", "js.hs-analytics.net", "hubspot.com"],
    "segment": ["cdn.segment.com", "api.segment.io"],
    "amplitude": ["cdn.amplitude.com", "api.amplitude.com"],
    "mixpanel": ["cdn.mxpnl.com", "api.mixpanel.com"],
    "heap": ["cdn.heapanalytics.com", "heapanalytics.com"],
    "fullstory": ["fullstory.com", "rs.fullstory.com"],
    "crazyegg": ["script.crazyegg.com", "crazyegg.com"],
    "optimizely": ["cdn.optimizely.com", "logx.optimizely.com"],
    "pardot": ["pi.pardot.com", "pardot.com"],
    "marketo": ["munchkin.marketo.net", "marketo.com"],
    "intercom": ["widget.intercom.io", "intercom.io"],
    "drift": ["js.driftt.com", "drift.com"],
    "crisp": ["client.crisp.chat", "crisp.chat"],
    "zendesk": ["static.zdassets.com", "zendesk.com"],
    "freshchat": ["wchat.freshchat.com", "freshchat.com"],
    "mouseflow": ["cdn.mouseflow.com", "mouseflow.com"],
    "lucky-orange": ["d10lpsik1i8c69.cloudfront.net", "luckyorange.com"],
    "matomo": ["matomo.cloud", "cdn.matomo.cloud"],
    "plausible": ["plausible.io"],
    "cloudflare": ["cdnjs.cloudflare.com", "cloudflare.com"],
    "recaptcha": ["www.google.com/recaptcha", "www.gstatic.com/recaptcha"],
    "stripe": ["js.stripe.com", "m.stripe.network"],
    "paypal": ["www.paypal.com", "www.paypalobjects.com"],
}

IGNORE_DOMAINS = {
    "www.googletagmanager.com", "googletagmanager.com",
    "www.google.com", "google.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "www.gstatic.com", "gstatic.com",
    "maps.googleapis.com", "maps.google.com",
}

# FOFA API configuration
FOFA_API_URL = "https://fofa.info/api/v1/search/all"
FOFA_NEXT_API_URL = "https://fofa.info/api/v1/search/next"


# ──────────────────────────────────────────────────────────────────────
# Session Manager - Persistent X.com cookie storage & validation
# ──────────────────────────────────────────────────────────────────────

SESSION_DIR = Path.home() / ".crawlgtm"
SESSION_FILE = SESSION_DIR / "session.json"
TELEGRAM_FILE = SESSION_DIR / "telegram.json"
FOFA_FILE = SESSION_DIR / "fofa.json"
HISTORY_FILE = SESSION_DIR / "history.json"
PID_FILE = SESSION_DIR / "scheduler.pid"
LOG_FILE = SESSION_DIR / "scheduler.log"

JS_COOKIE_SNIPPET = r"""[bold yellow]
┌─────────────────────────────────────────────────────────────────────┐
│  X.com - Cookie Extraction                                          │
│                                                                     │
│  auth_token is HttpOnly - JS cannot read it!                        │
│  You MUST copy BOTH cookies manually from DevTools:                 │
│                                                                     │
│  F12 → Application → Cookies → https://x.com                       │
│  1. Find 'auth_token' → double-click Value → copy                  │
│  2. Find 'ct0'        → double-click Value → copy                  │
│                                                                     │
│  OR paste this in Console to get ct0 automatically:                 │
└─────────────────────────────────────────────────────────────────────┘[/]

[green]// Paste in F12 Console at x.com:[/]
[white on black]
(function() {
  var ct0 = '';
  document.cookie.split(';').forEach(function(c) {
    var p = c.trim().split('=');
    if (p\[0] === 'ct0') ct0 = p.slice(1).join('=');
  });
  console.log('%c ct0 = ' + ct0, 'color:lime;font-size:14px');
  console.log('%c Now copy auth_token from Application > Cookies tab',
              'color:yellow;font-size:14px');
  prompt('ct0 (Ctrl+A, Ctrl+C):', ct0);
})();
[/]
"""

BW_COOKIE_SNIPPET = r"""[bold yellow]
┌─────────────────────────────────────────────────────────────────────┐
│  BuiltWith.com - Cookie Extraction                                  │
│                                                                     │
│  ASP.NET_SessionId is HttpOnly - JS cannot read it!                 │
│  You MUST copy it manually from DevTools:                           │
│                                                                     │
│  F12 → Application → Cookies → https://builtwith.com               │
│  Find 'ASP.NET_SessionId' → double-click Value → copy              │
└─────────────────────────────────────────────────────────────────────┘[/]

[green]// Step 1: Paste in F12 Console at builtwith.com (logged in):[/]
[white on black]
(function() {
  var found = {};
  document.cookie.split(';').forEach(function(c) {
    var parts = c.trim().split('=');
    var k = parts\[0];
    var v = parts.slice(1).join('=');
    if (k === 'g_state' || k === 'BWSSON') found\[k] = v;
  });
  found\['ASP.NET_SessionId'] = 'PASTE_FROM_DEVTOOLS';
  var json = JSON.stringify(found, null, 2);
  console.log('%c BuiltWith Cookies:', 'color:lime;font-size:14px');
  console.log(json);
  prompt('Copy this JSON (Ctrl+A, Ctrl+C):', json);
})();
[/]

[bold yellow]// Step 2: Copy ASP.NET_SessionId from:[/]
[dim]  F12 → Application → Cookies → builtwith.com → ASP.NET_SessionId[/]
[dim]  Replace 'PASTE_FROM_DEVTOOLS' in the JSON with the real value[/]
"""


class SessionManager:
    """Manages persistent X.com session cookies."""

    def __init__(self):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)

    def load(self) -> Optional[dict]:
        """Load saved session from disk."""
        if not SESSION_FILE.exists():
            return None
        try:
            data = json.loads(SESSION_FILE.read_text())
            if data.get("auth_token") and data.get("ct0"):
                return data
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    def save(self, auth_token: str, ct0: str):
        """Save session to disk."""
        data = {
            "auth_token": auth_token,
            "ct0": ct0,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        SESSION_FILE.write_text(json.dumps(data, indent=2))
        console.print(f"[green]  ✓ Session saved to {SESSION_FILE}[/]")

    def clear(self):
        """Remove saved session."""
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
            console.print("[yellow]  Session cleared.[/]")

    def validate(self, auth_token: str, ct0: str) -> tuple[bool, Optional[str]]:
        """Validate session by calling X.com API. Returns (valid, username)."""
        session = requests.Session()
        session.cookies.set("auth_token", auth_token, domain=".x.com")
        session.cookies.set("ct0", ct0, domain=".x.com")

        headers = {
            "Authorization": f"Bearer {X_BEARER}",
            "x-csrf-token": ct0,
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "User-Agent": USER_AGENT,
        }

        # Method 1: Try Viewer GraphQL query
        query_ids = self._get_query_ids(session)
        viewer_qid = query_ids.get("Viewer")
        if viewer_qid:
            try:
                params = {
                    "variables": json.dumps({}),
                    "features": json.dumps({
                        "responsive_web_graphql_exclude_directive_enabled": True,
                        "verified_phone_label_enabled": False,
                        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
                        "responsive_web_graphql_timeline_navigation_enabled": True,
                    }),
                }
                resp = session.get(
                    f"https://x.com/i/api/graphql/{viewer_qid}/Viewer",
                    headers=headers, params=params, timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    viewer = data.get("data", {}).get("viewer", {})
                    screen_name = viewer.get("user_results", {}).get("result", {}).get("legacy", {}).get("screen_name")
                    if screen_name:
                        return True, screen_name
            except Exception:
                pass

        # Method 2: Try account settings endpoint
        for api_base in ["https://x.com/i/api", "https://api.x.com"]:
            try:
                resp = session.get(
                    f"{api_base}/1.1/account/settings.json",
                    headers=headers, timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return True, data.get("screen_name", "unknown")
            except Exception:
                pass

        # Method 3: Check if x.com/home loads authenticated content
        try:
            resp = session.get("https://x.com/home", headers={
                "User-Agent": USER_AGENT,
            }, timeout=15, allow_redirects=False)
            if resp.status_code == 200:
                # If we get 200 (not redirect to login), session is valid
                # Try to extract screen_name from HTML
                html = resp.text
                match = re.search(r'"screen_name":"([^"]+)"', html)
                username = match.group(1) if match else "authenticated"
                return True, username
            # 302 to /i/flow/login means invalid
            location = resp.headers.get("location", "")
            if "login" in location or "flow" in location:
                return False, None
        except Exception:
            pass

        return False, None

    @staticmethod
    def _get_query_ids(session: requests.Session) -> dict:
        """Extract GraphQL query IDs and feature switches from X.com JS bundle."""
        query_ids = {}
        try:
            resp = session.get("https://x.com/", timeout=15, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html",
                "Accept-Encoding": "gzip, deflate",
            })
            if resp.status_code != 200:
                return {}

            # Try multiple patterns - X.com changes bundle paths frequently
            js_links = re.findall(
                r'src="(https://abs\.twimg\.com/responsive-web/client-web(?:-legacy)?/main\.[^"]+\.js)"',
                resp.text,
            )
            if not js_links:
                js_links = re.findall(
                    r'src="(https://abs\.twimg\.com/responsive-web/[^"]*?(?:main|api|endpoints)[^"]*?\.js)"',
                    resp.text,
                )
            if not js_links:
                return {}

            jr = session.get(js_links[0], timeout=15)
            if jr.status_code == 200:
                for qid, op in re.findall(r'queryId:"([^"]+)",operationName:"([^"]+)"', jr.text):
                    query_ids[op] = qid

                # Extract featureSwitches per operation for dynamic feature detection
                for m in re.finditer(
                    r'operationName:"([^"]+)"[^}]*?featureSwitches:\[([^\]]+)\]',
                    jr.text,
                ):
                    op_name = m.group(1)
                    feat_str = m.group(2)
                    feats = re.findall(r'"([^"]+)"', feat_str)
                    if feats:
                        query_ids[f"_features_{op_name}"] = feats
        except Exception:
            pass
        return query_ids

    def prompt_login(self) -> Optional[dict]:
        """Interactive login prompt - shows JS snippet and asks for cookies."""
        if not sys.stdin.isatty():
            console.print("[yellow]  ⚠ No saved session and not running interactively.[/]")
            console.print("[yellow]    Run: python3 crawl_gtm.py --login[/]")
            return None

        console.print(JS_COOKIE_SNIPPET)
        console.print("[bold cyan]Enter your X.com cookies:[/]\n")

        try:
            auth_token = input("  auth_token: ").strip()
            if not auth_token:
                console.print("[red]  auth_token is required.[/]")
                return None

            ct0 = input("  ct0: ").strip()
            if not ct0:
                console.print("[red]  ct0 is required.[/]")
                return None
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]  Cancelled.[/]")
            return None

        console.print("\n[dim]  Validating session...[/]")
        valid, username = self.validate(auth_token, ct0)

        if valid:
            console.print(f"[bold green]  ✓ Session valid! Logged in as @{username}[/]")
            self.save(auth_token, ct0)
            return {"auth_token": auth_token, "ct0": ct0, "username": username}
        else:
            console.print("[red]  ✗ Session invalid or expired. Check your cookies.[/]")
            return None

    def ensure_session(self) -> Optional[dict]:
        """Load existing session, validate it, or prompt for new one."""
        saved = self.load()

        if saved:
            console.print("[dim]  Checking saved session...[/]")
            valid, username = self.validate(saved["auth_token"], saved["ct0"])
            if valid:
                console.print(f"[green]  ✓ Session active (@{username})[/]")
                saved["username"] = username
                return saved
            else:
                console.print("[yellow]  ⚠ Saved session expired. Need new cookies.[/]")

        # Prompt for new login
        return self.prompt_login()


# ──────────────────────────────────────────────────────────────────────
# Telegram Notifier
# ──────────────────────────────────────────────────────────────────────

class TelegramNotifier:
    """Send crawlGTM results to Telegram."""

    API = "https://api.telegram.org/bot{token}/{method}"
    MAX_MSG = 4000  # Telegram max ~4096, leave margin

    def __init__(self):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self.config = self._load()

    def _load(self) -> dict:
        if TELEGRAM_FILE.exists():
            try:
                return json.loads(TELEGRAM_FILE.read_text())
            except (json.JSONDecodeError, KeyError):
                pass
        return {}

    def _save(self, token: str, chat_id: str):
        data = {"bot_token": token, "chat_id": chat_id}
        TELEGRAM_FILE.write_text(json.dumps(data, indent=2))
        console.print(f"[green]  ✓ Telegram config saved to {TELEGRAM_FILE}[/]")

    @property
    def is_configured(self) -> bool:
        return bool(self.config.get("bot_token") and self.config.get("chat_id"))

    def setup(self):
        """Interactive Telegram setup."""
        console.print("""
[bold cyan]Telegram Bot Setup[/]

[dim]1. Open Telegram and search for @BotFather
2. Send /newbot and follow the instructions
3. Copy the bot token (e.g., 123456:ABC-DEF...)
4. Add the bot to a group or start a private chat
5. To get chat_id, send a message to the bot then visit:
   https://api.telegram.org/bot<TOKEN>/getUpdates
   Look for "chat":{"id": XXXXXXXX}[/]
""")
        try:
            token = input("  Bot Token: ").strip()
            if not token:
                console.print("[red]  Token is required.[/]")
                return

            chat_id = input("  Chat ID: ").strip()
            if not chat_id:
                # Try to auto-detect from getUpdates
                console.print("[dim]  Trying to auto-detect chat ID...[/]")
                try:
                    resp = requests.get(
                        self.API.format(token=token, method="getUpdates"),
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        updates = resp.json().get("result", [])
                        if updates:
                            chat_id = str(
                                updates[-1].get("message", {}).get("chat", {}).get("id", "")
                            )
                            if chat_id:
                                console.print(f"[green]  Auto-detected chat_id: {chat_id}[/]")
                except Exception:
                    pass

                if not chat_id:
                    console.print("[red]  Chat ID is required.[/]")
                    return

            # Test connection
            console.print("[dim]  Testing connection...[/]")
            ok = self._send_raw(token, chat_id, "✅ crawlGTM connected!")
            if ok:
                self._save(token, chat_id)
                console.print("[bold green]  ✓ Telegram configured and tested![/]")
            else:
                console.print("[red]  ✗ Failed to send test message. Check token/chat_id.[/]")

        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]  Cancelled.[/]")

    def _send_raw(self, token: str, chat_id: str, text: str, parse_mode: str = "HTML") -> bool:
        """Send a single message via Telegram API."""
        try:
            resp = requests.post(
                self.API.format(token=token, method="sendMessage"),
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True,
                },
                timeout=15,
            )
            return resp.status_code == 200 and resp.json().get("ok", False)
        except Exception:
            return False

    def send(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send message using saved config."""
        if not self.is_configured:
            return False
        return self._send_raw(self.config["bot_token"], self.config["chat_id"], text, parse_mode)

    def send_long(self, text: str, parse_mode: str = "HTML"):
        """Send long text split into multiple messages."""
        lines = text.split("\n")
        chunk = ""
        for line in lines:
            # Truncate individual lines that exceed max message size
            if len(line) > self.MAX_MSG:
                line = line[: self.MAX_MSG - 20] + "... [truncated]"
            if len(chunk) + len(line) + 1 > self.MAX_MSG:
                if chunk:
                    self.send(chunk, parse_mode)
                    time.sleep(0.5)
                chunk = line
            else:
                chunk = f"{chunk}\n{line}" if chunk else line
        if chunk:
            self.send(chunk, parse_mode)

    def send_document(self, filepath: str, caption: str = "") -> bool:
        """Send a file as document."""
        if not self.is_configured:
            return False
        try:
            with open(filepath, "rb") as f:
                resp = requests.post(
                    self.API.format(
                        token=self.config["bot_token"], method="sendDocument"
                    ),
                    data={
                        "chat_id": self.config["chat_id"],
                        "caption": caption[:1024],
                    },
                    files={"document": f},
                    timeout=30,
                )
            return resp.status_code == 200
        except Exception:
            return False

    def notify_posts(self, posts: list[dict], source: str):
        """Send X.com posts found."""
        if not posts or not self.is_configured:
            return

        header = f"🐦 <b>X.com Posts ({source})</b>\n"
        header += f"Found <b>{len(posts)}</b> posts with GTM IDs\n"
        header += "─" * 35

        # Extract GTM IDs from posts
        all_ids = set()
        for p in posts:
            for m in GTM_ID_PATTERN.finditer(p.get("text", "")):
                all_ids.add(m.group(0).upper())

        lines = [header]
        for i, p in enumerate(posts[:20], 1):
            url = p.get("url", "")
            date = p.get("date", "")[:10]
            text = p.get("text", "")[:200].replace("<", "&lt;").replace(">", "&gt;")
            gtm_in_post = GTM_ID_PATTERN.findall(p.get("text", ""))
            gtm_str = ", ".join(set(g.upper() for g in gtm_in_post)) if gtm_in_post else "-"

            lines.append(f"\n<b>#{i}</b> {date}")
            lines.append(f"<code>{text}</code>")
            lines.append(f"GTM: <b>{gtm_str}</b>")
            if url:
                lines.append(f"🔗 {url}")

        if all_ids:
            lines.append(f"\n📋 <b>All GTM IDs found ({len(all_ids)}):</b>")
            lines.append(f"<code>{chr(10).join(sorted(all_ids))}</code>")

        self.send_long("\n".join(lines))

    def notify_results(self, results: list[dict], posts: list[dict], output_dir: str):
        """Send full analysis results to Telegram."""
        if not self.is_configured:
            return

        active = [r for r in results if r["status"] == "active"]
        all_domains = set()
        all_services = set()
        chains = {}

        for r in results:
            all_domains.update(r.get("domains", []))
            all_services.update(r.get("services_detected", []))
            for tid in r.get("tracking_ids", {}).get("GTM", []):
                chains.setdefault(r["gtm_id"], []).append(tid)

        # Summary message
        msg = "🔍 <b>crawlGTM Scan Complete</b>\n"
        msg += "─" * 35 + "\n\n"
        msg += f"📦 Containers: <b>{len(results)}</b> analyzed, <b>{len(active)}</b> active\n"
        msg += f"🌐 Domains: <b>{len(all_domains)}</b> unique\n"
        msg += f"🏷 Services: <b>{len(all_services)}</b> detected\n"
        msg += f"🐦 Posts: <b>{len(posts)}</b> collected\n"

        # Chain info
        if chains:
            msg += f"\n🔗 <b>GTM Chains:</b>\n"
            for parent, children in sorted(chains.items()):
                for child in children:
                    msg += f"  {parent} → {child}\n"

        self.send(msg)
        time.sleep(0.5)

        # Per-container details
        for r in sorted(active, key=lambda x: x["gtm_id"]):
            gtm = r["gtm_id"]
            ver = r.get("container_version", "?")
            size = r["raw_size"]
            domains = r.get("domains", [])
            urls = r.get("urls", [])
            scripts = r.get("scripts_loaded", [])
            pixels = r.get("pixels", [])
            services = r.get("services_detected", [])
            tids = r.get("tracking_ids", {})
            interesting = r.get("interesting_strings", [])
            custom_html = r.get("custom_html_tags", [])
            dl_vars = r.get("data_layer_vars", [])
            reverse = r.get("reverse_lookup_sites", [])

            detail = f"📦 <b>{gtm}</b> (v{ver}, {size:,} bytes)\n"
            detail += "─" * 35 + "\n"

            if tids:
                detail += "\n<b>Tracking IDs:</b>\n"
                for k, v in tids.items():
                    for vid in v:
                        detail += f"  {k}: <code>{vid}</code>\n"

            if services:
                detail += f"\n<b>Services:</b> {', '.join(services)}\n"

            if domains:
                detail += f"\n<b>Domains ({len(domains)}):</b>\n"
                for d in domains:
                    detail += f"  • {d}\n"

            if urls:
                detail += f"\n<b>URLs ({len(urls)}):</b>\n"
                for u in urls[:20]:
                    detail += f"  • <code>{u}</code>\n"
                if len(urls) > 20:
                    detail += f"  ... +{len(urls)-20} more\n"

            if scripts:
                detail += f"\n<b>Scripts:</b>\n"
                for s in scripts:
                    detail += f"  📜 <code>{s}</code>\n"

            if pixels:
                detail += f"\n<b>Pixels ({len(pixels)}):</b>\n"
                for p in pixels[:10]:
                    detail += f"  🎯 <code>{p}</code>\n"

            if custom_html:
                detail += f"\n<b>Custom HTML Tags ({len(custom_html)}):</b>\n"
                for h in custom_html[:5]:
                    safe = h[:150].replace("<", "&lt;").replace(">", "&gt;")
                    detail += f"  <code>{safe}</code>\n"

            if dl_vars:
                detail += f"\n<b>DataLayer Vars:</b> {', '.join(dl_vars[:15])}\n"

            if interesting:
                detail += f"\n<b>Interesting ({len(interesting)}):</b>\n"
                for s in interesting[:10]:
                    safe = s[:100].replace("<", "&lt;").replace(">", "&gt;")
                    detail += f"  💡 {safe}\n"

            if reverse:
                real_sites = [s for s in reverse if s.get("domain")]
                if real_sites:
                    detail += f"\n<b>Sites using this GTM ({len(real_sites)}):</b>\n"
                    for s in real_sites[:10]:
                        detail += f"  🌐 {s['domain']} ({s.get('source','')})\n"

            self.send_long(detail)
            time.sleep(0.3)

        # Send JSON file
        json_files = sorted(Path(output_dir).glob("crawlgtm_*.json"))
        if json_files:
            self.send_document(
                str(json_files[-1]),
                f"📎 Full results JSON ({len(results)} containers)",
            )

        # Send domains file
        dom_files = sorted(Path(output_dir).glob("domains_*.txt"))
        if dom_files:
            self.send_document(str(dom_files[-1]), "📎 Domains list")

        # Send GTM IDs file
        id_files = sorted(Path(output_dir).glob("gtm_ids_*.txt"))
        if id_files:
            self.send_document(str(id_files[-1]), "📎 GTM IDs list")

        console.print("[green]✓ Results sent to Telegram[/]")


# Well-known X.com internal bearer token (public, embedded in their JS)
X_BEARER = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)


# ──────────────────────────────────────────────────────────────────────
# X.com / Twitter Collector
# ──────────────────────────────────────────────────────────────────────

class XCollector:
    """Collects posts from X.com / Twitter."""

    def __init__(self, username: Optional[str] = None,
                 search_term: Optional[str] = None,
                 session_data: Optional[dict] = None,
                 filter_query: str = "GTM"):
        self.username = username.lstrip("@") if username else None
        self.search_term = search_term
        self.session_data = session_data  # {"auth_token": ..., "ct0": ...}
        self.filter_query = filter_query
        self.posts = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._query_ids = {}

        # Load session cookies
        if self.session_data:
            self.session.cookies.set("auth_token", session_data["auth_token"], domain=".x.com")
            self.session.cookies.set("ct0", session_data["ct0"], domain=".x.com")

        # Load query IDs
        self._query_ids = SessionManager._get_query_ids(self.session)

    def collect(self) -> list[dict]:
        """Try multiple methods to collect posts."""
        label = f"@{self.username}" if self.username else f'"{self.search_term}"'
        console.print(f"\n[bold cyan]📡 Collecting posts: {label}[/]")

        # Method 1: Authenticated session (most reliable)
        if self.session_data:
            if self.search_term:
                self._collect_via_search()
            if self.username:
                self._collect_via_authenticated_session()

        # Method 2: Wayback Machine (for user timelines)
        if not self.posts and self.username:
            self._collect_via_wayback()

        # Method 3: Nitter scraping
        if not self.posts and self.username:
            self._collect_via_nitter()

        # Method 4: Google cache
        if not self.posts:
            self._collect_via_google_cache()

        if self.posts:
            console.print(f"[green]✓ Collected {len(self.posts)} posts[/]")
        else:
            console.print("[yellow]⚠ No posts collected.[/]")
            if not self.session_data:
                console.print("[yellow]  Run with --login to set up X.com session first.[/]")

        return self.posts

    def _get_auth_headers(self) -> dict:
        """Get authenticated request headers."""
        ct0 = self.session_data.get("ct0", "") if self.session_data else ""
        return {
            "Authorization": f"Bearer {X_BEARER}",
            "x-csrf-token": ct0,
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Referer": "https://x.com/search",
        }

    def _collect_via_search(self):
        """Search X.com for posts matching search_term."""
        search_qid = self._query_ids.get("SearchTimeline")
        if not search_qid:
            console.print("  [dim]  SearchTimeline query ID not found[/]")
            return

        query = self.search_term
        if self.username:
            query = f"from:{self.username} {self.search_term}"

        console.print(f"  [dim]→ Searching X.com: {query}[/]")

        headers = self._get_auth_headers()

        # Dynamic features from JS bundle
        features = {f: True for f in self._query_ids.get("_features_SearchTimeline", [])}
        if not features:
            features = {f: True for f in self._query_ids.get("_features_UserTweets", [])}
        if not features:
            features = {
                "responsive_web_graphql_exclude_directive_enabled": True,
                "verified_phone_label_enabled": True,
                "responsive_web_graphql_skip_user_profile_image_extensions_enabled": True,
                "responsive_web_graphql_timeline_navigation_enabled": True,
            }

        try:
            params = {
                "variables": json.dumps({
                    "rawQuery": query,
                    "count": 40,
                    "querySource": "typed_query",
                    "product": "Latest",
                }),
                "features": json.dumps(features),
            }
            resp = self.session.get(
                f"https://x.com/i/api/graphql/{search_qid}/SearchTimeline",
                headers=headers, params=params, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                instructions = (
                    data.get("data", {})
                    .get("search_by_raw_query", {})
                    .get("search_timeline", {})
                    .get("timeline", {})
                    .get("instructions", [])
                )
                count = 0
                for instruction in instructions:
                    for entry in instruction.get("entries", []):
                        ic = entry.get("content", {}).get("itemContent", {})
                        if ic:
                            self._process_graphql_tweet(ic, accept_all=True)
                            count += 1
                if self.posts:
                    console.print(f"  [green]✓ Search: {len(self.posts)} posts found[/]")
                else:
                    console.print(f"  [dim]  Search returned {count} entries, 0 with GTM IDs[/]")
            elif resp.status_code == 401:
                console.print("  [red]✗ Session expired. Run: python3 crawl_gtm.py --login[/]")
            else:
                console.print(f"  [dim]  Search returned {resp.status_code}[/]")
        except Exception as e:
            console.print(f"  [dim]  Search error: {e}[/]")

    def _collect_via_authenticated_session(self):
        """Collect tweets using authenticated X.com session cookies."""
        console.print("  [dim]→ Trying authenticated session (user timeline)...[/]")

        user_qid = self._query_ids.get("UserByScreenName")
        tweets_qid = self._query_ids.get("UserTweets")

        if not user_qid:
            console.print("  [dim]  Could not find GraphQL query IDs[/]")
            return

        headers = self._get_auth_headers()
        headers["Referer"] = f"https://x.com/{self.username}"

        # Build features dynamically from JS bundle extraction
        user_features = {f: True for f in self._query_ids.get("_features_UserByScreenName", [])}
        tweet_features = {f: True for f in self._query_ids.get("_features_UserTweets", [])}

        # Fallback if dynamic extraction failed
        if not user_features:
            user_features = {
                "hidden_profile_subscriptions_enabled": True,
                "rweb_tipjar_consumption_enabled": True,
                "responsive_web_graphql_exclude_directive_enabled": True,
                "verified_phone_label_enabled": True,
                "responsive_web_graphql_skip_user_profile_image_extensions_enabled": True,
                "responsive_web_graphql_timeline_navigation_enabled": True,
            }
        if not tweet_features:
            tweet_features = user_features.copy()

        # Step 1: Get user ID
        try:
            params = {
                "variables": json.dumps({"screen_name": self.username, "withSafetyModeUserFields": True}),
                "features": json.dumps(user_features),
            }
            resp = self.session.get(
                f"https://x.com/i/api/graphql/{user_qid}/UserByScreenName",
                headers=headers, params=params, timeout=15,
            )
            if resp.status_code != 200:
                console.print(f"  [red]✗ User lookup failed ({resp.status_code})[/]")
                if resp.status_code == 401:
                    console.print("  [yellow]  Session expired. Run: python3 crawl_gtm.py --login[/]")
                return

            user_data = resp.json()
            user_result = user_data.get("data", {}).get("user", {}).get("result", {})
            user_id = user_result.get("rest_id")
            if not user_id:
                console.print("  [dim]  Could not resolve user ID[/]")
                return

            name = user_result.get("legacy", {}).get("name", self.username)
            console.print(f"  [green]  ✓ Target: {name} (ID: {user_id})[/]")

        except Exception as e:
            console.print(f"  [red]✗ User lookup error: {e}[/]")
            return

        # Step 2: Get user timeline
        if not tweets_qid:
            console.print("  [dim]  UserTweets query ID not found[/]")
            return

        try:
            params = {
                "variables": json.dumps({
                    "userId": user_id,
                    "count": 40,
                    "includePromotedContent": False,
                    "withQuickPromoteEligibilityTweetFields": False,
                    "withVoice": True,
                    "withV2Timeline": True,
                }),
                "features": json.dumps(tweet_features),
            }
            resp = self.session.get(
                f"https://x.com/i/api/graphql/{tweets_qid}/UserTweets",
                headers=headers, params=params, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                timeline = (
                    data.get("data", {})
                    .get("user", {})
                    .get("result", {})
                    .get("timeline_v2", data.get("data", {}).get("user", {}).get("result", {}).get("timeline", {}))
                    .get("timeline", {})
                    .get("instructions", [])
                )
                for instruction in timeline:
                    entries = instruction.get("entries", [])
                    for entry in entries:
                        content = entry.get("content", {})
                        item_content = content.get("itemContent", {})
                        if item_content:
                            self._process_graphql_tweet(item_content)
                        else:
                            items = content.get("items", [])
                            for item in items:
                                ic = item.get("item", {}).get("itemContent", {})
                                self._process_graphql_tweet(ic)

                if self.posts:
                    console.print(f"  [green]  ✓ Timeline: {len(self.posts)} posts matching '{self.filter_query}'[/]")
            elif resp.status_code == 401:
                console.print("  [red]✗ Session expired. Run: python3 crawl_gtm.py --login[/]")
            else:
                console.print(f"  [dim]  Timeline returned {resp.status_code}[/]")

        except Exception as e:
            console.print(f"  [dim]  Timeline error: {e}[/]")

    def _collect_via_wayback(self):
        """Search Wayback Machine for archived tweets."""
        console.print("  [dim]→ Trying Wayback Machine...[/]")
        try:
            # Search for archived tweet pages
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=twitter.com/{self.username}/status/*"
                f"&output=json&fl=timestamp,original,statuscode"
                f"&filter=statuscode:200&limit=200"
            )
            resp = self.session.get(cdx_url, timeout=20)
            if resp.status_code != 200:
                # Try x.com domain too
                cdx_url = cdx_url.replace("twitter.com", "x.com")
                resp = self.session.get(cdx_url, timeout=20)

            if resp.status_code != 200:
                console.print(f"  [dim]  Wayback CDX returned {resp.status_code}[/]")
                return

            rows = resp.json()
            if len(rows) <= 1:  # First row is headers
                console.print("  [dim]  No archived tweets found[/]")
                return

            console.print(f"  [cyan]  Found {len(rows) - 1} archived tweet URLs[/]")

            # Fetch a sample of archived tweets to find GTM mentions
            fetched = 0
            for row in rows[1:]:  # Skip header row
                if fetched >= 50:  # Limit to 50 fetches
                    break

                timestamp, original_url, _ = row
                wayback_url = f"https://web.archive.org/web/{timestamp}/{original_url}"

                try:
                    wr = self.session.get(wayback_url, timeout=10)
                    if wr.status_code == 200:
                        fetched += 1
                        text = wr.text

                        # Extract tweet text from archived page
                        soup = BeautifulSoup(text, "html.parser")

                        # Try multiple selectors for tweet text
                        tweet_text = ""
                        for selector in [
                            'div[data-testid="tweetText"]',
                            ".tweet-text", ".js-tweet-text",
                            'meta[property="og:description"]',
                            'meta[name="description"]',
                        ]:
                            elem = soup.select_one(selector)
                            if elem:
                                tweet_text = elem.get("content", "") or elem.get_text(strip=True)
                                if tweet_text:
                                    break

                        # Also check raw HTML for GTM patterns
                        if not tweet_text:
                            # Try to extract from title tag
                            title = soup.find("title")
                            if title:
                                tweet_text = title.get_text(strip=True)

                        if tweet_text and (
                            self.filter_query.lower() in tweet_text.lower()
                            or GTM_ID_PATTERN.search(tweet_text)
                        ):
                            # Extract tweet ID from URL
                            tid_match = re.search(r'/status/(\d+)', original_url)
                            tweet_id = tid_match.group(1) if tid_match else ""

                            self.posts.append({
                                "source": "wayback_machine",
                                "text": tweet_text[:1000],
                                "date": f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}",
                                "id": tweet_id,
                                "url": f"https://x.com/{self.username}/status/{tweet_id}",
                                "wayback_url": wayback_url,
                            })

                        # Also scan raw page for GTM IDs even if text doesn't match search
                        raw_gtm = GTM_ID_PATTERN.findall(text)
                        if raw_gtm:
                            tid_match = re.search(r'/status/(\d+)', original_url)
                            tweet_id = tid_match.group(1) if tid_match else ""
                            # Add if not already added
                            existing_ids = {p.get("id") for p in self.posts}
                            if tweet_id and tweet_id not in existing_ids:
                                self.posts.append({
                                    "source": "wayback_machine_raw",
                                    "text": f"[Archived page contains GTM IDs: {', '.join(set(raw_gtm))}] {tweet_text[:500]}",
                                    "date": f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}",
                                    "id": tweet_id,
                                    "url": f"https://x.com/{self.username}/status/{tweet_id}",
                                    "wayback_url": wayback_url,
                                    "gtm_ids_found": list(set(raw_gtm)),
                                })

                except Exception:
                    continue

            if self.posts:
                console.print(f"  [green]✓ Wayback Machine: {len(self.posts)} posts with GTM references[/]")
            else:
                console.print(f"  [dim]  Checked {fetched} archived pages, no GTM matches[/]")

        except Exception as e:
            console.print(f"  [dim]  Wayback error: {e}[/]")


    def _process_graphql_tweet(self, item_content: dict, accept_all: bool = False):
        """Extract tweet data from GraphQL response item."""
        tweet_result = item_content.get("tweet_results", {}).get("result", {})
        if not tweet_result:
            return

        # Handle tweet with visibility results wrapper
        if tweet_result.get("__typename") == "TweetWithVisibilityResults":
            tweet_result = tweet_result.get("tweet", {})

        legacy = tweet_result.get("legacy", {})
        text = legacy.get("full_text", "")
        tweet_id = legacy.get("id_str", tweet_result.get("rest_id", ""))
        created_at = legacy.get("created_at", "")
        user_legacy = tweet_result.get("core", {}).get("user_results", {}).get("result", {}).get("legacy", {})
        screen_name = user_legacy.get("screen_name", self.username or "")

        if text and (accept_all or self.filter_query.lower() in text.lower() or GTM_ID_PATTERN.search(text)):
            self.posts.append({
                "source": "x_graphql",
                "text": text,
                "date": created_at,
                "id": tweet_id,
                "url": f"https://x.com/{screen_name}/status/{tweet_id}",
            })

    def _collect_via_nitter(self):
        """Collect via Nitter instances (no auth needed)."""
        console.print("  [dim]→ Trying Nitter instances...[/]")

        for instance in NITTER_INSTANCES:
            try:
                # Search for GTM mentions
                search_url = f"{instance}/{self.username}/search?f=tweets&q=GTM"
                resp = self.session.get(search_url, timeout=10)
                if resp.status_code != 200:
                    # Try profile timeline
                    resp = self.session.get(f"{instance}/{self.username}", timeout=10)
                    if resp.status_code != 200:
                        continue

                soup = BeautifulSoup(resp.text, "html.parser")
                tweet_divs = soup.select(".timeline-item, .tweet-body, .tweet-content")

                if not tweet_divs:
                    # Try alternative selectors
                    tweet_divs = soup.select("[class*='tweet'], [class*='status']")

                for div in tweet_divs:
                    text = div.get_text(strip=True)
                    if self.filter_query.lower() in text.lower() or GTM_ID_PATTERN.search(text):
                        link = div.find("a", href=True)
                        post_url = ""
                        if link and "/status/" in str(link.get("href", "")):
                            href = link["href"]
                            if href.startswith("http"):
                                # Absolute URL from nitter - extract path
                                path = re.sub(r'^https?://[^/]+', '', href)
                                post_url = f"https://x.com{path}"
                            else:
                                post_url = f"https://x.com{href}"

                        self.posts.append({
                            "source": f"nitter:{instance}",
                            "text": text,
                            "date": "",
                            "url": post_url,
                        })

                if self.posts:
                    console.print(f"  [green]✓ Nitter ({instance}): {len(self.posts)} posts[/]")
                    return

            except Exception:
                continue

        if not self.posts:
            console.print("  [dim]  No Nitter instances available[/]")

    def _collect_via_google_cache(self):
        """Search Google cache for tweets mentioning GTM."""
        if not self.username and not self.search_term:
            return
        console.print("  [dim]→ Trying Google cache/search...[/]")
        try:
            if self.username:
                query = f'site:x.com "{self.username}" "GTM-"'
            else:
                query = f'site:x.com "{self.search_term}" "GTM-"'
            resp = self.session.get(
                "https://www.google.com/search",
                params={"q": query, "num": 50},
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html",
                    "Accept-Encoding": "gzip, deflate",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                # Extract snippet text from search results
                for result in soup.select(".g, .tF2Cxc"):
                    snippet = result.get_text(separator=" ", strip=True)
                    if GTM_ID_PATTERN.search(snippet):
                        link = result.find("a", href=True)
                        url = link["href"] if link else ""
                        self.posts.append({
                            "source": "google_cache",
                            "text": snippet[:500],
                            "date": "",
                            "url": url,
                        })

                if self.posts:
                    console.print(f"  [green]✓ Google cache: {len(self.posts)} results with GTM[/]")
                else:
                    console.print("  [dim]  No GTM results in Google cache[/]")
            else:
                console.print(f"  [dim]  Google returned {resp.status_code}[/]")

        except Exception as e:
            console.print(f"  [dim]  Google cache error: {e}[/]")


# ──────────────────────────────────────────────────────────────────────
# GTM ID Extractor
# ──────────────────────────────────────────────────────────────────────

def extract_gtm_ids(texts: list[str]) -> set[str]:
    """Extract unique GTM IDs from text content."""
    gtm_ids = set()
    for text in texts:
        found = GTM_ID_PATTERN.findall(text)
        for gid in found:
            gtm_ids.add(gid.upper())
    return gtm_ids


def extract_all_tracking_ids(text: str) -> dict[str, set[str]]:
    """Extract all tracking IDs (GTM, GA, UA, AW) from text."""
    return {
        "GTM": set(m.upper() for m in GTM_ID_PATTERN.findall(text)),
        "GA4": set(m.upper() for m in GA_ID_PATTERN.findall(text)),
        "UA": set(m.upper() for m in UA_ID_PATTERN.findall(text)),
        "AW": set(m.upper() for m in AW_ID_PATTERN.findall(text)),
    }


# ──────────────────────────────────────────────────────────────────────
# GTM Container Analyzer
# ──────────────────────────────────────────────────────────────────────

class GTMAnalyzer:
    """Analyzes Google Tag Manager containers."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def analyze(self, gtm_id: str) -> dict:
        """Full analysis of a GTM container."""
        result = {
            "gtm_id": gtm_id,
            "status": "unknown",
            "raw_size": 0,
            "domains": [],
            "urls": [],
            "tracking_ids": {},
            "services_detected": [],
            "custom_html_tags": [],
            "scripts_loaded": [],
            "pixels": [],
            "data_layer_vars": [],
            "container_version": "",
            "interesting_strings": [],
            "domains_under_gtm": [],
        }

        try:
            # Fetch GTM container JS
            url = GTM_JS_URL.format(gtm_id=gtm_id)
            resp = self.session.get(url, timeout=20)

            if resp.status_code == 404:
                result["status"] = "not_found"
                return result
            elif resp.status_code != 200:
                result["status"] = f"error_{resp.status_code}"
                return result

            js_content = resp.text
            result["raw_size"] = len(js_content)
            result["status"] = "active"

            # Parse container
            self._extract_container_data(js_content, result)
            self._extract_domains(js_content, result)
            self._extract_urls(js_content, result)
            self._extract_tracking_ids(js_content, result)
            self._detect_services(result)
            self._extract_custom_html(js_content, result)
            self._extract_datalayer_vars(js_content, result)
            self._extract_interesting_strings(js_content, result)
            self._extract_container_version(js_content, result)

        except requests.exceptions.Timeout:
            result["status"] = "timeout"
        except Exception as e:
            result["status"] = f"error: {str(e)}"

        return result

    def _extract_container_data(self, js: str, result: dict):
        """Try to extract the embedded JSON container configuration."""
        # Pattern 1: var data = {...}
        m = re.search(r'var\s+data\s*=\s*(\{.+?\});', js, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(1))
                result["_container_data"] = data
                return
            except json.JSONDecodeError:
                pass

        # Pattern 2: function argument with resource
        m = re.search(r'\}\)\(document,\s*(\{.+?\})\s*\)', js, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(1))
                result["_container_data"] = data
                return
            except json.JSONDecodeError:
                pass

        # Pattern 3: Look for "resource" JSON blob
        m = re.search(r'"resource"\s*:\s*\{[^}]+\}', js)
        if m:
            result["_has_resource_block"] = True

    def _extract_domains(self, js: str, result: dict):
        """Extract all domains from the GTM JS using URL parsing and strict TLD validation."""
        domains = set()

        # Method 1: Extract from full URLs (most reliable)
        for match in URL_PATTERN.finditer(js):
            url = match.group(0).rstrip("'\")}];,")
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                if host:
                    host = host.lower().strip(".")
                    if self._is_valid_domain(host):
                        domains.add(host)
            except Exception:
                pass

        # Method 2: Extract quoted strings that look like domains
        for match in re.finditer(r'["\']([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+)["\']', js):
            candidate = match.group(1).lower().strip(".")
            if self._is_valid_domain(candidate):
                domains.add(candidate)

        # Method 3: Protocol-relative URLs
        for match in re.finditer(r'//([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+)', js):
            candidate = match.group(1).lower().strip(".")
            if self._is_valid_domain(candidate):
                domains.add(candidate)

        # Separate into "interesting" domains and ignored
        interesting = sorted(domains - IGNORE_DOMAINS)
        result["domains"] = interesting
        result["domains_under_gtm"] = interesting

    # Common JS property paths that look like domains but aren't
    _FALSE_POSITIVE_TLDS = {"id", "name", "type", "value", "length", "data", "key", "text"}
    _FALSE_POSITIVE_PATTERNS = re.compile(
        r'^(module|application|interaction|asset|card|user|pageview|marketing|'
        r'event|element|container|session|page|request|response|object|item|'
        r'document|window|navigator|location|screen|history|cookie|storage|'
        r'click|scroll|submit|load|error|input|change|focus|blur|resize)\b',
        re.IGNORECASE,
    )

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Check if a string is a valid domain with a real TLD."""
        if not domain or len(domain) < 4:
            return False
        if "." not in domain:
            return False
        # No IP addresses
        if all(c.isdigit() or c == "." for c in domain):
            return False
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        # Filter out JS property paths like user.id, module.name, etc.
        tld = parts[-1]
        if tld in GTMAnalyzer._FALSE_POSITIVE_TLDS:
            return False
        if GTMAnalyzer._FALSE_POSITIVE_PATTERNS.match(parts[0]):
            # Allow if it has a valid public TLD (e.g., application.com is valid)
            if tld not in VALID_TLDS:
                return False
            # Still reject if only 2 parts and TLD is ambiguous
            if len(parts) == 2 and tld in {"co", "io", "me", "to", "is", "am", "it", "at", "no"}:
                # Only accept if the first part looks like a real brand (>3 chars)
                if len(parts[0]) <= 3:
                    return False
        # Check two-part TLD first (e.g., co.uk, com.br)
        if len(parts) >= 3:
            two_part_tld = f"{parts[-2]}.{parts[-1]}"
            if two_part_tld in VALID_TLDS:
                return True
        # Check single TLD
        if tld in VALID_TLDS:
            return True
        return False

    def _extract_urls(self, js: str, result: dict):
        """Extract full URLs from the GTM JS."""
        urls = set()
        for match in URL_PATTERN.finditer(js):
            url = match.group(0).rstrip("'\")}];,")
            if len(url) > 15 and "googletagmanager.com/gtm.js" not in url:
                urls.add(url)
        result["urls"] = sorted(urls)

        # Identify scripts specifically
        scripts = [u for u in urls if any(u.endswith(ext) for ext in [".js", ".min.js"])]
        result["scripts_loaded"] = sorted(scripts)

        # Identify pixels/tracking
        pixels = [
            u for u in urls
            if any(kw in u.lower() for kw in [
                "pixel", "track", "/tr?", "collect?", "beacon",
                "event?", "analytics", "log?", "ping?",
            ])
        ]
        result["pixels"] = sorted(pixels)

    def _extract_tracking_ids(self, js: str, result: dict):
        """Extract all tracking IDs from the container."""
        ids = extract_all_tracking_ids(js)
        # Remove the current GTM ID from results
        ids["GTM"].discard(result["gtm_id"])
        result["tracking_ids"] = {k: sorted(v) for k, v in ids.items() if v}

    def _detect_services(self, result: dict):
        """Detect third-party services based on domains."""
        detected = set()
        all_domains = set(result.get("domains", []))
        all_urls = set(result.get("urls", []))
        combined = " ".join(all_domains) + " " + " ".join(all_urls)

        for service, signatures in SERVICE_SIGNATURES.items():
            for sig in signatures:
                if sig in combined:
                    detected.add(service)
                    break

        result["services_detected"] = sorted(detected)

    def _extract_custom_html(self, js: str, result: dict):
        """Extract custom HTML tags (potential injection points)."""
        # Custom HTML in GTM is usually in escaped form within the JS
        html_patterns = [
            re.compile(r'(?:customHtml|html)["\']\s*:\s*["\'](.+?)["\']', re.DOTALL),
            re.compile(r'\\x3cscript[^>]*\\x3e(.+?)\\x3c/script\\x3e', re.DOTALL),
            re.compile(r'<script[^>]*>(.+?)</script>', re.DOTALL),
        ]

        tags = []
        for pattern in html_patterns:
            for match in pattern.finditer(js):
                content = match.group(1)
                # Unescape
                content = (
                    content.replace("\\x3c", "<")
                    .replace("\\x3e", ">")
                    .replace("\\x26", "&")
                    .replace("\\x22", '"')
                    .replace("\\x27", "'")
                    .replace("\\n", "\n")
                    .replace("\\t", "\t")
                    .replace("\\/", "/")
                )
                if len(content) > 10:
                    tags.append(content[:500])  # Truncate long tags

        result["custom_html_tags"] = tags[:20]  # Limit to 20 tags

    def _extract_datalayer_vars(self, js: str, result: dict):
        """Extract dataLayer variable references."""
        dl_vars = set()
        # Pattern: dataLayer references
        for m in re.finditer(r'dataLayer[.\[]["\']([\w.]+)', js):
            dl_vars.add(m.group(1))
        # Pattern: variable macros
        for m in re.finditer(r'"key"\s*:\s*"([\w.]+)"', js):
            var_name = m.group(1)
            if not var_name.startswith("gtm.") and len(var_name) > 2:
                dl_vars.add(var_name)

        result["data_layer_vars"] = sorted(dl_vars)

    def _extract_interesting_strings(self, js: str, result: dict):
        """Extract potentially interesting strings (endpoints, keys, etc)."""
        interesting = set()

        # API endpoints
        for m in re.finditer(r'https?://[^\s"\'<>]+/api/[^\s"\'<>]+', js):
            interesting.add(f"API: {m.group(0)[:200]}")

        # Webhook URLs
        for m in re.finditer(r'https?://[^\s"\'<>]*webhook[^\s"\'<>]*', js, re.IGNORECASE):
            interesting.add(f"Webhook: {m.group(0)[:200]}")

        # Email addresses
        for m in re.finditer(r'[\w.+-]+@[\w-]+\.[\w.-]+', js):
            interesting.add(f"Email: {m.group(0)}")

        # Potential API keys (long alphanumeric strings)
        for m in re.finditer(r'["\']([a-zA-Z0-9]{32,})["\']', js):
            val = m.group(1)
            # Skip common hashes/non-keys
            if not val.isdigit() and not val.islower():
                interesting.add(f"Key?: {val[:60]}")

        result["interesting_strings"] = sorted(interesting)[:30]

    def _extract_container_version(self, js: str, result: dict):
        """Extract container version info."""
        m = re.search(r'"version"\s*:\s*"(\d+)"', js)
        if m:
            result["container_version"] = m.group(1)


# ──────────────────────────────────────────────────────────────────────
# Async GTM Analyzer (for parallel processing)
# ──────────────────────────────────────────────────────────────────────

async def analyze_gtm_async(gtm_id: str, session: aiohttp.ClientSession) -> dict:
    """Analyze a GTM container asynchronously."""
    analyzer = GTMAnalyzer()
    # Use sync analyzer wrapped - aiohttp for fetching, then parse
    result = {
        "gtm_id": gtm_id,
        "status": "unknown",
        "raw_size": 0,
        "domains": [],
        "urls": [],
        "tracking_ids": {},
        "services_detected": [],
        "custom_html_tags": [],
        "scripts_loaded": [],
        "pixels": [],
        "data_layer_vars": [],
        "container_version": "",
        "interesting_strings": [],
        "domains_under_gtm": [],
    }

    try:
        url = GTM_JS_URL.format(gtm_id=gtm_id)
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 404:
                result["status"] = "not_found"
                return result
            elif resp.status != 200:
                result["status"] = f"error_{resp.status}"
                return result

            js_content = await resp.text()
            result["raw_size"] = len(js_content)
            result["status"] = "active"

            # Use sync methods for parsing
            analyzer._extract_container_data(js_content, result)
            analyzer._extract_domains(js_content, result)
            analyzer._extract_urls(js_content, result)
            analyzer._extract_tracking_ids(js_content, result)
            analyzer._detect_services(result)
            analyzer._extract_custom_html(js_content, result)
            analyzer._extract_datalayer_vars(js_content, result)
            analyzer._extract_interesting_strings(js_content, result)
            analyzer._extract_container_version(js_content, result)

    except asyncio.TimeoutError:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = f"error: {str(e)}"

    return result


async def analyze_all_gtm_async(gtm_ids: list[str]) -> list[dict]:
    """Analyze multiple GTM containers in parallel."""
    results = []
    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": USER_AGENT},
    ) as session:
        tasks = [analyze_gtm_async(gid, session) for gid in gtm_ids]
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Analyzing {len(gtm_ids)} GTM containers...",
                total=len(gtm_ids),
            )
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.update(task, advance=1)

    return results


# ──────────────────────────────────────────────────────────────────────
# Reverse GTM Lookup - Find domains using a GTM ID
# ──────────────────────────────────────────────────────────────────────

class GTMReverseLookup:
    """Find websites using specific GTM container IDs."""

    def __init__(self, builtwith_cookies: dict | None = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.bw_cookies = builtwith_cookies or {}
        # Load BuiltWith cookies from file if not provided
        if not self.bw_cookies:
            bw_session_file = os.path.join(
                os.path.expanduser("~"), ".crawlgtm", "builtwith_session.json"
            )
            if os.path.exists(bw_session_file):
                try:
                    with open(bw_session_file) as f:
                        self.bw_cookies = json.load(f)
                except Exception:
                    pass

    def lookup(self, gtm_id: str) -> list[dict]:
        """Search for websites using this GTM ID across multiple sources."""
        results = []

        # Method 1: BuiltWith (best source for GTM lookups)
        results.extend(self._search_builtwith(gtm_id))

        # Method 2: PublicWWW search
        results.extend(self._search_publicwww(gtm_id))

        # Method 3: SpyOnWeb
        results.extend(self._search_spyonweb(gtm_id))

        # Method 4: Wayback Machine CDX (find sites that loaded this GTM JS)
        results.extend(self._search_wayback_cdx(gtm_id))

        # Method 5: DuckDuckGo search
        results.extend(self._search_duckduckgo(gtm_id))

        # Method 6: Google search (with rate limit awareness)
        results.extend(self._search_google(gtm_id))

        # Method 7: FOFA search
        results.extend(self._search_fofa(gtm_id))

        # Deduplicate by domain
        seen = set()
        unique = []
        # Valid TLDs for domain validation
        valid_tld = re.compile(
            r'\.(com|net|org|io|co|br|de|fr|uk|es|it|nl|ru|cn|jp|au|ca|in|mx|ar|cl|pe|gr|pl|se|dk|no|mu|cc'
            r'|site|online|store|fun|shop|app|dev|tech|biz|info|us|eu|pt|cz|at|ch|be|fi|ie|nz|za|kr|tw|hk|sg'
            r'|co\.uk|com\.br|com\.au|co\.za|com\.mx|com\.ar|com\.hk|com\.co|com\.pe|com\.cl)$'
        )
        for r in results:
            domain = r.get("domain", "").lower().strip()
            if not domain or domain in seen:
                continue
            # Must look like a real domain (not a filename like favicon.ico)
            if not valid_tld.search(domain):
                continue
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z]{2,}$', domain):
                continue
            # Filter out search engines and generic domains
            skip = ["google.", "bing.", "yahoo.", "duckduckgo.", "youtube.",
                    "gstatic.", "googleapis.", "schema.org", "w3.org",
                    "twitter.com", "x.com", "facebook.com", "reddit.com",
                    "builtwith.com", "publicwww.com", "spyonweb.com",
                    "web.archive.org", "doubleclick.net", "googlesyndication.",
                    "gmail.com"]
            if not any(s in domain for s in skip):
                seen.add(domain)
                r["domain"] = domain
                unique.append(r)

        return unique

    def _search_builtwith(self, gtm_id: str) -> list[dict]:
        """Search BuiltWith for sites using this GTM container via relationships page."""
        results = []

        # Primary: Use authenticated /relationships/tag/ endpoint
        # Works with both GTM-XXXXXXX and G-XXXXXXX IDs
        relationship_url = f"https://builtwith.com/relationships/tag/{gtm_id}"

        try:
            cookies = {}
            if self.bw_cookies:
                cookies = self.bw_cookies.copy()

            resp = self.session.get(
                relationship_url,
                cookies=cookies,
                timeout=20,
                allow_redirects=True,
            )

            if resp.status_code == 200 and len(resp.text) > 500:
                soup = BeautifulSoup(resp.text, "html.parser")

                # BuiltWith relationships page - extract domain links
                # Pattern 1: Links to /detailed/ pages (most common)
                for link in soup.select("a[href*='/detailed/']"):
                    href = link.get("href", "")
                    m = re.search(r'/detailed/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', href)
                    if m:
                        domain = m.group(1).lower()
                        if len(domain) > 3:
                            results.append({
                                "domain": domain,
                                "source": "builtwith",
                                "url": f"https://builtwith.com{href}" if href.startswith("/") else href,
                            })

                # Pattern 2: Links to /relationships/ pages (related sites)
                for link in soup.select("a[href*='/relationships/']"):
                    href = link.get("href", "")
                    text = link.get_text(strip=True)
                    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
                        results.append({
                            "domain": text.lower(),
                            "source": "builtwith",
                            "url": f"https://builtwith.com{href}" if href.startswith("/") else href,
                        })

                # Pattern 3: Table rows with domain info (primary method)
                for row in soup.select("tr"):
                    cells = row.find_all("td")
                    if len(cells) >= 3:
                        domain_text = cells[1].get_text(strip=True) if len(cells) > 1 else ""
                        if not domain_text:
                            domain_text = cells[0].get_text(strip=True)
                        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain_text):
                            link = row.find("a")
                            href = link.get("href", "") if link else ""
                            entry = {
                                "domain": domain_text.lower(),
                                "source": "builtwith",
                                "url": f"https://builtwith.com{href}" if href.startswith("/") else href,
                            }
                            # Extract first/last detected dates
                            if len(cells) >= 4:
                                entry["first_detected"] = cells[2].get_text(strip=True)
                                entry["last_detected"] = cells[3].get_text(strip=True)
                            if len(cells) >= 5:
                                entry["duration"] = cells[4].get_text(strip=True)
                            results.append(entry)

                # Pattern 4: Any link text that looks like a domain
                for link in soup.select("a"):
                    text = link.get_text(strip=True)
                    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
                        href = link.get("href", "")
                        # Skip navigation and non-domain links
                        if text.lower() not in ("builtwith.com", "pro.builtwith.com"):
                            results.append({
                                "domain": text.lower(),
                                "source": "builtwith",
                                "url": href,
                            })

                # Pattern 5: Extract domains from page text via regex
                page_text = soup.get_text()
                for m in re.findall(
                    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
                    r'\.(?:com|net|org|io|co|br|de|fr|uk|es|it|nl|ru|cn|jp|au|ca|in|mx|ar|cl|pe'
                    r'|co\.uk|com\.br|com\.au|co\.za|com\.mx|com\.ar|com\.co|com\.pe|com\.cl))\b',
                    page_text,
                ):
                    if len(m) > 4 and m.lower() not in ("builtwith.com", "pro.builtwith.com"):
                        results.append({"domain": m.lower(), "source": "builtwith"})

                # If no results from relationships, save HTML for debug
                if not results and len(resp.text) > 500:
                    console.print(f"    [dim]BuiltWith returned page ({len(resp.text)} bytes) but no domains parsed[/]")

        except Exception as e:
            console.print(f"    [dim]BuiltWith error: {e}[/]")

        # Fallback: try trends URL without auth (free tier)
        if not results:
            try:
                fallback_url = f"https://trends.builtwith.com/websitelist/{gtm_id}"
                resp = self.session.get(fallback_url, timeout=15, allow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 1000:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for link in soup.select("a"):
                        text = link.get_text(strip=True)
                        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
                            results.append({"domain": text.lower(), "source": "builtwith"})
            except Exception:
                pass

        return results

    def _search_publicwww(self, gtm_id: str) -> list[dict]:
        """Search PublicWWW for GTM ID usage in source code."""
        results = []
        try:
            url = f"https://publicwww.com/websites/{urllib.parse.quote(gtm_id)}/"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.select("a.website-url, .results a[href*='://'], #results a"):
                    text = link.get_text(strip=True)
                    href = link.get("href", "")
                    if text and "." in text and len(text) > 3:
                        results.append({
                            "domain": text.lower(),
                            "source": "publicwww",
                            "url": href,
                        })
                # Fallback: extract domains from visible text only (not raw HTML)
                if not results:
                    page_text = soup.get_text()
                    for m in re.findall(
                        r'\b([a-zA-Z0-9-]+\.(?:com|net|org|io|co|br|de|fr|uk|es|it|nl|ru|cn|jp|au|ca|in'
                        r'|co\.uk|com\.br|com\.au|com\.mx|com\.ar))\b',
                        page_text,
                    ):
                        if len(m) > 4:
                            results.append({"domain": m.lower(), "source": "publicwww"})
        except Exception:
            pass
        return results

    def _search_spyonweb(self, gtm_id: str) -> list[dict]:
        """Search SpyOnWeb for GTM ID relationships."""
        results = []
        try:
            url = f"https://spyonweb.com/{gtm_id}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.select("a.link"):
                    text = link.get_text(strip=True)
                    if "." in text and len(text) > 3:
                        results.append({
                            "domain": text.lower(),
                            "source": "spyonweb",
                        })
        except Exception:
            pass
        return results

    def _search_wayback_cdx(self, gtm_id: str) -> list[dict]:
        """Search Wayback Machine CDX for sites that loaded this GTM container."""
        results = []
        try:
            # Search for the GTM JS URL being loaded (referer tells us which site)
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=www.googletagmanager.com/gtm.js?id={gtm_id}"
                f"&output=json&fl=original,timestamp,statuscode&limit=50"
                f"&from=2023&filter=statuscode:200"
            )
            resp = self.session.get(cdx_url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    # For each archived GTM load, try to find the referring page
                    timestamps = [row[1] for row in data[1:]][:10]
                    for ts in timestamps:
                        try:
                            wb_url = f"https://web.archive.org/web/{ts}/https://www.googletagmanager.com/gtm.js?id={gtm_id}"
                            self.session.head(wb_url, timeout=10, allow_redirects=True)
                            # The referer page won't be in HEAD, but CDX tells us it existed
                        except Exception:
                            pass

            # Also search CDX for pages containing the GTM ID string
            cdx_url2 = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.com/*&output=json&fl=original&limit=20"
                f"&filter=original:.*{gtm_id}.*"
            )
            resp2 = self.session.get(cdx_url2, timeout=15)
            if resp2.status_code == 200:
                data2 = resp2.json()
                for row in data2[1:] if len(data2) > 1 else []:
                    url_str = row[0] if row else ""
                    m = re.search(r'https?://([^/]+)', url_str)
                    if m:
                        results.append({
                            "domain": m.group(1).lower(),
                            "source": "wayback",
                        })
        except Exception:
            pass
        return results

    def _search_duckduckgo(self, gtm_id: str) -> list[dict]:
        """Search DuckDuckGo for mentions of the GTM ID."""
        results = []
        try:
            resp = self.session.get(
                f"https://html.duckduckgo.com/html/?q=%22{gtm_id}%22",
                timeout=10,
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.select("a.result__a"):
                    href = link.get("href", "")
                    m = re.search(r'https?://([^/&]+)', href)
                    if m:
                        results.append({
                            "domain": m.group(1).lower(),
                            "source": "duckduckgo",
                            "url": href,
                        })
                # Also extract from result snippets
                for snippet in soup.select(".result__snippet"):
                    text = snippet.get_text()
                    for m in re.findall(r'([a-zA-Z0-9-]+\.(?:com|net|org|io|br|co\.uk|com\.br))\b', text):
                        results.append({"domain": m.lower(), "source": "duckduckgo"})
        except Exception:
            pass
        return results

    def _search_google(self, gtm_id: str) -> list[dict]:
        """Search Google for the GTM ID (with care for rate limits)."""
        results = []
        try:
            resp = self.session.get(
                f"https://www.google.com/search?q=%22{gtm_id}%22&num=20",
                timeout=10,
            )
            if resp.status_code == 200:
                # Extract domains from search result URLs
                for m in re.findall(r'href="https?://([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^"]*"', resp.text):
                    results.append({"domain": m.lower(), "source": "google"})
        except Exception:
            pass
        return results

    def _search_fofa(self, gtm_id: str) -> list[dict]:
        """Search FOFA for sites using this GTM ID via cursor pagination.

        Uses /search/next (fofaquery style) to fetch ALL results.
        Falls back to web scraper if no API key or API fails.
        """
        fofa_key = load_fofa_key()

        # If no API key, go straight to web scraper
        if not fofa_key:
            return fofa_web_reverse_lookup(gtm_id)

        results = []
        seen = set()
        api_failed = False

        for query in [f'body="{gtm_id}"', f'header="{gtm_id}"', f'"{gtm_id}"']:
            qbase64 = base64.b64encode(query.encode()).decode()
            fofa_email = load_fofa_email()
            params = {
                "key": fofa_key,
                "qbase64": qbase64,
                "fields": "host,link",
                "size": 10000,
                "full": "true",
            }
            if fofa_email:
                params["email"] = fofa_email

            try:
                while True:
                    resp = self.session.get(FOFA_NEXT_API_URL, params=params, timeout=30)
                    if resp.status_code != 200:
                        api_failed = True
                        break

                    data = resp.json()
                    if data.get("error") or data.get("errmsg"):
                        api_failed = True
                        break

                    for row in data.get("results", []):
                        host = row[0] if len(row) > 0 else ""
                        link = row[1] if len(row) > 1 else ""
                        if host:
                            domain = host.split(":")[0].lower().strip()
                            if domain.startswith("http"):
                                domain = re.sub(r'^https?://', '', domain).split("/")[0]
                            if domain and "." in domain and len(domain) > 3 and domain not in seen:
                                seen.add(domain)
                                results.append({
                                    "domain": domain,
                                    "source": "fofa",
                                    "url": link if link else f"https://{domain}",
                                })

                    next_token = data.get("next")
                    if not next_token:
                        break
                    params["next"] = next_token
                    time.sleep(0.5)

            except Exception:
                api_failed = True

            if api_failed:
                break

        # Fallback to web scraper if API failed
        if api_failed and not results:
            return fofa_web_reverse_lookup(gtm_id)

        return results


# ──────────────────────────────────────────────────────────────────────
# FOFA GTM Discovery - Search FOFA for GTM containers
# ──────────────────────────────────────────────────────────────────────

FOFA_WEB_URL = "https://en.fofa.info/result"


def fofa_web_search(query: str, max_pages: int = 1) -> list[dict]:
    """
    Search FOFA by scraping the web UI (no API key needed).

    Returns up to 10 results per page. Without login, only page 1
    returns unique results; subsequent pages may repeat.

    Args:
        query: Raw FOFA query string (e.g., 'body="GTM-XXXXXXX"').
        max_pages: Pages to fetch (default 1; unauthenticated caps at ~10 results).

    Returns:
        List of dicts with keys: host, domain, url, ip, source.
    """
    qbase64 = base64.b64encode(query.encode()).decode()
    results = []
    seen = set()

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://en.fofa.info/",
    }

    for page in range(1, max_pages + 1):
        try:
            params = {"qbase64": qbase64, "page": page, "page_size": 10}
            resp = requests.get(
                FOFA_WEB_URL, params=params, headers=headers,
                timeout=20, allow_redirects=True,
            )

            if resp.status_code != 200:
                if "-3000" in resp.text or "abnormal" in resp.text.lower():
                    console.print("[yellow]  \u26a0 FOFA web: IP rate-limited (-3000)[/]")
                else:
                    console.print(f"[yellow]  \u26a0 FOFA web: HTTP {resp.status_code}[/]")
                break

            html = resp.text

            # Detect rate-limit even on 200
            if "-3000" in html:
                console.print("[yellow]  \u26a0 FOFA web: IP rate-limited (-3000)[/]")
                break

            soup = BeautifulSoup(html, "html.parser")

            # Extract total result count
            if page == 1:
                count_match = re.search(r'<span[^>]*>([0-9,]+)</span>\s*results', html)
                if count_match:
                    console.print(f"[dim]  FOFA web: {count_match.group(1)} total results[/]")

            # Extract result entries via hsxa-host class
            host_spans = soup.select("span.hsxa-host a")
            if not host_spans:
                # Fallback: broader link pattern
                host_spans = [
                    a for a in soup.select("a[href]")
                    if a.get("href", "").startswith("http")
                    and "fofa.info" not in a.get("href", "")
                    and "static" not in a.get("href", "")
                    and "javascript" not in a.get("href", "")
                    and "v5static" not in a.get("href", "")
                    and "twitter" not in a.get("href", "")
                    and "github" not in a.get("href", "")
                ]

            if not host_spans and page == 1:
                console.print("[yellow]  FOFA web: no results found[/]")
                break

            page_count = 0
            for a_tag in host_spans:
                href = a_tag.get("href", "").strip()
                if not href or "fofa.info" in href:
                    continue

                url = href if href.startswith("http") else f"https://{href}"
                try:
                    parsed = urllib.parse.urlparse(url)
                    domain = parsed.hostname or ""
                except Exception:
                    domain = ""

                if not domain or domain in seen:
                    continue
                seen.add(domain)

                ip = ""
                ip_match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)
                if ip_match:
                    ip = domain

                results.append({
                    "host": a_tag.get_text(strip=True) or domain,
                    "domain": domain,
                    "url": url,
                    "ip": ip,
                    "source": "fofa-web",
                })
                page_count += 1

            if page_count == 0:
                break

            console.print(f"[dim]  FOFA web page {page}: {page_count} results[/]")

            if page < max_pages:
                time.sleep(3)

        except requests.exceptions.Timeout:
            console.print("[yellow]  \u26a0 FOFA web: timeout[/]")
            break
        except Exception as e:
            console.print(f"[yellow]  \u26a0 FOFA web: {e}[/]")
            break

    return results


def fofa_web_reverse_lookup(gtm_id: str) -> list[dict]:
    """
    Search FOFA web UI for sites using a specific GTM ID (no API key).

    Tries body search first, then plain text fallback.
    Returns list of dicts with domain, source, url keys.
    """
    results = []
    seen = set()

    for query in [f'body="{gtm_id}"', f'"{gtm_id}"']:
        raw = fofa_web_search(query, max_pages=1)
        for r in raw:
            domain = r.get("domain", "").lower().strip()
            if domain and domain not in seen and "." in domain and len(domain) > 3:
                seen.add(domain)
                results.append({
                    "domain": domain,
                    "source": "fofa-web",
                    "url": r.get("url", f"https://{domain}"),
                })
        if results:
            break
        time.sleep(2)

    return results


class FofaCollector:
    """Collect GTM IDs from FOFA search engine API.

    Uses a multi-strategy approach to maximize GTM ID discovery:
    1. Search FOFA for pages referencing googletagmanager
    2. Extract GTM IDs from HTTP response headers (header field)
    3. Scan discovered hosts to extract GTM IDs from HTML
    """

    def __init__(self, api_key: str = "", email: str = "", max_pages: int = 5, page_size: int = 10000):
        if not api_key:
            api_key = load_fofa_key()
        if not email:
            email = load_fofa_email()
        self.api_key = api_key
        self.email = email
        self.max_pages = max_pages
        self.page_size = page_size
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    @staticmethod
    def _quiet_scan_url(url: str) -> set[str]:
        """Scan a URL for GTM IDs without printing errors (silent version)."""
        gtm_ids = set()
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=10,
                allow_redirects=True,
                verify=False,
            )
            if resp.status_code == 200:
                for m in GTM_ID_PATTERN.finditer(resp.text):
                    gtm_ids.add(m.group(0).upper())
        except Exception:
            pass
        return gtm_ids

    def _fofa_search(self, fofa_query: str, fields: str = "host,title,link,header") -> list[list]:
        """Execute FOFA search using /search/next cursor pagination (fofaquery style).

        Fetches ALL available results by following the cursor 'next' token,
        not limited by page count.
        """
        qbase64 = base64.b64encode(fofa_query.encode()).decode()
        all_results = []

        params = {
            "key": self.api_key,
            "qbase64": qbase64,
            "fields": fields,
            "size": self.page_size,
            "full": "true",
        }
        if self.email:
            params["email"] = self.email

        page = 0
        while True:
            page += 1
            try:
                resp = self.session.get(FOFA_NEXT_API_URL, params=params, timeout=30)

                if resp.status_code == 401:
                    console.print("[red]  ✗ FOFA API: authentication failed (invalid key)[/]")
                    break

                if resp.status_code != 200:
                    console.print(f"[yellow]  ⚠ FOFA API returned status {resp.status_code}[/]")
                    break

                data = resp.json()

                if data.get("error") or data.get("errmsg"):
                    console.print(f"[red]  ✗ FOFA: {data.get('errmsg', 'unknown error')}[/]")
                    break

                results = data.get("results", [])
                total_available = data.get("size", 0)

                if not results:
                    if page == 1:
                        console.print("[yellow]  No FOFA results[/]")
                    break

                all_results.extend(results)
                console.print(
                    f"[dim]  Fetched {len(results)} results "
                    f"(total: {len(all_results)}/{total_available})[/]"
                )

                # Cursor-based pagination: follow 'next' token
                next_token = data.get("next")
                if not next_token:
                    break
                params["next"] = next_token

                time.sleep(0.5)

            except requests.exceptions.Timeout:
                console.print(f"[yellow]  ⚠ FOFA timeout[/]")
                break
            except json.JSONDecodeError:
                console.print("[yellow]  ⚠ FOFA returned invalid JSON[/]")
                break
            except Exception as e:
                console.print(f"[yellow]  ⚠ FOFA error: {e}[/]")
                break

        return all_results

    def collect(self, query: str, scan_hosts: bool = False) -> tuple[set, list]:
        """
        Search FOFA and extract GTM IDs from results.

        Strategy:
        1. Build FOFA query to find GTM-enabled sites
        2. Extract GTM IDs from HTTP headers where available
        3. Collect host URLs for scanning
        4. Scan hosts to extract GTM IDs from actual page HTML

        Args:
            query: FOFA search query (e.g., 'domain="example.com"', 'org="Company"',
                   'header="GTM-"', or any FOFA dork syntax).
            scan_hosts: If True, also scan discovered hosts for additional GTM IDs.

        Returns:
            Tuple of (set of GTM IDs, list of discovered host URLs).
        """
        all_gtm_ids = set()
        all_hosts = []
        seen_hosts = set()

        # Extract GTM IDs directly from the query itself
        # (e.g., user searched for body="GTM-5QGGLMHR")
        for gid in GTM_ID_PATTERN.findall(query):
            all_gtm_ids.add(gid.upper())
        if all_gtm_ids:
            console.print(
                f"[green]  GTM IDs from query: {', '.join(sorted(all_gtm_ids))}[/]"
            )

        # Build the FOFA query - combine user query with GTM targeting
        query_lower = query.lower()
        if "gtm" not in query_lower and "googletagmanager" not in query_lower:
            fofa_query = f'{query} && "googletagmanager"'
        else:
            fofa_query = query

        console.print(f"[cyan]  FOFA query: {fofa_query}[/]")

        # Fetch results with header field (available on free tier)
        results = self._fofa_search(fofa_query, fields="host,title,link,header")

        for row in results:
            host = row[0] if len(row) > 0 else ""
            title = row[1] if len(row) > 1 else ""
            link = row[2] if len(row) > 2 else ""
            header = row[3] if len(row) > 3 else ""

            # Extract GTM IDs from HTTP response headers
            if header:
                for gid in GTM_ID_PATTERN.findall(header):
                    all_gtm_ids.add(gid.upper())

            # Extract GTM IDs from page title (rare but possible)
            if title:
                for gid in GTM_ID_PATTERN.findall(title):
                    all_gtm_ids.add(gid.upper())

            # Collect unique host URLs
            clean_host = ""
            if link and link.startswith("http"):
                clean_host = link.strip().rstrip("/")
            elif host:
                h = host.strip()
                # Remove port for hostname-only entries
                if h.startswith("http"):
                    clean_host = h.rstrip("/")
                else:
                    if ":" in h:
                        h = h.split(":")[0]
                    if h and "." in h:
                        clean_host = f"https://{h}"

            if clean_host and clean_host not in seen_hosts:
                seen_hosts.add(clean_host)
                all_hosts.append(clean_host)

        # Fallback: try body and header-specific searches if initial query found no GTM IDs
        if not all_gtm_ids and not query_lower.startswith(("header=", "body=")):
            fallback_queries = []
            if "gtm" not in query_lower:
                fallback_queries.append(f'{query} && body="GTM-"')
                fallback_queries.append(f'{query} && header="GTM-"')
            else:
                fallback_queries.append(f'body="GTM-" && {query}')
                fallback_queries.append(f'header="GTM-" && {query}')
            for fb_query in fallback_queries:
                console.print(f"[dim]  Fallback search: {fb_query}[/]")
                fb_results = self._fofa_search(fb_query, fields="host,title,link,header")
                for row in fb_results:
                    header = row[3] if len(row) > 3 else ""
                    if header:
                        for gid in GTM_ID_PATTERN.findall(header):
                            all_gtm_ids.add(gid.upper())
                    title = row[1] if len(row) > 1 else ""
                    if title:
                        for gid in GTM_ID_PATTERN.findall(title):
                            all_gtm_ids.add(gid.upper())
                    # Add hosts
                    host = row[0] if len(row) > 0 else ""
                    link = row[2] if len(row) > 2 else ""
                    clean_host = ""
                    if link and link.startswith("http"):
                        clean_host = link.strip().rstrip("/")
                    elif host:
                        h = host.strip()
                        if h.startswith("http"):
                            clean_host = h.rstrip("/")
                        elif "." in h:
                            clean_host = f"https://{h.split(':')[0]}"
                    if clean_host and clean_host not in seen_hosts:
                        seen_hosts.add(clean_host)
                        all_hosts.append(clean_host)
                if all_gtm_ids:
                    break  # Stop fallback if we found GTM IDs

        console.print(
            f"[green]  ✓ FOFA: {len(all_gtm_ids)} GTM IDs from headers, "
            f"{len(all_hosts)} unique hosts discovered[/]"
        )

        # Scan discovered hosts for GTM IDs from actual page HTML
        # This is the primary extraction method since body field requires premium
        hosts_to_scan = all_hosts
        if scan_hosts and hosts_to_scan:
            console.print(f"[cyan]  Scanning {len(hosts_to_scan)} FOFA hosts for GTM IDs...[/]")
            scanned = 0
            errors = 0
            for host_url in hosts_to_scan:
                try:
                    host_gtms = self._quiet_scan_url(host_url)
                    if host_gtms:
                        new_gtms = host_gtms - all_gtm_ids
                        all_gtm_ids.update(host_gtms)
                        scanned += 1
                        if new_gtms:
                            console.print(
                                f"    [green]+{len(new_gtms)} GTM IDs from {host_url}: "
                                f"{', '.join(sorted(new_gtms)[:5])}[/]"
                            )
                except Exception:
                    errors += 1
            console.print(
                f"[green]  ✓ Host scanning: {scanned}/{len(hosts_to_scan)} hosts yielded GTM IDs"
                f"{f', {errors} unreachable' if errors else ''}, "
                f"{len(all_gtm_ids)} total GTM IDs[/]"
            )
        elif not scan_hosts and all_hosts and not all_gtm_ids:
            console.print(
                f"[yellow]  Tip: Use --fofa-scan to scan the {len(all_hosts)} "
                f"discovered hosts for GTM IDs[/]"
            )

        return all_gtm_ids, all_hosts

    def reverse_lookup(self, gtm_id: str) -> list[dict]:
        """Search FOFA for websites using a specific GTM ID using cursor pagination.

        Uses /search/next to fetch ALL results, not limited by page count.
        Falls back to web scraper if no API key or API fails.
        """
        # If no API key, go straight to web scraper
        if not self.api_key:
            return fofa_web_reverse_lookup(gtm_id)

        results = []
        seen = set()
        api_failed = False

        for query in [f'body="{gtm_id}"', f'header="{gtm_id}"', f'"{gtm_id}"']:
            qbase64 = base64.b64encode(query.encode()).decode()
            params = {
                "key": self.api_key,
                "qbase64": qbase64,
                "fields": "host,link",
                "size": 10000,
                "full": "true",
            }
            if self.email:
                params["email"] = self.email

            try:
                while True:
                    resp = self.session.get(FOFA_NEXT_API_URL, params=params, timeout=30)

                    if resp.status_code != 200:
                        api_failed = True
                        break

                    data = resp.json()
                    if data.get("error") or data.get("errmsg"):
                        api_failed = True
                        break

                    for row in data.get("results", []):
                        host = row[0] if len(row) > 0 else ""
                        link = row[1] if len(row) > 1 else ""
                        if host:
                            domain = host.split(":")[0].lower().strip()
                            if domain.startswith("http"):
                                domain = re.sub(r'^https?://', '', domain).split("/")[0]
                            if domain and "." in domain and len(domain) > 3 and domain not in seen:
                                seen.add(domain)
                                results.append({
                                    "domain": domain,
                                    "source": "fofa",
                                    "url": link if link else f"https://{domain}",
                                })

                    next_token = data.get("next")
                    if not next_token:
                        break
                    params["next"] = next_token
                    time.sleep(0.5)

            except Exception:
                api_failed = True

            if api_failed:
                break

        # Fallback to web scraper if API failed
        if api_failed and not results:
            return fofa_web_reverse_lookup(gtm_id)

        return results


# ──────────────────────────────────────────────────────────────────────
# BuiltWith Session Management
# ──────────────────────────────────────────────────────────────────────

BW_SESSION_FILE = SESSION_DIR / "builtwith_session.json"


def _parse_bw_cookies(raw_json: str) -> dict:
    """Parse BuiltWith cookies from JSON (dict or browser cookie array)."""
    data = json.loads(raw_json)
    if isinstance(data, dict):
        return data
    elif isinstance(data, list):
        cookies = {}
        for c in data:
            if isinstance(c, dict) and "name" in c and "value" in c:
                cookies[c["name"]] = c["value"]
        return cookies
    return {}


def load_bw_session() -> dict:
    """Load BuiltWith cookies from disk."""
    if BW_SESSION_FILE.exists():
        try:
            data = json.loads(BW_SESSION_FILE.read_text())
            if isinstance(data, dict) and (data.get("BWSSON") or data.get("ASP.NET_SessionId")):
                return data
        except Exception:
            pass
    return {}


def save_bw_session(cookies: dict):
    """Save BuiltWith cookies to disk."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    BW_SESSION_FILE.write_text(json.dumps(cookies, indent=2))


def validate_bw_session(cookies: dict) -> bool:
    """Test if BuiltWith session is valid."""
    if not cookies:
        return False
    try:
        resp = requests.get(
            "https://builtwith.com/relationships/tag/GTM-XXXXXXX",
            cookies=cookies,
            headers={"User-Agent": USER_AGENT},
            timeout=15,
            allow_redirects=False,
        )
        if resp.status_code == 200:
            return True
        if resp.status_code in (301, 302):
            loc = resp.headers.get("location", "")
            if "login" in loc.lower():
                return False
        return resp.status_code == 200
    except Exception:
        return False


def prompt_bw_login() -> dict:
    """Interactive prompt for BuiltWith cookies."""
    if not sys.stdin.isatty():
        console.print("[yellow]  ⚠ BuiltWith session needed but not running interactively.[/]")
        return {}

    console.print(BW_COOKIE_SNIPPET)
    console.print("[bold cyan]Enter your BuiltWith cookies:[/]\n")

    try:
        raw = input("  Paste cookies JSON: ").strip()
        if not raw:
            return {}

        bw_cookies = _parse_bw_cookies(raw)
        if not bw_cookies:
            console.print("[red]  Could not parse cookies.[/]")
            return {}

        # ASP.NET_SessionId is HttpOnly - prompt separately
        session_id = bw_cookies.get("ASP.NET_SessionId", "")
        if not session_id or session_id == "PASTE_FROM_DEVTOOLS":
            console.print("\n[bold yellow]  ASP.NET_SessionId is HttpOnly - paste from DevTools:[/]")
            console.print("[dim]  F12 → Application → Cookies → builtwith.com → ASP.NET_SessionId[/]")
            sid = input("\n  ASP.NET_SessionId: ").strip()
            if sid:
                bw_cookies["ASP.NET_SessionId"] = sid
            else:
                bw_cookies.pop("ASP.NET_SessionId", None)

        if bw_cookies:
            save_bw_session(bw_cookies)
            console.print(f"\n[green]  ✓ BuiltWith session saved! ({len(bw_cookies)} cookies)[/]")

        return bw_cookies

    except (json.JSONDecodeError, EOFError, KeyboardInterrupt):
        console.print("[yellow]  Cancelled or invalid input.[/]")
        return {}


def ensure_bw_session() -> dict:
    """Load BuiltWith session, validate, or prompt for new one."""
    saved = load_bw_session()

    if saved:
        console.print("[dim]  Checking BuiltWith session...[/]")
        if validate_bw_session(saved):
            console.print("[green]  ✓ BuiltWith session active[/]")
            return saved
        else:
            console.print("[yellow]  ⚠ BuiltWith session expired. Need new cookies.[/]")

    return prompt_bw_login()


# ──────────────────────────────────────────────────────────────────────
# FOFA Session Management
# ──────────────────────────────────────────────────────────────────────


def load_fofa_key() -> str:
    """Load FOFA API key from disk."""
    if FOFA_FILE.exists():
        try:
            data = json.loads(FOFA_FILE.read_text())
            return data.get("key", "")
        except Exception:
            pass
    return ""


def load_fofa_email() -> str:
    """Load FOFA email from disk."""
    if FOFA_FILE.exists():
        try:
            data = json.loads(FOFA_FILE.read_text())
            return data.get("email", "")
        except Exception:
            pass
    return ""


def save_fofa_key(key: str, email: str = ""):
    """Save FOFA API key and email to disk."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    fofa_data = {"key": key, "saved_at": datetime.now(timezone.utc).isoformat()}
    if email:
        fofa_data["email"] = email
    FOFA_FILE.write_text(json.dumps(fofa_data, indent=2))


def validate_fofa_key(key: str, email: str = "") -> bool:
    """Test if FOFA API key is valid."""
    if not key or len(key) < 10:
        return False
    if not email:
        email = load_fofa_email()
    try:
        qbase64 = base64.b64encode(b'title="test"').decode()
        params = {"key": key, "qbase64": qbase64, "fields": "host", "size": 1}
        if email:
            params["email"] = email
        resp = requests.get(
            FOFA_API_URL,
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return not data.get("error") and not data.get("errmsg", "").startswith("[50")
        return False
    except Exception:
        return False


def prompt_fofa_setup() -> str:
    """Interactive prompt for FOFA API key."""
    if not sys.stdin.isatty():
        console.print("[yellow]  ⚠ FOFA setup needed but not running interactively.[/]")
        return ""

    console.print(r"""[bold yellow]
┌─────────────────────────────────────────────────────────────────────┐
│  FOFA API Key Setup                                                 │
│                                                                     │
│  1. Go to https://en.fofa.info/ and create an account               │
│  2. Navigate to your profile → API Key                              │
│  3. Copy your email and API key                                     │
└─────────────────────────────────────────────────────────────────────┘[/]
""")

    try:
        email = input("  FOFA email: ").strip()
        key = input("  FOFA API key: ").strip()
        if not key:
            console.print("[yellow]  Skipped FOFA setup.[/]")
            return ""

        console.print("[dim]  Validating FOFA key...[/]")
        if validate_fofa_key(key, email):
            save_fofa_key(key, email)
            console.print("[bold green]  ✓ FOFA API key saved and validated![/]")
            return key
        else:
            console.print("[yellow]  ⚠ FOFA key could not be validated (may still work). Saving anyway.[/]")
            save_fofa_key(key, email)
            return key

    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]  Cancelled.[/]")
        return ""


def ensure_fofa_key() -> str:
    """Load FOFA key, validate, or prompt for new one."""
    saved = load_fofa_key()
    if saved:
        return saved
    return prompt_fofa_setup()


# ──────────────────────────────────────────────────────────────────────
# First Run - Interactive Setup Wizard
# ──────────────────────────────────────────────────────────────────────

SETUP_DONE_FILE = SESSION_DIR / ".setup_done"


def is_first_run() -> bool:
    """Check if this is the first time running crawlGTM."""
    return not SETUP_DONE_FILE.exists()


def mark_setup_done():
    """Mark first-run setup as complete."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    SETUP_DONE_FILE.write_text(datetime.now(timezone.utc).isoformat())


def first_run_wizard():
    """Interactive setup wizard for first-time users."""
    console.print(Panel(
        "[bold]Welcome to crawlGTM![/]\n\n"
        "First-run setup: configure your API sessions.\n"
        "You can reconfigure any of these later with:\n"
        "  [cyan]--login[/]           X.com session\n"
        "  [cyan]--bw-login[/]        BuiltWith session\n"
        "  [cyan]--fofa-setup[/]      FOFA API key + email\n"
        "  [cyan]--telegram-setup[/]  Telegram notifications",
        title="[bold cyan]First Run Setup[/]",
        border_style="cyan",
    ))

    if not sys.stdin.isatty():
        console.print("[yellow]Not running interactively — skipping setup wizard.[/]")
        console.print("[dim]Run with --login, --bw-login, --fofa-setup to configure manually.[/]")
        mark_setup_done()
        return

    # Step 1: FOFA API key + email (required)
    console.print("\n[bold]━━━ Step 1/4: FOFA API Key + Email (for GTM discovery) ━━━[/]")
    try:
        prompt_fofa_setup()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]  Skipped.[/]")

    # Step 2: X.com session (required)
    console.print("\n[bold]━━━ Step 2/4: X.com Session (for post collection) ━━━[/]")
    try:
        sm = SessionManager()
        sm.prompt_login()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]  Skipped.[/]")

    # Step 3: BuiltWith session (required)
    console.print("\n[bold]━━━ Step 3/4: BuiltWith Session (for reverse lookup) ━━━[/]")
    try:
        prompt_bw_login()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]  Skipped.[/]")

    # Step 4: Telegram (optional)
    console.print("\n[bold]━━━ Step 4/4: Telegram Notifications (optional) ━━━[/]")
    try:
        choice = input("  Configure Telegram bot now? [y/N]: ").strip().lower()
        if choice == "y":
            tg = TelegramNotifier()
            tg.setup()
        else:
            console.print("[dim]  Skipped. Use --telegram-setup later.[/]")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]  Skipped.[/]")

    mark_setup_done()

    # Show status summary
    console.print()
    sm = SessionManager()
    saved = sm.load()
    bw = load_bw_session()
    fofa = load_fofa_key()
    tg = TelegramNotifier()

    fofa_email = load_fofa_email()
    fofa_status = "[green]✓ configured[/]" if fofa else "[yellow]✗ not configured[/]"
    if fofa and fofa_email:
        fofa_status += f" [dim]({fofa_email})[/]"

    console.print(Panel(
        f"[bold]FOFA:[/]      {fofa_status}\n"
        f"[bold]X.com:[/]     {'[green]✓ configured[/]' if saved else '[yellow]✗ not configured[/]'}\n"
        f"[bold]BuiltWith:[/] {'[green]✓ configured[/]' if bw else '[yellow]✗ not configured[/]'}\n"
        f"[bold]Telegram:[/]  {'[green]✓ configured[/]' if tg.is_configured else '[dim]✗ not configured[/]'}",
        title="[bold green]Setup Complete[/]",
        border_style="green",
    ))
    console.print()


# ──────────────────────────────────────────────────────────────────────
# Output & Visualization
# ──────────────────────────────────────────────────────────────────────

def render_results(results: list[dict], posts: list[dict], output_dir: str):
    """Render analysis results to terminal and save to files."""

    # ── Summary Table ──
    console.print()
    table = Table(
        title="🔍 GTM Container Analysis Summary",
        box=box.HEAVY_HEAD,
        show_lines=True,
    )
    table.add_column("GTM ID", style="bold cyan", min_width=14)
    table.add_column("Status", min_width=8)
    table.add_column("Size", justify="right", min_width=8)
    table.add_column("Domains", justify="right", min_width=8)
    table.add_column("Services", justify="right", min_width=9)
    table.add_column("Scripts", justify="right", min_width=8)
    table.add_column("Pixels", justify="right", min_width=7)
    table.add_column("Version", justify="center", min_width=8)

    for r in sorted(results, key=lambda x: x["gtm_id"]):
        status_color = "green" if r["status"] == "active" else "red"
        table.add_row(
            r["gtm_id"],
            f"[{status_color}]{r['status']}[/]",
            _human_size(r["raw_size"]),
            str(len(r["domains"])),
            str(len(r["services_detected"])),
            str(len(r["scripts_loaded"])),
            str(len(r["pixels"])),
            r.get("container_version", "-"),
        )

    console.print(table)

    # ── Detailed per-container output ──
    for r in sorted(results, key=lambda x: x["gtm_id"]):
        if r["status"] != "active":
            continue

        console.print()
        tree = Tree(
            f"[bold cyan]📦 {r['gtm_id']}[/] "
            f"[dim](v{r.get('container_version', '?')}, {_human_size(r['raw_size'])})[/]"
        )

        # Services
        if r["services_detected"]:
            svc_branch = tree.add("[bold yellow]🏷  Services Detected[/]")
            for svc in r["services_detected"]:
                svc_branch.add(f"[yellow]{svc}[/]")

        # Tracking IDs
        if r["tracking_ids"]:
            tid_branch = tree.add("[bold magenta]🔢 Tracking IDs[/]")
            for id_type, ids in r["tracking_ids"].items():
                for tid in ids:
                    tid_branch.add(f"[magenta]{id_type}: {tid}[/]")

        # Domains
        if r["domains"]:
            dom_branch = tree.add(f"[bold green]🌐 Domains ({len(r['domains'])})[/]")
            for domain in r["domains"]:
                # Color interesting domains differently
                if any(
                    kw in domain
                    for kw in ["track", "pixel", "analytics", "ad", "collect"]
                ):
                    dom_branch.add(f"[red]{domain}[/]")
                else:
                    dom_branch.add(f"[green]{domain}[/]")

        # Scripts
        if r["scripts_loaded"]:
            scr_branch = tree.add(f"[bold blue]📜 Scripts ({len(r['scripts_loaded'])})[/]")
            for script in r["scripts_loaded"][:30]:
                scr_branch.add(f"[blue]{script}[/]")

        # Pixels
        if r["pixels"]:
            pix_branch = tree.add(f"[bold red]🎯 Tracking Pixels ({len(r['pixels'])})[/]")
            for pixel in r["pixels"][:20]:
                pix_branch.add(f"[red]{pixel}[/]")

        # Interesting Strings
        if r["interesting_strings"]:
            int_branch = tree.add(
                f"[bold white]💡 Interesting ({len(r['interesting_strings'])})[/]"
            )
            for s in r["interesting_strings"][:15]:
                int_branch.add(f"[white]{s}[/]")

        # DataLayer Variables
        if r["data_layer_vars"]:
            dl_branch = tree.add(
                f"[bold cyan]📊 DataLayer Vars ({len(r['data_layer_vars'])})[/]"
            )
            for var in r["data_layer_vars"][:30]:
                dl_branch.add(f"[cyan]{var}[/]")

        # Reverse Lookup Sites (domains shown in RED as requested)
        reverse_sites = r.get("reverse_lookup_sites", [])
        if reverse_sites:
            rev_branch = tree.add(
                f"[bold red]🔍 Domains Using This GTM ({len(reverse_sites)})[/]"
            )
            for site in reverse_sites:
                domain = site.get("domain", "?")
                source = site.get("source", "")
                extra = ""
                if site.get("first_detected"):
                    extra += f" | first: {site['first_detected']}"
                if site.get("last_detected"):
                    extra += f" | last: {site['last_detected']}"
                if site.get("duration"):
                    extra += f" | {site['duration']}"
                rev_branch.add(
                    f"[bold red]{domain}[/] [dim]({source}{extra})[/]"
                )

        console.print(tree)

    # ── Domain to GTM mapping ──
    domain_map = defaultdict(set)
    for r in results:
        if r["status"] == "active":
            for domain in r["domains"]:
                domain_map[domain].add(r["gtm_id"])

    if domain_map:
        console.print()
        dtable = Table(
            title="🌐 Domain → GTM Container Mapping",
            box=box.SIMPLE_HEAVY,
        )
        dtable.add_column("Domain", style="green", min_width=30)
        dtable.add_column("GTM Containers", style="cyan")
        dtable.add_column("# Containers", justify="right")

        for domain, containers in sorted(
            domain_map.items(), key=lambda x: -len(x[1])
        )[:100]:
            dtable.add_row(
                domain,
                ", ".join(sorted(containers)),
                str(len(containers)),
            )

        console.print(dtable)

    # ── Service distribution ──
    service_map = defaultdict(set)
    for r in results:
        if r["status"] == "active":
            for svc in r["services_detected"]:
                service_map[svc].add(r["gtm_id"])

    if service_map:
        console.print()
        stable = Table(
            title="🏷  Service Distribution Across Containers",
            box=box.SIMPLE_HEAVY,
        )
        stable.add_column("Service", style="yellow", min_width=20)
        stable.add_column("Containers", style="cyan")
        stable.add_column("Count", justify="right")

        for svc, containers in sorted(
            service_map.items(), key=lambda x: -len(x[1])
        ):
            stable.add_row(
                svc,
                ", ".join(sorted(containers)),
                str(len(containers)),
            )

        console.print(stable)

    # ── Save results ──
    _save_results(results, posts, domain_map, output_dir)


def _save_results(results: list[dict], posts: list[dict],
                  domain_map: dict, output_dir: str):
    """Save all results to JSON files."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Clean results (remove internal keys)
    clean_results = []
    for r in results:
        clean = {k: v for k, v in r.items() if not k.startswith("_")}
        clean_results.append(clean)

    # Full results
    full_output = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "gtm_containers_analyzed": len(results),
        "active_containers": sum(1 for r in results if r["status"] == "active"),
        "x_posts_collected": len(posts),
        "posts": posts,
        "containers": clean_results,
        "domain_mapping": {
            domain: sorted(containers)
            for domain, containers in sorted(domain_map.items())
        },
    }

    outfile = os.path.join(output_dir, f"crawlgtm_{timestamp}.json")
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2, default=str)

    console.print(f"\n[bold green]💾 Results saved to {outfile}[/]")

    # GTM IDs only (for piping)
    ids_file = os.path.join(output_dir, f"gtm_ids_{timestamp}.txt")
    with open(ids_file, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['gtm_id']}\n")
    console.print(f"[green]💾 GTM IDs saved to {ids_file}[/]")

    # Domains only
    all_domains = set()
    for r in results:
        all_domains.update(r.get("domains", []))
    if all_domains:
        dom_file = os.path.join(output_dir, f"domains_{timestamp}.txt")
        with open(dom_file, "w", encoding="utf-8") as f:
            for d in sorted(all_domains):
                f.write(f"{d}\n")
        console.print(f"[green]💾 Domains saved to {dom_file}[/]")


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    if size_bytes == 0:
        return "0 B"
    for unit in ["B", "KB", "MB"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} GB"


# ──────────────────────────────────────────────────────────────────────
# Input helpers
# ──────────────────────────────────────────────────────────────────────

def load_gtm_ids_from_file(filepath: str) -> set[str]:
    """Load GTM IDs from a file (one per line, or mixed text)."""
    ids = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            for m in GTM_ID_PATTERN.finditer(content):
                ids.add(m.group(0).upper())
    except FileNotFoundError:
        console.print(f"[red]Error: File not found: {filepath}[/]")
    except Exception as e:
        console.print(f"[red]Error reading {filepath}: {e}[/]")
    return ids


def load_posts_from_file(filepath: str) -> list[dict]:
    """Load posts from a JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "posts" in data:
            return data["posts"]
        return []
    except FileNotFoundError:
        console.print(f"[red]Error: File not found: {filepath}[/]")
        return []
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON in {filepath}: {e}[/]")
        return []


# ──────────────────────────────────────────────────────────────────────
# Interactive URL scanner
# ──────────────────────────────────────────────────────────────────────

def scan_url_for_gtm(url: str) -> set[str]:
    """Scan a webpage for GTM container IDs."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    gtm_ids = set()

    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        if resp.status_code == 200:
            # Find GTM IDs in page source
            for m in GTM_ID_PATTERN.finditer(resp.text):
                gtm_ids.add(m.group(0).upper())

            # Also check for gtm.js script tags
            soup = BeautifulSoup(resp.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if "googletagmanager.com" in src:
                    for m in GTM_ID_PATTERN.finditer(src):
                        gtm_ids.add(m.group(0).upper())

    except Exception as e:
        console.print(f"[red]Error scanning {url}: {e}[/]")

    return gtm_ids


# ──────────────────────────────────────────────────────────────────────
# Scheduler - Background & periodic execution
# ──────────────────────────────────────────────────────────────────────

def load_history() -> dict:
    """Load processing history to avoid redoing work."""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            pass
    return {"seen_post_ids": [], "seen_gtm_ids": [], "runs": [], "total_domains_found": 0}


def save_history(history: dict):
    """Save processing history to disk."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def setup_logging():
    """Configure file logging for background mode."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("crawlgtm")
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)
    return logger


def _read_pid_file() -> Optional[int]:
    """Read PID from file, return None if invalid."""
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        PID_FILE.unlink(missing_ok=True)
        return None


def scheduler_status():
    """Show scheduler status."""
    pid = _read_pid_file()
    if pid is not None:
        try:
            os.kill(pid, 0)
            console.print(f"[bold green]✓ Scheduler running (PID {pid})[/]")
            if LOG_FILE.exists():
                lines = LOG_FILE.read_text().splitlines()
                if lines:
                    console.print(f"[dim]  Last log: {lines[-1]}[/]")
            if HISTORY_FILE.exists():
                h = load_history()
                console.print(f"[dim]  Posts seen: {len(h.get('seen_post_ids', []))}[/]")
                console.print(f"[dim]  GTMs processed: {len(h.get('seen_gtm_ids', []))}[/]")
                console.print(f"[dim]  Total runs: {len(h.get('runs', []))}[/]")
                console.print(f"[dim]  Total domains found: {h.get('total_domains_found', 0)}[/]")
            return True
        except OSError:
            PID_FILE.unlink(missing_ok=True)
    console.print("[yellow]No scheduler running[/]")
    return False


def stop_scheduler():
    """Stop background scheduler."""
    pid = _read_pid_file()
    if pid is not None:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            PID_FILE.unlink(missing_ok=True)
            console.print(f"[bold green]✓ Scheduler stopped (PID {pid})[/]")
            return True
        except OSError:
            PID_FILE.unlink(missing_ok=True)
            console.print("[yellow]Scheduler was not running (stale PID file removed)[/]")
            return False
    console.print("[yellow]No scheduler running[/]")
    return False


def run_scan(args, sm, history: dict, logger=None) -> dict:
    """Execute a single scan cycle. Returns updated history."""
    log = logger.info if logger else lambda m: console.print(f"[dim]  {m}[/]")

    seen_posts = set(history.get("seen_post_ids", []))
    seen_gtms = set(history.get("seen_gtm_ids", []))
    run_start = datetime.now(timezone.utc).isoformat()

    new_post_ids = []
    new_gtm_ids = []
    new_domains = 0

    # ── Session ──
    needs_xcom = bool(args.xuser or args.search)
    session_data = None
    if needs_xcom:
        session_data = sm.load()
        if not session_data:
            msg = "No X.com session available - skipping X.com collection"
            log(msg)
            if not any([args.gtm, args.file, args.posts_file, args.scan_url, getattr(args, "fofa", None)]):
                return history

    # ── Collect posts ──
    all_posts = []
    all_gtm_ids = set()

    if args.search:
        collector = XCollector(
            username=args.xuser,
            search_term=args.search,
            session_data=session_data,
        )
        posts = collector.collect()
        # Filter out already-seen posts
        fresh_posts = [p for p in posts if p.get("id", p.get("url", "")) not in seen_posts]
        log(f"Posts: {len(posts)} total, {len(fresh_posts)} new")
        new_post_ids.extend(p.get("id", p.get("url", "")) for p in fresh_posts)
        all_posts.extend(fresh_posts)
        texts = [p["text"] for p in fresh_posts]
        ids = extract_gtm_ids(texts)
        all_gtm_ids.update(ids)

    elif args.xuser:
        collector = XCollector(
            username=args.xuser,
            session_data=session_data,
        )
        posts = collector.collect()
        fresh_posts = [p for p in posts if p.get("id", p.get("url", "")) not in seen_posts]
        log(f"Posts: {len(posts)} total, {len(fresh_posts)} new")
        new_post_ids.extend(p.get("id", p.get("url", "")) for p in fresh_posts)
        all_posts.extend(fresh_posts)
        texts = [p["text"] for p in fresh_posts]
        ids = extract_gtm_ids(texts)
        all_gtm_ids.update(ids)

    # Direct GTM IDs
    if args.gtm:
        for gid in args.gtm:
            gid_clean = gid.upper().strip()
            if GTM_ID_PATTERN.fullmatch(gid_clean):
                all_gtm_ids.add(gid_clean)

    if args.file:
        all_gtm_ids.update(load_gtm_ids_from_file(args.file))

    if getattr(args, "posts_file", None):
        try:
            file_posts = load_posts_from_file(args.posts_file)
            all_posts.extend(file_posts)
            texts = [p.get("text", str(p)) for p in file_posts]
            ids = extract_gtm_ids(texts)
            all_gtm_ids.update(ids)
            log(f"Posts file: {len(ids)} GTM IDs from {len(file_posts)} posts")
        except Exception as e:
            log(f"Posts file error: {e}")

    if args.scan_url:
        for url in args.scan_url:
            all_gtm_ids.update(scan_url_for_gtm(url))

    # From FOFA
    if getattr(args, "fofa", None):
        fofa_key = load_fofa_key()
        if fofa_key:
            try:
                fofa = FofaCollector(
                    api_key=fofa_key,
                    max_pages=getattr(args, "fofa_pages", 5) or 5,
                )
                fofa_ids, _ = fofa.collect(
                    args.fofa,
                    scan_hosts=getattr(args, "fofa_scan", False),
                )
                all_gtm_ids.update(fofa_ids)
                log(f"FOFA: {len(fofa_ids)} GTM IDs found")
            except Exception as e:
                log(f"FOFA error: {e}")
        else:
            log("FOFA: no API key configured - skipping")

    # Filter out already-processed GTM IDs
    fresh_gtm_ids = all_gtm_ids - seen_gtms
    if not fresh_gtm_ids:
        log("No new GTM IDs to process")
        # Still save new post IDs
        history["seen_post_ids"] = list(seen_posts | set(new_post_ids))
        history["runs"].append({"ts": run_start, "new_posts": len(new_post_ids), "new_gtms": 0, "new_domains": 0})
        return history

    log(f"GTM IDs: {len(all_gtm_ids)} total, {len(fresh_gtm_ids)} new → {', '.join(sorted(fresh_gtm_ids))}")

    # ── Analyze ──
    if not logger:
        console.print(f"\n[bold]📋 New GTM IDs to analyze ({len(fresh_gtm_ids)}):[/]")
        for gid in sorted(fresh_gtm_ids):
            console.print(f"  [cyan]{gid}[/]")
        console.print()

    gtm_list = sorted(fresh_gtm_ids)
    results = asyncio.run(analyze_all_gtm_async(gtm_list))
    new_gtm_ids.extend(gtm_list)

    # Deep mode
    if args.deep:
        linked_ids = set()
        for r in results:
            for tid_list in r.get("tracking_ids", {}).values():
                for tid in tid_list:
                    if tid.startswith("GTM-") and tid not in all_gtm_ids and tid not in seen_gtms:
                        linked_ids.add(tid)
        if linked_ids:
            log(f"Deep mode: {len(linked_ids)} linked GTM containers")
            if not logger:
                console.print(f"\n[bold yellow]🔗 Deep mode: Found {len(linked_ids)} linked GTM containers[/]")
            linked_results = asyncio.run(analyze_all_gtm_async(sorted(linked_ids)))
            results.extend(linked_results)
            new_gtm_ids.extend(sorted(linked_ids))

    # ── Reverse lookup ──
    if args.reverse_lookup:
        bw_cookies = load_bw_session()
        if not bw_cookies and not logger:
            bw_cookies = ensure_bw_session()

        if bw_cookies:
            if not logger:
                console.print("\n[bold]🔄 Performing reverse lookups...[/]")
            lookup = GTMReverseLookup(builtwith_cookies=bw_cookies)
            for r in results:
                if r["status"] == "active":
                    log(f"Reverse lookup: {r['gtm_id']}")
                    if not logger:
                        console.print(f"  [cyan]Looking up {r['gtm_id']}...[/]")
                    sites = lookup.lookup(r["gtm_id"])
                    r["reverse_lookup_sites"] = sites
                    new_domains += len(sites)
                    if sites:
                        log(f"  {r['gtm_id']}: {len(sites)} sites found")
                        if not logger:
                            console.print(f"  [green]{r['gtm_id']}: found {len(sites)} sites[/]")
                            for s in sites[:10]:
                                console.print(f"    → {s['domain']} [dim]({s.get('source', '?')})[/]")
                    else:
                        log(f"  {r['gtm_id']}: no sites")
                        if not logger:
                            console.print(f"  [dim]{r['gtm_id']}: no sites found[/]")
        else:
            log("No BuiltWith session - skipping reverse lookup")

    # ── Output ──
    if not logger:
        render_results(results, all_posts, args.output)
    else:
        # Background: save JSON silently
        os.makedirs(args.output, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        clean = []
        for r in results:
            clean.append({k: v for k, v in r.items() if not k.startswith("_")})
        outfile = os.path.join(args.output, f"crawlgtm_{timestamp}.json")
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump({"containers": clean, "posts": all_posts}, f, indent=2, default=str)
        log(f"Results saved to {outfile}")

    # ── Telegram ──
    tg = TelegramNotifier() if args.telegram else None
    if tg and tg.is_configured:
        source = f"@{args.xuser}" if args.xuser else f"search: {args.search}" if args.search else "scan"
        if all_posts:
            tg.notify_posts(all_posts, source)
        tg.notify_results(results, all_posts, args.output)
        log("Telegram notification sent")

    # ── Update history ──
    history["seen_post_ids"] = list(seen_posts | set(new_post_ids))
    history["seen_gtm_ids"] = list(seen_gtms | set(new_gtm_ids))
    history["total_domains_found"] = history.get("total_domains_found", 0) + new_domains
    history["runs"].append({
        "ts": run_start,
        "new_posts": len(new_post_ids),
        "new_gtms": len(fresh_gtm_ids),
        "new_domains": new_domains,
    })

    return history


def run_scheduler(args, interval_seconds: int):
    """Run scan in a loop with given interval. Daemonizes to background."""
    # Validate sessions before daemonizing
    sm = SessionManager()
    needs_xcom = bool(args.xuser or args.search)
    if needs_xcom:
        session_data = sm.load()
        if not session_data:
            console.print("[red]✗ X.com session required. Run: python3 crawl_gtm.py --login[/]")
            sys.exit(1)

    if args.reverse_lookup:
        bw = load_bw_session()
        if not bw:
            console.print("[red]✗ BuiltWith session required. Run: python3 crawl_gtm.py --bw-login[/]")
            sys.exit(1)

    # Check if already running
    pid = _read_pid_file()
    if pid is not None:
        try:
            os.kill(pid, 0)
            console.print(f"[yellow]⚠ Scheduler already running (PID {pid}). Use --stop first.[/]")
            sys.exit(1)
        except OSError:
            PID_FILE.unlink(missing_ok=True)

    # Show plan
    if interval_seconds >= 86400:
        interval_str = f"{interval_seconds // 86400} day(s)"
    else:
        interval_str = f"{interval_seconds // 3600} hour(s)"

    console.print(Panel(
        f"[bold]Interval:[/] every {interval_str}\n"
        f"[bold]Source:[/] {'@' + args.xuser if args.xuser else args.search if args.search else 'offline'}\n"
        f"[bold]Deep:[/] {'yes' if args.deep else 'no'}\n"
        f"[bold]Reverse Lookup:[/] {'yes' if args.reverse_lookup else 'no'}\n"
        f"[bold]Telegram:[/] {'yes' if args.telegram else 'no'}\n"
        f"[bold]Log:[/] {LOG_FILE}\n"
        f"[bold]Stop:[/] python3 crawl_gtm.py --stop",
        title="[bold cyan]⏰ Starting Scheduler[/]",
        border_style="cyan",
    ))

    # Run first scan in foreground
    console.print("\n[bold]▶ Running initial scan...[/]\n")
    history = load_history()
    history = run_scan(args, sm, history)
    save_history(history)

    # Daemonize
    console.print(f"\n[bold cyan]🔄 Daemonizing... next scan in {interval_str}[/]")
    console.print(f"[dim]  PID file: {PID_FILE}[/]")
    console.print(f"[dim]  Log file: {LOG_FILE}[/]")
    console.print(f"[dim]  Stop: python3 crawl_gtm.py --stop[/]")
    console.print(f"[dim]  Status: python3 crawl_gtm.py --scheduler-status[/]")

    pid = os.fork()
    if pid > 0:
        # Parent exits
        console.print(f"[bold green]✓ Scheduler started (PID {pid})[/]")
        sys.exit(0)

    # Child: become daemon
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    # Redirect stdio to /dev/null for proper daemon behavior
    devnull_r = open(os.devnull, "r")
    devnull_w = open(os.devnull, "w")
    sys.stdin.close()
    sys.stdin = devnull_r
    sys.stdout.close()
    sys.stdout = devnull_w
    sys.stderr.close()
    sys.stderr = devnull_w

    # Write PID
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    # Setup logging
    logger = setup_logging()
    logger.info(f"Scheduler started (PID {os.getpid()}) - interval: {interval_str}")

    # Handle SIGTERM gracefully
    running = True

    def handle_sigterm(signum, frame):
        nonlocal running
        running = False
        logger.info("Received SIGTERM - shutting down")

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    # Daemon loop
    while running:
        try:
            # Sleep in small chunks to respond to SIGTERM quickly
            for _ in range(interval_seconds):
                if not running:
                    break
                time.sleep(1)

            if not running:
                break

            logger.info("=" * 50)
            logger.info("Starting scheduled scan")

            history = load_history()
            history = run_scan(args, sm, history, logger=logger)
            save_history(history)

            run = history["runs"][-1] if history["runs"] else {}
            logger.info(
                f"Scan complete: {run.get('new_posts', 0)} new posts, "
                f"{run.get('new_gtms', 0)} new GTMs, "
                f"{run.get('new_domains', 0)} new domains"
            )
        except Exception as e:
            logger.error(f"Scan error: {e}")
            time.sleep(60)  # Wait a bit before retrying

    PID_FILE.unlink(missing_ok=True)
    logger.info("Scheduler stopped")


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    # ── CTI Monitoring Banner (random color on each run) ──
    _themes = [
        {"accent": "cyan",    "glow": "bold cyan",    "dim_accent": "dim cyan"},
        {"accent": "red",     "glow": "bold red",     "dim_accent": "dim red"},
        {"accent": "green",   "glow": "bold green",   "dim_accent": "dim green"},
        {"accent": "magenta", "glow": "bold magenta", "dim_accent": "dim magenta"},
        {"accent": "yellow",  "glow": "bold yellow",  "dim_accent": "dim yellow"},
        {"accent": "blue",    "glow": "bold blue",    "dim_accent": "dim blue"},
    ]
    _t = random.choice(_themes)
    _a, _g, _d = _t["accent"], _t["glow"], _t["dim_accent"]
    _now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    _logo_text = (
        "                         _ _____ _____ __  __\n"
        "  ___ _ __ __ ___      _| |  ___|_   _|  \\/  |\n"
        " / __| '__/ _` \\\\ \\\\ /\\\\ / / | |_ __| | | |\\/| |\n"
        "| (__| | | (_| |\\\\ V  V /| |  _|  | | | |  | |\n"
        " \\___|_|  \\__,_| \\_/\\_/ |_|_|    |_| |_|  |_|"
    )
    _logo = f"[{_g}]{_logo_text}[/]"

    _status_line = (
        f"  [{_a}]STATUS[/] [bold white]ONLINE[/]"
        f"  [{_d}]|[/]  [{_a}]MODE[/] [bold white]CTI RECON[/]"
        f"  [{_d}]|[/]  [{_a}]TIME[/] [bold white]{_now}[/]"
    )

    _pipeline = (
        f"  [{_d}]01[/] [{_a}]COLLECT[/] [dim]X.com / FOFA / URLs[/]\n"
        f"  [{_d}]02[/] [{_a}]ANALYZE[/] [dim]GTM Containers / JS Payloads[/]\n"
        f"  [{_d}]03[/] [{_a}]TRACK[/]   [dim]Pixels / GA / Meta / TikTok[/]\n"
        f"  [{_d}]04[/] [{_a}]MAP[/]     [dim]Domains / Reverse Lookup / WHOIS[/]\n"
        f"  [{_d}]05[/] [{_a}]DETECT[/]  [dim]Skimmers / Malware / IOCs[/]"
    )

    _sources = (
        f"  [{_a}]INTEL[/]  "
        f"[dim]FOFA[/] [{_d}]/[/] [dim]BuiltWith[/] [{_d}]/[/] "
        f"[dim]PublicWWW[/] [{_d}]/[/] [dim]SpyOnWeb[/] [{_d}]/[/] "
        f"[dim]Wayback[/] [{_d}]/[/] [dim]X.com[/]"
    )

    banner = Panel(
        f"{_logo}\n\n{_status_line}\n\n{_pipeline}\n\n{_sources}",
        title=f"[{_g}]crawlGTM[/] [{_d}]v4.0[/]",
        subtitle=f"[{_d}]Cyber Threat Intelligence[/] [{_a}]|[/] [{_d}]GTM Reconnaissance Platform[/]",
        border_style=_a,
        padding=(1, 2),
    )
    console.print(banner)

    # ── First Run Setup Wizard ──
    if is_first_run():
        first_run_wizard()

    parser = argparse.ArgumentParser(
        description="crawlGTM - Google Tag Manager OSINT & Recon Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First run - setup X.com session
  %(prog)s --login

  # Search X.com for GTM-related posts
  %(prog)s --search "magecart GTM"

  # Collect from a specific X.com user
  %(prog)s --xuser sdcyberresearch

  # Analyze specific GTM IDs
  %(prog)s --gtm GTM-XXXXXXX GTM-YYYYYYY --deep

  # Scan a website to find its GTM IDs
  %(prog)s --scan-url https://example.com --deep

  # Reverse lookup: find which domains use a GTM container
  %(prog)s --gtm GTM-XXXXXXX --reverse-lookup

  # Load GTM IDs from file
  %(prog)s --file gtm_ids.txt --deep

  # Search FOFA for GTM containers on a domain
  %(prog)s --fofa 'domain="example.com"' --deep
  %(prog)s --fofa 'org="Company Name"' --deep --reverse-lookup
  %(prog)s --fofa 'body="GTM-"' --fofa-pages 10

  # Full flow: X.com → GTM → BuiltWith reverse lookup
  %(prog)s --xuser sdcyberresearch --deep --reverse-lookup

  # Background scheduler (runs first scan, then daemonizes):
  %(prog)s --xuser sdcyberresearch --deep --reverse-lookup --hours 1
  %(prog)s --xuser sdcyberresearch --deep --reverse-lookup --days 1
  %(prog)s --stop                    # Stop background scheduler
  %(prog)s --scheduler-status        # Check if running
  %(prog)s --clear-history           # Reset (re-scan everything)

  # Setup sessions (run once):
  %(prog)s --login                    # X.com cookies
  %(prog)s --bw-login                 # BuiltWith cookies
        """,
    )

    # Session management
    session_group = parser.add_argument_group("Session Management")
    session_group.add_argument(
        "--login",
        action="store_true",
        help="Set up X.com session (enter cookies from browser)",
    )
    session_group.add_argument(
        "--logout",
        action="store_true",
        help="Clear saved X.com session",
    )
    session_group.add_argument(
        "--session-status",
        action="store_true",
        help="Check if saved X.com session is valid",
    )
    session_group.add_argument(
        "--bw-login",
        action="store_true",
        help="Set up BuiltWith.com session (enter cookies from browser)",
    )
    session_group.add_argument(
        "--fofa-setup",
        action="store_true",
        help="Set up FOFA API key (for GTM discovery via fofa.info)",
    )
    session_group.add_argument(
        "--telegram-setup",
        action="store_true",
        help="Configure Telegram bot for notifications",
    )

    # Input sources
    input_group = parser.add_argument_group("Input Sources")
    input_group.add_argument(
        "--xuser", "-x",
        help="X.com username to collect GTM posts from (e.g., sdcyberresearch)",
    )
    input_group.add_argument(
        "--search", "-s",
        help="Search X.com for posts matching this term (e.g., 'magecart GTM')",
    )
    input_group.add_argument(
        "--gtm", "-g",
        nargs="+",
        help="GTM container IDs to analyze directly (e.g., GTM-XXXXXXX)",
    )
    input_group.add_argument(
        "--file", "-f",
        help="File containing GTM IDs (one per line or mixed text)",
    )
    input_group.add_argument(
        "--posts-file",
        help="JSON file containing posts to parse for GTM IDs",
    )
    input_group.add_argument(
        "--scan-url", "-u",
        nargs="+",
        help="URLs to scan for GTM container IDs",
    )
    input_group.add_argument(
        "--fofa",
        help='FOFA search query to discover GTM IDs (e.g., \'domain="example.com"\', \'org="Company"\', \'body="GTM-"\')',
    )
    input_group.add_argument(
        "--fofa-pages",
        type=int,
        default=5,
        metavar="N",
        help="Max pages to fetch from FOFA (default: 5, 100 results/page)",
    )
    input_group.add_argument(
        "--fofa-scan",
        action="store_true",
        help="Also scan FOFA-discovered hosts for additional GTM IDs",
    )

    # Analysis options
    analysis_group = parser.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--reverse-lookup", "-r",
        action="store_true",
        help="Perform reverse lookup to find websites using each GTM ID",
    )
    analysis_group.add_argument(
        "--deep",
        action="store_true",
        help="Deep analysis: also analyze linked GTM containers found inside containers",
    )
    analysis_group.add_argument(
        "--bw-cookies",
        help="BuiltWith session cookies as JSON string (or 'save' to enter interactively)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory (default: output)",
    )
    output_group.add_argument(
        "--json-only",
        action="store_true",
        help="Only output JSON, no rich terminal output",
    )
    output_group.add_argument(
        "--telegram", "-t",
        action="store_true",
        help="Send results to Telegram (configure with --telegram-setup first)",
    )

    # Scheduler options
    sched_group = parser.add_argument_group("Scheduler (Background)")
    sched_group.add_argument(
        "--hours",
        type=int,
        metavar="N",
        help="Run in background, repeat every N hours (max 12)",
    )
    sched_group.add_argument(
        "--days",
        type=int,
        metavar="N",
        help="Run in background, repeat every N days (max 5)",
    )
    sched_group.add_argument(
        "--stop",
        action="store_true",
        help="Stop the background scheduler",
    )
    sched_group.add_argument(
        "--scheduler-status",
        action="store_true",
        help="Show scheduler status",
    )
    sched_group.add_argument(
        "--clear-history",
        action="store_true",
        help="Clear processing history (re-scan everything)",
    )

    args = parser.parse_args()

    sm = SessionManager()

    # ── Scheduler commands ──
    if args.stop:
        stop_scheduler()
        return

    if args.scheduler_status:
        scheduler_status()
        return

    if args.clear_history:
        if HISTORY_FILE.exists():
            HISTORY_FILE.unlink()
            console.print("[green]✓ History cleared - next scan will process everything[/]")
        else:
            console.print("[yellow]No history to clear[/]")
        return

    # Validate --hours / --days
    if args.hours and args.days:
        console.print("[red]✗ Use --hours OR --days, not both[/]")
        sys.exit(1)

    if args.hours is not None:
        if args.hours < 1 or args.hours > 12:
            console.print("[red]✗ --hours must be between 1 and 12[/]")
            sys.exit(1)

    if args.days is not None:
        if args.days < 1 or args.days > 5:
            console.print("[red]✗ --days must be between 1 and 5[/]")
            sys.exit(1)

    # ── Standalone session commands ──
    if args.login:
        sm.prompt_login()
        return

    if args.logout:
        sm.clear()
        return

    if args.session_status:
        saved = sm.load()
        if saved:
            valid, username = sm.validate(saved["auth_token"], saved["ct0"])
            if valid:
                console.print(f"[bold green]✓ X.com session active (@{username})[/]")
            else:
                console.print("[yellow]⚠ X.com session expired[/]")
        else:
            console.print("[yellow]No X.com session saved[/]")
        bw = load_bw_session()
        if bw:
            if validate_bw_session(bw):
                console.print("[bold green]✓ BuiltWith session active[/]")
            else:
                console.print("[yellow]⚠ BuiltWith session expired[/]")
        else:
            console.print("[yellow]No BuiltWith session saved[/]")
        fofa_key = load_fofa_key()
        if fofa_key:
            if validate_fofa_key(fofa_key):
                console.print(f"[bold green]✓ FOFA API key active ({fofa_key[:8]}...)[/]")
            else:
                console.print("[yellow]⚠ FOFA API key invalid or expired[/]")
        else:
            console.print("[yellow]No FOFA API key saved[/]")
        return

    if args.bw_login:
        prompt_bw_login()
        return

    if args.fofa_setup:
        prompt_fofa_setup()
        return

    if args.telegram_setup:
        tg = TelegramNotifier()
        tg.setup()
        return

    # Init Telegram if requested
    tg = TelegramNotifier() if args.telegram else None
    if args.telegram and not (tg and tg.is_configured):
        console.print("[yellow]⚠ Telegram not configured. Run: python3 crawl_gtm.py --telegram-setup[/]")
        tg = None

    # ── Validate inputs ──
    needs_xcom = bool(args.xuser or args.search)
    has_offline_input = any([args.gtm, args.file, args.posts_file, args.scan_url, args.fofa])

    if not needs_xcom and not has_offline_input:
        parser.print_help()
        console.print("\n[red]Error: Provide at least one input source[/]")
        sys.exit(1)

    # ── Scheduler mode: run_scheduler handles everything ──
    if args.hours or args.days:
        interval = args.hours * 3600 if args.hours else args.days * 86400
        run_scheduler(args, interval)
        return  # run_scheduler exits after daemonizing

    # ── Auto-prompt X.com session if needed ──
    session_data = None
    if needs_xcom:
        session_data = sm.ensure_session()
        if not session_data:
            console.print("[yellow]⚠ Continuing without X.com session (fallback methods only).[/]")

    # ── Collect GTM IDs ──
    all_gtm_ids = set()
    all_posts = []

    # From X.com search
    if args.search:
        collector = XCollector(
            username=args.xuser,  # optional: narrow search to user
            search_term=args.search,
            session_data=session_data,
        )
        posts = collector.collect()
        all_posts.extend(posts)
        texts = [p["text"] for p in posts]
        ids = extract_gtm_ids(texts)
        if ids:
            console.print(f"[green]✓ Found {len(ids)} GTM IDs from search: {', '.join(sorted(ids))}[/]")
        all_gtm_ids.update(ids)
        if tg and posts:
            tg.notify_posts(posts, f"search: {args.search}")

    # From X.com user timeline
    elif args.xuser:
        collector = XCollector(
            username=args.xuser,
            session_data=session_data,
        )
        posts = collector.collect()
        all_posts.extend(posts)
        texts = [p["text"] for p in posts]
        ids = extract_gtm_ids(texts)
        if ids:
            console.print(f"[green]✓ Found {len(ids)} GTM IDs from X.com posts: {', '.join(sorted(ids))}[/]")
        all_gtm_ids.update(ids)
        if tg and posts:
            tg.notify_posts(posts, f"@{args.xuser}")

    # From direct GTM IDs
    if args.gtm:
        for gid in args.gtm:
            gid_clean = gid.upper().strip()
            if GTM_ID_PATTERN.fullmatch(gid_clean):
                all_gtm_ids.add(gid_clean)
            else:
                console.print(f"[yellow]⚠ Invalid GTM ID format: {gid}[/]")

    # From file
    if args.file:
        file_ids = load_gtm_ids_from_file(args.file)
        console.print(f"[green]✓ Loaded {len(file_ids)} GTM IDs from {args.file}[/]")
        all_gtm_ids.update(file_ids)

    # From posts file
    if args.posts_file:
        file_posts = load_posts_from_file(args.posts_file)
        all_posts.extend(file_posts)
        texts = [p.get("text", str(p)) for p in file_posts]
        ids = extract_gtm_ids(texts)
        console.print(f"[green]✓ Found {len(ids)} GTM IDs from posts file[/]")
        all_gtm_ids.update(ids)

    # From URL scanning
    if args.scan_url:
        for url in args.scan_url:
            console.print(f"[cyan]🔍 Scanning {url}...[/]")
            url_ids = scan_url_for_gtm(url)
            if url_ids:
                console.print(f"[green]✓ Found {len(url_ids)} GTM IDs on {url}: {', '.join(sorted(url_ids))}[/]")
            else:
                console.print(f"[yellow]  No GTM IDs found on {url}[/]")
            all_gtm_ids.update(url_ids)

    # From FOFA search
    if args.fofa:
        fofa_key = load_fofa_key()
        if not fofa_key:
            console.print("[yellow]⚠ FOFA API key not configured. Using web scraper...[/]")
        if fofa_key:
            console.print(f"\n[bold]🔍 FOFA API: Searching for GTM containers...[/]")
            fofa = FofaCollector(
                api_key=fofa_key,
                max_pages=args.fofa_pages,
            )
            fofa_gtm_ids, fofa_hosts = fofa.collect(
                args.fofa,
                scan_hosts=args.fofa_scan,
            )
            new_from_fofa = fofa_gtm_ids - all_gtm_ids
            if fofa_gtm_ids:
                console.print(
                    f"[green]✓ FOFA: {len(fofa_gtm_ids)} GTM IDs total, "
                    f"{len(new_from_fofa)} new: {', '.join(sorted(new_from_fofa)[:20])}"
                    f"{'...' if len(new_from_fofa) > 20 else ''}[/]"
                )
            all_gtm_ids.update(fofa_gtm_ids)
        else:
            # No API key - use web scraper
            console.print(f"\n[bold]🔍 FOFA Web: Searching for GTM containers...[/]")
            query = args.fofa
            query_lower = query.lower()
            if "gtm" not in query_lower and "googletagmanager" not in query_lower:
                fofa_query = f'{query} && "googletagmanager"'
            else:
                fofa_query = query
            web_results = fofa_web_search(fofa_query, max_pages=1)
            fofa_hosts = []
            for r in web_results:
                url = r.get("url", "")
                if url:
                    fofa_hosts.append(url)
            if fofa_hosts and args.fofa_scan:
                console.print(f"[cyan]  Scanning {len(fofa_hosts)} FOFA hosts for GTM IDs...[/]")
                for host_url in fofa_hosts:
                    try:
                        host_gtms = scan_url_for_gtm(host_url)
                        if host_gtms:
                            new_gtms = host_gtms - all_gtm_ids
                            all_gtm_ids.update(host_gtms)
                            if new_gtms:
                                console.print(
                                    f"    [green]+{len(new_gtms)} GTM IDs from {host_url}: "
                                    f"{', '.join(sorted(new_gtms)[:5])}[/]"
                                )
                    except Exception:
                        pass
            elif fofa_hosts and not args.fofa_scan:
                console.print(
                    f"[yellow]  Tip: Use --fofa-scan to scan the {len(fofa_hosts)} "
                    f"discovered hosts for GTM IDs[/]"
                )

    # ── Analyze containers ──
    if not all_gtm_ids:
        console.print("\n[red]No GTM IDs found to analyze.[/]")
        console.print("[dim]Tips:[/]")
        console.print("[dim]  - Provide IDs directly: --gtm GTM-XXXXXXX[/]")
        console.print("[dim]  - Scan a URL: --scan-url https://example.com[/]")
        console.print("[dim]  - Search FOFA: --fofa 'body=\"GTM-\"'[/]")
        console.print("[dim]  - Provide a file: --file gtm_ids.txt[/]")
        sys.exit(0)

    console.print(f"\n[bold]📋 GTM IDs to analyze ({len(all_gtm_ids)}):[/]")
    for gid in sorted(all_gtm_ids):
        console.print(f"  [cyan]{gid}[/]")

    # Run async analysis
    console.print()
    gtm_list = sorted(all_gtm_ids)
    results = asyncio.run(analyze_all_gtm_async(gtm_list))

    # Deep mode: find and analyze linked GTM containers
    if args.deep:
        linked_ids = set()
        for r in results:
            for tid_list in r.get("tracking_ids", {}).values():
                for tid in tid_list:
                    if tid.startswith("GTM-") and tid not in all_gtm_ids:
                        linked_ids.add(tid)

        if linked_ids:
            console.print(
                f"\n[bold yellow]🔗 Deep mode: Found {len(linked_ids)} linked GTM containers[/]"
            )
            linked_results = asyncio.run(analyze_all_gtm_async(sorted(linked_ids)))
            results.extend(linked_results)

    # ── Reverse lookup with auto BuiltWith session ──
    if args.reverse_lookup:
        # Handle --bw-cookies CLI arg
        bw_cookies = {}
        if getattr(args, "bw_cookies", None):
            try:
                bw_cookies = _parse_bw_cookies(args.bw_cookies)
                save_bw_session(bw_cookies)
            except (json.JSONDecodeError, Exception):
                pass

        # Auto-prompt: load/validate/prompt BuiltWith session
        if not bw_cookies:
            bw_cookies = ensure_bw_session()

        console.print("\n[bold]🔄 Performing reverse lookups...[/]")
        lookup = GTMReverseLookup(builtwith_cookies=bw_cookies)

        first_empty = True
        for r in results:
            if r["status"] == "active":
                console.print(f"  [cyan]Looking up {r['gtm_id']}...[/]")
                sites = lookup.lookup(r["gtm_id"])
                r["reverse_lookup_sites"] = sites
                if sites:
                    first_empty = False
                    console.print(
                        f"  [green]{r['gtm_id']}: "
                        f"found {len(sites)} sites[/]"
                    )
                    for s in sites[:10]:
                        console.print(f"    → {s['domain']} [dim]({s.get('source', '?')})[/]")
                else:
                    console.print(f"  [dim]{r['gtm_id']}: no sites found[/]")

                    # If first lookup returns nothing and we have cookies,
                    # session might be expired → retry with new cookies
                    if first_empty and bw_cookies:
                        console.print("[dim]  Checking if BuiltWith session is still valid...[/]")
                        if not validate_bw_session(bw_cookies):
                            console.print("[yellow]  ⚠ BuiltWith session expired! Requesting new cookies...[/]")
                            bw_cookies = prompt_bw_login()
                            if bw_cookies:
                                lookup = GTMReverseLookup(builtwith_cookies=bw_cookies)
                                # Retry this container
                                sites = lookup.lookup(r["gtm_id"])
                                r["reverse_lookup_sites"] = sites
                                if sites:
                                    console.print(
                                        f"  [green]{r['gtm_id']}: "
                                        f"found {len(sites)} sites[/]"
                                    )
                                    for s in sites[:10]:
                                        console.print(f"    → {s['domain']} [dim]({s.get('source', '?')})[/]")
                    first_empty = False

    # ── Output ──
    if not args.json_only:
        render_results(results, all_posts, args.output)
    else:
        # JSON only output
        os.makedirs(args.output, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        clean = []
        for r in results:
            clean.append({k: v for k, v in r.items() if not k.startswith("_")})
        outfile = os.path.join(args.output, f"crawlgtm_{timestamp}.json")
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump({"containers": clean, "posts": all_posts}, f, indent=2, default=str)
        print(outfile)

    # Stats
    active = sum(1 for r in results if r["status"] == "active")
    total_domains = set()
    total_services = set()
    for r in results:
        total_domains.update(r.get("domains", []))
        total_services.update(r.get("services_detected", []))

    console.print(Panel(
        f"[bold]Containers:[/] {len(results)} analyzed, {active} active\n"
        f"[bold]Domains:[/] {len(total_domains)} unique domains found\n"
        f"[bold]Services:[/] {len(total_services)} third-party services detected\n"
        f"[bold]Posts:[/] {len(all_posts)} X.com posts collected",
        title="[bold green]✅ Scan Complete[/]",
        border_style="green",
    ))

    # ── Telegram notification ──
    if tg:
        console.print("\n[cyan]📨 Sending results to Telegram...[/]")
        tg.notify_results(results, all_posts, args.output)


if __name__ == "__main__":
    main()
