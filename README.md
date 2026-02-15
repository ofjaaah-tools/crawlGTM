<p align="center">
  <img src="assets/banner.svg" alt="crawlGTM Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/version-3.0-7b2ff7.svg" alt="v3.0">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/scheduler-background-purple.svg" alt="Background Scheduler">
  <img src="https://img.shields.io/badge/reverse--lookup-BuiltWith-ff0080.svg" alt="BuiltWith">
  <img src="https://img.shields.io/badge/FOFA-integrated-orange.svg" alt="FOFA">
  <img src="https://img.shields.io/badge/bugs--fixed-17-00d4ff.svg" alt="17 bugs fixed">
</p>

# crawlGTM

**Google Tag Manager OSINT & Reconnaissance Tool**

Automated pipeline to collect malicious GTM container IDs from X.com (Twitter) security researchers and FOFA search engine, analyze the container JavaScript, perform reverse lookups via BuiltWith + FOFA to discover victim domains, and run on a background scheduler to continuously monitor for new threats.

---

## Flow

```
X.com Posts ─┐
FOFA Search ─┼─> Extract GTM IDs --> Analyze Containers --> Reverse Lookup --> Victim Domains
File / URL  ─┘        |                    |                     |                  |
                      v                    v                     v                  v
                 GTM-XXXXXXX        Domains, Scripts,     BuiltWith + FOFA +    RED output
                 Regex + Deep       Pixels, Services      5 OSINT sources       JSON + TXT
```

---

## Features

- **X.com Collection** -- Authenticated GraphQL API with dynamic query ID + feature extraction from JS bundle
- **Multi-source Fallback** -- GraphQL -> Wayback Machine -> Nitter -> Google cache (automatic fallback chain)
- **Multi-input** -- X.com user timeline, search, direct GTM IDs, file, posts JSON, URL scanning, FOFA search
- **FOFA Integration** -- Search FOFA (fofa.info) for GTM containers by domain, org, or keyword; auto-scan discovered hosts
- **Container Analysis** -- Domains, URLs, scripts, pixels, tracking IDs (GA4/UA/AW/GTM), 30+ service signatures, custom HTML tags, dataLayer vars, interesting strings (API keys, webhooks, emails)
- **Deep Mode** -- Follows linked GTM containers found inside other containers (chain analysis)
- **Reverse Lookup** -- 7 sources: BuiltWith, PublicWWW, SpyOnWeb, Wayback CDX, DuckDuckGo, Google, FOFA
- **Async Analysis** -- Parallel container fetching via `aiohttp` + `asyncio`
- **Background Scheduler** -- `--hours N` (1-12) or `--days N` (1-5), daemonizes after first scan
- **Deduplication** -- Tracks processed posts and GTM IDs across runs, never re-scans what was already done
- **Telegram Notifications** -- Send results + files to Telegram bot automatically
- **First Run Wizard** -- Interactive setup on first launch: configures X.com, BuiltWith, FOFA, and Telegram
- **Session Management** -- Auto-prompt for X.com / BuiltWith / FOFA sessions, auto-detect expiry, re-prompt

---

## Installation

```bash
git clone https://github.com/ofjaaah-tools/crawlGTM.git
cd crawlGTM
pip install -r requirements.txt
```

### Dependencies

```
requests>=2.28.0
aiohttp>=3.8.0
beautifulsoup4>=4.11.0
rich>=13.0.0
```

---

## Quick Start

```bash
# 1. First run - interactive setup wizard (X.com, BuiltWith, FOFA, Telegram)
python3 crawl_gtm.py --gtm GTM-XXXXXXX
# On first launch, the wizard will guide you through configuring all sessions.

# 2. Analyze specific GTM IDs with deep chain analysis
python3 crawl_gtm.py --gtm GTM-KX36TXD --deep

# 3. Scan a website for GTM containers
python3 crawl_gtm.py --scan-url https://example.com --deep

# 4. Search FOFA for GTM containers
python3 crawl_gtm.py --fofa 'domain="example.com"' --deep --fofa-scan

# 5. Load GTM IDs from file
python3 crawl_gtm.py --file gtm_ids.txt --deep

# 6. Full flow: X.com -> Deep Analysis -> Reverse Lookup
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup
```

---

## Session Setup

On **first run**, an interactive setup wizard guides you through configuring all integrations (X.com, BuiltWith, FOFA, Telegram). You can skip any step and configure later.

You can also set up each session individually:

### 1. X.com Session

#### Extract cookies from browser

1. Open **https://x.com** and log in
2. Press **F12** -> DevTools
3. Go to **Application** -> **Cookies** -> **https://x.com**

**`auth_token`** is HttpOnly -- you MUST copy it manually from DevTools:

> **F12 -> Application -> Cookies -> x.com -> auth_token** (double-click value -> copy)

**`ct0`** can be extracted via Console:

```javascript
(function() {
  var ct0 = '';
  document.cookie.split(';').forEach(function(c) {
    var p = c.trim().split('=');
    if (p[0] === 'ct0') ct0 = p.slice(1).join('=');
  });
  console.log('%c ct0 = ' + ct0, 'color:lime;font-size:14px');
  prompt('ct0 (Ctrl+A, Ctrl+C):', ct0);
})();
```

#### Save session

```bash
python3 crawl_gtm.py --login
# Paste auth_token and ct0 when prompted
```

Session is saved to `~/.crawlgtm/session.json` and reused automatically.

---

### 2. BuiltWith Session (for reverse lookup)

1. Open **https://builtwith.com** and log in (Pro/Team account)
2. Press **F12** -> **Application** -> **Cookies**

```javascript
(function() {
  var found = {};
  document.cookie.split(';').forEach(function(c) {
    var parts = c.trim().split('=');
    var k = parts[0];
    var v = parts.slice(1).join('=');
    if (k === 'g_state' || k === 'BWSSON') found[k] = v;
  });
  found['ASP.NET_SessionId'] = 'PASTE_FROM_DEVTOOLS';
  prompt('Copy JSON:', JSON.stringify(found, null, 2));
})();
```

```bash
python3 crawl_gtm.py --bw-login
# Paste JSON, then ASP.NET_SessionId separately
```

---

### 3. FOFA API Key (for GTM discovery)

1. Go to **https://en.fofa.info/** and create an account
2. Navigate to your **Profile** -> **API Key**
3. Copy your API key

```bash
python3 crawl_gtm.py --fofa-setup
# Paste your FOFA API key when prompted
```

Key is saved to `~/.crawlgtm/fofa.json`.

---

### Session Management

```bash
python3 crawl_gtm.py --session-status   # Check all sessions (X.com, BuiltWith, FOFA)
python3 crawl_gtm.py --login            # Re-login X.com
python3 crawl_gtm.py --bw-login         # Re-login BuiltWith
python3 crawl_gtm.py --fofa-setup       # Re-configure FOFA API key
python3 crawl_gtm.py --logout           # Clear X.com session
```

> **Auto-prompt:** If a session expires mid-scan, the tool detects the failure and asks for new cookies/keys.

---

## Usage

### Collect from X.com

```bash
# User timeline
python3 crawl_gtm.py --xuser sdcyberresearch

# Search X.com
python3 crawl_gtm.py --search "magecart GTM skimmer"

# Combined: search within a user's posts
python3 crawl_gtm.py --xuser sdcyberresearch --search "magecart"
```

### Analyze specific GTM IDs

```bash
# Single ID
python3 crawl_gtm.py --gtm GTM-XXXXXXX --deep --reverse-lookup

# Multiple IDs
python3 crawl_gtm.py --gtm GTM-XXXXXXX GTM-YYYYYYY GTM-ZZZZZZZ --deep

# From file (one per line or mixed text)
python3 crawl_gtm.py --file gtm_ids.txt --deep --reverse-lookup

# From JSON posts file
python3 crawl_gtm.py --posts-file collected_posts.json --deep
```

### Scan websites

```bash
python3 crawl_gtm.py --scan-url https://example.com --deep
python3 crawl_gtm.py --scan-url https://site1.com https://site2.com
```

### FOFA search

```bash
# Search by domain
python3 crawl_gtm.py --fofa 'domain="example.com"' --deep --fofa-scan

# Search by organization
python3 crawl_gtm.py --fofa 'org="Company Name"' --deep --reverse-lookup

# Broad GTM discovery (finds pages with GTM in HTTP headers)
python3 crawl_gtm.py --fofa 'header="GTM-"' --fofa-pages 3 --fofa-scan

# Custom FOFA dork
python3 crawl_gtm.py --fofa '"googletagmanager.com/gtm.js"' --fofa-pages 5 --fofa-scan
```

`--fofa-scan` scans the discovered hosts to extract GTM IDs from their HTML (recommended).
`--fofa-pages N` controls pagination (default: 5 pages, 100 results/page).

### Full flow

```bash
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup
```

This will:
1. Collect posts from `@sdcyberresearch` containing GTM IDs
2. Analyze each GTM container (domains, scripts, pixels, services)
3. Follow linked containers found inside (deep mode chain analysis)
4. Reverse lookup each container across 7 OSINT sources (including FOFA)
5. Output everything with victim domains highlighted in **RED**

---

## Background Scheduler

Run the tool periodically in background. It daemonizes after the first scan and only processes **new** posts and GTM IDs (deduplication via `~/.crawlgtm/history.json`).

```bash
# Every 1 hour
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --hours 1

# Every 6 hours with Telegram
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --hours 6 --telegram

# Every 1 day
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --days 1
```

### Management

```bash
python3 crawl_gtm.py --scheduler-status  # Check if running
python3 crawl_gtm.py --stop              # Stop scheduler
python3 crawl_gtm.py --clear-history     # Reset (re-scan everything)
```

| Flag | Range |
|------|-------|
| `--hours N` | 1-12 |
| `--days N` | 1-5 |

### How deduplication works

```
Run 1: 8 posts found -> 7 GTM IDs -> 76 victim domains -> saved to history
Run 2: 8 posts found -> 0 new     -> "No new GTM IDs to process" -> skip
Run 3: 9 posts found -> 1 new     -> analyze only the new one
```

Logs: `~/.crawlgtm/scheduler.log`

---

## Telegram Notifications

```bash
python3 crawl_gtm.py --telegram-setup                                    # Configure bot
python3 crawl_gtm.py --xuser sdcyberresearch --deep --telegram           # Run with alerts
python3 crawl_gtm.py --xuser sdcyberresearch --deep --hours 1 --telegram # Scheduler + alerts
```

Setup: **@BotFather** -> `/newbot` -> copy token -> send message to bot -> get chat_id from `getUpdates`

---

## Output

Results are saved to `output/` (configurable with `--output`):

| File | Content |
|------|---------|
| `crawlgtm_TIMESTAMP.json` | Full analysis results (containers + posts + domain mapping) |
| `gtm_ids_TIMESTAMP.txt` | GTM IDs found (one per line, pipe-friendly) |
| `domains_TIMESTAMP.txt` | All domains extracted (one per line) |

### Container extraction details

| Data | Description |
|------|-------------|
| **Status** | active / not_found / error |
| **Domains** | All domains referenced in the container JS (TLD-validated) |
| **URLs** | Full URLs found in the container |
| **Scripts** | External .js files loaded by the container |
| **Pixels** | Tracking pixel URLs (Facebook, Google, etc.) |
| **Tracking IDs** | GA4 (G-xxx), UA (UA-xxx), AW (AW-xxx), linked GTMs |
| **Services** | 30+ service signatures (Google Analytics, Facebook Pixel, Hotjar, Stripe, Clarity, HubSpot, etc.) |
| **Custom HTML** | Custom HTML tags (potential injection points for Magecart) |
| **DataLayer Vars** | dataLayer variables referenced |
| **Interesting** | API keys, webhooks, emails, base64 blobs |
| **Container Version** | Version number for change tracking |
| **Reverse Lookup** | Victim domains from BuiltWith + 5 other OSINT sources |

### JSON structure

```json
{
  "scan_date": "2026-02-15T11:45:24+00:00",
  "gtm_containers_analyzed": 2,
  "active_containers": 2,
  "x_posts_collected": 0,
  "containers": [
    {
      "gtm_id": "GTM-KX36TXD",
      "status": "active",
      "raw_size": 317891,
      "domains": ["ve-interactive.cn", "veinteractive.com", "..."],
      "tracking_ids": {"GTM": ["GTM-WL9BCSS"], "GA4": ["G-ASSISTANT"]},
      "services_detected": ["google-analytics", "google-ads"],
      "scripts_loaded": ["https://cct.google/taggy/agent.js"],
      "reverse_lookup_sites": [
        {"domain": "victim-shop.com", "source": "builtwith"},
        {"domain": "another-site.co.uk", "source": "publicwww"}
      ]
    }
  ],
  "domain_mapping": {"ve-interactive.cn": ["GTM-KX36TXD", "GTM-WL9BCSS"]}
}
```

---

## Files

```
~/.crawlgtm/
  session.json              # X.com cookies (auth_token + ct0)
  builtwith_session.json    # BuiltWith cookies
  telegram.json             # Telegram bot config
  history.json              # Scheduler deduplication state
  scheduler.pid             # Background scheduler PID
  scheduler.log             # Scheduler activity log
```

---

## Full CLI Reference

```
Session Management:
  --login               Setup X.com session (enter cookies)
  --logout              Clear saved X.com session
  --session-status      Check if sessions are active
  --bw-login            Setup BuiltWith session (enter cookies)
  --telegram-setup      Configure Telegram bot

Input Sources:
  --xuser, -x USER      X.com username to collect GTM posts from
  --search, -s TERM     Search X.com for matching posts
  --gtm, -g ID [ID..]   GTM container IDs to analyze directly
  --file, -f FILE       File containing GTM IDs (one per line or mixed text)
  --posts-file FILE     JSON file with posts to parse for GTM IDs
  --scan-url, -u URL    URLs to scan for GTM container IDs

Analysis Options:
  --reverse-lookup, -r  Find websites using each GTM (6 OSINT sources)
  --deep                Follow linked GTM containers (chain analysis)
  --bw-cookies JSON     BuiltWith cookies as JSON string

Output Options:
  --output, -o DIR      Output directory (default: output)
  --json-only           JSON output only, no terminal UI
  --telegram, -t        Send results to Telegram

Scheduler (Background):
  --hours N             Repeat every N hours (1-12)
  --days N              Repeat every N days (1-5)
  --stop                Stop background scheduler
  --scheduler-status    Show scheduler status
  --clear-history       Clear history (re-scan everything)
```

---

## Example Output

```
   ▄████▄   ██▀███   ▄▄▄       █     █░ ██▓      ▄████ ▄▄▄█████▓ ███▄ ▄███▓
  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▓█░ █ ░█░▓██▒     ██▒ ▀█▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒
  ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒█░ █ ░█ ▒██░    ▒██░▄▄▄░▒ ▓██░ ▒░▓██    ▓██░
  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ░█░ █ ░█ ▒██░    ░▓█  ██▓░ ▓██▓ ░ ▒██    ▒██
  ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒░░██▒██▓ ░██████▒░▒▓███▀▒  ▒██▒ ░ ▒██▒   ░██▒

  GTM OSINT & Reconnaissance Tool

📋 GTM IDs to analyze (1):
  GTM-KX36TXD

Analyzing 1 GTM containers... ━━━━━━━━━━━━━━━━━━━━ 100%

🔗 Deep mode: Found 1 linked GTM container

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┓
┃ GTM ID         ┃ Status   ┃     Size ┃  Domains ┃  Services ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━┩
│ GTM-KX36TXD    │ active   │ 310.4 KB │       12 │         2 │
│ GTM-WL9BCSS    │ active   │ 294.1 KB │       12 │         2 │
└────────────────┴──────────┴──────────┴──────────┴───────────┘

📦 GTM-KX36TXD (v18, 310.4 KB)
├── 🏷  Services: google-ads, google-analytics
├── 🔢 Tracking IDs: GTM-WL9BCSS, G-ASSISTANT
├── 🌐 Domains (12): ve-interactive.cn, veinteractive.com, ...
├── 📜 Scripts: cct.google/taggy/agent.js
└── 💡 Interesting: eyIwIjoiQlIi... (potential base64)

╭──────────────────── ✅ Scan Complete ────────────────────╮
│ Containers: 2 analyzed, 2 active                         │
│ Domains: 12 unique domains found                         │
│ Services: 2 third-party services detected                │
╰──────────────────────────────────────────────────────────╯
```

---

## v2.0 Changelog

- **17 bugs fixed** after comprehensive code audit
- Fixed scheduler mode ignoring `--posts-file` input
- Fixed daemon not redirecting stdout/stderr (crash prevention)
- Fixed Google cache search crashing with `None` username
- Fixed GTM ID validation allowing over-long IDs (`match` -> `fullmatch`)
- Fixed Telegram notifications silently skipped for `--gtm`/`--file` inputs
- Fixed Wayback CDX requests using wrong User-Agent
- Added proper error handling for missing/invalid input files
- Added UTF-8 encoding to all file operations
- Added PID file corruption handling for scheduler
- Fixed Nitter URL construction for absolute hrefs
- Fixed PublicWWW fallback regex producing false positive domains
- Fixed Telegram `send_long()` failing silently on oversized lines
- Removed dead code (unused variables)

---

## Author

**@ofjaaah** -- [X.com](https://x.com/oaborges_)

## License

MIT
