<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg" alt="Platform">
</p>

```
   ▄████▄   ██▀███   ▄▄▄       █     █░ ██▓      ▄████ ▄▄▄█████▓ ███▄ ▄███▓
  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▓█░ █ ░█░▓██▒     ██▒ ▀█▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒
  ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒█░ █ ░█ ▒██░    ▒██░▄▄▄░▒ ▓██░ ▒░▓██    ▓██░
  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ░█░ █ ░█ ▒██░    ░▓█  ██▓░ ▓██▓ ░ ▒██    ▒██
  ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒░░██▒██▓ ░██████▒░▒▓███▀▒  ▒██▒ ░ ▒██▒   ░██▒
  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▓░▒ ▒  ░ ▒░▓  ░ ░▒   ▒  ▒ ░░   ░ ▒░   ░  ░
    ░  ▒    ░▒ ░ ▒░  ▒   ▒▒ ░  ▒ ░ ░  ░ ░ ▒  ░  ░   ░    ░    ░  ░      ░
  ░          ░   ░   ░   ▒     ░   ░    ░ ░   ░ ░   ░  ░         ░      ░
  ░ ░          ░         ░  ░    ░        ░  ░      ░                    ░
  ░
```

# crawlGTM

**Google Tag Manager OSINT & Reconnaissance Tool**

Automated pipeline to collect malicious GTM container IDs from X.com (Twitter) security researchers, analyze the container JavaScript, perform reverse lookups via BuiltWith to discover victim domains, and run on a background scheduler to continuously monitor for new threats.

---

## Flow

```
X.com Posts → Extract GTM IDs → Analyze Containers → BuiltWith Reverse Lookup → Victim Domains
     │              │                   │                       │                      │
     ▼              ▼                   ▼                       ▼                      ▼
  @researcher   GTM-XXXXXXX      Domains, Scripts,       76 domains found        RED output
  8 posts       7 IDs found      Pixels, Services        across 6 containers     + JSON + TXT
```

---

## Features

- **X.com Collection** — Authenticated GraphQL API with dynamic feature extraction from JS bundle
- **Multi-source Input** — X.com user timeline, search, direct GTM IDs, file, URL scanning
- **Container Analysis** — Domains, URLs, scripts, pixels, tracking IDs, services, custom HTML, data layer vars, interesting strings
- **Deep Mode** — Follows linked GTM containers found inside other containers (chain analysis)
- **BuiltWith Reverse Lookup** — Discovers which websites use each malicious GTM container (authenticated)
- **Background Scheduler** — `--hours N` (1-12) or `--days N` (1-5), daemonizes after first scan
- **Deduplication** — Tracks processed posts and GTM IDs, never re-scans what was already done
- **Telegram Notifications** — Send results to Telegram bot automatically
- **Session Management** — Auto-prompt for sessions on first run, re-prompt on expiry

---

## Installation

```bash
git clone https://github.com/OFJAAAH/crawlGTM.git
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

## Session Setup

The tool requires authenticated sessions for X.com and BuiltWith. On first execution it will auto-prompt for cookies, but you can also set them up manually.

### 1. X.com Session

#### Extract cookies from browser

1. Open **https://x.com** and log in
2. Press **F12** → DevTools
3. Go to **Application** → **Cookies** → **https://x.com**

**`auth_token`** is HttpOnly — you MUST copy it manually from DevTools:

> **F12 → Application → Cookies → x.com → auth_token** (double-click value → copy)

**`ct0`** can be extracted via Console. Paste this in **F12 → Console**:

```javascript
// ── X.com ct0 Cookie Extraction ──
(function() {
  var ct0 = '';
  document.cookie.split(';').forEach(function(c) {
    var p = c.trim().split('=');
    if (p[0] === 'ct0') ct0 = p.slice(1).join('=');
  });
  console.log('%c ct0 = ' + ct0, 'color:lime;font-size:14px');
  console.log('%c Now copy auth_token from: Application → Cookies → x.com', 'color:yellow;font-size:14px');
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

### 2. BuiltWith Session

#### Extract cookies from browser

1. Open **https://builtwith.com** and log in (you need a Pro/Team account)
2. Press **F12** → DevTools

**`ASP.NET_SessionId`** is HttpOnly — you MUST copy it manually:

> **F12 → Application → Cookies → builtwith.com → ASP.NET_SessionId** (double-click value → copy)

**`g_state`** and **`BWSSON`** can be extracted via Console. Paste this in **F12 → Console**:

```javascript
// ── BuiltWith Cookie Extraction ──
(function() {
  var found = {};
  document.cookie.split(';').forEach(function(c) {
    var parts = c.trim().split('=');
    var k = parts[0];
    var v = parts.slice(1).join('=');
    if (k === 'g_state' || k === 'BWSSON') found[k] = v;
  });
  found['ASP.NET_SessionId'] = 'PASTE_FROM_DEVTOOLS';
  var json = JSON.stringify(found, null, 2);
  console.log('%c BuiltWith Cookies:', 'color:cyan;font-size:14px');
  console.log(json);
  console.log('%c Replace ASP.NET_SessionId with value from Application → Cookies', 'color:yellow;font-size:14px');
  prompt('Copy this JSON (Ctrl+A, Ctrl+C):', json);
})();
```

#### Save session

```bash
python3 crawl_gtm.py --bw-login
# Paste the JSON when prompted
# Then paste ASP.NET_SessionId separately when asked
```

Session is saved to `~/.crawlgtm/builtwith_session.json`.

---

### Session Management

```bash
# Check all sessions
python3 crawl_gtm.py --session-status

# Re-login X.com (when session expires)
python3 crawl_gtm.py --login

# Re-login BuiltWith
python3 crawl_gtm.py --bw-login

# Clear X.com session
python3 crawl_gtm.py --logout
```

> **Auto-prompt:** If you run the tool without sessions configured, it will automatically prompt you to enter cookies. If a session expires mid-scan, it will detect the failure and ask for new cookies.

---

## Usage

### Basic — Collect from X.com user

```bash
# Collect GTM IDs from a security researcher's timeline
python3 crawl_gtm.py --xuser sdcyberresearch

# Search X.com for specific terms
python3 crawl_gtm.py --search "magecart GTM skimmer"
```

### Full Flow — X.com + Deep Analysis + Reverse Lookup

```bash
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup
```

This will:
1. Collect posts from `@sdcyberresearch` containing GTM IDs
2. Analyze each GTM container (domains, scripts, pixels, services)
3. Follow linked containers found inside (deep mode)
4. Reverse lookup each container on BuiltWith to find victim domains
5. Output everything with victim domains highlighted in **RED**

### Analyze specific GTM IDs

```bash
# Single ID
python3 crawl_gtm.py --gtm GTM-XXXXXXX --deep --reverse-lookup

# Multiple IDs
python3 crawl_gtm.py --gtm GTM-XXXXXXX GTM-YYYYYYY GTM-ZZZZZZZ --deep

# From file
python3 crawl_gtm.py --file gtm_ids.txt --deep --reverse-lookup
```

### Scan a website

```bash
# Find and analyze GTM containers on a website
python3 crawl_gtm.py --scan-url https://example.com --deep

# Multiple URLs
python3 crawl_gtm.py --scan-url https://site1.com https://site2.com
```

---

## Background Scheduler

Run the tool periodically in background. It daemonizes after the first scan and only processes **new** posts and GTM IDs (deduplication via `~/.crawlgtm/history.json`).

```bash
# Every 1 hour (max 12)
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --hours 1

# Every 6 hours
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --hours 6

# Every 1 day (max 5)
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --days 1

# Every 3 days with Telegram notifications
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --days 3 --telegram
```

### Scheduler Management

```bash
# Check if scheduler is running
python3 crawl_gtm.py --scheduler-status

# Stop background scheduler
python3 crawl_gtm.py --stop

# Clear history (force re-scan of everything)
python3 crawl_gtm.py --clear-history
```

### Limits

| Flag | Min | Max |
|------|-----|-----|
| `--hours N` | 1 | 12 |
| `--days N` | 1 | 5 |

You cannot use `--hours` and `--days` at the same time.

### How deduplication works

```
Run 1: 8 posts found → 7 GTM IDs → 76 victim domains → saved to history
Run 2: 8 posts found → 0 new     → "No new GTM IDs to process" → skip
Run 3: 9 posts found → 1 new     → 1 new GTM ID → analyze only this one
```

The scheduler logs all activity to `~/.crawlgtm/scheduler.log`.

---

## Telegram Notifications

```bash
# Configure bot (one-time setup)
python3 crawl_gtm.py --telegram-setup

# Run with Telegram notifications
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --telegram

# Background scheduler with Telegram
python3 crawl_gtm.py --xuser sdcyberresearch --deep --reverse-lookup --hours 1 --telegram
```

Setup:
1. Open Telegram → search **@BotFather** → `/newbot`
2. Copy the **Bot Token**
3. Send a message to your bot, then get your **Chat ID** from:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Run `--telegram-setup` and enter token + chat ID

---

## Output

Results are saved to the output directory (default: `output/`):

| File | Content |
|------|---------|
| `crawlgtm_TIMESTAMP.json` | Full analysis results in JSON |
| `gtm_ids_TIMESTAMP.txt` | GTM IDs found (one per line) |
| `domains_TIMESTAMP.txt` | Victim domains found (one per line) |

### What is extracted from each GTM container

| Data | Description |
|------|-------------|
| **Status** | Active or not (404) |
| **Domains** | All domains referenced in the container JS |
| **Scripts** | External .js files loaded by the container |
| **Pixels** | Tracking pixel URLs (Facebook, Google, etc.) |
| **Tracking IDs** | GA4 (G-xxx), UA (UA-xxx), AW (AW-xxx), linked GTMs |
| **Services** | 30+ service signatures (Google Analytics, Facebook Pixel, Hotjar, Stripe, etc.) |
| **Custom HTML** | Custom HTML tags (potential injection points) |
| **DataLayer Vars** | dataLayer variables referenced |
| **Interesting Strings** | API keys, webhooks, emails, base64 encoded data |
| **Container Version** | Version number for tracking changes |
| **Reverse Lookup** | Victim domains using this container (via BuiltWith) |

### JSON structure

```json
{
  "scan_date": "2026-02-15T00:18:05+00:00",
  "containers": [
    {
      "gtm_id": "GTM-PLM3ZJ28",
      "status": "active",
      "raw_size": 294300,
      "domains": ["ve-interactive.cn", "veinteractive.com", "..."],
      "tracking_ids": {"GTM": ["GTM-NF7Z75PB"], "GA4": ["G-ASSISTANT"]},
      "services_detected": ["google-analytics", "google-ads"],
      "scripts_loaded": ["https://cct.google/taggy/agent.js"],
      "interesting_strings": ["eyIwIjoiQlIi..."],
      "reverse_lookup_sites": [
        {"domain": "starlearners-eshop.com", "source": "builtwith"},
        {"domain": "mycruise.co.uk", "source": "builtwith"}
      ]
    }
  ],
  "posts": [...]
}
```

---

## Files

```
~/.crawlgtm/
├── session.json              # X.com cookies (auth_token + ct0)
├── builtwith_session.json    # BuiltWith cookies (BWSSON + ASP.NET_SessionId)
├── telegram.json             # Telegram bot config
├── history.json              # Scheduler deduplication state
├── scheduler.pid             # Background scheduler PID
└── scheduler.log             # Scheduler activity log
```

---

## Full Reference

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
  --file, -f FILE       File containing GTM IDs
  --posts-file FILE     JSON file with posts to parse
  --scan-url, -u URL    URLs to scan for GTM IDs

Analysis Options:
  --reverse-lookup, -r  Find websites using each GTM via BuiltWith
  --deep                Follow linked GTM containers (chain analysis)
  --bw-cookies JSON     BuiltWith cookies as JSON string

Output Options:
  --output, -o DIR      Output directory (default: output)
  --json-only           JSON output only, no terminal UI
  --telegram, -t        Send results to Telegram

Scheduler (Background):
  --hours N             Repeat every N hours (1-12), runs in background
  --days N              Repeat every N days (1-5), runs in background
  --stop                Stop background scheduler
  --scheduler-status    Show scheduler status
  --clear-history       Clear processing history (re-scan everything)
```

---

## Example Output

```
📡 Collecting posts: @sdcyberresearch
  ✓ Timeline: 8 posts matching 'GTM'
✓ Found 7 GTM IDs from X.com posts

📋 GTM IDs to analyze (7):
  GTM-57TWMFMJ, GTM-5QGGLMHR, GTM-K955GFDM, GTM-NKH8K2JD,
  GTM-PLM3ZJ28, GTM-PLWPKNGV, GTM-WWWNW2KJ

🔗 Deep mode: Found 1 linked GTM container (GTM-NF7Z75PB)

🔄 Performing reverse lookups...
  GTM-PLM3ZJ28: found 28 sites
  GTM-PLWPKNGV: found 27 sites
  GTM-5QGGLMHR: found 10 sites
  GTM-NKH8K2JD: found 5 sites (malinandgoetz.com, .ca, .co.uk, .co, .com.hk)
  GTM-WWWNW2KJ: found 5 sites
  GTM-K955GFDM: found 1 site

╭──────────────────── ✅ Scan Complete ────────────────────╮
│ Containers: 8 analyzed, 8 active                         │
│ Domains: 12 unique domains found                         │
│ Services: 2 third-party services detected                │
│ Posts: 8 X.com posts collected                            │
│ Victim Domains: 76 found via BuiltWith                   │
╰──────────────────────────────────────────────────────────╯
```

---

## Author

**@ofjaaah** — [X.com](https://x.com/oaborges_)

## License

MIT
