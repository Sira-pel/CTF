# Client-side chains, parser gaps, and Java targets

Open on demand for hard web targets. Companion to [client-side.md](client-side.md), [client-side-advanced.md](client-side-advanced.md), and [server-side-advanced.md](server-side-advanced.md).

## Client-side (admin-bot) chains

- bfcache: navigate away and `history.back()` to restore a page from cache, skipping server-side checks.
- Service worker: if you can serve JS same-origin, register an SW (`Service-Worker-Allowed` widens scope).
- Header-too-large / error pages: oversized cookies or headers force a different, less-protected response.
- DOM clobbering: `<form id=x><input name=y>` overrides `window.x.y` when a sanitizer keeps ids/names.
- DOMPurify mXSS: sanitized HTML that is parsed again in another context (SVG/MathML, `innerHTML` twice); note sequels often patch the mXSS but leave a parser differential.
- Sanitizer API / Worker contexts are newer XSS sinks — check what the allowlist misses and where sanitized markup is re-parsed.
- Strict CSP (nonce/hash): gadgets in allowed CDNs, JSONP endpoints, or Angular-style template sinks.
- XS-Leak oracles to recover hidden notes: frame counting, error events, cache timing.

## Server-side parser gaps

- Request smuggling / Content-Length mismatch: two layers disagree on body length → smuggled second request.
- Response splitting through a proxy that pipes raw upstream bytes.
- `js-yaml` / YAML: unsafe types in old loaders; JSON injected into YAML.
- Next.js `/_next/image` (< 14.2.31 / 15.4.5): cache-key confusion caches header-dependent image responses for other users (CVE-2025-57752); check `remotePatterns` for SSRF.
- Type confusion: `parseInt("1e9")`, arrays vs strings from `qs`, `Number` vs `BigInt`.
- Rails: check strong-params gaps for mass assignment, and YAML/`Marshal` deserialization paths for RCE.

## Java targets

- RMI / Hessian / native deserialization: list classpath jars; with no Commons libs, JDK-only chains (JDK7u21, JRE8u20) work only on old JDKs.
