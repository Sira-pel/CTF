# Client-side chains, parser gaps, and Java targets

Open on demand for hard web targets. Companion to [client-side.md](client-side.md), [client-side-advanced.md](client-side-advanced.md), and [server-side-advanced.md](server-side-advanced.md).

## Client-side (admin-bot) chains

- bfcache: navigate away and `history.back()` to restore a page from cache, skipping server-side checks.
- Service worker: if you can serve JS same-origin, register an SW (`Service-Worker-Allowed` widens scope).
- Header-too-large / error pages: oversized cookies or headers force a different, less-protected response.
- DOM clobbering: `<form id=x><input name=y>` overrides `window.x.y` when a sanitizer keeps ids/names.
- DOMPurify mXSS: sanitized HTML that is parsed again in another context (SVG/MathML, `innerHTML` twice).

## Server-side parser gaps

- Request smuggling / Content-Length mismatch: two layers disagree on body length → smuggled second request.
- Response splitting through a proxy that pipes raw upstream bytes.
- `js-yaml` / YAML: unsafe types in old loaders; JSON injected into YAML.
- Next.js `/_next/image`: cache key vs fetched URL mismatch → cache poisoning / SSRF.
- Type confusion: `parseInt("1e9")`, arrays vs strings from `qs`, `Number` vs `BigInt`.

## Java targets

- RMI / Hessian / native deserialization: list classpath jars; JDK-only gadget chains exist when no Commons libs are present.
