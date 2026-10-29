# Security — CodeWatch

This document describes CodeWatch's security model: what it protects, how, and how to configure it. For the API-key mechanics see [authentication.md](authentication.md).

## 1. Threat model

CodeWatch is a self-hosted scanner. Primary threats considered:

| Threat | Mitigation |
|---|---|
| Unauthorized API access | API-key auth on every `/api/*` route |
| Credential theft via exposed endpoints | Constant-time compare, secret display modes, key injection via server-side proxy only |
| Abuse / DoS of the API | Per-client rate limiting (sliding window + burst) |
| SSRF through remote scan targets | Scheme allowlist + private-network blocklist at resolve time |
| Arbitrary local file scanning | `MYSCAN_ALLOWED_PATHS` allowlist; reserved paths always blocked |
| Cross-origin web attacks | CORS origin allowlist |
| Secret leakage in reports/UI | `full`/`masked`/`smart` display modes; masking by default |
| Client identity spoofing behind proxies | Opt-in `MYSCAN_TRUST_PROXY` |

## 2. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MYSCAN_API_KEY` | *(empty)* | Required API key. **Empty = auth disabled — dev only.** |
| `MYSCAN_RATE_LIMIT` | `300` | Requests per minute (sliding window) per client |
| `MYSCAN_RATE_LIMIT_BURST` | `60` | Burst cap (requests/second) |
| `MYSCAN_CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins; `*` allowed but discouraged |
| `MYSCAN_ALLOWED_PATHS` | *(empty)* | Semicolon-separated local directories that may be scanned |
| `MYSCAN_TRUST_PROXY` | `0` | Set `1` to derive client identity from `X-Forwarded-For` |
| `MYSCAN_HOST` / `MYSCAN_PORT` | `0.0.0.0` / `8443` | Bind address / port |
| `MYSCAN_DB` | `src/codewatch.db` | SQLite path |
| `MYSCAN_LLM_ENHANCE` | `1` | LLM enrichment toggle (`0` = off) |
| `MYSCAN_LLM_MAX_FINDINGS` | `20` | Max LLM-enriched findings per scan |
| `MYSCAN_LLM_TIMEOUT` | `30` | Per-finding LLM timeout (s) |
| `MYSCAN_LLM_CONCURRENCY` | `4` | Parallel LLM workers |

## 3. Authentication

See [authentication.md](authentication.md). Summary:

- When `MYSCAN_API_KEY` is set, all `/api/*` routes require it (`/health` stays open).
- Accepted transports: `Authorization: Bearer`, `Authorization: Basic` (password part), `X-API-Key`, `?token=`.
- Comparison is constant-time (`hmac.compare_digest`).
- Unauthorized → `401` + `WWW-Authenticate: Bearer realm="myscan"`.

## 4. Rate limiting

- Applied to every `/api/*` request (not `/health`); `OPTIONS` preflight exempt.
- Sliding 60-second window (`MYSCAN_RATE_LIMIT`) + 1-second burst cap (`MYSCAN_RATE_LIMIT_BURST`).
- Client key: `request.remote_addr`, or first hop of `X-Forwarded-For` when `MYSCAN_TRUST_PROXY` is `1|true|yes`.
- State bounded to 10,000 clients with stale-entry eviction.
- Exceeded → `429 {"error": "Rate limit exceeded. Please retry later."}` + `Retry-After`.

## 5. CORS

- Applied to every response; non-allowlisted origins receive no CORS headers.
- `Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Max-Age: 3600`; preflight returns `204`.

## 6. SSRF protection (remote scan targets)

- Allowed schemes: `http`, `https`, `git`, `ssh` (scp-style `git@host:org/repo.git` counts as ssh).
- `file://`, `ftp://`, `gopher://` etc. are rejected.
- The hostname is resolved with `getaddrinfo` and **every** resolved address is checked against:
  - RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`), unspecified (`0.0.0.0/8`), multicast (`224/4`), reserved (`240/4`), IPv6 ULA (`fc00::/7`), IPv4-mapped (`::ffff:0:0/96`, normalized before checks).
- Blocked → `400`.

## 7. Local path guards

- Target strings are capped at 4096 chars.
- When `MYSCAN_ALLOWED_PATHS` is set, the resolved path must be inside one of the allowed bases.
- When it is unset, `/etc`, `/usr`, and `C:\Windows` are **always** refused (case-insensitive).

## 8. Secret handling

- Detected secrets are stored in `findings.raw_secret` but the **displayed** value depends on `secret_display`:
  - `smart` (default): masks weak passwords, default credentials, and production secrets; may show non-sensitive values.
  - `masked`: always shows `prefix••••suffix` (4 visible chars each).
  - `full`: shows the raw value (**dangerous** — use only in trusted environments).
- HTML reports render a red warning banner when secrets are shown in full.
- `SecretAnalyzer` computes strength, estimated crack time, environment, and business impact.

## 9. Frontend proxy (key hygiene)

The Next.js proxy (`frontend/src/proxy.ts`) rewrites `/api/*` and `/health` to the backend and injects `MYSCAN_API_KEY` as `?token=` **server-side**. The browser never receives the key.

## 10. Hardening checklist

1. **Always** set `MYSCAN_API_KEY` outside local development.
2. Keep the API port (8443) on a private network; terminate TLS at a reverse proxy.
3. Set `MYSCAN_ALLOWED_PATHS` to only the directories that should be scanned.
4. Set `MYSCAN_CORS_ORIGINS` to the exact UI origin.
5. Run as an unprivileged user; apply `NoNewPrivileges`.
6. Prefer `secret_display=smart` or `masked`.
7. Use scoped/rotatable LLM provider keys.
8. If exposing through a proxy, set `MYSCAN_TRUST_PROXY=1` and ensure the proxy overwrites `X-Forwarded-For`.

## 11. Known scope / limitations

- **Single shared API key** — no per-user RBAC or UI login (roadmap item).
- Secrets in transit rely on the surrounding TLS proxy (CodeWatch serves HTTP).
- LLM enrichment sends code snippets to the configured provider — disable (`MYSCAN_LLM_ENHANCE=0`) for air-gapped or sensitive repositories.
