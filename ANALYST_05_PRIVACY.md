# ANALYST_05 — PRIVACY & ANONYMITY ANALYSIS

**Reviewer:** Cryptography & Privacy Expert (Anonymity Networks, Traffic Analysis Resistance)
**Date:** 2026-06-24
**Scope:** All privacy, security, Tor, and metadata-leak surfaces in local-relay
**Files Analyzed:**
- `internal/backend/tor.go`
- `internal/security/firewall.go`
- `internal/auth/apikey.go`
- `internal/log/redact.go`
- `internal/config/config.go`
- `cmd/relay/main.go`
- `config.yaml`

---

## EXECUTIVE SUMMARY

local-relay is a Go HTTP/SOCKS5 proxy that routes traffic through Tor (SOCKS5 to 127.0.0.1:9050) with circuit rotation, API key auth, request logging with header redaction, and a host-based bypass list. The privacy posture is **moderate** — it gets the Tor basics right but has significant gaps in metadata hygiene, header redaction completeness, and bypass-list privacy implications. The biggest privacy risks are: (1) the bypass list deanonymizes traffic to listed domains, (2) API key can be sent in URL query parameters, (3) header redaction misses critical fingerprinting/leak headers, and (4) body logging leaks the first 200 bytes of every request/response.

**Overall Privacy Score: 5/10**

---

## FILE-BY-FILE ANALYSIS

---

### 1. `internal/backend/tor.go` — Tor Backend

#### (1) Traffic Analysis Resistance: MODERATE
- **SOCKS5 proxying through Tor** is correctly implemented. The handshake uses method 0x00 (no auth), address type 0x03 (domain name), which is standard for Tor SOCKS5.
- **Circuit rotation** is request-count-based (`maxCircuitAge = 100`). After 100 requests through a single circuit, `ShouldRotate()` returns true and `RequestNewCircuit()` sends `SIGNAL NEWNYM` via the Tor control port. This is correct but has limitations:
  - **No time-based rotation.** A low-volume user could keep the same circuit for hours/days, allowing an adversary to correlate timing patterns.
  - **No padding or dummy traffic.** Real request sizes and timing are passed through unmodified, enabling website traffic fingerprinting (e.g., the "website fingerprinting" attack class).
  - **`SetNoDelay(true)` on line 67** disables Nagle's algorithm. While this improves latency, it makes TCP timing more granular and precise — directly aiding traffic analysis by reducing buffering-based timing noise.
  - **KeepAlive (30s)** generates periodic packets even when idle, which could be used as a heartbeat signal by a local adversary.
- **No Tor stream isolation.** All connections share the same SOCKS5 port. If Tor is configured with `IsolateSOCKSAuth`, different API keys could get different circuits, but this code doesn't set SOCKS5 auth — all traffic shares one circuit pool.

#### (2) Metadata Leaked
- **Control port password** (`controlPass`) is stored in plaintext in the struct. If the process memory is dumped (e.g., via `/proc/<pid>/mem`), the Tor control password is exposed.
- **`circuitAge` counter** is in memory but not logged — good.
- **DNS resolution** happens through Tor (domain name sent in SOCKS5 request), so no local DNS leak — good.
- **SOCKS5 target address** is sent in cleartext over the local TCP connection to Tor, but this is localhost-only, so the risk is limited to local privilege escalation.

#### (3) Bypass List Impact
- This file contains `DirectBackend` (lines 224–258), which dials directly without Tor. When the Router sends traffic through DirectBackend, all anonymity is lost — the destination sees the user's real IP.
- **No circuit isolation between bypass and non-bypass traffic.** The same Tor instance serves both paths.

#### (4) Header Redaction
- N/A (this is the transport layer, not logging).

#### (5) Privacy Score: **6/10**
- **Strengths:** Correct SOCKS5 handshake, circuit rotation via control port, localhost-only binding, domain-based DNS through Tor.
- **Weaknesses:** No time-based rotation, no padding, SetNoDelay hurts timing resistance, no stream isolation, control password in plaintext memory.

---

### 2. `internal/security/firewall.go` — Firewall & Rate Limiter

#### (1) Traffic Analysis Resistance: LOW
- The firewall operates at the connection-routing level, not the traffic-analysis level. It blocks private IPs and rate-limits by client IP.
- **Rate limiter keyed on `clientIP`** (line 97). When traffic arrives via the HTTP proxy from a local application, the client IP is `127.0.0.1`. When traffic arrives via the SOCKS5 proxy, there is no client IP extraction visible in this file — the caller must provide it. If the caller passes `127.0.0.1`, all local clients share one rate limit bucket, which is correct for a local relay but means rate limiting doesn't differentiate users.
- **No traffic padding, no timing normalization, no constant-rate forwarding.** The firewall does nothing to resist traffic analysis.

#### (2) Metadata Leaked
- **Client IP addresses stored in rate limiter map** (line 141: `rl.limiters[key]`). In memory, these accumulate until cleanup (every 5 minutes). This is a minor leak — the IPs are local-only.
- **Private IP ranges blocked** (RFC 1918, link-local, loopback, etc.) — good for preventing SSRF attacks that could probe the local network.
- **No `.onion` address validation.** The firewall doesn't check if a target is a `.onion` address. This is fine — `.onion` addresses aren't IP-based and pass through the firewall's IP checks without issue.
- **`allowedDomains` whitelist** (lines 86–95): When non-empty, only listed domains are permitted. This is a privacy-positive feature — it prevents accidental connections to untrusted domains. However, the default config does NOT enable this (the map is empty in `config.yaml`), so by default all domains are allowed.

#### (3) Bypass List Impact
- The firewall itself doesn't implement the bypass list (that's the Router). But `AllowHost()` is the gatekeeper — if a bypass host passes the firewall's IP checks, it proceeds to the router, which may then send it through DirectBackend.
- **No warning or logging when a bypassed host passes the firewall.** A user could add `evil.com` to the bypass list and never be alerted that their real IP is exposed.

#### (4) Header Redaction
- N/A.

#### (5) Privacy Score: **5/10**
- **Strengths:** Comprehensive private IP blocking, rate limiting prevents abuse, domain allowlist support.
- **Weaknesses:** No traffic analysis resistance, no DNS validation, no bypass logging, rate limiter stores IPs in memory without encryption.

---

### 3. `internal/auth/apikey.go` — API Key Authentication

#### (1) Traffic Analysis Resistance: N/A
- Authentication doesn't affect traffic analysis. However, the API key itself is a metadata leak vector (see below).

#### (2) Metadata Leaked — CRITICAL ISSUES
- **API key in URL query parameter** (line 48: `r.URL.Query().Get(a.queryParam)` where `queryParam = "api_key"`). This is a **critical privacy and security flaw**:
  - URL query parameters appear in: HTTP server access logs, browser history, proxy logs, HTTP Referer headers, intermediary caches, and network monitoring tools.
  - Even if the proxy redacts the `Proxy-Authorization` header, the key in the URL may be logged by the destination server or any intermediary.
  - This also means the API key is visible in the URL bar if the proxy is accessed via a browser.
- **API key accepted via 3 channels:** X-Api-Key header, Proxy-Authorization header, and `api_key` URL parameter. The header channels are fine; the URL channel is not.
- **Constant-time comparison** (`crypto/subtle.ConstantTimeCompare` on line 27) — this is **correct and important**. It prevents timing side-channel attacks that could leak the key byte-by-byte.
- **API key stored in plaintext** in the `APIKeyAuth` struct. No encryption at rest.
- **Auth is disabled by default** (`config.yaml` line 23: `enabled: false`). This means anyone with network access to `127.0.0.1:18080` can use the proxy without authentication.
- **No key rotation mechanism.** The key is set at startup and never changed without restart.

#### (3) Bypass List Impact
- N/A.

#### (4) Header Redaction
- `Proxy-Authorization` is in the default redact list (`redact.go` line 12). Good — if the key is sent via this header, it will be redacted in logs.
- `X-Api-Key` is in the default redact list (`redact.go` line 10). Good.
- **But `api_key` in URL query parameters is NOT automatically redacted** unless the URL happens to contain `key=` (which it does — `api_key=key...` matches). However, `RedactURL()` checks for `"key="` as a substring. The URL would be `http://...?api_key=SECRET`, which contains `key=`, so `RedactURL` would catch it. **This is a fragile check** — it relies on substring matching and would miss `api_key` if the parameter were named differently (e.g., `token`, `access_key`, `auth_key`).

#### (5) Privacy Score: **4/10**
- **Strengths:** Constant-time comparison prevents timing attacks, header-based auth channels are fine, redact list covers the headers.
- **Weaknesses:** API key in URL query parameter is a critical flaw, auth disabled by default, no key rotation, fragile URL redaction.

---

### 4. `internal/log/redact.go` — Header & Body Redaction

#### (1) Traffic Analysis Resistance: N/A
- Redaction affects what is logged, not what is transmitted.

#### (2) Metadata Leaked — SIGNIFICANT GAPS

**Redacted headers (default set, line 8–15):**
| Header | Redacted | Verdict |
|--------|----------|---------|
| Authorization | ✅ | Correct |
| X-Api-Key | ✅ | Correct |
| Cookie | ✅ | Correct |
| Proxy-Authorization | ✅ | Correct |
| Set-Cookie | ✅ | Correct |
| Proxy-Authenticate | ✅ | Correct |

**Headers that SHOULD be redacted but ARE NOT:**
| Header | Risk | Severity |
|--------|------|----------|
| `X-Forwarded-For` | Leaks real client IP through proxy chain | HIGH |
| `X-Real-IP` | Leaks real client IP | HIGH |
| `Forwarded` (RFC 7239) | Leaks real client IP, protocol, host | HIGH |
| `Via` | Reveals proxy chain topology | MEDIUM |
| `User-Agent` | Browser/OS fingerprinting — highly identifying | MEDIUM |
| `Accept-Language` | Language/locale fingerprinting | MEDIUM |
| `Referer` | Reveals navigation history / previous page | MEDIUM |
| `X-Request-ID` | Can be used for cross-service tracking | LOW |
| `X-Correlation-ID` | Same as above | LOW |
| `True-Client-IP` | CDN-specific real IP header | HIGH |
| `X-Api-Key` (already covered) | — | — |

**Body redaction (lines 63–73):**
- Bodies <= 200 bytes: fully replaced with `[REDACTED]`. Good.
- Bodies > 200 bytes: **first 200 bytes are LOGGED**, then truncated with `...[REDACTED]`. This is a **significant leak** — 200 bytes of body content can contain:
  - JSON fields with personal data
  - Authentication tokens in POST bodies
  - Partial form submissions
  - API request payloads with sensitive parameters
- **Recommendation:** Redact ALL body content, or at minimum only log body size/content-type.

**URL redaction (lines 75–80):**
- Only redacts URLs containing `token=` or `key=` as substrings. This is **too narrow**:
  - Misses: `session=`, `sid=`, `access_token=`, `auth=`, `password=`, `secret=`, `jwt=`, `bearer=`, `code=`, `state=`, `redirect_uri=`
  - Misses: any non-standard parameter names used for secrets
  - The check is case-sensitive (`strings.Contains` without `strings.ToLower`), so `Token=` or `KEY=` would bypass it
- **Recommendation:** Use a regex-based approach or redact all query parameters by default.

**`RedactValue` (lines 56–61):**
- Shows first 4 characters + `***`. For an API key like `sk-1234567890abcdef`, this leaks `sk-1***` — the key prefix. This could reveal the key type (e.g., `sk-` = secret key). Minor issue but worth noting.

#### (3) Bypass List Impact
- N/A.

#### (4) Header Redaction Completeness: **INCOMPLETE**
- 6 headers redacted out of ~15 that should be. Missing X-Forwarded-For, X-Real-IP, Forwarded, User-Agent, Accept-Language, Referer, Via, True-Client-IP.
- Body redaction leaks first 200 bytes.
- URL redaction is substring-based and misses most sensitive parameter names.

#### (5) Privacy Score: **4/10**
- **Strengths:** Default redact list covers the most critical auth headers, constant-time redaction of values, body size limiting.
- **Weaknesses:** Missing 8+ fingerprinting/leak headers, body logging leaks 200 bytes, URL redaction is fragile and narrow, case-sensitive matching, RedactValue leaks key prefix.

---

### 5. `internal/config/config.go` — Configuration

#### (1) Traffic Analysis Resistance: MODERATE
- **Good defaults:** Tor backend at `127.0.0.1:9050`, server binds to `127.0.0.1` only (preventing remote access), rotation enabled by default with interval 1 (request-based).
- **Rotation interval is 1** in defaults (line 70), meaning circuit rotation is checked every 1 request. However, the actual rotation only happens when `circuitAge >= maxCircuitAge` (100), so the interval of 1 means the check runs frequently but rotation is still every 100 requests.
- **Connection timeout:** 30s for Tor, 10s for direct. Reasonable.

#### (2) Metadata Leaked
- **API key in plaintext YAML** (line 44: `APIKey string \`yaml:"api_key"\``). If the config file has restrictive permissions, this is acceptable. But the file is `config.yaml` with no apparent permission enforcement.
- **Environment variable overrides** (lines 121–141): `PROXY_AUTH_KEY` env var is processed. Environment variables are visible in `/proc/<pid>/environ` on Linux — a local attacker can read them.
- **Health endpoint** (line 83–85) exposes backend type and request count. If the health endpoint is accessible (it binds to `127.0.0.1:18888`), a local attacker can learn:
  - Backend type (tor/socks5/http)
  - Number of requests processed
  - Whether rotation is active
- **No config file permission checking.** The code reads config but doesn't verify file permissions (should be 0600 for files containing secrets).

#### (3) Bypass List Impact
- `BypassConfig` stores a list of hostnames (line 34: `Hosts []string`). **No validation** is performed on these hosts:
  - No check that they resolve to local/private IPs
  - No warning if they resolve to public IPs (which would bypass Tor)
  - No limit on list size
  - No mechanism to require explicit consent for adding public domains

#### (4) Header Redaction
- Default redact list in config (line 79) matches the hardcoded defaults in `redact.go`. User can extend via `redact_headers` config. This is good — extensible redaction.

#### (5) Privacy Score: **6/10**
- **Strengths:** Localhost binding, Tor default, rotation enabled, API key minimum length (16 chars), extensible redact list.
- **Weaknesses:** API key in plaintext, no config file permission checks, health endpoint leaks operational data, no bypass list validation, env vars visible in procfs.

---

### 6. `cmd/relay/main.go` — Application Entry Point

#### (1) Traffic Analysis Resistance: MODERATE
- Creates TorBackend with health check — if Tor is down, warns but doesn't block.
- Circuit rotation configured: `MaxCircuitAge: 100` (hardcoded on line 81, ignoring `cfg.Rotation.Interval`).
- **Bug/Issue:** `MaxCircuitAge` is hardcoded to 100 on line 81, not read from config. The `RotationConfig.Interval` (which is the check interval) is separate from the actual circuit age threshold. This means the circuit age is not configurable.
- **Bypass hosts are passed to the router** (line 99: `router.SetBypassHosts(cfg.Bypass.Hosts)`), but there's no warning when bypass traffic occurs.

#### (2) Metadata Leaked
- **Startup log leaks operational details** (lines 64–70):
  ```
  "version", Version, "http", cfg.Server.HTTP, "socks5", cfg.Server.SOCKS5,
  "backend", cfg.Backend.Type, "backend_addr", cfg.Backend.Address
  ```
  This logs: version, listen addresses, backend type, and backend address. An attacker with log access learns the entire network topology.
- **Bypass host list logged** (line 100):
  ```
  logger.Info("Bypass hosts configured", "hosts", cfg.Bypass.Hosts)
  ```
  This **leaks the bypass list in plaintext logs**. If logs are shipped to a centralized system, the bypass domains are exposed, revealing which services the user accesses without Tor.
- **Request count exposed** (lines 158–159): `info["requests"] = rotator.GetCount()` — the health endpoint reveals total request count, enabling traffic volume analysis.
- **Version/commit/buildtime** in binary (lines 24–26) and printed via `-version` flag — fingerprinting vector.

#### (3) Bypass List Impact
- **Critical:** The bypass list is configured in `config.yaml` with `codebuff.com`, `www.codebuff.com`, and `api.codebuff.com`. These domains are routed through `DirectBackend`, meaning:
  - All HTTP requests to codebuff.com go through the user's real IP
  - An adversary monitoring the user's network can see all codebuff.com traffic
  - A codebuff.com server can log the user's real IP
  - **This completely deanonymizes the user for these domains**
- The bypass list is also logged, so even if the user removes it from config, the logs reveal what was bypassed.
- **No per-request logging of bypass vs. Tor routing.** It's impossible to audit which requests went through Tor and which didn't.

#### (4) Header Redaction
- Logger is set up with `slog` (lines 190–215) writing to `os.Stdout`. The `HeaderRedactor` from `redact.go` is presumably used in the HTTP proxy middleware, but main.go doesn't directly show where redaction is applied. The actual redaction happens in `proxy.NewHTTPProxy` and `proxy.NewSOCKS5Proxy` (not in this file's scope but referenced).

#### (5) Privacy Score: **5/10**
- **Strengths:** Clean architecture, health check for Tor, graceful shutdown, signal handling.
- **Weaknesses:** Bypass list logged in plaintext, startup log leaks topology, request count exposed, MaxCircuitAge hardcoded, no audit trail for bypass vs. Tor routing.

---

### 7. `config.yaml` — Configuration File

#### (1) Traffic Analysis Resistance: MODERATE
- Tor backend enabled with default port 9050 — correct.
- Rotation enabled with interval 10 — means rotation check runs every 10 requests. Combined with `MaxCircuitAge=100` (hardcoded), circuits rotate every ~100 requests.
- Server binds to localhost only (`127.0.0.1:18080`, `127.0.0.1:11080`) — prevents remote exploitation.

#### (2) Metadata Leaked
- **Bypass list reveals user's services:** `codebuff.com`, `www.codebuff.com`, `api.codebuff.com`. Anyone with config access knows what the user is proxying for.
- **Auth disabled** (`enabled: false`, `api_key: ""`). The proxy is completely open to any local process.
- **Health endpoint on `127.0.0.1:18888`** — accessible to any local process, leaks backend type and request count.
- **Logging level `info`** — reasonable, but `debug` would leak even more. The config allows switching to debug, which would log headers and potentially more metadata.

#### (3) Bypass List Impact — CRITICAL
```
bypass:
  hosts:
    - "localhost"
    - "127.0.0.1"
    - "codebuff.com"
    - "www.codebuff.com"
    - "api.codebuff.com"
```
- `localhost` and `127.0.0.1` bypasses are benign — they're local addresses that wouldn't go through Tor anyway (and the firewall blocks them from being forwarded).
- **`codebuff.com` domains bypass Tor entirely.** This is the most significant privacy issue in the entire project. All HTTP/API traffic to codebuff.com goes through the user's real IP, completely deanonymizing the user for this service.
- **No wildcard matching** (good — prevents `*.codebuff.com` from accidentally including subdomains not intended).
- **No domain validation** — nothing prevents adding `google.com` or `facebook.com` to the bypass list.

#### (4) Header Redaction
- Config redaction list matches defaults:
  ```yaml
  redact_headers:
    - Authorization
    - X-Api-Key
    - Cookie
    - Proxy-Authorization
    - Set-Cookie
  ```
- `max_body_log_size: 200` — as noted in the redact.go analysis, this means 200 bytes of body are logged.

#### (5) Privacy Score: **4/10**
- **Strengths:** Localhost binding, rotation enabled, reasonable logging level.
- **Weaknesses:** Auth disabled, codebuff.com bypass deanonymizes user, health endpoint exposed, body logging leaks 200 bytes.

---

## CROSS-CUTTING PRIVACY CONCERNS

### A. The Bypass List Problem
The bypass list is the **single largest privacy risk** in this system. When a domain is in the bypass list:
1. Traffic goes through `DirectBackend`, using the user's real IP
2. No Tor circuit is used — no anonymity
3. The bypass list itself is logged at startup (line 100 of main.go)
4. There is no per-request audit trail distinguishing Tor vs. direct traffic
5. There is no warning mechanism when bypass traffic occurs

**Recommendation:** Add explicit logging when bypass traffic occurs (request URL + "DIRECT" vs "TOR" label). Require user confirmation for non-private bypass domains. Consider a "bypass mode" that disables Tor entirely rather than silently mixing traffic.

### B. API Key in URL
The `api_key` query parameter is a critical flaw. Even though `RedactURL()` catches `key=` substrings, this is fragile. API keys should only be accepted via headers.

**Recommendation:** Remove URL query parameter authentication entirely. If it must remain, document the security implications prominently.

### C. Incomplete Header Redaction
Missing headers (X-Forwarded-For, X-Real-IP, Forwarded, User-Agent, Accept-Language, Referer, Via, True-Client-IP) mean that request logs contain fingerprinting and IP-leak data.

**Recommendation:** Add all privacy-sensitive headers to the default redact list. Consider a "maximum privacy" mode that redacts everything except method, URL path, status code, and response size.

### D. Body Logging
Logging 200 bytes of body content defeats the purpose of header redaction. A POST request with JSON body `{"email":"user@example.com","token":"abc123"}` would have the email and token logged.

**Recommendation:** Default to `max_body_log_size: 0` (no body logging). Make body logging opt-in with explicit warning.

### E. No Stream Isolation
All Tor traffic goes through a single SOCKS5 port with no authentication, meaning all requests share Tor circuits. If Tor is configured with `IsolateSOCKSAuth`, different SOCKS5 usernames would get different circuits — but this code doesn't use SOCKS5 auth.

**Recommendation:** Consider adding SOCKS5 username/password authentication (even if trivial) to enable Tor stream isolation.

---

## PRIVACY SCORE SUMMARY

| Component | Score | Key Issue |
|-----------|-------|-----------|
| `tor.go` | 6/10 | No time-based rotation, SetNoDelay hurts timing resistance |
| `firewall.go` | 5/10 | No traffic analysis resistance, no bypass logging |
| `apikey.go` | 4/10 | API key in URL query params, auth disabled by default |
| `redact.go` | 4/10 | 8+ missing headers, body leaks 200 bytes, fragile URL redaction |
| `config.go` | 6/10 | Good defaults but plaintext secrets, no bypass validation |
| `main.go` | 5/10 | Bypass list logged, topology exposed, no audit trail |
| `config.yaml` | 4/10 | Auth disabled, codebuff.com bypass deanonymizes user |
| **OVERALL** | **5/10** | Functional Tor proxy with significant privacy gaps |

---

## TOP 10 RECOMMENDATIONS (PRIORITIZED)

1. **[CRITICAL]** Remove API key from URL query parameter authentication. Headers only.
2. **[CRITICAL]** Add per-request logging of "TOR" vs "DIRECT" routing for bypass auditability.
3. **[HIGH]** Add missing headers to default redact list: X-Forwarded-For, X-Real-IP, Forwarded, User-Agent, Accept-Language, Referer, Via, True-Client-IP.
4. **[HIGH]** Change `max_body_log_size` default to 0 (no body logging). Make body logging opt-in.
5. **[HIGH]** Enable auth by default in `config.yaml`. Add config file permission validation (0600).
6. **[MEDIUM]** Add time-based circuit rotation (e.g., rotate every 30 minutes in addition to request count).
7. **[MEDIUM]** Fix `SetNoDelay(true)` — remove it or make it configurable. Nagle's algorithm provides timing noise that helps resist traffic analysis.
8. **[MEDIUM]** Add SOCKS5 username authentication to enable Tor stream isolation.
9. **[MEDIUM]** Use regex-based URL redaction that catches all sensitive parameter names, not just `token=` and `key=`.
10. **[LOW]** Validate bypass list entries — warn or block public domains that would bypass Tor.

---

*End of ANALYST_05 privacy analysis.*
