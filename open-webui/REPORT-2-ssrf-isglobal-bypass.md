# SSRF filter bypass: `validate_url()` trusts `is_global`, which misclassifies IPv4-mapped & NAT64-embedded addresses

**Target:** open-webui (github.com/open-webui/open-webui)
**Version:** 0.10.2
**Weakness:** CWE-918 (Server-Side Request Forgery) — filter bypass
**Auth required:** any authenticated user (the guard protects user-reachable fetches: RAG `POST /api/v1/retrieval/process/web`, per-user webhooks, image-by-URL edit)

## Severity
Conditional on deployment:
- **High** on any instance running the official image built on `python:3.11-slim` **before the
  gh-113171 fix (Python < 3.11.9 / < 3.12.4)** — full SSRF to loopback / RFC1918 / cloud metadata
  (`169.254.169.254`) with no special network. CVSS:3.1 `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L`.
- **Medium** on fully-patched Python **in NAT64/DNS64 networks** (common in IPv6-only and
  dual-stack Kubernetes/cloud) — SSRF to metadata/internal via the `64:ff9b::/96` prefix.

## Root cause
The whole SSRF defense for user-supplied URLs funnels through one predicate. In
`backend/open_webui/retrieval/web/utils.py`:

`validate_url()` (lines 105-116):
```python
if not ENABLE_LOCAL_WEB_FETCH:
    ipv4_addresses, ipv6_addresses = resolve_hostname(parsed_url.hostname)
    for ip in ipv4_addresses + ipv6_addresses:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:          # <-- SOLE gate
            raise ValueError(ERROR_MESSAGES.INVALID_URL)
```
The connect-time anti-rebinding gates use the **same** predicate — `_ssrf_safe_new_conn`
(line 149) and `_SSRFSafeResolver.resolve` (line 205) — so a value that fools `is_global`
fools every layer at once.

`ipaddress.is_global` is not a reliable "is this address externally routable" check:

1. **IPv4-mapped IPv6** — `::ffff:169.254.169.254`. Before CPython gh-113171
   (fixed in 3.11.9 / 3.12.4), `IPv6Address.is_global` did **not** unwrap the embedded IPv4 and
   returned `True` for these. The shipped Dockerfile base is `python:3.11-slim-bookworm`; images
   built before that point release are affected. An attacker submits
   `http://[::ffff:169.254.169.254]/` (or `[::ffff:127.0.0.1]`, `[::ffff:10.0.0.1]`).
2. **NAT64 well-known prefix** — `64:ff9b::/96` embeds an IPv4 but is a *global* IPv6 prefix, so
   `is_global` returns `True` on **all** current Python. In a network with a NAT64 gateway,
   `64:ff9b::a9fe:a9fe` is translated to `169.254.169.254`. Attacker submits
   `http://[64:ff9b::169.254.169.254]/`.

Both literals pass the earlier gates: `validators.url()` accepts them and
`urllib.parse.urlparse().hostname` extracts the IPv6 (verified).

## Steps to reproduce
1. As any authenticated user, trigger a user-controlled fetch — e.g.
   `POST /api/v1/retrieval/process/web` with `{"url": "http://[64:ff9b::169.254.169.254]/", "process": false}`
   (the `process:false` variant returns fetched content directly).
2. On an affected Python (< 3.11.9), also works with `http://[::ffff:169.254.169.254]/` on any
   network — no NAT64 required.
3. The server fetches the internal/metadata target instead of rejecting it.

## Proof of concept
`poc/poc_ssrf_isglobal.py` (self-contained, no target install) drives the exact `is_global` gate:
```
[::ffff:169.254.169.254]     ::ffff:169.254.169.254     False   block    # only False on >=3.11.9
[64:ff9b::169.254.169.254]   64:ff9b::a9fe:a9fe          True    ALLOW    # metadata, ALL Python
[64:ff9b::10.0.0.1]          64:ff9b::a00:1              True    ALLOW    # RFC1918, ALL Python
```
plus an embedded-IPv4 reality check confirming the mapped addresses target link-local/loopback.
(The IPv4-mapped rows print `False` on a patched interpreter; they return `True`, i.e. ALLOW, on
the pre-fix 3.11.x the Docker base historically shipped.)

## Impact
Read access to cloud instance metadata (IAM credentials on AWS/GCP/Azure), internal-only
services, and loopback admin surfaces — the classic SSRF pivot. Because the gate is shared with
the rebinding protection, the bypass is not mitigated by the existing DNS-rebinding defenses.

## Remediation
Do not rely on `is_global` alone. Before allowing a fetch, normalize each resolved address and:
- if it is IPv4-mapped IPv6 (`addr.ipv4_mapped is not None`), re-check the embedded IPv4 and
  reject when it is not global;
- reject NAT64-embedded targets (addresses within `64:ff9b::/96`, and any locally-configured
  NAT64 prefix) by extracting and re-checking the embedded IPv4;
- explicitly block loopback/link-local/private/reserved for both families rather than
  allow-by-`is_global`.
Also pin the container to a patched CPython (>= 3.11.9 / 3.12.4) as defense-in-depth.

## References
- CPython gh-113171 — `ipaddress`: IPv4-mapped/-compatible IPv6 misclassified by
  `is_private`/`is_global` (fixed 3.11.9, 3.12.4, 3.13.0).

## Disclosure
Reported privately via huntr; embargoed per huntr OSV policy (90 days). Not publicly disclosed.
