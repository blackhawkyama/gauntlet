# 🚁 SpaceX/Starlink Bugcrowd Hunt — LIVE SESSION

**Date:** July 5, 2026 11:35 UTC  
**Target:** *.spacex.com + *.starlink.com (Bugcrowd scope)  
**Objective:** Exploit IDOR vulnerabilities in supplier portal & rideshare APIs  
**Payout:** $500-$5,000 per valid IDOR (enterprise target)

---

## PHASE 1: RECON RESULTS ✅

### Live Targets Identified

| Target | Status | Notes |
|--------|--------|-------|
| supplierportal.spacex.com | 302 (Auth) | **PRIMARY TARGET** - Supplier IDOR |
| api.spacex.com | 200 (Cloudflare) | API endpoint - likely IDOR vectors |
| rideshare.spacex.com | 302 (Fastly) | **SECONDARY TARGET** - Ride history/driver IDOR |
| auth.spacex.com | 302 (USGov) | Authentication service |
| staging.spacex.com | 302 | **BONUS** - Staging often weaker security |
| supplierportal.starlink.com | 000 (WAF) | Skip (DataDome-level blocking) |

### Subdomain Findings
```
api.spacex.com → Cloudflare + own IPs (104.19.191.164, 104.17.160.227)
supplierportal.spacex.com → Direct IP (192.31.243.82)
rideshare.spacex.com → Fastly CDN (146.75.94.133)
auth.spacex.com → USGov Traffic Manager (192.31.242.224)
staging.spacex.com → Direct Cloudflare (104.18.11.141, 104.18.10.141)
api.starlink.com → Fastly CDN (151.101.x.x)
```

---

## PHASE 2: AUTH FLOW MAPPING (NEXT)

### Attack Plan for supplierportal.spacex.com

**Step 1: Follow the 302 redirect chain**
```
GET /admin → 302 to /auth/login?redirect=/admin
GET /auth/login → 200 (login form or SSO)
```

**Step 2: Identify session/user parameters**
- Look for: User IDs, supplier IDs, org IDs in URLs/responses
- Common IDOR patterns: `/supplier/{id}/documents`, `/user/{id}/profile`

**Step 3: Test IDOR with sequential IDs**
```
GET /api/supplier/1 (your ID)
GET /api/supplier/2 (another supplier's data?)
GET /api/supplier/100 (escalation)
```

### Attack Plan for api.spacex.com

**Step 1: Enumerate API endpoints**
```
GET /api/v1/
GET /api/v2/
GET /api/riders/
GET /api/suppliers/
```

**Step 2: Look for common IDOR endpoints**
```
/api/users/{id}
/api/suppliers/{id}
/api/rides/{id}
/api/documents/{id}
```

### Attack Plan for rideshare.spacex.com

**Step 1: Authentication endpoint mapping**
```
POST /login (credentials)
POST /oauth/authorize (OAuth)
GET /user/profile (post-auth)
```

**Step 2: IDOR in ride history**
```
GET /api/rides (your rides)
GET /api/rides/123 (another user's ride?)
GET /api/driver/456 (driver profile)
```

---

## TOOLS & SCRIPTS READY

### Custom IDOR Enumeration Script
```bash
# Will create: burp-intruder.txt with sequential ID payloads
for i in {1..10000}; do echo $i; done > /tmp/idor_ids.txt
```

### Burp Suite Configuration
- Proxy: Set to intercept supplier portal login
- Repeater: Test IDOR with ID substitution
- Intruder: Automate ID enumeration

### Manual Testing Checklist
- [ ] Capture login request
- [ ] Extract session token format
- [ ] Identify user/supplier ID format
- [ ] Test ID manipulation in request
- [ ] Verify unauthorized data access

---

## EXPECTED VULNERABILITIES

### High Probability (>80%)
1. **Supplier Portal IDOR**
   - Sequential supplier IDs → cross-supplier document access
   - Estimated payout: $1,000-$2,500

2. **API User Enumeration**
   - /api/suppliers/{id} without proper auth
   - /api/users/{id} profile leakage
   - Estimated payout: $500-$1,500

### Medium Probability (40-60%)
3. **Rideshare Ride History IDOR**
   - /api/rides/{ride_id} cross-user access
   - /api/driver/{driver_id} profile manipulation
   - Estimated payout: $1,000-$2,000

### Bonus (Opportunistic)
4. **Staging Environment Weaknesses**
   - staging.spacex.com with debug credentials
   - Estimated payout: $500-$3,000

---

## NEXT STEPS

1. ✅ WAF check complete
2. 🔄 **NOW:** Map auth flows on supplierportal.spacex.com
3. 🔄 **THEN:** Probe api.spacex.com for IDOR
4. 🔄 **THEN:** Test rideshare.spacex.com
5. 📊 **FINALLY:** Document findings & submit to Bugcrowd

**Estimated time to first valid IDOR:** 2-4 hours  
**Estimated total hunt time:** 12-24 hours  

---

## OPERATIONAL SECURITY

✅ **Respectful Recon:**
- No aggressive scanning (use Burp, not Nuclei)
- Respect rate limits
- Rotate User-Agents
- Space out requests

✅ **Documentation:**
- Screenshot each IDOR payload
- Record request/response pairs
- Note timestamp & HTTP method
- Describe impact clearly

✅ **Responsible Disclosure:**
- No data exfiltration
- No persistence
- No system modification
- Report immediately upon discovery

---

**Status:** READY FOR PHASE 2  
**Hunter:** blackhawkyama  
**Session Start:** 2026-07-05 11:35 UTC  
**Current Time:** [LIVE]

