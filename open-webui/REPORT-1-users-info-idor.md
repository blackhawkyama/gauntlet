# Broken Object-Level Authorization: any user can read any other user's email & role via `GET /api/v1/users/{user_id}/info`

**Target:** open-webui (github.com/open-webui/open-webui)
**Version:** 0.10.2 (latest at time of report; code present since the endpoint's introduction)
**Weakness:** CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-213 (Exposure of Sensitive Information)
**Severity:** Medium — CVSS:3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` = **4.3**
**Auth required:** any single authenticated, non-pending account (`role: user`)

## Summary
The endpoint `GET /api/v1/users/{user_id}/info` returns a target user's `email` and `role`
(plus `bio`, status, and group memberships) to **any** authenticated caller. It performs no
check that the caller owns, or has any relationship to, the requested `user_id`. A normal
low-privilege user can therefore harvest the email address of any account and determine which
accounts are administrators — useful reconnaissance for targeted phishing / admin takeover.

## Affected code
`backend/open_webui/routers/users.py:491-510`
```python
@router.get('/{user_id}/info', response_model=UserInfoResponse)
async def get_user_info_by_id(
    user_id: str, user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)
):
    user = await Users.get_user_by_id(user_id, db=db)   # <-- caller-supplied id, no access check
    if user:
        groups = await Groups.get_groups_by_member_id(user_id, db=db)
        return UserInfoResponse(**{**user.model_dump(), 'groups': [...], 'is_active': ...})
```
The dependency `get_verified_user` (`backend/open_webui/utils/auth.py`) only asserts the caller
is a logged-in, non-pending user. Unlike sibling endpoints, there is **no**
`user_id == user.id or user.role == 'admin' or has_access(...)` gate before the record is read.

The response model deliberately includes the sensitive fields
(`backend/open_webui/models/users.py:204-211`):
```python
class UserInfoResponse(UserStatus):
    id: str
    name: str
    email: str     # sensitive
    role: str      # sensitive
    bio: str | None = None
    groups: list | None = []
    is_active: bool = False
```

## Steps to reproduce
1. On any open-webui instance, register/obtain **two** accounts: an attacker (`role: user`) and a victim (any user; an `admin` shows the highest-impact leak).
2. Obtain the victim's `user_id`. Note this is routinely exposed to ordinary users elsewhere — e.g. `message.user_id` in any channel the attacker can read, `chat.user_id` on shared chats, author ids on shared notes, and member lists on shared resources.
3. As the attacker, call:
   ```
   GET /api/v1/users/<victim_user_id>/info
   Authorization: Bearer <attacker_token>
   ```
4. The 200 response contains the victim's `email` and `role`.

## Proof of concept
`poc/poc_users_info_idor.py` reproduces the exact code path — the `UserInfoResponse` model and
the handler body are copied verbatim from the target, and `get_verified_user` mirrors the real
dependency (authenticates the caller, performs no ownership check).

Output:
```
HTTP 200
Response body: {... 'email': 'alice.admin@corp.example', 'role': 'admin', ...}
[LEAK CONFIRMED] A role=user caller retrieved another user's email='alice.admin@corp.example'
and role='admin' with no ownership/relationship check.
```

## Impact
- **Email harvesting:** any registered user can enumerate email addresses of other users given
  their id (ids leak through normal collaboration features).
- **Admin enumeration:** the returned `role` lets an attacker identify administrator accounts to
  target with phishing / credential attacks.
- On instances with open sign-up (`ENABLE_SIGNUP`), the attacker precondition is trivially met.

## Remediation
Restrict this endpoint to the requesting user, admins, or callers with an established
relationship (shared chat/channel/group), **and** trim `UserInfoResponse` to only the fields the
UI consumes. The frontend call sites (`getUserInfoById`) only ever render `.name` — `email` and
`role` are not needed. Mirror the restraint already shown by `get_user_active_status_by_id` and
`get_user_profile_image_by_id`, which return minimal non-sensitive data for the same
"any verified user, any user_id" pattern.

## Disclosure
Reported privately via huntr; embargoed per huntr OSV policy (90 days). Not publicly disclosed.
