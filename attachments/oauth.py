"""
routes/auth.py — Authentication endpoints (login, signup, Google OAuth, password reset, etc.)
"""
 
from typing import Optional
 
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
 
from services import sessions as session_svc
from services.mailer import send_email_change_email, send_reset_email
from shared import (
    FRONTEND_URL,
    GOOGLE_CLIENT_ID,
    asyncio,
    get_token_from_header,
    localdb,
    rate_limit_check,
    re,
    time,
    traceback,
    uuid,
    verify_token,
    verify_token_with_session,
)
 
 
def _real_client_ip(request: Request) -> str:
    """Return the real client IP for rate-limiting purposes.
 
    Behind IIS reverse proxy, `request.client.host` is always 127.0.0.1
    because IIS terminates the connection and forwards over loopback. IIS
    APPENDS the address it actually observed to the RIGHT of any existing
    `X-Forwarded-For` header, so the RIGHTMOST entry is the only one we can
    trust.
 
    SECURITY: we must NOT use the leftmost XFF entry — it is fully
    attacker-controlled. A client can send `X-Forwarded-For: 1.2.3.4` and
    IIS preserves it on the left, so trusting the leftmost value lets an
    attacker forge a fresh IP on every request and completely bypass the
    per-IP rate limits (5 logins/min, etc.). Reading the rightmost entry
    pins the limit to the address the trusted proxy connected to.
 
    Falls back to X-Real-IP, then the direct connection, when no XFF is
    present (eg. dev environment with no proxy).
    """
    xff = request.headers.get("x-forwarded-for") or ""
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if parts:
        # Rightmost = the hop IIS actually connected to (trusted proxy chain).
        return parts[-1]
    real = (request.headers.get("x-real-ip") or "").strip()
    if real:
        return real
    return request.client.host if request.client else "unknown"
 
 
# ── Helper: issue a token AND create the user_sessions row in one shot.
#    Used by every login path (password login, signup, Google OAuth).
async def _issue_token_with_session(user_id: str, request: Request) -> str:
    """Create a session row + return a 4-segment token bound to it.
    The token's expiry matches localdb._TOKEN_EXPIRY (30 days)."""
    jti = uuid.uuid4().hex
    expires_at_epoch = time.time() + localdb._TOKEN_EXPIRY
    try:
        await session_svc.create_session(
            user_id,
            request,
            expires_at_epoch=expires_at_epoch,
            jti=jti,
        )
    except Exception as e:
        # If session row insert fails (eg. DB hiccup), fall back to a legacy
        # 3-segment token so login still works. Session listing won't show
        # this device but the user can still use the app.
        print(f"[auth] session create failed (issuing legacy token): {e}")
        return localdb.create_access_token(user_id)
    return localdb.create_access_token(user_id, jti=jti)
 
 
router = APIRouter()
 
 
# ── Pydantic Models ──
 
 
class AuthLoginRequest(BaseModel):
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
 
 
class AuthSignupRequest(BaseModel):
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
    full_name: Optional[str] = Field("", description="User full name")
 
 
class AuthTokenRequest(BaseModel):
    # Optional in the body so callers can authenticate via the
    # Authorization: Bearer header or marketnow_token cookie alone — the
    # /api/auth/me handler resolves all three sources. If the field were
    # required (Field(...)), an empty body would fail Pydantic validation
    # with 422, masking the real error: "you're not authenticated" → 401.
    access_token: str = Field(
        "", description="Access token (optional — header / cookie also accepted)"
    )
 
 
class ChangePasswordRequest(BaseModel):
    access_token: str = Field(..., description="Current session token")
    new_password: str = Field(..., description="New password (min 8 chars)")
 
 
class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="User email to send reset link")
 
 
class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="Reset token from email link")
    email: str = Field(..., description="User email")
    new_password: str = Field(..., description="New password")
 
 
# ============ Google OAuth (Continue with Google) ============
 
 
@router.post("/api/auth/google")
async def auth_google(request: Request):
    """Verify Google OAuth credential token, create/login user."""
    # Guard the body parse: an empty or non-JSON POST (bot scan, health probe,
    # or a client that sent nothing) makes request.json() raise
    # JSONDecodeError, which otherwise propagates as an unhandled 500 with a
    # full traceback in the logs. Treat any unparseable/ non-object body as a
    # missing credential → clean 400.
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400, content={"error": "Google credential token required"}
        )
    credential = (body.get("credential") or "").strip()
    if not credential:
        return JSONResponse(
            status_code=400, content={"error": "Google credential token required"}
        )
    if not GOOGLE_CLIENT_ID:
        return JSONResponse(
            status_code=503, content={"error": "Google OAuth not configured"}
        )
 
    # Verify the Google ID token's CRYPTOGRAPHIC SIGNATURE against Google's
    # public keys, plus audience + issuer + expiry. This is critical:
    # without signature verification, an attacker who knows our (public)
    # GOOGLE_CLIENT_ID could craft a fake JWT with arbitrary claims and log
    # in as ANY user. The previous version of this endpoint just decoded the
    # JWT payload and checked claims — which provided ZERO security since
    # claims aren't authenticated until the signature is checked.
    #
    # google-auth's verify_oauth2_token does:
    #   1. Verify signature against Google's rotating JWKS (cached internally).
    #   2. Verify `aud` matches our GOOGLE_CLIENT_ID.
    #   3. Verify `iss` is accounts.google.com.
    #   4. Verify `exp` not past.
    # All in one call. Raises ValueError on ANY check failure.
    try:
        from google.auth.transport import requests as _google_requests
        from google.oauth2 import id_token as _google_id_token
 
        idinfo = _google_id_token.verify_oauth2_token(
            credential,
            _google_requests.Request(),
            GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10,  # tolerate small clock drift between us and Google
        )
    except ValueError as e:
        # Library raises ValueError for ANY validation failure (bad signature,
        # wrong audience, expired, etc.). Don't leak the internal reason — a
        # generic message is enough for legitimate users.
        print(f"[auth/google] ID token rejected: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Google sign-in failed: invalid or expired credential. Try again."
            },
        )
    except Exception as e:
        print(f"[auth/google] verification error: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Google sign-in is temporarily unavailable. Try again in a moment."
            },
        )
 
    # Pull the verified claims (idinfo is the validated payload)
    email = (idinfo.get("email") or "").strip().lower()
    name = idinfo.get("name") or ""
    email_verified = bool(idinfo.get("email_verified"))
 
    if not email:
        return JSONResponse(
            status_code=400, content={"error": "No email in Google token"}
        )
    if not email_verified:
        return JSONResponse(
            status_code=400,
            content={"error": "Your Google account's email isn't verified yet."},
        )
 
    # Check if user exists
    existing = await localdb.get_user_by_email(email)
    if existing:
        # Login existing user
        token = await _issue_token_with_session(existing["id"], request)
        response = JSONResponse(
            content={
                "access_token": token,
                "user": {
                    "id": existing["id"],
                    "email": existing["email"],
                    "name": existing.get("full_name", name),
                    "is_admin": bool(existing.get("is_admin", False)),
                },
                "is_new": False,
            }
        )
    else:
        # Create new user (random secure password since they use Google to login)
        import secrets as _secrets
 
        random_pw = _secrets.token_urlsafe(32)
        user = await localdb.create_user(email, random_pw, name)
        token = await _issue_token_with_session(user["id"], request)
        response = JSONResponse(
            content={
                "access_token": token,
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "name": name,
                    "is_admin": False,  # new signups are never admin
                },
                "is_new": True,
            }
        )
 
    is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )
    response.set_cookie(
        key="marketnow_token",
        value=token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=is_https,
        samesite="lax",
        path="/",
    )
    return response
 
 
# ============ Auth endpoints (Local PostgreSQL) ============
 
 
@router.post("/api/auth/login")
async def auth_login(body: AuthLoginRequest, request: Request):
    """Login with email and password. Returns access_token + user info. Sets HttpOnly cookie."""
    # Rate limit: 5 login attempts per minute per IP
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"login:{client_ip}", max_requests=5, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many login attempts. Please wait a minute."},
        )
 
    try:
        user = await localdb.authenticate_user(body.email.strip(), body.password)
        token = await _issue_token_with_session(user["id"], request)
 
        resp_data = {
            "access_token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user.get("full_name", ""),
                "is_admin": bool(user.get("is_admin", False)),
            },
        }
 
        response = JSONResponse(content=resp_data)
        # Only set `secure=True` when the request was actually made over HTTPS —
        # otherwise browsers silently drop the cookie and the user stays logged out.
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        response.set_cookie(
            key="marketnow_token",
            value=token,
            max_age=60 * 60 * 24 * 30,
            httponly=True,
            secure=is_https,
            samesite="lax",
            path="/",
        )
        return response
    except ValueError as e:
        return JSONResponse(status_code=401, content={"error": str(e)})
    except Exception as e:
        # Log full traceback to the backend console so ops can diagnose
        # genuine 5xx-class failures (DB down, etc.) without the user
        # seeing the internals.
        traceback.print_exc()
        return JSONResponse(
            status_code=400, content={"error": str(e) or "login failed"}
        )
 
 
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PASSWORD_SPECIAL_RE = re.compile(r"[!@#$%^&*()_+\-=\[\]{}|;:'\",.<>?/\\`~]")
# Digits plus the punctuation real phone numbers are written with. Not a
# format validator — see the note at the call site in update-profile.
_PHONE_RE = re.compile(r"^[0-9+\-() .]+$")
 
 
def _validate_password(pw: str) -> str | None:
    """Return None if password passes policy, else an error string.
 
    Policy is identical to the one /api/auth/reset-password enforces:
        • 8+ chars
        • no spaces
        • at least one special symbol
    Keeping signup + reset consistent so users can't sign up with a weaker
    password than they can reset to."""
    if not pw or len(pw) < 8:
        return "Password must be at least 8 characters."
    if " " in pw:
        return "Password must not contain spaces."
    if not _PASSWORD_SPECIAL_RE.search(pw):
        return "Password must contain at least 1 special symbol (e.g. @, #, $, !)."
    return None
 
 
@router.post("/api/auth/signup")
async def auth_signup(body: AuthSignupRequest, request: Request):
    """Register a new user. Returns access_token + user info.
 
    Validates email format AND password policy before touching the DB so
    bad data never reaches authenticate_user / lookup."""
    # Rate limit: 3 signups per minute per IP
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"signup:{client_ip}", max_requests=3, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many signup attempts. Please wait a minute."},
        )
 
    # Email format check — rejects garbage before we hit Postgres.
    email_clean = (body.email or "").strip().lower()
    if not _EMAIL_RE.match(email_clean):
        return JSONResponse(
            status_code=400, content={"error": "Please enter a valid email address."}
        )
 
    # Unified password policy (matches /api/auth/reset-password)
    pw_err = _validate_password(body.password or "")
    if pw_err:
        return JSONResponse(status_code=400, content={"error": pw_err})
 
    try:
        user = await localdb.create_user(
            email_clean, body.password, (body.full_name or "").strip()[:120]
        )
        token = await _issue_token_with_session(user["id"], request)

        # Mirror auth_login / auth_google: set the HttpOnly cookie so a fresh
        # signup has the same dual-path auth (Bearer header + cookie) as a
        # login. Without it, a signed-up user with localStorage unavailable
        # (private mode) would have NO credential at all on their next request.
        response = JSONResponse(
            content={
                "access_token": token,
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "name": user.get("full_name", ""),
                    "is_admin": False,  # new signups are never admin
                },
            }
        )
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        response.set_cookie(
            key="marketnow_token",
            value=token,
            max_age=60 * 60 * 24 * 30,
            httponly=True,
            secure=is_https,
            samesite="lax",
            path="/",
        )
        return response
    except ValueError as e:
        return JSONResponse(status_code=409, content={"error": str(e)})
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(
            status_code=400, content={"error": str(e) or "signup failed"}
        )
 
 
@router.post("/api/auth/me")
async def auth_me(body: AuthTokenRequest, request: Request):
    """Get current user from access_token (body, header, or HttpOnly cookie).
 
    When the caller's session is an admin impersonation, we surface
    `impersonator_id` + `impersonator_email` so the frontend can render
    the "Acting as user X — end impersonation" banner. For ordinary
    sessions both fields are null.
    """
    token = (
        body.access_token
        or get_token_from_header(request)
        or request.cookies.get("marketnow_token", "")
    )
    if not token:
        return JSONResponse(
            status_code=401, content={"error": "No access token provided"}
        )
 
    user_id, jti = await verify_token_with_session(token)
    if not user_id:
        return JSONResponse(
            status_code=401, content={"error": "Invalid or expired token"}
        )
 
    user = await localdb.get_user_by_id(user_id)
    if not user:
        return JSONResponse(status_code=401, content={"error": "User not found"})
 
    impersonator_id: Optional[str] = None
    impersonator_email: Optional[str] = None
    if jti:
        impersonator_id = await localdb.get_session_impersonator(jti)
        if impersonator_id:
            imp = await localdb.get_user_by_id(impersonator_id)
            impersonator_email = imp["email"] if imp else None
 
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("full_name", ""),
            # Drives the frontend's admin/customer routing decision. The
            # backend re-checks on every privileged endpoint, so a
            # tampered local value just causes a 403 — never a real
            # privilege escalation.
            "is_admin": bool(user.get("is_admin", False)),
            # Settings-page profile fields. Returned even when empty so
            # the frontend can render the fields without a second roundtrip.
            "display_name": user.get("display_name", ""),
            "work_description": user.get("work_description", ""),
            "instructions": user.get("instructions", ""),
            # Shown under the user's name in the header avatar dropdown.
            "job_title": user.get("job_title", ""),
            "phone": user.get("phone", ""),
            # Impersonation context — non-null only when this session was
            # opened via /api/admin/users/{id}/impersonate.
            "impersonator_id": impersonator_id,
            "impersonator_email": impersonator_email,
        },
    }
 
 
class UpdateProfileRequest(BaseModel):
    """Each field is Optional — only what's passed gets written. A request
    with just `display_name` set must not blank out `instructions`."""
 
    access_token: str = Field(
        "", description="Session token (header / cookie also accepted)"
    )
    full_name: Optional[str] = None
    display_name: Optional[str] = None
    work_description: Optional[str] = None
    instructions: Optional[str] = None
    job_title: Optional[str] = None
    phone: Optional[str] = None
 
 
@router.post("/api/auth/update-profile")
async def auth_update_profile(body: UpdateProfileRequest, request: Request):
    """Update one or more of the user's profile fields.
 
    Backs the Settings → Profile section. Field-by-field validation:
        • full_name / display_name        ≤ 100 chars
        • work_description                ≤ 200 chars
        • instructions                    ≤ 4000 chars  (gives room for a real
                                            "context the AI copilot should remember"
                                            blurb without inviting abuse)
    """
    token = (
        body.access_token
        or get_token_from_header(request)
        or request.cookies.get("marketnow_token", "")
    )
    user_id = await verify_token(token)
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
 
    payload: dict = {}
    if body.full_name is not None:
        v = body.full_name.strip()
        if len(v) > 100:
            return JSONResponse(
                status_code=400,
                content={"error": "Full name is too long (max 100 chars)."},
            )
        payload["full_name"] = v
    if body.display_name is not None:
        v = body.display_name.strip()
        if len(v) > 100:
            return JSONResponse(
                status_code=400,
                content={"error": "Display name is too long (max 100 chars)."},
            )
        payload["display_name"] = v
    if body.work_description is not None:
        v = body.work_description.strip()
        if len(v) > 200:
            return JSONResponse(
                status_code=400,
                content={"error": "Work description is too long (max 200 chars)."},
            )
        payload["work_description"] = v
    if body.instructions is not None:
        v = body.instructions.strip()
        if len(v) > 4000:
            return JSONResponse(
                status_code=400,
                content={"error": "Instructions are too long (max 4000 chars)."},
            )
        payload["instructions"] = v
    if body.job_title is not None:
        v = body.job_title.strip()
        if len(v) > 80:
            return JSONResponse(
                status_code=400,
                content={"error": "Job title is too long (max 80 chars)."},
            )
        payload["job_title"] = v
    if body.phone is not None:
        v = body.phone.strip()
        if len(v) > 32:
            return JSONResponse(
                status_code=400,
                content={"error": "Phone number is too long (max 32 chars)."},
            )
        # Character-class check only, no format enforcement: the field accepts
        # international numbers in whatever shape the user writes them, and a
        # stricter pattern would reject valid ones. This just keeps free text
        # (and injected markup) out of a field that should hold a number.
        if v and not _PHONE_RE.match(v):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Phone number can only contain digits, spaces, and + - ( ) characters."
                },
            )
        payload["phone"] = v
 
    if not payload:
        return JSONResponse(status_code=400, content={"error": "No fields to update."})
 
    ok = await localdb.update_user_profile(user_id, **payload)
    if not ok:
        return JSONResponse(
            status_code=400, content={"error": "Profile update failed."}
        )
 
    # Re-fetch so the response mirrors /api/auth/me — saves the frontend
    # an extra request after every save.
    user = await localdb.get_user_by_id(user_id)
    return {
        "status": "ok",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("full_name", ""),
            "is_admin": bool(user.get("is_admin", False)),
            "display_name": user.get("display_name", ""),
            "work_description": user.get("work_description", ""),
            "instructions": user.get("instructions", ""),
            "job_title": user.get("job_title", ""),
            "phone": user.get("phone", ""),
        },
    }
 
 
@router.post("/api/auth/logout")
async def auth_logout(request: Request):
    """Logout — revokes the current session row, clears HttpOnly cookie, and
    instructs client to discard token. The revocation invalidates the in-process
    cache so the token can't be reused even if a copy is held elsewhere."""
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    if token:
        info = localdb.verify_access_token_full(token)
        jti = info.get("jti") if info else None
        if jti:
            try:
                pool = await localdb.get_pool()
                await pool.execute(
                    "UPDATE user_sessions SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL",
                    jti,
                )
                session_svc.invalidate_cache(jti)
            except Exception as e:
                print(f"[auth/logout] session revoke failed (non-fatal): {e}")
    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie("marketnow_token", path="/")
    return response
 
 
# ============ Active Sessions ("Where you're signed in") ============
 
 
@router.get("/api/auth/sessions")
async def auth_list_sessions(request: Request):
    """List every active session for the current user. Each row is annotated
    with `is_current` so the UI can highlight the calling device.
 
    Legacy-token upgrade: if the calling token was issued before the
    active-sessions feature shipped (3-segment, no jti), we silently:
      1. Create a session row for the calling device
      2. Issue a fresh 4-segment token bound to that row
      3. Return the new token in `upgraded_token` so the frontend can swap
         it into localStorage / cookie on the next request
 
    Without this upgrade, devices on legacy tokens would forever show their
    OTHER devices' sessions in the list with no "THIS DEVICE" badge — the
    backend has no way to match a token without a jti to a session row.
 
    Rate-limited to 60 reads/min/IP — listing is read-only but we still cap
    it so the panel can't be polled into a DOS vector."""
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"sessions_list:{client_ip}", max_requests=60, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many requests. Please wait a minute."},
        )
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
 
    # Verify token (signature + expiry) and capture jti — DON'T require the
    # session-row check here; legacy tokens have no jti and we want to
    # upgrade them, not reject them.
    info = localdb.verify_access_token_full(token)
    if not info:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    user_id = info["user_id"]
    jti = info.get("jti")
 
    upgraded_token: Optional[str] = None
    if jti is None:
        # ── Legacy token detected — transparently upgrade ──────────────
        # Create a session row for THIS device so it appears in the list
        # with `is_current=true`, and issue a new 4-segment token the
        # frontend will use from now on. Best-effort: if the upgrade
        # fails (eg. DB hiccup), fall through and serve the list anyway.
        try:
            new_jti = uuid.uuid4().hex
            expires_at_epoch = time.time() + localdb._TOKEN_EXPIRY
            await session_svc.create_session(
                user_id,
                request,
                expires_at_epoch=expires_at_epoch,
                jti=new_jti,
            )
            upgraded_token = localdb.create_access_token(user_id, jti=new_jti)
            jti = new_jti
            print(f"[sessions/list] upgraded legacy token for user {user_id}")
        except Exception as e:
            print(f"[sessions/list] legacy upgrade failed (non-fatal): {e}")
    else:
        # 4-segment token — confirm the session row is still active before
        # we list anything (revoked sessions shouldn't be able to read).
        valid = await session_svc.validate_session(jti)
        if valid is None:
            return JSONResponse(status_code=401, content={"error": "Unauthorized"})
 
    # Opportunistic prune of expired/revoked rows for this user — keeps the
    # table small over time without needing a cron. Cheap (one DELETE).
    try:
        await session_svc.prune_user_sessions(user_id)
    except Exception as e:
        print(f"[sessions/list] prune skipped: {e}")
 
    sessions = await session_svc.list_sessions(user_id, current_jti=jti)
    response_data = {
        "sessions": sessions,
        "count": len(sessions),
        "current_session_jti": jti,
    }
    if upgraded_token:
        response_data["upgraded_token"] = upgraded_token
 
    response = JSONResponse(content=response_data)
    if upgraded_token:
        # Also set the new token as the HttpOnly cookie so subsequent
        # cookie-auth requests pick it up automatically. The frontend
        # additionally syncs it to localStorage via the response body.
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        response.set_cookie(
            key="marketnow_token",
            value=upgraded_token,
            max_age=60 * 60 * 24 * 30,
            httponly=True,
            secure=is_https,
            samesite="lax",
            path="/",
        )
    return response
 
 
class RevokeSessionRequest(BaseModel):
    session_id: str = Field(..., description="user_sessions.id to revoke")
 
 
@router.post("/api/auth/sessions/revoke")
async def auth_revoke_session(body: RevokeSessionRequest, request: Request):
    """Revoke ONE specific session. Scoped to the calling user — you can't
    revoke another user's session (DB query enforces user_id match). The
    targeted device is logged out within ≤60 s as its cache entry expires.
 
    Defense-in-depth: refuses to revoke the CALLING session itself. Without
    this check, a stale frontend snapshot or multi-tab race could lock the
    user out of the very device they're currently using. Returns 409 with a
    clear error so the UI knows to direct the user to the Logout button
    instead.
 
    Rate-limited to 30 revokes/min/IP."""
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"sessions_revoke:{client_ip}", max_requests=30, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many revoke attempts. Please wait a minute."},
        )
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    user_id, caller_jti = await verify_token_with_session(token)
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    try:
        ok = await session_svc.revoke_session(
            user_id, body.session_id, caller_jti=caller_jti
        )
    except session_svc.SelfRevokeError as e:
        return JSONResponse(
            status_code=409, content={"error": str(e), "code": "self_revoke"}
        )
    if not ok:
        return JSONResponse(
            status_code=404, content={"error": "Session not found or already revoked"}
        )
    return {"status": "revoked", "session_id": body.session_id}
 
 
@router.post("/api/auth/sessions/revoke-others")
async def auth_revoke_other_sessions(request: Request):
    """Revoke EVERY session for the current user EXCEPT the calling one.
    Useful for 'log me out everywhere else' after a password change.
    Tighter rate limit (10/min/IP) since this is a destructive bulk op."""
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"sessions_revoke_all:{client_ip}", max_requests=10, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many bulk revoke attempts. Please wait a minute."},
        )
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    user_id, jti = await verify_token_with_session(token)
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    revoked = await session_svc.revoke_others(user_id, except_jti=jti)
    return {"status": "ok", "revoked_count": revoked}
 
 
@router.post("/api/auth/change-password")
async def auth_change_password(body: ChangePasswordRequest, request: Request):
    """Change password for authenticated user.
 
    SECURITY: accepts the access token from the Authorization header (or
    cookie) FIRST, falling back to the body field only for legacy callers.
    Tokens in request bodies are weaker than headers — they leak through
    server logs, proxies, and client-side error surfaces — so the header
    path is preferred. The new password must clear the same policy gate
    that signup and reset-password enforce.
    """
    # Prefer header → cookie → body. The body path is kept for the legacy
    # frontend code that still posts `{access_token, new_password}`.
    token = (
        get_token_from_header(request)
        or request.cookies.get("marketnow_token", "")
        or body.access_token
    )
    user_id = await verify_token(token)
    if not user_id:
        return JSONResponse(
            status_code=401, content={"error": "No user found. Please login again."}
        )
 
    # Enforce the unified password policy — previously this endpoint was
    # the only password-setting path that skipped it, so an authenticated
    # user (or anyone with a stolen session) could weaken the account to
    # a 1-character password and lock the legitimate user out via online
    # brute-force guessing.
    pw_err = _validate_password(body.new_password or "")
    if pw_err:
        return JSONResponse(status_code=400, content={"error": pw_err})
 
    # Keep the acting device signed in (revoke only the OTHER sessions) —
    # a self-service password change shouldn't 401 the very tab doing it.
    current_jti = None
    try:
        _info = localdb.verify_access_token_full(token)
        current_jti = (_info or {}).get("jti")
    except Exception:
        current_jti = None
 
    try:
        ok = await localdb.change_user_password(
            user_id, body.new_password, except_jti=current_jti
        )
        if not ok:
            return JSONResponse(
                status_code=400, content={"error": "Password update failed"}
            )
        return {"status": "password_updated"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
 
 
# ═══════════════════════════════════════════════════════════
# Email change (Settings → Profile)
#
# Two steps, deliberately. /request validates and mails a confirmation
# link to the NEW address; /confirm applies it. Nothing changes until the
# link is opened, so a mistyped address costs the user one ignored email
# instead of permanent lockout from their own account.
# ═══════════════════════════════════════════════════════════
 
 
class ChangeEmailRequest(BaseModel):
    new_email: str = Field(..., description="The address to switch to")
    password: str = Field(..., description="Current password, re-confirmed")
 
 
class ConfirmEmailChangeRequest(BaseModel):
    token: str = Field(..., description="Token from the confirmation link")
 
 
@router.post("/api/auth/change-email/request")
async def auth_change_email_request(body: ChangeEmailRequest, request: Request):
    """Start an email change. Mails a confirmation link to the NEW address.
 
    Re-confirming the password matters here even though the caller already
    holds a valid session: email is the account-recovery channel, so an
    attacker on a borrowed/stolen session could otherwise redirect recovery
    to their own inbox and take the account permanently. The password is the
    one thing a session token alone doesn't grant.
    """
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    user_id = await verify_token(token)
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Please sign in."})
 
    new_email = (body.new_email or "").strip().lower()
    if not _EMAIL_RE.match(new_email):
        return JSONResponse(
            status_code=400, content={"error": "Please enter a valid email address."}
        )
 
    # Rate limit per user AND per target address — this endpoint sends mail
    # to an attacker-chosen address, so without a cap it's an open relay for
    # inbox flooding. Mirrors the forgot-password limits.
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"change_email_user:{user_id}", max_requests=3, window=3600) or \
       rate_limit_check(f"change_email_ip:{client_ip}", max_requests=10, window=3600):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many email change requests. Please try again later."},
        )
 
    user = await localdb.get_user_by_id(user_id)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Please sign in."})
 
    if new_email == (user["email"] or "").strip().lower():
        return JSONResponse(
            status_code=400,
            content={"error": "That's already your email address."},
        )
 
    # Verify the current password by re-authenticating with the CURRENT email.
    try:
        await localdb.authenticate_user(user["email"], body.password or "")
    except ValueError:
        return JSONResponse(
            status_code=403, content={"error": "That password isn't correct."}
        )
 
    # Fail fast on a taken address. consume_email_change_token re-checks at
    # confirm time too, because the address can be claimed during the window.
    existing = await localdb.get_user_by_email(new_email)
    if existing:
        return JSONResponse(
            status_code=409,
            content={"error": "An account with that email already exists."},
        )
 
    try:
        change_token = await localdb.create_email_change_token(user_id, new_email)
        base_url = FRONTEND_URL.rstrip("/") if FRONTEND_URL else "http://localhost:3000"
        confirm_link = f"{base_url}/confirm-email-change?token={change_token}"
        await asyncio.to_thread(
            send_email_change_email, new_email, confirm_link, user["email"]
        )
    except Exception:
        traceback.print_exc()
        # Clean up the pending row minted above — the confirmation mail never
        # left, so leaving it would make Settings show "waiting on
        # confirmation at <new address>" for a link no mailbox received,
        # while the user's remaining rate-limit slots tick away.
        try:
            await localdb.delete_email_change_tokens_for_user(user_id)
        except Exception:
            pass  # best-effort; the row self-expires in 30 min regardless
        return JSONResponse(
            status_code=502,
            content={
                "error": "Could not send the confirmation email. Please try again."
            },
        )
 
    return {
        "status": "confirmation_sent",
        "new_email": new_email,
        "message": f"Confirmation sent to {new_email}. Your email changes once you open that link.",
    }
 
 
@router.post("/api/auth/change-email/confirm")
async def auth_change_email_confirm(body: ConfirmEmailChangeRequest, request: Request):
    """Apply a pending email change.
 
    Deliberately NOT session-gated: the confirmation link is opened from the
    new mailbox, which may well be a different browser or device where the
    user isn't signed in. Possession of the one-time token IS the credential
    here — exactly the same trust model as /api/auth/reset-password, which is
    public for the same reason.
    """
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"confirm_email_ip:{client_ip}", max_requests=10, window=60):
        return JSONResponse(
            status_code=429, content={"error": "Too many attempts. Please wait a minute."}
        )
 
    result = await localdb.consume_email_change_token((body.token or "").strip())
    if not result:
        return JSONResponse(
            status_code=400,
            content={
                "error": "This link is invalid, has expired, or that address was taken. "
                "Request the change again from Settings."
            },
        )
    return {"status": "email_updated", "email": result["email"]}
 
 
@router.get("/api/auth/change-email/pending")
async def auth_change_email_pending(request: Request):
    """Any outstanding request, so Settings can show a pending banner rather
    than looking like the request silently failed."""
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    user_id = await verify_token(token)
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Please sign in."})
    return {"pending": await localdb.get_pending_email_change(user_id)}
 
 
@router.post("/api/auth/forgot-password")
async def auth_forgot_password(body: ForgotPasswordRequest, request: Request):
    """Send a password reset email via Gmail SMTP with a secure reset link."""
    email = body.email.strip().lower()
    if not email:
        return JSONResponse(status_code=400, content={"error": "Email is required."})
 
    # Rate limit BOTH by IP and by target email so this endpoint can't be used
    # to flood a victim's inbox or to enumerate accounts via timing/volume:
    #   • 3 requests / hour per email address
    #   • 10 requests / hour per client IP
    # Both counters are advanced on every call (no short-circuit) so neither
    # dimension can be starved.
    client_ip = _real_client_ip(request)
    ip_limited = rate_limit_check(
        f"forgot_pw_ip:{client_ip}", max_requests=10, window=3600
    )
    email_limited = rate_limit_check(
        f"forgot_pw_email:{email}", max_requests=3, window=3600
    )
    if ip_limited or email_limited:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too many password reset requests. Please wait and try again later."
            },
        )
 
    # Generic response returned in BOTH the exists and does-not-exist cases so
    # the endpoint never reveals whether an account is registered (anti-enumeration).
    success_response = {
        "status": "reset_email_sent",
        "message": "If an account with that email exists, a password reset link has been sent.",
    }
 
    try:
        # Create reset token in PostgreSQL
        token = await localdb.create_reset_token(email)
 
        # Build reset link. URL-encode the email: a raw '+' in a query string
        # is decoded as a space by the frontend (URLSearchParams form-encoding
        # rules), so an unencoded link for user+tag@gmail.com would arrive as
        # "user tag@gmail.com" and fail the email==token_email check in
        # /api/auth/reset-password on every attempt.
        from urllib.parse import quote as _quote

        base_url = FRONTEND_URL.rstrip("/") if FRONTEND_URL else "http://localhost:3000"
        reset_link = f"{base_url}/reset-password?token={token}&email={_quote(email, safe='')}"
 
        # Send email via SMTP
        await asyncio.to_thread(send_reset_email, email, reset_link)
        return success_response
    except Exception:
        traceback.print_exc()
        return success_response
 
 
@router.post("/api/auth/reset-password")
async def auth_reset_password(body: ResetPasswordRequest, request: Request):
    """Reset user password using the token sent via email."""
    # Rate limit by IP (10 / 60s) so the one-time reset token can't be
    # brute-forced by hammering this endpoint with guessed token values.
    client_ip = _real_client_ip(request)
    if rate_limit_check(f"reset_pw_ip:{client_ip}", max_requests=10, window=60):
        return JSONResponse(
            status_code=429,
            content={"error": "Too many attempts. Please wait a minute."},
        )
 
    email = body.email.strip().lower()
    new_password = body.new_password
 
    # Password validation: 8+ chars, no spaces, at least 1 special symbol
    if not new_password or len(new_password) < 8:
        return JSONResponse(
            status_code=400,
            content={"error": "Password must be at least 8 characters."},
        )
    if " " in new_password:
        return JSONResponse(
            status_code=400, content={"error": "Password must not contain spaces."}
        )
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', new_password):
        return JSONResponse(
            status_code=400,
            content={
                "error": "Password must contain at least 1 special symbol (e.g. @, #, $, !)"
            },
        )
 
    # Verify and consume the token from PostgreSQL (one-time use)
    token_email = await localdb.consume_reset_token(body.token)
    if not token_email or token_email != email:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid or expired reset link. Please request a new one."
            },
        )
 
    try:
        ok = await localdb.update_user_password(email, new_password)
        if not ok:
            return JSONResponse(
                status_code=400, content={"error": "No account found with this email."}
            )
        return {
            "status": "password_reset",
            "message": "Password has been reset successfully. You can now log in.",
        }
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(
            status_code=500, content={"error": f"Failed to reset password: {str(e)}"}
        )