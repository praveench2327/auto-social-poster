"""
routes/meta_oauth.py — Facebook + Instagram OAuth + publish.
 
Mirrors routes/linkedin_oauth.py exactly so the patterns match: same
social_accounts table, same redirect-uri derivation, same usage tracking.
 
One OAuth flow (Facebook Login) returns a user token. We exchange it for
a long-lived user token, then call /me/accounts to discover the user's
Facebook Pages and the Instagram Business Account linked to each Page.
We pick the first Page and store TWO rows in social_accounts:
  • platform='facebook'  → page_id + page-access-token
  • platform='instagram' → ig_user_id + same page-access-token (IG Business
    posts authenticate using the Page's token, not a separate one)
 
Endpoints:
  GET  /api/meta/auth-url            — start the Facebook consent flow
  POST /api/meta/oauth-callback      — exchange code, store FB + IG rows
  GET  /api/facebook/status          — has the user connected a FB Page?
  POST /api/facebook/disconnect      — wipe the FB row (does NOT touch IG)
  POST /api/facebook/publish         — text + optional photo to FB Page
  GET  /api/instagram/status         — has the user connected an IG Business?
  POST /api/instagram/disconnect     — wipe the IG row
  POST /api/instagram/publish        — image_url + caption to IG Business
 
The "disconnect FB but keep IG" split is intentional. A user may have
multiple Pages and want to publish to IG via one Page while disconnecting
the Facebook publishing surface — the model maps cleanly to two rows.
 
For a clean "disconnect everything Meta" the frontend calls both endpoints
in sequence.
"""
 
from __future__ import annotations
 
import asyncio
import datetime
import os
import secrets
import time
import uuid
from typing import Optional
from urllib.parse import urlparse
 
import httpx
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, Response
 
from deps import META_APP_ID, META_APP_SECRET, META_LOGIN_CONFIG_ID
from services.crypto import decrypt_secret, encrypt_secret
from services.meta_api import (
    META_OAUTH_SCOPES,
    MetaAPIError,
    build_auth_url,
    exchange_code_for_token,
    exchange_for_long_lived,
    fetch_user_pages,
    fetch_userinfo,
    publish_facebook_photo,
    publish_facebook_text,
    publish_instagram_image,
)
from services.oauth_state import issue_state, verify_state
from shared import (
    FRONTEND_URL,
    get_token_from_header,
    localdb,
    verify_token,
)
 
router = APIRouter()
 
 
# ─────────────────────────────────────────────────────────────────────
# Ephemeral image host for immediate Instagram publishing.
#
# IG's Content Publishing API can't take uploaded bytes — Meta fetches the
# image from a public URL we provide. The manual composer posts a File, so
# we briefly hold the bytes in memory and hand Meta a public link. Entries
# only need to outlive the ~30s container flow; they expire fast and are
# cleaned opportunistically. (Single-process store — fine for the immediate
# publish path; scheduled posts use the durable /api/public/post-image
# route backed by the DB instead.)
# ─────────────────────────────────────────────────────────────────────
_TMP_IMAGES: dict[str, tuple[bytes, str, float]] = {}
_TMP_TTL_SECONDS = 600
 
 
def _to_jpeg(data: bytes) -> tuple[bytes, str]:
    """Convert any image to JPEG (Instagram only accepts JPEG). Falls back to
    the original bytes if Pillow isn't available or the image can't be read."""
    try:
        import io
 
        from PIL import Image
 
        img = Image.open(io.BytesIO(data)).convert("RGB")
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=90)
        return out.getvalue(), "image/jpeg"
    except Exception as e:
        print(f"[instagram] JPEG conversion skipped: {e}", flush=True)
        return data, "image/jpeg"
 
 
async def _upload_public_image(data: bytes) -> Optional[str]:
    """Upload JPEG bytes to a public host and return a direct HTTPS URL that
    Meta can fetch. Uses litterbox (temporary, auto-expiring) so we don't
    depend on a local tunnel / PUBLIC_BASE_URL being reachable from the
    internet. Returns None on failure (caller falls back to self-hosting)."""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(
                "https://litterbox.catbox.moe/resources/internals/api.php",
                data={"reqtype": "fileupload", "time": "1h"},
                files={"fileToUpload": ("post.jpg", data, "image/jpeg")},
            )
        url = (r.text or "").strip()
        if r.status_code == 200 and url.startswith("https://"):
            return url
        print(
            f"[instagram] public upload non-URL response ({r.status_code}): {url[:120]}",
            flush=True,
        )
    except Exception as e:
        print(f"[instagram] public upload failed: {e}", flush=True)
    return None
 
 
def _tmp_put_image(data: bytes, mime: str) -> str:
    now = time.time()
    for k in [k for k, (_, _, exp) in list(_TMP_IMAGES.items()) if exp < now]:
        _TMP_IMAGES.pop(k, None)
    key = secrets.token_urlsafe(16)
    _TMP_IMAGES[key] = (data, mime, now + _TMP_TTL_SECONDS)
    return key
 
 
@router.get("/api/public/ig-image/{key}")
async def public_ig_image(key: str):
    """Serve a just-uploaded image for Meta to fetch during IG publish."""
    item = _TMP_IMAGES.get(key)
    if not item or item[2] < time.time():
        _TMP_IMAGES.pop(key, None)
        return JSONResponse(status_code=404, content={"error": "expired"})
    return Response(
        content=item[0], media_type=item[1], headers={"Cache-Control": "no-store"}
    )
 
 
# ─────────────────────────────────────────────────────────────────────
# Helpers — same shape as linkedin_oauth._redirect_uri / _credentials_ok
# ─────────────────────────────────────────────────────────────────────
def _redirect_uri(request: Request) -> str:
    """Derive the OAuth redirect URI. Must EXACTLY match one of the
    "Valid OAuth Redirect URIs" configured in the Meta app's Facebook
    Login → Settings tab, or Meta returns 'URL Blocked'."""
    origin = request.headers.get("origin") or request.headers.get("referer", "").rstrip(
        "/"
    )
    if origin:
        parsed = urlparse(origin)
        base = f"{parsed.scheme}://{parsed.netloc}"
    else:
        base = FRONTEND_URL.rstrip("/") if FRONTEND_URL else "http://localhost:5173"
    return f"{base}/meta-callback"
 
 
def _credentials_ok() -> Optional[JSONResponse]:
    """503 when META_APP_ID/SECRET aren't set. Centralised so every
    endpoint returns the same payload — the frontend's ErrorPanel
    pattern-matches on this message."""
    if not META_APP_ID or not META_APP_SECRET:
        return JSONResponse(
            status_code=503,
            content={
                "error": (
                    "Meta API not configured. Set META_APP_ID + "
                    "META_APP_SECRET in backend/.env to enable Facebook + "
                    "Instagram publishing."
                ),
            },
        )
    return None
 
 
async def _require_user(
    request: Request,
) -> tuple[Optional[str], Optional[JSONResponse]]:
    """Resolve the calling user from token. Returns (user_id, None) on
    success or (None, 401 response) when not signed in."""
    token = get_token_from_header(request) or request.cookies.get("marketnow_token", "")
    user_id = await verify_token(token)
    if not user_id:
        return None, JSONResponse(status_code=401, content={"error": "Please sign in."})
    return user_id, None
 
 
# ─────────────────────────────────────────────────────────────────────
# 1. Auth URL — frontend redirects the user to Facebook for consent
# ─────────────────────────────────────────────────────────────────────
@router.get("/api/meta/auth-url")
async def meta_auth_url(request: Request):
    err = _credentials_ok()
    if err:
        return err
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
    redirect_uri = _redirect_uri(request)
    return {
        # When META_LOGIN_CONFIG_ID is set, build_auth_url uses the
        # Facebook-Login-for-Business `config_id` URL shape (no `scope`
        # param) — that's the only flavour Meta accepts for apps that
        # created their Login product via the 2024 redesign.
        "auth_url": build_auth_url(
            META_APP_ID,
            redirect_uri,
            state=issue_state(user_id),
            config_id=META_LOGIN_CONFIG_ID,
        ),
        "redirect_uri": redirect_uri,
        "scopes": META_OAUTH_SCOPES,
    }
 
 
# ─────────────────────────────────────────────────────────────────────
# 2. Callback — exchange code, find Pages + IG, store rows
# ─────────────────────────────────────────────────────────────────────
@router.post("/api/meta/oauth-callback")
async def meta_oauth_callback(request: Request):
    err = _credentials_ok()
    if err:
        return err
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
 
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body."})
    code = (body.get("code") or "").strip()
    if not code:
        return JSONResponse(status_code=400, content={"error": "OAuth code required."})
 
    # ── CSRF: validate state matches the authenticated user ──
    # /auth-url encodes `state = user_id`. Meta echoes that state back
    # in the redirect → frontend MUST pass it to this callback. If
    # state ≠ session user_id, the code came from a different consent
    # flow — refuse the exchange so a stolen code can't be redeemed
    # cross-account (or to silently link the attacker's pages to the
    # victim's Market Now account).
    state = (body.get("state") or "").strip()
    if not state:
        return JSONResponse(
            status_code=400,
            content={"error": "OAuth state required (CSRF protection)."},
        )
    if not verify_state(state, user_id):
        print(
            f"[meta] CSRF state mismatch: session_user={user_id} state={state[:8]}..."
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "OAuth state mismatch — refusing code exchange. Please retry the connect flow."
            },
        )
 
    redirect_uri = _redirect_uri(request)
    try:
        # 1. short-lived user token
        short = await asyncio.to_thread(
            exchange_code_for_token,
            code,
            redirect_uri,
            META_APP_ID,
            META_APP_SECRET,
        )
        short_token = short.get("access_token", "")
 
        # 2. long-lived user token (~60 days)
        long_lived = await asyncio.to_thread(
            exchange_for_long_lived,
            short_token,
            META_APP_ID,
            META_APP_SECRET,
        )
        user_token = long_lived.get("access_token", "")
        user_token_expires_in = int(long_lived.get("expires_in") or 5184000)
 
        # 3. sanity-check that the token works and enumerate Pages
        userinfo = await asyncio.to_thread(fetch_userinfo, user_token)
        pages = await asyncio.to_thread(fetch_user_pages, user_token)
    except MetaAPIError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
 
    if not pages:
        # User completed OAuth but doesn't manage any Pages. Common when
        # someone clicks "Connect" on a personal account — Meta won't let
        # you post to a personal Facebook timeline via API, only Pages.
        return JSONResponse(
            status_code=400,
            content={
                "error": (
                    "No Facebook Pages found on your account. To publish via "
                    "Market Now you need to be Admin / Editor of at least "
                    "one Facebook Page. Create a Page at facebook.com/pages/create "
                    "and try again."
                ),
                "code": "no_pages",
            },
        )
 
    # Pick the first Page as the "active" one. Frontend can offer a Page
    # picker later — for now this matches LinkedIn's "one connection per
    # user" model. The other Pages stay accessible via the user token if
    # we ever add a picker; we just don't persist them by default.
    primary = pages[0]
    page_id = primary["page_id"]
    page_name = primary["page_name"]
    page_token = primary["page_access_token"]
 
    # Instagram: the IG Business account may be linked to ANY of the user's
    # Pages — /me/accounts orders Pages arbitrarily, so keying IG off
    # pages[0] made the connect silently skip Instagram whenever the
    # IG-linked Page wasn't first ("redirected to Facebook and Instagram
    # never connected"). Prefer the primary Page's IG when present, else
    # scan every Page for the first linked IG Business account.
    ig_page = (
        primary
        if primary["ig_user_id"]
        else next((p for p in pages if p["ig_user_id"]), None)
    )
    ig_user_id = ig_page["ig_user_id"] if ig_page else ""
    ig_username = ig_page["ig_username"] if ig_page else ""
    # IG publishing authenticates with the token of the Page the IG account
    # is LINKED to — using the primary Page's token would 403 when they
    # differ.
    ig_page_token = ig_page["page_access_token"] if ig_page else ""
 
    # Page tokens for managed Pages don't really expire (only when the
    # user revokes the app or the underlying user token does), but we
    # still store the user-token expiry as a hint for the UI's "reconnect
    # soon" banner. ~60 days from now.
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=user_token_expires_in
    )
 
    pool = await localdb.get_pool()
 
    # Store Facebook row
    await pool.execute(
        """INSERT INTO social_accounts
             (user_id, platform, platform_user_id, platform_username,
              access_token, refresh_token, token_expires_at, scopes)
           VALUES ($1, 'facebook', $2, $3, $4, $5, $6, $7)
           ON CONFLICT (user_id, platform) DO UPDATE SET
             platform_user_id = $2,
             platform_username = $3,
             access_token = $4,
             refresh_token = $5,
             token_expires_at = $6,
             scopes = $7,
             updated_at = now()""",
        uuid.UUID(user_id),
        page_id,
        page_name,
        # Tokens are encrypted at rest. page_token → access_token;
        # user_token stored in refresh_token so we can re-discover Pages
        # without rerunning OAuth from scratch.
        encrypt_secret(page_token),
        encrypt_secret(user_token),
        expires_at,
        META_OAUTH_SCOPES,
    )
 
    # Store Instagram row IFF the Page has an IG Business Account linked
    if ig_user_id:
        await pool.execute(
            """INSERT INTO social_accounts
                 (user_id, platform, platform_user_id, platform_username,
                  access_token, refresh_token, token_expires_at, scopes)
               VALUES ($1, 'instagram', $2, $3, $4, $5, $6, $7)
               ON CONFLICT (user_id, platform) DO UPDATE SET
                 platform_user_id = $2,
                 platform_username = $3,
                 access_token = $4,
                 refresh_token = $5,
                 token_expires_at = $6,
                 scopes = $7,
                 updated_at = now()""",
            uuid.UUID(user_id),
            ig_user_id,
            ig_username or page_name,
            encrypt_secret(ig_page_token or page_token),
            encrypt_secret(user_token),
            expires_at,
            META_OAUTH_SCOPES,
        )
 
    return {
        "status": "connected",
        "meta_user_name": userinfo.get("name", ""),
        "facebook": {
            "page_id": page_id,
            "page_name": page_name,
        },
        "instagram": (
            {"ig_user_id": ig_user_id, "ig_username": ig_username}
            if ig_user_id
            else None
        ),
        "expires_at": expires_at.isoformat(),
        # Surface all Pages so a future UI can offer a picker without
        # rerunning OAuth.
        "all_pages": pages,
    }
 
 
# ─────────────────────────────────────────────────────────────────────
# 3. Status — Facebook
# ─────────────────────────────────────────────────────────────────────
@router.get("/api/facebook/status")
async def facebook_status(request: Request):
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
 
    pool = await localdb.get_pool()
    row = await pool.fetchrow(
        """SELECT platform_username, platform_user_id, token_expires_at
           FROM social_accounts
           WHERE user_id = $1 AND platform = 'facebook'""",
        uuid.UUID(user_id),
    )
    if not row:
        return {
            "connected": False,
            "api_configured": bool(META_APP_ID and META_APP_SECRET),
        }
    expires_at = row["token_expires_at"]
    expired = bool(
        expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc)
    )
    return {
        "connected": True,
        "api_configured": True,
        "expired": expired,
        "page_name": row["platform_username"],
        "page_id": row["platform_user_id"],
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
 
 
# ─────────────────────────────────────────────────────────────────────
# 4. Status — Instagram
# ─────────────────────────────────────────────────────────────────────
@router.get("/api/instagram/status")
async def instagram_status(request: Request):
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
 
    pool = await localdb.get_pool()
    row = await pool.fetchrow(
        """SELECT platform_username, platform_user_id, token_expires_at
           FROM social_accounts
           WHERE user_id = $1 AND platform = 'instagram'""",
        uuid.UUID(user_id),
    )
    if not row:
        return {
            "connected": False,
            "api_configured": bool(META_APP_ID and META_APP_SECRET),
        }
    expires_at = row["token_expires_at"]
    expired = bool(
        expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc)
    )
    return {
        "connected": True,
        "api_configured": True,
        "expired": expired,
        "ig_username": row["platform_username"],
        "ig_user_id": row["platform_user_id"],
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
 
 
# ─────────────────────────────────────────────────────────────────────
# 5. Disconnect — Facebook only / Instagram only
# ─────────────────────────────────────────────────────────────────────
@router.post("/api/facebook/disconnect")
async def facebook_disconnect(request: Request):
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
    pool = await localdb.get_pool()
    await pool.execute(
        "DELETE FROM social_accounts WHERE user_id = $1 AND platform = 'facebook'",
        uuid.UUID(user_id),
    )
    return {"status": "disconnected"}
 
 
@router.post("/api/instagram/disconnect")
async def instagram_disconnect(request: Request):
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
    pool = await localdb.get_pool()
    await pool.execute(
        "DELETE FROM social_accounts WHERE user_id = $1 AND platform = 'instagram'",
        uuid.UUID(user_id),
    )
    return {"status": "disconnected"}
 
 
# ─────────────────────────────────────────────────────────────────────
# 6. Publish — Facebook Page
# ─────────────────────────────────────────────────────────────────────
@router.post("/api/facebook/publish")
async def facebook_publish(
    request: Request,
    post: str = Form(...),
    image: UploadFile = File(None),
    tracked_post_id: str = Form(""),
):
    """Publish a post (text or photo+caption) to the user's connected
    Facebook Page.
 
    Multipart form fields:
      • post             — required, the post body text
      • image            — optional, a single image to attach (≤ 10 MB)
      • tracked_post_id  — optional ROI-tracked post to attach the resulting
                           Graph post id to, so the metrics poller can read
                           its impressions/reactions/comments.
    """
    err = _credentials_ok()
    if err:
        return err
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
 
    body_text = (post or "").strip()
    if not body_text:
        return JSONResponse(
            status_code=400, content={"error": "Post text is required."}
        )
 
    pool = await localdb.get_pool()
    row = await pool.fetchrow(
        """SELECT platform_user_id, platform_username, access_token, token_expires_at
           FROM social_accounts
           WHERE user_id = $1 AND platform = 'facebook'""",
        uuid.UUID(user_id),
    )
    if not row or not row["access_token"]:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Facebook not connected. Click 'Connect Facebook' first."
            },
        )
 
    expires_at = row["token_expires_at"]
    if expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc):
        return JSONResponse(
            status_code=400,
            content={
                "error": ("Facebook session expired. Please reconnect your account."),
            },
        )
 
    page_id = row["platform_user_id"]
    # Tokens are stored encrypted at rest — decrypt before use (legacy
    # plaintext rows pass through decrypt_secret unchanged).
    page_token = decrypt_secret(row["access_token"])
 
    # Optional image — same 10 MB hard cap as the LinkedIn path
    image_bytes: Optional[bytes] = None
    image_mime: str = "image/png"
    if image is not None and image.filename:
        data = await image.read()
        if len(data) > 10 * 1024 * 1024:
            return JSONResponse(
                status_code=400,
                content={"error": "Image too large — keep it under 10 MB."},
            )
        image_bytes = data
        image_mime = image.content_type or "image/png"
 
    try:
        if image_bytes:
            result = await asyncio.to_thread(
                publish_facebook_photo,
                page_id,
                page_token,
                body_text,
                image_bytes,
                image_mime,
            )
        else:
            result = await asyncio.to_thread(
                publish_facebook_text,
                page_id,
                page_token,
                body_text,
            )
    except MetaAPIError as e:
        msg = str(e)
        # Log the raw Meta error so the real cause is visible in the console —
        # not every OAuthException is an expired token.
        print(f"[facebook] publish failed (page_id={page_id}): {msg}", flush=True)
        low = msg.lower()
        # Genuine invalid/expired token → reconnect.
        if (
            "190" in msg
            or "session has been invalidated" in low
            or "session is invalid" in low
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Facebook session no longer valid. Please reconnect."
                },
            )
        # Permission / page-role errors (#200, #10, #3, #283) — the connected
        # account didn't grant posting rights for this Page, or isn't an admin
        # of a Page. Surface the real reason instead of "session invalid".
        if (
            any(code in msg for code in ("#200", "#10)", "(#3)", "#283"))
            or "permission" in low
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "error": (
                        "Facebook didn't grant posting permission for this Page. Reconnect and, in the "
                        "Facebook dialog, choose the Page and allow 'Manage your Page posts'. The account "
                        "must be an admin of a Facebook Page. (Meta said: "
                        + msg[:200]
                        + ")"
                    )
                },
            )
        # Anything else — show the actual Meta message, don't swallow it.
        return JSONResponse(
            status_code=502, content={"error": f"Facebook error: {msg[:300]}"}
        )
 
    # Reject empty post_id — previously a "successful" Meta response with
    # no `id` field returned status=posted, post_id="" which the UI showed
    # as a confirmation. The user had no way to verify or link to the post.
    post_id = result.get("id", "") or result.get("post_id", "")
    if not post_id:
        print(f"[facebook] empty post_id from Meta result={result}")
        return JSONResponse(
            status_code=502,
            content={
                "error": "Facebook accepted the post but did not return a post ID. The post may not have published — please check your Facebook Page."
            },
        )
 
    try:
        await localdb.track_usage(
            user_id,
            "facebook-post",
            "Facebook Post",
            query=body_text[:120],
            input_values={"has_image": bool(image_bytes), "post_len": len(body_text)},
            increment=1,
        )
    except Exception:
        pass
 
    # Best-effort ROI metrics linking — see the LinkedIn publish route for
    # why this never fails the request. The Graph id already arrives in the
    # "<page_id>_<post_id>" form the insights endpoints need.
    linked = False
    if tracked_post_id.strip():
        try:
            linked = await localdb.link_post_to_platform(
                post_id=tracked_post_id.strip(),
                user_id=user_id,
                platform_post_id=post_id,
                channel="facebook",
            )
        except Exception as e:
            print(f"[facebook] metrics auto-link failed (non-fatal): {e}", flush=True)
 
    return {
        "status": "posted",
        "post_id": post_id,
        "method": "facebook_graph_api",
        "metrics_linked": linked,
    }
 
 
# ─────────────────────────────────────────────────────────────────────
# 7. Publish — Instagram Business
#    IG fundamentally needs a publicly-reachable image_url; multipart
#    uploads are NOT supported by the Graph Content Publishing API.
# ─────────────────────────────────────────────────────────────────────
@router.post("/api/instagram/publish")
async def instagram_publish(request: Request):
    """Publish a single-image post to the user's connected Instagram
    Business Account.
 
    JSON body:
      • image_url — REQUIRED, a public HTTPS URL to a JPEG/PNG
      • caption   — optional, the post caption (≤ 2200 chars per IG limits)
 
    Why image_url instead of multipart upload: IG's Content Publishing
    API does NOT accept raw bytes. Meta's servers fetch the image from
    the URL we pass. So the URL must be reachable from the public
    internet — localhost URLs do not work in dev.
    """
    err = _credentials_ok()
    if err:
        return err
    user_id, unauth = await _require_user(request)
    if unauth:
        return unauth
 
    # Accept either a multipart upload (manual composer sends an image File)
    # or a JSON body with a ready-made public image_url.
    content_type = request.headers.get("content-type", "")
    image_url = ""
    caption = ""
    # Optional ROI-tracked post to attach the resulting media id to, so the
    # metrics poller can read its insights. Read from whichever body form
    # the caller used.
    tracked_post_id = ""
    if "multipart" in content_type:
        form = await request.form()
        caption = (form.get("caption") or form.get("post") or "").strip()
        image_url = (form.get("image_url") or "").strip()
        tracked_post_id = (form.get("tracked_post_id") or "").strip()
        upload = form.get("image")
        if upload is not None and hasattr(upload, "read"):
            data = await upload.read()
            if len(data) > 10 * 1024 * 1024:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Image too large — keep it under 10 MB."},
                )
            # Instagram's Content Publishing API only accepts JPEG. AI-generated
            # / uploaded images are often PNG, which Meta rejects with code 9004
            # ("media URI doesn't meet our requirements"). Normalise to JPEG.
            data, mime = _to_jpeg(data)
            # Data-exposure tradeoff: when PUBLIC_BASE_URL is configured we
            # self-host the image from our own /api/public/ig-image endpoint
            # so the user's image is NEVER handed to the third-party public
            # host (litterbox.catbox.moe). Only when no self-host base is
            # configured do we fall back to litterbox so Meta can still fetch
            # the bytes (localhost URLs are unreachable from Meta's servers).
            base = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")
            if base:
                key = _tmp_put_image(data, mime)
                image_url = f"{base}/api/public/ig-image/{key}"
            else:
                image_url = await _upload_public_image(data) or ""
                if not image_url:
                    return JSONResponse(
                        status_code=502,
                        content={
                            "error": "Could not host the image for Instagram (public upload failed and no PUBLIC_BASE_URL fallback).",
                        },
                    )
    else:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400, content={"error": "Invalid JSON body."}
            )
        image_url = (body.get("image_url") or "").strip()
        caption = (body.get("caption") or "").strip()
        tracked_post_id = (body.get("tracked_post_id") or "").strip()
 
    if not image_url:
        return JSONResponse(
            status_code=400,
            content={
                "error": "An image is required for Instagram — attach or generate one."
            },
        )
    if not image_url.startswith(("http://", "https://")):
        return JSONResponse(
            status_code=400,
            content={"error": "image_url must start with http:// or https://."},
        )
 
    pool = await localdb.get_pool()
    row = await pool.fetchrow(
        """SELECT platform_user_id, platform_username, access_token, token_expires_at
           FROM social_accounts
           WHERE user_id = $1 AND platform = 'instagram'""",
        uuid.UUID(user_id),
    )
    if not row or not row["access_token"]:
        return JSONResponse(
            status_code=400,
            content={
                "error": (
                    "Instagram not connected. Click 'Connect Instagram' "
                    "first. Note: your Instagram must be a Business or "
                    "Creator account linked to a Facebook Page."
                ),
            },
        )
 
    expires_at = row["token_expires_at"]
    if expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc):
        return JSONResponse(
            status_code=400,
            content={
                "error": "Instagram session expired. Please reconnect your account.",
            },
        )
 
    ig_user_id = row["platform_user_id"]
    # Tokens are stored encrypted at rest — decrypt before use (legacy
    # plaintext rows pass through decrypt_secret unchanged).
    page_token = decrypt_secret(row["access_token"])
 
    try:
        result = await asyncio.to_thread(
            publish_instagram_image,
            ig_user_id,
            page_token,
            image_url,
            caption,
        )
    except MetaAPIError as e:
        msg = str(e)
        # Log the raw Meta error — "session invalid" is a catch-all that hides
        # the real cause (image fetch failure, permission, media processing…).
        print(
            f"[instagram] publish failed (ig_user_id={ig_user_id}, image_url={image_url}): {msg}",
            flush=True,
        )
        low = msg.lower()
        if (
            "190" in msg
            or "session has been invalidated" in low
            or "session is invalid" in low
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Instagram session no longer valid. Please reconnect."
                },
            )
        # Everything else — surface the actual Meta reason.
        return JSONResponse(
            status_code=502, content={"error": f"Instagram error: {msg[:300]}"}
        )
 
    # Reject empty media_id — previously the UI showed "Posted" even when
    # Meta returned an unexpected structure with no `id`. The user had no
    # way to verify the post or link to it.
    media_id = result.get("id", "")
    if not media_id:
        print(f"[instagram] empty media_id from Meta result={result}")
        return JSONResponse(
            status_code=502,
            content={
                "error": "Instagram accepted the post but did not return a media ID. The post may not have published — please check your Instagram account."
            },
        )
 
    try:
        await localdb.track_usage(
            user_id,
            "instagram-post",
            "Instagram Post",
            query=caption[:120],
            input_values={"caption_len": len(caption), "image_url": image_url[:200]},
            increment=1,
        )
    except Exception:
        pass
 
    # Best-effort ROI metrics linking. This matters most for Instagram:
    # public IG URLs contain a shortcode, not the numeric media id the
    # insights API needs, and Meta removed the public shortcode→id lookup.
    # So publishing through Market Now is the ONLY reliable way to link an
    # IG post for metrics — manual linking can't recover it later.
    linked = False
    if tracked_post_id:
        try:
            linked = await localdb.link_post_to_platform(
                post_id=tracked_post_id,
                user_id=user_id,
                platform_post_id=media_id,
                channel="instagram",
            )
        except Exception as e:
            print(f"[instagram] metrics auto-link failed (non-fatal): {e}", flush=True)
 
    return {
        "status": "posted",
        "media_id": media_id,
        "method": "instagram_graph_api",
        "metrics_linked": linked,
    }