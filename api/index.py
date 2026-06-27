import os
from datetime import datetime, timezone

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pymongo import MongoClient
from starlette.middleware.sessions import SessionMiddleware


load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_FILE = os.path.join(BASE_DIR, "index.html")
APP_NAME = os.getenv("APP_NAME", "Restaurant Checklist")
SESSION_USER_KEY = "user"

SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")
MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "restaurant_checklist_local")
MONGODB_USERS_COLLECTION = os.getenv("MONGODB_USERS_COLLECTION", "users")

app = FastAPI(title=APP_NAME)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY or "missing-secret-key-change-before-deploy",
    https_only=os.getenv("SESSION_HTTPS_ONLY", "true").lower() == "true",
    same_site="lax",
    max_age=60 * 60 * 24 * 14,
)

oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def missing_settings() -> list[str]:
    required = {
        "SECRET_KEY": SECRET_KEY,
        "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
        "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET,
    }
    return [key for key, value in required.items() if not value]


def current_user(request: Request):
    return request.session.get(SESSION_USER_KEY)


def callback_url(request: Request) -> str:
    if OAUTH_REDIRECT_URI:
        return OAUTH_REDIRECT_URI
    return str(request.url_for("google_callback"))


def record_login(user: dict) -> None:
    if not MONGODB_URI:
        return
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    users = client[MONGODB_DB][MONGODB_USERS_COLLECTION]
    users.update_one(
        {"email": user["email"]},
        {"$set": user, "$setOnInsert": {"created_at": datetime.now(timezone.utc)}},
        upsert=True,
    )


def login_page(missing: list[str] | None = None) -> HTMLResponse:
    missing = missing or []
    disabled = "disabled" if missing else ""
    missing_html = ""
    if missing:
        missing_html = (
            '<div class="notice">'
            "<strong>Setup needed</strong>"
            f"<span>Missing: {', '.join(missing)}</span>"
            "</div>"
        )
    return HTMLResponse(
        f"""<!doctype html>
<html lang="th">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{APP_NAME} Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
      body {{
        min-height: 100vh;
        margin: 0;
        display: grid;
        place-items: center;
        font-family: Kanit, sans-serif;
        background: #fdf2f8;
        background-image: radial-gradient(#fbcfe8 1px, transparent 1px);
        background-size: 20px 20px;
        color: #1f2937;
      }}
      main {{
        width: min(92vw, 420px);
        background: white;
        border-top: 8px solid #f472b6;
        border-radius: 24px;
        box-shadow: 0 20px 60px rgba(15, 23, 42, 0.12);
        padding: 32px;
        text-align: center;
      }}
      h1 {{ margin: 0 0 8px; font-size: 28px; }}
      p {{ color: #64748b; margin: 0 0 24px; }}
      a, button {{
        width: 100%;
        border: 0;
        border-radius: 14px;
        background: #111827;
        color: white;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        min-height: 48px;
        font: inherit;
        font-weight: 700;
        text-decoration: none;
      }}
      button:disabled {{ opacity: 0.45; }}
      .g {{
        width: 26px;
        height: 26px;
        border-radius: 50%;
        background: white;
        color: #111827;
        display: grid;
        place-items: center;
        font-weight: 800;
      }}
      .notice {{
        margin-bottom: 18px;
        border: 1px solid #fed7aa;
        background: #fff7ed;
        color: #9a3412;
        border-radius: 14px;
        padding: 12px;
        text-align: left;
        display: grid;
        gap: 4px;
        font-size: 14px;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>ใบเช็คของก่อนซื้อ</h1>
      <p>เข้าสู่ระบบด้วย Gmail ก่อนใช้งาน</p>
      {missing_html}
      {'<button disabled>Login with Gmail</button>' if disabled else '<a href="/login"><span class="g">G</span><span>Login with Gmail</span></a>'}
    </main>
  </body>
</html>"""
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if current_user(request):
        return RedirectResponse(url="/app", status_code=303)
    return login_page(missing_settings())


@app.get("/login")
async def login(request: Request):
    missing = missing_settings()
    if missing:
        return login_page(missing)
    return await oauth.google.authorize_redirect(request, callback_url(request))


@app.get("/auth/google", name="google_callback")
async def google_callback(request: Request):
    if missing_settings():
        return RedirectResponse(url="/", status_code=303)

    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if userinfo is None:
        userinfo = await oauth.google.userinfo(token=token)

    email = userinfo.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google account did not provide an email.")

    user = {
        "email": email,
        "name": userinfo.get("name", ""),
        "picture": userinfo.get("picture", ""),
        "login_time": datetime.now(timezone.utc),
    }
    record_login(user)
    request.session[SESSION_USER_KEY] = {
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"],
    }
    return RedirectResponse(url="/app", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


@app.get("/app")
async def app_page(request: Request):
    if not current_user(request):
        return RedirectResponse(url="/", status_code=303)
    return FileResponse(APP_FILE, media_type="text/html")


@app.get("/api/me")
async def me(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in first.")
    return JSONResponse({"user": user})


@app.get("/health")
async def health():
    return {"status": "ok", "missing_settings": missing_settings()}
