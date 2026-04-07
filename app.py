from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import mysql.connector  # type: ignore
import requests
import streamlit as st
from dotenv import load_dotenv


load_dotenv()
TABLE_RESOURCES = "datahub_resources"
TABLE_GOOGLE_SIGNUPS = "datahub_google_signups"
TABLE_USER_QUERIES = "datahub_user_queries"
LOGGER = logging.getLogger("datahub")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


def _first_env(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value is not None and value.strip():
            return value.strip()
    return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _sanitize_text(raw: str) -> str:
    text = raw or ""
    secret_keys = [
        "MYSQL_PASSWORD",
        "DB_PASSWORD",
        "GITHUB_TOKEN",
        "GOOGLE_CLIENT_SECRET",
        "APP_SESSION_SECRET",
        "ADMIN_PASSWORD",
    ]
    for key in secret_keys:
        val = os.getenv(key, "")
        if val:
            text = text.replace(val, "[REDACTED]")
    markers = ["password", "passwd", "token", "secret", "authorization", "api_key", "access_key"]
    lowered = text.lower()
    for marker in markers:
        if marker in lowered:
            return "Sensitive error details redacted."
    return text


def report_error(context: str, exc: Exception) -> None:
    safe = _sanitize_text(str(exc))
    LOGGER.error("[%s] %s", context, safe)


def public_error(message: str) -> None:
    st.error(message)


@dataclass(slots=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Data Creator Hub")
    app_session_secret: str = os.getenv("APP_SESSION_SECRET", "change-me")
    admin_username: str = os.getenv("ADMIN_USERNAME", "john")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "jon6y.crae")
    admin_emails: str = os.getenv("ADMIN_EMAILS", "")

    mysql_host: str = _first_env("MYSQL_HOST", "DB_HOST", default="")
    mysql_port: int = int(_first_env("MYSQL_PORT", "DB_PORT", default="3306"))
    mysql_database: str = _first_env("MYSQL_DATABASE", "DB_NAME", "DB_DATABASE", default="")
    mysql_user: str = _first_env("MYSQL_USER", "DB_USER", default="")
    mysql_password: str = _first_env("MYSQL_PASSWORD", "DB_PASSWORD", default="")
    mysql_ssl_ca: str = os.getenv("MYSQL_SSL_CA", "")
    mysql_ssl_disabled: bool = _env_bool("MYSQL_SSL_DISABLED", default=False)
    mysql_connect_timeout: int = int(os.getenv("MYSQL_CONNECT_TIMEOUT", "10"))

    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    google_redirect_uri: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8501")

    use_github_upload: bool = os.getenv("USE_GITHUB_UPLOAD", "true").lower() in {"1", "true", "yes"}
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    github_repo: str = os.getenv("GITHUB_REPO", "")
    github_branch: str = os.getenv("GITHUB_BRANCH", "main")
    github_upload_dir: str = os.getenv("GITHUB_UPLOAD_DIR", "resources")

    @property
    def mysql_enabled(self) -> bool:
        return all([self.mysql_host, self.mysql_database, self.mysql_user, self.mysql_password])

    @property
    def github_enabled(self) -> bool:
        return all([self.github_token, self.github_repo, self.github_branch]) and self.use_github_upload

    @property
    def admin_email_set(self) -> set[str]:
        return {email.strip().lower() for email in self.admin_emails.split(",") if email.strip()}


class MySQLStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        if not settings.mysql_enabled:
            raise RuntimeError("MySQL is not configured. Set MYSQL_HOST, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD.")

    def _connect(self):
        kwargs: dict[str, Any] = {
            "host": self.settings.mysql_host,
            "port": self.settings.mysql_port,
            "database": self.settings.mysql_database,
            "user": self.settings.mysql_user,
            "password": self.settings.mysql_password,
            "autocommit": False,
            "charset": "utf8mb4",
            "connection_timeout": self.settings.mysql_connect_timeout,
            "ssl_disabled": self.settings.mysql_ssl_disabled,
        }
        ssl_ca = (self.settings.mysql_ssl_ca or "").strip()
        if not self.settings.mysql_ssl_disabled and ssl_ca:
            resolved_ca = os.path.abspath(ssl_ca)
            if not os.path.exists(resolved_ca):
                raise RuntimeError(f"MYSQL_SSL_CA not found at: {resolved_ca}")
            kwargs["ssl_ca"] = resolved_ca
        return mysql.connector.connect(**kwargs)

    def ensure_schema(self) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {TABLE_RESOURCES} (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    resource_type VARCHAR(16) NOT NULL,
                    category VARCHAR(100),
                    external_url TEXT,
                    file_name VARCHAR(255),
                    file_size BIGINT,
                    mime_type VARCHAR(150),
                    github_path TEXT,
                    view_url TEXT,
                    download_url TEXT,
                    created_by VARCHAR(120),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {TABLE_GOOGLE_SIGNUPS} (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    google_sub VARCHAR(100) UNIQUE,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    full_name VARCHAR(255),
                    picture_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {TABLE_USER_QUERIES} (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(sql, params)
            return list(cur.fetchall())
        finally:
            conn.close()

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(sql, params)
            return cur.fetchone()
        finally:
            conn.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()
            return int(cur.lastrowid or 0)
        finally:
            conn.close()


@st.cache_resource(show_spinner=False)
def get_settings() -> Settings:
    return Settings()


@st.cache_resource(show_spinner=False)
def get_store(settings: Settings) -> MySQLStore:
    store = MySQLStore(settings)
    store.ensure_schema()
    return store


@st.cache_resource(show_spinner=False)
def get_github_ops(settings: Settings) -> GitHubOps | None:
    if not settings.github_enabled:
        return None
    return GitHubOps(settings)


@st.cache_data(ttl=60, show_spinner=False)
def get_resources_cached(_store: MySQLStore) -> list[dict[str, Any]]:
    return _store.query_all(f"SELECT * FROM {TABLE_RESOURCES} ORDER BY created_at DESC")


@st.cache_data(ttl=60, show_spinner=False)
def get_queries_cached(_store: MySQLStore) -> list[dict[str, Any]]:
    return _store.query_all(f"SELECT * FROM {TABLE_USER_QUERIES} ORDER BY created_at DESC")


@st.cache_data(ttl=60, show_spinner=False)
def get_google_signups_cached(_store: MySQLStore) -> list[dict[str, Any]]:
    return _store.query_all(f"SELECT * FROM {TABLE_GOOGLE_SIGNUPS} ORDER BY created_at DESC")


def clear_data_caches() -> None:
    get_resources_cached.clear()
    get_queries_cached.clear()
    get_google_signups_cached.clear()


def init_session_state() -> None:
    st.session_state.setdefault("admin_ok", False)
    st.session_state.setdefault("google_user", None)


@dataclass(slots=True)
class GitHubUpload:
    repo_path: str
    view_url: str
    download_url: str


class GitHubOps:
    def __init__(self, settings: Settings) -> None:
        if not settings.github_enabled:
            raise ValueError("GitHub uploads are not configured.")
        self.repo = settings.github_repo
        self.branch = settings.github_branch
        self.upload_dir = settings.github_upload_dir.strip("/")
        self.base = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"token {settings.github_token}",
                "Accept": "application/vnd.github+json",
            }
        )

    def _sha(self, repo_path: str) -> str | None:
        resp = self.session.get(f"{self.base}/repos/{self.repo}/contents/{repo_path}", params={"ref": self.branch}, timeout=30)
        if resp.status_code >= 300:
            return None
        data = resp.json()
        if isinstance(data, dict):
            return data.get("sha")
        return None

    def upload_bytes(self, filename: str, payload: bytes) -> GitHubUpload:
        clean = "".join(ch for ch in filename if ch.isalnum() or ch in {".", "-", "_"})
        clean = clean or "resource.bin"
        unique_name = f"{uuid.uuid4().hex}_{clean}"
        repo_path = f"{self.upload_dir}/{unique_name}"
        content_b64 = base64.b64encode(payload).decode("utf-8")
        body: dict[str, Any] = {
            "message": f"[DataHub] Upload {unique_name}",
            "content": content_b64,
            "branch": self.branch,
        }
        sha = self._sha(repo_path)
        if sha:
            body["sha"] = sha

        resp = self.session.put(f"{self.base}/repos/{self.repo}/contents/{repo_path}", json=body, timeout=40)
        if resp.status_code >= 300:
            raise RuntimeError(f"GitHub upload failed: {resp.status_code} {resp.text}")

        view_url = f"https://github.com/{self.repo}/blob/{self.branch}/{repo_path}"
        download_url = f"https://raw.githubusercontent.com/{self.repo}/{self.branch}/{repo_path}"
        return GitHubUpload(repo_path=repo_path, view_url=view_url, download_url=download_url)

    def delete_path(self, repo_path: str) -> bool:
        sha = self._sha(repo_path)
        if not sha:
            return False
        payload = {"message": f"[DataHub] Delete {repo_path}", "sha": sha, "branch": self.branch}
        resp = self.session.delete(f"{self.base}/repos/{self.repo}/contents/{repo_path}", json=payload, timeout=30)
        return resp.status_code < 300


def google_auth_url(settings: Settings, state: str) -> str:
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"


def _sign_state(settings: Settings, payload: str) -> str:
    key = settings.app_session_secret.encode("utf-8")
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def new_oauth_state(settings: Settings) -> str:
    nonce = secrets.token_urlsafe(18)
    ts = str(int(time.time()))
    payload = f"{nonce}.{ts}"
    sig = _sign_state(settings, payload)
    return f"{payload}.{sig}"


def verify_oauth_state(settings: Settings, state: str, max_age_seconds: int = 600) -> bool:
    parts = state.split(".")
    if len(parts) != 3:
        return False
    nonce, ts_raw, sig = parts
    if not nonce or not ts_raw or not sig:
        return False
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    if int(time.time()) - ts > max_age_seconds:
        return False
    expected = _sign_state(settings, f"{nonce}.{ts_raw}")
    return hmac.compare_digest(expected, sig)


def exchange_google_code(settings: Settings, code: str) -> dict[str, Any]:
    payload = urllib.parse.urlencode(
        {
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": settings.google_redirect_uri,
            "grant_type": "authorization_code",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_google_profile(access_token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def inject_styles() -> None:
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=IBM+Plex+Mono:wght@400;500&family=Fraunces:ital,wght@0,300;0,400;1,300&display=swap');
          :root {
            --bg: #0a0a0f;
            --surface: #111118;
            --surface2: #171723;
            --border: #2a2a3a;
            --accent: #f97316;
            --accent2: #fb923c;
            --accent3: #43e97b;
            --text: #e8e8f0;
            --muted: #8b8bb5;
          }
          .stApp {
            background:
              linear-gradient(rgba(108,99,255,0.03) 1px, transparent 1px),
              linear-gradient(90deg, rgba(108,99,255,0.03) 1px, transparent 1px),
              var(--bg);
            background-size: 40px 40px, 40px 40px, auto;
            color: var(--text);
            font-family: 'Fraunces', Georgia, serif;
          }
          h1, h2, h3 {
            font-family: 'Syne', sans-serif;
            letter-spacing: -0.02em;
            color: #fff;
          }
          .hero {
            background: linear-gradient(135deg, rgba(108,99,255,0.15), rgba(255,101,132,0.12));
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 1.2rem 1.3rem;
            margin-bottom: 1rem;
          }
          .hero-kicker {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.75rem;
            color: var(--accent);
            letter-spacing: 0.15em;
            text-transform: uppercase;
          }
          .resource-card {
            border: 1px solid var(--border);
            background: var(--surface);
            border-radius: 16px;
            padding: 0.95rem;
            margin-bottom: 0.8rem;
          }
          .google-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.55rem;
            border: 1px solid #d8d8d8;
            border-radius: 10px;
            padding: 0.56rem 0.9rem;
            font-family: 'Syne', sans-serif;
            font-weight: 700;
            color: #1f2937;
            text-decoration: none;
            background: #ffffff;
          }
          .google-btn:hover { background: #f8fafc; }
          .google-btn svg { display: block; }
          .signup-card {
            border: 1px solid var(--border);
            background: var(--surface);
            border-radius: 16px;
            padding: 1rem;
          }
          .resource-meta {
            color: var(--muted);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.74rem;
          }
          .small-note {
            color: var(--muted);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.78rem;
          }
          div.stButton > button,
          div.stFormSubmitButton > button,
          div[data-testid="stLinkButton"] a {
            background: linear-gradient(135deg, #f97316, #ea580c) !important;
            color: #fff !important;
            border: 1px solid #c2410c !important;
            border-radius: 10px !important;
          }
          div.stButton > button:hover,
          div.stFormSubmitButton > button:hover,
          div[data-testid="stLinkButton"] a:hover {
            background: linear-gradient(135deg, #fb923c, #f97316) !important;
            border-color: #9a3412 !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def fmt_size(value: Any) -> str:
    if value in (None, ""):
        return "-"
    size = float(value)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def save_google_signup(store: MySQLStore, profile: dict[str, Any]) -> None:
    google_sub = profile.get("sub")
    email = profile.get("email")
    full_name = profile.get("name") or "Creator"
    picture_url = profile.get("picture")
    if not google_sub or not email:
        return
    existing = store.query_one(f"SELECT id FROM {TABLE_GOOGLE_SIGNUPS} WHERE email=%s", (email,))
    if existing:
        store.execute(
            f"""
            UPDATE {TABLE_GOOGLE_SIGNUPS}
            SET google_sub=%s, full_name=%s, picture_url=%s
            WHERE id=%s
            """,
            (google_sub, full_name, picture_url, existing["id"]),
        )
        clear_data_caches()
        return
    store.execute(
        f"""
        INSERT INTO {TABLE_GOOGLE_SIGNUPS} (google_sub, email, full_name, picture_url)
        VALUES (%s, %s, %s, %s)
        """,
        (google_sub, email, full_name, picture_url),
    )
    clear_data_caches()


def handle_google_callback(settings: Settings, store: MySQLStore | None) -> None:
    code = st.query_params.get("code")
    state = st.query_params.get("state")
    error = st.query_params.get("error")
    if error:
        st.query_params.clear()
        public_error("Google signup was cancelled or could not be completed.")
        return
    if not code:
        return
    if isinstance(state, list):
        state = state[0] if state else ""
    if isinstance(code, list):
        code = code[0] if code else ""
    if not state or not verify_oauth_state(settings, state):
        st.query_params.clear()
        st.error("Google auth failed (invalid state).")
        return
    try:
        token = exchange_google_code(settings, code)
        profile = fetch_google_profile(token.get("access_token", ""))
        if store:
            save_google_signup(store, profile)
        st.session_state["google_user"] = profile
        st.query_params.clear()
        if store:
            st.success("You are signed up for updates.")
        else:
            st.warning("Signed in with Google, but signup could not be saved because MySQL is unavailable.")
        st.rerun()
    except Exception as exc:
        report_error("google_callback", exc)
        public_error("Google signup failed. Please try again.")


def current_google_email() -> str:
    user = st.session_state.get("google_user") or {}
    return str(user.get("email") or "").strip().lower()


def is_allowed_admin(settings: Settings) -> bool:
    email = current_google_email()
    return bool(email) and email in settings.admin_email_set


def render_public_hub(store: MySQLStore | None, settings: Settings) -> None:
    st.markdown(
        """
        <div class="hero">
          <div class="hero-kicker">AI | DATA ENGINEERING | MACHINE LEARNING</div>
          <h2 style="margin:0.4rem 0 0.5rem 0;">Resource Hub For The Data Community</h2>
          <p style="margin:0;color:#b8b8d4;">Browse hand-picked PDFs, docs, repos, and links for data learning.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    hero_left, hero_right = st.columns([2.1, 1], gap="large")
    with hero_left:
        q = st.text_input("Search resources", placeholder="Try: prompt engineering, airflow, mlops...")
        type_filter = st.selectbox("Type", ["All", "File", "Link"])
    with hero_right:
        st.markdown("<div class='signup-card'><h3 style='margin-top:0'>Get Updates</h3>", unsafe_allow_html=True)
        st.caption("Sign in with Google to receive updates when new resources are published.")
        user = st.session_state.get("google_user")
        if settings.google_client_id and settings.google_client_secret:
            if user:
                st.success(f"Signed in as {user.get('email', 'Google user')}")
                if is_allowed_admin(settings):
                    st.caption("Admin email recognized.")
            else:
                sign_url = google_auth_url(settings, new_oauth_state(settings))
                st.markdown(
                    f"""
                    <a class="google-btn" href="{sign_url}" target="_self" rel="noopener">
                      <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303C33.65 32.657 29.206 36 24 36c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.963 3.037l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/>
                        <path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.963 3.037l5.657-5.657C34.046 6.053 29.268 4 24 4c-7.682 0-14.318 4.337-17.694 10.691z"/>
                        <path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.14 35.091 26.715 36 24 36c-5.185 0-9.617-3.329-11.283-7.946l-6.522 5.025C9.53 39.556 16.227 44 24 44z"/>
                        <path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.084 5.571l.003-.002 6.19 5.238C37.03 39.1 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/>
                      </svg>
                      <span>Sign up with Google</span>
                    </a>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable Google signups.")
        st.markdown("</div>", unsafe_allow_html=True)

    if store is None:
        st.warning("Public resources are unavailable until MySQL is configured.")
        return

    rows = get_resources_cached(store)
    if q.strip():
        needle = q.strip().lower()
        rows = [r for r in rows if needle in (r.get("title") or "").lower() or needle in (r.get("description") or "").lower()]
    if type_filter != "All":
        rows = [r for r in rows if (r.get("resource_type") or "").lower() == type_filter.lower()]

    st.caption(f"{len(rows)} resource(s)")
    for item in rows:
        created_at = item.get("created_at")
        if isinstance(created_at, datetime):
            created = created_at.strftime("%Y-%m-%d")
        else:
            created = str(created_at or "")
        st.markdown(f"<div class='resource-card'><h3 style='margin:0'>{item.get('title')}</h3>", unsafe_allow_html=True)
        if item.get("description"):
            st.write(item["description"])
        st.markdown(
            f"<div class='resource-meta'>Type: {(item.get('resource_type') or '').upper()} | Category: {item.get('category') or '-'} | Uploaded: {created}</div>",
            unsafe_allow_html=True,
        )
        c1, c2, c3 = st.columns(3)
        with c1:
            if item.get("view_url"):
                st.link_button("View", item["view_url"], use_container_width=True)
            elif item.get("external_url"):
                st.link_button("Open Link", item["external_url"], use_container_width=True)
        with c2:
            if item.get("download_url"):
                st.link_button("Download", item["download_url"], use_container_width=True)
            elif item.get("external_url"):
                st.link_button("Visit", item["external_url"], use_container_width=True)
        with c3:
            st.markdown(f"<span class='small-note'>{fmt_size(item.get('file_size'))}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


def render_questions_page(store: MySQLStore | None) -> None:
    st.markdown(
        """
        <div class="hero">
          <div class="hero-kicker">COMMUNITY DESK</div>
          <h2 style="margin:0.4rem 0 0.5rem 0;">Ask A Question</h2>
          <p style="margin:0;color:#b8b8d4;">Send your learning question, feedback, or resource request.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.form("query_form", clear_on_submit=True):
        name = st.text_input("Name")
        email = st.text_input("Email")
        message = st.text_area("Message")
        send = st.form_submit_button("Send Message")
    if send:
        if not store:
            st.error("MySQL is not configured.")
        elif not (name.strip() and email.strip() and message.strip()):
            st.warning("Please fill in all fields.")
        else:
            store.execute(
                f"INSERT INTO {TABLE_USER_QUERIES} (name, email, message) VALUES (%s, %s, %s)",
                (name.strip(), email.strip(), message.strip()),
            )
            clear_data_caches()
            st.success("Message received. Thank you.")


def render_admin_panel(store: MySQLStore | None, github: GitHubOps | None, settings: Settings) -> None:
    st.subheader("Admin")
    if not is_allowed_admin(settings):
        st.warning("Admin area is restricted to allowlisted Google account emails.")
        st.caption("Set ADMIN_EMAILS in .env and sign in with that Google account.")
        return

    if not st.session_state.get("admin_ok"):
        with st.form("admin_login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Sign in")
        if submit:
            if username == settings.admin_username and password == settings.admin_password:
                st.session_state["admin_ok"] = True
                st.success("Admin login successful.")
                st.rerun()
            else:
                st.error("Invalid credentials.")
        return

    st.success("Admin access granted.")
    if st.button("Logout Admin"):
        st.session_state["admin_ok"] = False
        st.rerun()

    if store is None:
        st.error("MySQL is required for admin operations.")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["Upload File", "Add Link", "Messages", "Google Signups"])

    with tab1:
        st.caption("Files are uploaded to your GitHub repo via PAT.")
        with st.form("upload_form", clear_on_submit=True):
            title = st.text_input("Title")
            description = st.text_area("Description")
            category = st.text_input("Category", value="General")
            upload = st.file_uploader("Upload PDF/DOC/ZIP/etc")
            do_upload = st.form_submit_button("Upload Resource")
        if do_upload:
            if not upload:
                st.warning("Choose a file first.")
            elif not title.strip():
                st.warning("Title is required.")
            elif not github:
                st.error("GitHub upload is not configured. Set USE_GITHUB_UPLOAD=true and GitHub env keys.")
            else:
                try:
                    result = github.upload_bytes(upload.name, upload.getvalue())
                    store.execute(
                        f"""
                        INSERT INTO {TABLE_RESOURCES} (
                            title, description, resource_type, category, file_name, file_size, mime_type,
                            github_path, view_url, download_url, created_by
                        ) VALUES (%s, %s, 'file', %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            title.strip(),
                            description.strip(),
                            category.strip() or "General",
                            upload.name,
                            int(upload.size or 0),
                            upload.type or "application/octet-stream",
                            result.repo_path,
                            result.view_url,
                            result.download_url,
                            settings.admin_username,
                        ),
                    )
                    clear_data_caches()
                    st.success("File uploaded and published.")
                except Exception as exc:
                    report_error("admin_file_upload", exc)
                    public_error("Upload failed. Please verify GitHub configuration and try again.")

    with tab2:
        with st.form("link_form", clear_on_submit=True):
            title = st.text_input("Link Title")
            description = st.text_area("Link Description")
            category = st.text_input("Category", value="General", key="link_category")
            url = st.text_input("Link URL", placeholder="https://...")
            add_link = st.form_submit_button("Publish Link")
        if add_link:
            if not (title.strip() and url.strip()):
                st.warning("Title and URL are required.")
            else:
                store.execute(
                    f"""
                    INSERT INTO {TABLE_RESOURCES} (
                        title, description, resource_type, category, external_url, view_url, download_url, created_by
                    ) VALUES (%s, %s, 'link', %s, %s, %s, %s, %s)
                    """,
                    (
                        title.strip(),
                        description.strip(),
                        category.strip() or "General",
                        url.strip(),
                        url.strip(),
                        url.strip(),
                        settings.admin_username,
                    ),
                )
                clear_data_caches()
                st.success("Link added.")

    with tab3:
        st.markdown("### User messages")
        q_rows = get_queries_cached(store)
        st.dataframe(q_rows, use_container_width=True, hide_index=True)

    with tab4:
        st.markdown("### Google signups")
        g_rows = get_google_signups_cached(store)
        st.dataframe(g_rows, use_container_width=True, hide_index=True)

    st.markdown("### Manage Existing Resources")
    resources = get_resources_cached(store)
    for item in resources:
        cols = st.columns([6, 2, 2])
        cols[0].write(f"**{item.get('title')}**  \n`{item.get('resource_type')}` | {item.get('category') or 'General'}")
        if item.get("view_url"):
            cols[1].link_button("Open", item["view_url"], use_container_width=True)
        if cols[2].button("Delete", key=f"delete_{item['id']}", use_container_width=True):
            if item.get("github_path") and github:
                github.delete_path(item["github_path"])
            store.execute(f"DELETE FROM {TABLE_RESOURCES} WHERE id=%s", (item["id"],))
            clear_data_caches()
            st.success("Deleted.")
            st.rerun()


def main() -> None:
    settings = get_settings()
    init_session_state()
    st.set_page_config(page_title=settings.app_name, page_icon="book", layout="wide")
    inject_styles()

    store: MySQLStore | None = None
    db_error: bool = False
    github: GitHubOps | None = None

    try:
        store = get_store(settings)
    except Exception as exc:
        report_error("db_init", exc)
        db_error = True
        store = None

    try:
        github = get_github_ops(settings)
    except Exception as exc:
        report_error("github_init", exc)
        st.warning("GitHub upload is currently unavailable.")

    handle_google_callback(settings, store)

    st.title(settings.app_name)
    st.caption("A curated learning portal for data enthusiasts.")
    if db_error:
        public_error("Database connection is unavailable. Please check configuration and network access.")

    pages = ["Resource Hub", "Ask A Question"]
    if is_allowed_admin(settings):
        pages.append("Admin")
    page = st.radio("Navigation", pages, horizontal=True, label_visibility="collapsed")

    if page == "Resource Hub":
        render_public_hub(store, settings)
    elif page == "Ask A Question":
        render_questions_page(store)
    else:
        render_admin_panel(store, github, settings)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        report_error("fatal", exc)
        public_error("An unexpected error occurred. Please try again.")
