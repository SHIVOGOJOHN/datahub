# Data Creator Hub (Streamlit)

Simple Streamlit resource hub for your TikTok data/AI audience:
- Public beautiful frontend for resources (files + links)
- Dedicated `Ask A Question` page for learner messages
- Admin-only upload page 
- Admin page visibility locked to allowlisted Google emails (`ADMIN_EMAILS`)
- Google OAuth signup for email updates
- MySQL storage for resources, Google signups, and user queries/messages
- GitHub PAT upload pipeline for file resources

## 1) Setup

1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and fill in your real values.
   - Set `ADMIN_EMAILS` to your Gmail (or comma-separated admin emails).
   - For managed MySQL (Aiven, etc.), set:
     - `MYSQL_SSL_DISABLED=false`
     - `MYSQL_SSL_CA=ca.pem` (or absolute path to the CA certificate)

## 2) Run

```bash
streamlit run app.py
```

## 3) Notes

- For Google OAuth, set `GOOGLE_REDIRECT_URI` to your deployed app URL (or local `http://localhost:8501` during development), and register the same URI in Google Cloud Console.
- Set `APP_SESSION_SECRET` to a long random value for signed OAuth state validation.
- Admin tab is only shown when the signed-in Google account email is in `ADMIN_EMAILS`.
- For GitHub uploads, use a PAT with `repo` scope.
- The app auto-creates required MySQL tables on startup.
