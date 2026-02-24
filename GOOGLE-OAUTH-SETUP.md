# Google Sign-In (Continue with Google) Setup

If you see **"Google sign-in not configured"**, add Google OAuth credentials and set these in your backend `.env`:

## 1. Create OAuth credentials in Google Cloud

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Select or create a project.
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
4. Application type: **Web application**.
5. Name: e.g. "M-Sync" or "M-Sync Dev".
6. **Authorized redirect URIs** – add exactly:
   - **Local:** `http://localhost:4000/api/auth/google/callback`
   - **Production:** `https://your-api-domain.com/api/auth/google/callback`
7. Save. Copy the **Client ID** and **Client secret**.

## 2. Set environment variables

In your backend `.env` (or root `m-sync/.env`):

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
```

For **local dev** (no ngrok), you do **not** need to set `BACKEND_BASE_URL`; the backend defaults to `http://localhost:4000`.

For **ngrok** or **production**, set:

```env
BACKEND_BASE_URL=https://starrier-gilda-demurest.ngrok-free.dev
```

(or your ngrok/production URL). Use **https**. The backend will force **https** for redirect URIs when the URL contains `ngrok`, so the redirect URI sent to Google is always `https://your-ngrok-url/api/auth/google/callback`. Add that exact URI in Google Cloud Console → Credentials → your OAuth client → Authorized redirect URIs.

## 3. Run the database migration (required for Google sign-in)

The `users` table needs a `google_id` column and nullable `password_hash`. Run:

```bash
mysql -u root -p msync < backend/database/alter-users-google-oauth.sql
```

(Use your DB user/password and database name. If `google_id` already exists, skip or comment out the first line in that file.)

## 4. Restart the backend

Restart the Node server so it picks up the new env vars. Then try **Login with Google** again.

## Troubleshooting

- **"Sign-in failed. Close and try again."** – Check the **backend terminal** for the real error (e.g. `[Google OAuth] callback error` or `redirectError:`). Common causes: redirect URI in Google Console doesn’t match exactly (must be `https://your-ngrok-url.ngrok-free.dev/api/auth/google/callback`), or the migration wasn’t run (you’ll see "Unknown column 'google_id'").
- **{"error":"Login failed"}** – Check the backend terminal for "Login error:". If you see "Column 'password_hash' cannot be null" or similar, run the migration above. If the account was created with Google only, use "Login with Google" instead of email/password.
- **Ngrok:** Use `https://` in `BACKEND_BASE_URL` (e.g. `https://starrier-gilda-demurest.ngrok-free.dev`).

---

## Using ngrok (free tier)

If your backend is served through **ngrok** (e.g. `https://xxx.ngrok-free.dev`), the free tier shows a “You are about to visit…” warning page. This app works around it:

- **Backend:** When a request hits an auth URL (e.g. `/api/auth/google`, `/api/auth/google/callback`, `/api/auth/callback`) without the `ngrok-skip-browser-warning` header, the server returns a small HTML page that refetches the same URL with that header and then redirects. So after you click “Visit Site” once, sign-in completes.
- **Dashboard & extension:** All API requests to an ngrok URL include the `ngrok-skip-browser-warning` header so programmatic calls skip the warning.

To remove the warning entirely, use a paid ngrok plan or another tunnel that doesn’t show the interstitial.
