# M-Sync API Routes

Base URL: `http://localhost:4000` (or your deployed URL).

All authenticated routes expect: `Authorization: Bearer <jwt_token>` or `token` in body/query.

---

## Auth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | No | Register: body `{ email, password, full_name? }`. Returns `{ user, token }`. |
| POST | `/api/auth/login` | No | Login: body `{ email, password }`. Returns `{ user, token }`. |
| GET | `/api/auth/me` | Yes | Current user profile. |
| GET | `/api/auth/callback` | No | OAuth callback from CRM (redirect URI – must not contain "ghl"). |

---

## Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/users/profile` | Yes | Profile + plan + credits. |
| GET | `/api/users/credits` | Yes | `{ credits_remaining }`. |
| GET | `/api/users/feature-flags` | Yes | `{ flags: { auto_save_on_send: boolean, ... } }` for extension. |

---

## GoHighLevel (GHL)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/ghl/connect` | Yes | Redirect to GHL OAuth. |
| GET | `/api/ghl/status` | Yes | `{ connected, location_id? }`. |
| GET | `/api/ghl/contacts/:email` | Yes | Search contact by email. |
| GET | `/api/ghl/contacts/:contactId/profile` | Yes | Contact profile + tasks. |
| POST | `/api/ghl/contacts` | Yes | Create/update contact. Body: GHL contact fields. |
| POST | `/api/ghl/tasks` | Yes | Create task. Body: contactId, title, etc. |
| PATCH | `/api/ghl/tasks/:taskId` | Yes | Update task (e.g. complete). |
| POST | `/api/ghl/sync-email` | Yes | Log email to CRM (uses 1 credit). Body: `{ gmail_message_id, ghl_contact_id?, subject? }`. |

---

## Signature parsing

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/signature/parse` | Yes | Body `{ raw_text, email_message_id?, save? }`. Returns parsed `{ full_name, company, phone, email }`. |

---

## Admin (role = admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin/users` | Admin | List users with plan. |
| GET | `/api/admin/plans` | Admin | List plans. |
| PATCH | `/api/admin/users/:id` | Admin | Update user: `{ plan_id?, credits_remaining?, role? }`. |
| GET | `/api/admin/synced-emails` | Admin | List synced emails (all users). Query: `limit`, `offset`. |
| GET | `/api/admin/sync-logs` | Admin | List sync attempts. Query: `limit`, `offset`, `user_id`, `date_from`, `date_to`. |
| GET | `/api/admin/feature-flags` | Admin | List feature flags. |
| PATCH | `/api/admin/feature-flags` | Admin | Set flag: body `{ flag_key, enabled: boolean }`. |
