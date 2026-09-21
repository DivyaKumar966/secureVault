# Secure Vault — Secure Sharing Setup

## User flow
- Dashboard → **Secure File Sharing**
- Select a vault file
- Optional share password
- Optional expiry
- Optional maximum download/access limit
- Optional download permission
- Create, copy, open or revoke the secure link

## Render link generation
The application does **not** hard-code `localhost` into generated share links. In production it uses `APP_URL` when it is a real public URL; otherwise it uses the forwarded Render host automatically.

Recommended Render environment variable:
```text
APP_URL=https://YOUR-RENDER-SERVICE.onrender.com
```

The generated link will look like:
```text
https://YOUR-RENDER-SERVICE.onrender.com/share/<token>
```

## Important
- Keep the existing Cloudinary upload/storage flow unchanged.
- Keep `DATABASE_URL`, Cloudinary credentials, Google OAuth credentials and `SESSION_SECRET` in Render Environment Variables.
- Do not commit `.env`.

## Admin
The Admin Portal now exposes only Secure Share information: file, owner, password-protection state, download/access limits, expiry, status and revoke/open actions. The actual share password is never displayed.
