# Secure Vault — Hackathon Local Demo

This version is prepared for a **local Tuesday hackathon demo**.

## What was changed

- Secure Share now uses `APP_URL` instead of building links from the current request host.
- Local share links use:
  `http://localhost:3000/share/<token>`
- A recipient can open the share link in another browser/device and see only the shared file.
- Password-protected shares use a short-lived public-share authorization session.
- Image, video and PDF files can be previewed from the Secure Share page.
- Download controls, expiry, maximum downloads and revoke are enforced server-side.
- Share tokens are generated with `crypto.randomBytes()`.
- Existing file upload/storage flow is preserved. `config/multer.js` and `config/cloudinary.js` were not modified.
- Existing authentication and Google login flow are preserved.
- Landing page and shared application styles were redesigned using the existing black / royal-blue / light-gray palette. Existing logo files were not changed.

## Local setup

1. Open a terminal in this folder.
2. Install dependencies:

```bash
npm install
```

3. Confirm `.env` contains:

```env
PORT=3000
NODE_ENV=development
APP_URL=http://localhost:3000
```

4. Make sure `DATABASE_URL`, Cloudinary credentials and the existing authentication credentials point to your working local/demo environment.

5. Start:

```bash
node app.js
```

6. Open:

```text
http://localhost:3000
```

## Secure Share demo

1. Register/login.
2. Upload a file through the existing Vault file pages.
3. Open **Tools → Secure File Sharing**.
4. Select the existing Vault file.
5. Optionally set a password, expiry and download limit.
6. Create the secure link.
7. Copy the `http://localhost:3000/share/...` link.
8. Open it in Chrome Incognito or another device connected to the same machine/network using the host machine's LAN IP when required.
9. The recipient sees only the shared file.

### Important for another physical phone

`localhost` on a phone means the phone itself, not the laptop running Secure Vault. For a phone on the same Wi-Fi, use the laptop's LAN address for the demo, for example:

```text
http://192.168.x.x:3000/share/<token>
```

If you want generated links to automatically use the LAN address during the demo, set `APP_URL` in `.env` to the laptop's LAN address before starting the server.

## Database

The application automatically creates the Secure Vault feature tables when it starts, including `secure_shares`, `audit_logs`, `login_events` and `identity_items`. Existing `media` storage is reused.

## Security note

This local-demo package contains the project's existing `.env` because the demo environment requested a ready-to-run local package. **Do not publish this ZIP or commit `.env` to GitHub.** Rotate credentials immediately if this package is ever shared outside your trusted demo environment.

## Local Hackathon Admin Portal

Open `http://localhost:3000/admin/login` for the separate administrator login.

Default local demo credentials:
- Email: `admin@securevault.local`
- Password: `SecureVault@Admin123`

Change `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` before any public deployment. The admin portal uses a separate session flag and does not change the normal user authentication flow.


## Hackathon Admin Portal
Admin is separate from normal user authentication.

- `/admin/login`
- `/admin/dashboard` — platform overview
- `/admin/users` — registered users
- `/admin/files` — all stored files
- `/admin/shares` — secure-share management and revoke
- `/admin/audit` — user + admin audit center
- `/admin/settings` — runtime/admin configuration

The website includes a persistent Light/Dark theme toggle. The existing Multer/Cloudinary file-storage flow is preserved.
