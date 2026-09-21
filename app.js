import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import upload from "./config/multer.js";
import cloudinary from "./config/cloudinary.js";
import env from "dotenv";
import { Readable } from "stream";
import crypto from "crypto";
import os from "os";

// ================= ENV =================
env.config();

// ================= APP =================
const app = express();
const port = process.env.PORT || 3000;
const configuredAppUrl = (process.env.APP_URL || `http://localhost:${port}`).replace(/\/$/, "");

function getAppUrl(req) {
    const requestHost = req.get("x-forwarded-host") || req.get("host");
    const forwardedProto = req.get("x-forwarded-proto");
    const protocol = forwardedProto ? forwardedProto.split(",")[0].trim() : req.protocol;
    const requestUrl = requestHost ? `${protocol}://${requestHost}`.replace(/\/$/, "") : null;

    // Render / production: never generate localhost links. If APP_URL is not
    // configured or still points to localhost, use the public proxy host.
    if (process.env.NODE_ENV === "production") {
        if (process.env.APP_URL && !/localhost|127\.0\.0\.1/i.test(process.env.APP_URL)) {
            return configuredAppUrl;
        }
        if (requestUrl) return requestUrl;
        return configuredAppUrl;
    }

    // Local demo: respect a non-local APP_URL when explicitly configured.
    if (process.env.APP_URL && !/localhost|127\.0\.0\.1/i.test(process.env.APP_URL)) {
        return configuredAppUrl;
    }

    // Prefer the current host when the app is opened through a LAN IP.
    if (requestHost && !/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(requestHost)) {
        return requestUrl;
    }

    // When opened on localhost, automatically pick a private IPv4 address
    // so a phone on the same Wi-Fi can open the generated link.
    const interfaces = os.networkInterfaces();
    for (const entries of Object.values(interfaces)) {
        for (const entry of entries || []) {
            if (entry.family === "IPv4" && !entry.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(entry.address)) {
                return `http://${entry.address}:${port}`;
            }
        }
    }

    return `http://localhost:${port}`;
}

const saltRounds = 10;

// Render / reverse-proxy support for reliable client IPs.
app.set("trust proxy", 1);

// ================= SESSION =================
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 7 * 24 * 60 * 60 * 1000
        }
    })
);

// ================= MIDDLEWARE =================
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

// Make authentication state available to all EJS pages.
app.use((req, res, next) => {
    res.locals.isAdmin = req.session?.isAdmin === true;
    res.locals.adminEmail = req.session?.adminEmail || null;
    res.locals.currentPath = req.path;
    next();
});

// ================= POSTGRESQL =================
const db = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

db.connect()
    .then(client => {
        console.log("PostgreSQL connected successfully");
        client.release();
    })
    .catch(err => console.log("PostgreSQL connection error:", err));

// ======================================================
// DATABASE BOOTSTRAP FOR NEW SECURE VAULT FEATURES
// ======================================================
async function ensureFeatureTables() {
    await db.query(`
        ALTER TABLE media
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL,
        ADD COLUMN IF NOT EXISTS is_self_destruct BOOLEAN NOT NULL DEFAULT FALSE
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action VARCHAR(80) NOT NULL,
            details TEXT,
            ip_address VARCHAR(100),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS login_events (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider VARCHAR(30) NOT NULL DEFAULT 'local',
            ip_address VARCHAR(100),
            user_agent TEXT,
            fingerprint VARCHAR(128),
            suspicious BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS secure_shares (
            id SERIAL PRIMARY KEY,
            media_id INT NOT NULL REFERENCES media(id) ON DELETE CASCADE,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(128) UNIQUE NOT NULL,
            password_hash VARCHAR(255),
            expires_at TIMESTAMP NULL,
            max_downloads INT NULL,
            download_count INT NOT NULL DEFAULT 0,
            allow_download BOOLEAN NOT NULL DEFAULT TRUE,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS identity_items (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            media_id INT NOT NULL REFERENCES media(id) ON DELETE CASCADE,
            label VARCHAR(120) NOT NULL,
            category VARCHAR(80) NOT NULL DEFAULT 'Identity',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, media_id, label)
        )
    `);
}

ensureFeatureTables()
    .then(() => console.log("Secure Vault feature tables ready"))
    .catch(err => console.log("Feature table setup error:", err));

// ======================================================
// HELPERS
// ======================================================
function requireAuth(req, res, next) {
    if (!req.isAuthenticated()) return res.redirect("/login");
    next();
}

function clientIp(req) {
    return req.ip || req.headers["x-forwarded-for"] || "unknown";
}

function fingerprintFor(req) {
    return crypto
        .createHash("sha256")
        .update(`${clientIp(req)}|${req.get("user-agent") || "unknown"}`)
        .digest("hex");
}

async function recordAudit(req, action, details = "") {
    if (!req.user?.id) return;
    try {
        await db.query(
            `INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent)
             VALUES ($1,$2,$3,$4,$5)`,
            [req.user.id, action, details, clientIp(req), req.get("user-agent") || "unknown"]
        );
    } catch (err) {
        console.log("Audit log error:", err.message);
    }
}

async function recordLogin(req, user, provider = "local") {
    const fingerprint = fingerprintFor(req);
    const [previous, anyLogin] = await Promise.all([
        db.query(
            `SELECT id FROM login_events
             WHERE user_id = $1 AND fingerprint = $2
             LIMIT 1`,
            [user.id, fingerprint]
        ),
        db.query(
            `SELECT id FROM login_events
             WHERE user_id = $1
             LIMIT 1`,
            [user.id]
        )
    ]);
    const suspicious = anyLogin.rows.length > 0 && previous.rows.length === 0;

    await db.query(
        `INSERT INTO login_events
         (user_id, provider, ip_address, user_agent, fingerprint, suspicious)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [user.id, provider, clientIp(req), req.get("user-agent") || "unknown", fingerprint, suspicious]
    );

    req.user = user;
    await recordAudit(
        req,
        suspicious ? "SUSPICIOUS_LOGIN" : "LOGIN",
        `${provider} login from ${req.get("user-agent") || "unknown"}`
    );
}

function cloudinaryResourceType(fileType) {
    if (fileType === "video") return "video";
    if (fileType === "image") return "image";
    return "raw";
}

async function deleteCloudinaryFile(file) {
    await cloudinary.uploader.destroy(file.public_id, {
        resource_type: cloudinaryResourceType(file.file_type)
    });
}

function uploadToCloudinary(buffer, resourceType = "auto", originalName = "file") {
    return new Promise((resolve, reject) => {
        const extension = originalName.includes(".")
            ? originalName.substring(originalName.lastIndexOf("."))
            : "";

        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: "secure-vault",
                resource_type: resourceType,
                use_filename: false,
                public_id: `vault-${Date.now()}-${crypto.randomBytes(5).toString("hex")}${resourceType === "raw" ? extension : ""}`
            },
            (error, result) => error ? reject(error) : resolve(result)
        );

        Readable.from(buffer).pipe(uploadStream);
    });
}

function expiryToDate(value) {
    if (!value || value === "none") return null;
    const now = Date.now();
    const map = {
        "1h": 60 * 60 * 1000,
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
        "30d": 30 * 24 * 60 * 60 * 1000
    };
    if (map[value]) return new Date(now + map[value]);
    return null;
}

async function purgeExpiredFiles() {
    try {
        const result = await db.query(
            `SELECT * FROM media
             WHERE is_self_destruct = TRUE
             AND expires_at IS NOT NULL
             AND expires_at <= NOW()`
        );

        for (const file of result.rows) {
            try {
                await deleteCloudinaryFile(file);
            } catch (err) {
                console.log("Cloudinary expiry deletion error:", err.message);
            }

            await db.query(`DELETE FROM media WHERE id = $1`, [file.id]);
        }

        if (result.rows.length) {
            console.log(`Self-destruct cleanup removed ${result.rows.length} file(s)`);
        }
    } catch (err) {
        console.log("Self-destruct cleanup error:", err.message);
    }
}

setInterval(purgeExpiredFiles, 5 * 60 * 1000);
purgeExpiredFiles();

// ======================================================
// ADMIN AUTHENTICATION - SEPARATE FROM USER AUTH
// ======================================================
const adminEmail = (process.env.ADMIN_EMAIL || "admin@securevault.local").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "SecureVault@Admin123";

function requireAdmin(req, res, next) {
    if (req.session?.isAdmin === true && req.session?.adminEmail === adminEmail) return next();
    return res.redirect("/admin/login");
}

async function ensureAdminTables() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS admin_audit_logs (
            id SERIAL PRIMARY KEY,
            admin_email VARCHAR(150) NOT NULL,
            action VARCHAR(100) NOT NULL,
            details TEXT,
            ip_address VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
}

async function recordAdminAudit(req, action, details = "") {
    try {
        await db.query(
            `INSERT INTO admin_audit_logs (admin_email, action, details, ip_address)
             VALUES ($1,$2,$3,$4)`,
            [adminEmail, action, details, clientIp(req)]
        );
    } catch (err) {
        console.log("Admin audit error:", err.message);
    }
}

ensureAdminTables()
    .then(() => console.log("Admin tables ready"))
    .catch(err => console.log("Admin table setup error:", err.message));

// ======================================================
// ADMIN PORTAL
// ======================================================
app.get("/admin/login", (req, res) => {
    if (req.session?.isAdmin) return res.redirect("/admin/dashboard");
    res.render("admin-login.ejs", { error: null, adminEmail });
});

app.post("/admin/login", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (email !== adminEmail || password !== adminPassword) {
        return res.status(401).render("admin-login.ejs", {
            error: "Invalid administrator credentials.",
            adminEmail: ""
        });
    }

    req.session.isAdmin = true;
    req.session.adminEmail = adminEmail;
    await recordAdminAudit(req, "ADMIN_LOGIN", "Administrator signed in");
    res.redirect("/admin/dashboard");
});

app.get("/admin/dashboard", requireAdmin, (req, res) => {
    res.redirect("/admin/shares");
});

app.get("/admin/users", requireAdmin, (req, res) => res.redirect("/admin/shares"));
app.get("/admin/files", requireAdmin, (req, res) => res.redirect("/admin/shares"));
app.get("/admin/shares", requireAdmin, async (req, res) => {
    try {
        const result = await db.query(`SELECT s.id,s.token,s.created_at,s.expires_at,s.download_count,s.max_downloads,s.allow_download,s.revoked,
            (s.password_hash IS NOT NULL) AS password_protected, m.file_name,u.email
            FROM secure_shares s
            JOIN media m ON m.id=s.media_id
            JOIN users u ON u.id=s.user_id
            ORDER BY s.created_at DESC`);
        res.render("admin-shares.ejs", { shares: result.rows, adminEmail: req.session.adminEmail });
    } catch (err) {
        console.log("Admin shares error:", err.message);
        res.status(500).send("Unable to load secure shares.");
    }
});

app.get("/admin/audit", requireAdmin, (req, res) => res.redirect("/admin/shares"));
app.get("/admin/settings", requireAdmin, (req, res) => res.redirect("/admin/shares"));
app.get("/admin/logout", async (req, res) => {
    if (req.session?.isAdmin) await recordAdminAudit(req, "ADMIN_LOGOUT", "Administrator signed out");
    delete req.session.isAdmin;
    delete req.session.adminEmail;
    res.redirect("/admin/login");
});

// ======================================================
// HOME
// ======================================================
app.get("/", (req, res) => res.render("home.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));

// ======================================================
// DASHBOARD - EXISTING FLOW PRESERVED + STATS
// ======================================================
app.get("/dashboard", requireAuth, async (req, res) => {
    try {
        const stats = await db.query(
            `SELECT
                COUNT(*)::int AS total,
                COALESCE(SUM(file_size),0)::bigint AS bytes,
                COUNT(*) FILTER (WHERE file_type='image')::int AS images,
                COUNT(*) FILTER (WHERE file_type='video')::int AS videos,
                COUNT(*) FILTER (WHERE file_type='document')::int AS documents,
                COUNT(*) FILTER (WHERE file_type='text')::int AS texts
             FROM media WHERE user_id=$1`,
            [req.user.id]
        );
        res.render("dashboard.ejs", { stats: stats.rows[0] });
    } catch (err) {
        console.log(err);
        res.render("dashboard.ejs", {
            stats: { total: 0, bytes: 0, images: 0, videos: 0, documents: 0, texts: 0 }
        });
    }
});

// ======================================================
// LOGOUT - EXISTING FLOW PRESERVED
// ======================================================
app.get("/logout", (req, res, next) => {
    req.logout(err => {
        if (err) return next(err);
        req.session.destroy(() => res.redirect("/"));
    });
});

// ======================================================
// FILES PAGE - EXISTING FLOW PRESERVED
// ======================================================
app.get("/files/:type", requireAuth, async (req, res) => {
    const allowed = ["image", "video", "document", "text"];
    const type = req.params.type;
    if (!allowed.includes(type)) return res.status(404).send("Invalid file type.");

    try {
        const result = await db.query(
            `SELECT * FROM media WHERE user_id=$1 AND file_type=$2 ORDER BY uploaded_at DESC`,
            [req.user.id, type]
        );
        res.render("files.ejs", { type, files: result.rows });
    } catch (err) {
        console.log(err);
        res.status(500).send("Database Error");
    }
});

// ======================================================
// GOOGLE LOGIN
// ======================================================
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/secrets", (req, res, next) => {
    passport.authenticate("google", (err, user) => {
        if (err || !user) return res.redirect("/login");
        req.login(user, async loginErr => {
            if (loginErr) return next(loginErr);
            try { await recordLogin(req, user, "google"); } catch (e) { console.log("Google login log error:", e.message); }
            res.redirect("/dashboard");
        });
    })(req, res, next);
});

// ======================================================
// LOCAL LOGIN - SAME USER FLOW, WITH SECURITY LOGGING
// ======================================================
app.post("/login", (req, res, next) => {
    passport.authenticate("local", (err, user) => {
        if (err) return next(err);
        if (!user) return res.redirect("/login");
        req.login(user, async loginErr => {
            if (loginErr) return next(loginErr);
            try { await recordLogin(req, user, "local"); } catch (e) { console.log("Login log error:", e.message); }
            res.redirect("/dashboard");
        });
    })(req, res, next);
});

// ======================================================
// REGISTER - EXISTING FLOW PRESERVED
// ======================================================
app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    try {
        const checkResult = await db.query(`SELECT * FROM users WHERE email=$1`, [email]);
        if (checkResult.rows.length > 0) return res.redirect("/login");

        const hash = await bcrypt.hash(password, saltRounds);
        const result = await db.query(
            `INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *`,
            [email, hash]
        );
        const user = result.rows[0];
        req.login(user, async err => {
            if (err) return res.status(500).send("Login error");
            try { await recordLogin(req, user, "local"); } catch (e) { console.log("Register log error:", e.message); }
            res.redirect("/dashboard");
        });
    } catch (err) {
        console.log(err);
        res.status(500).send("Registration failed");
    }
});

// ======================================================
// UPLOAD FILE - EXISTING FLOW + OPTIONAL SELF-DESTRUCT
// ======================================================
app.post("/upload", upload.single("file"), async (req, res) => {
    try {
        if (!req.isAuthenticated()) return res.redirect("/login");
        if (!req.file) return res.status(400).send("No file selected.");

        const type = req.body.type;
        const mime = req.file.mimetype;
        const fileSize = req.file.size;
        const MB = 1024 * 1024;

        if (type === "image" && !mime.startsWith("image/")) return res.send("Only Image files are allowed.");
        if (type === "video" && !mime.startsWith("video/")) return res.send("Only Video files are allowed.");

        if (type === "document") {
            const allowedDocs = [
                "application/pdf", "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.ms-powerpoint",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ];
            if (!allowedDocs.includes(mime)) return res.send("Only Document files are allowed.");
        }

        if (type === "text") {
            const allowedText = ["text/plain", "application/json", "text/csv", "application/xml", "text/xml"];
            if (!allowedText.includes(mime)) return res.send("Only Text files are allowed.");
        }

        if (type === "video" && fileSize > 100 * MB) return res.send("Video size must be below 100 MB.");
        if (type !== "video" && fileSize > 10 * MB) return res.send("File size must be below 10 MB.");

        const resourceType = type === "video" ? "video" : type === "image" ? "image" : "raw";
        const result = await uploadToCloudinary(req.file.buffer, resourceType, req.file.originalname);
        const expiresAt = expiryToDate(req.body.expiry);
        const selfDestruct = Boolean(expiresAt);

        await db.query(
            `INSERT INTO media
             (user_id,file_name,file_type,file_url,public_id,file_size,expires_at,is_self_destruct)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [req.user.id, req.file.originalname, type, result.secure_url, result.public_id, result.bytes, expiresAt, selfDestruct]
        );

        await recordAudit(req, "FILE_UPLOADED", `${req.file.originalname} (${type})${selfDestruct ? " with self-destruct" : ""}`);
        res.redirect("/files/" + type);
    } catch (err) {
        console.log("UPLOAD ERROR:", err);
        res.status(500).send("Upload failed: " + err.message);
    }
});

// ======================================================
// DOWNLOAD FILE
// ======================================================
app.get("/download/:id", requireAuth, async (req, res) => {
    try {
        const result = await db.query(`SELECT * FROM media WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).send("File not found.");
        const file = result.rows[0];
        if (file.is_self_destruct && file.expires_at && new Date(file.expires_at) <= new Date()) {
            return res.status(410).send("This file has self-destructed.");
        }

        const response = await fetch(file.file_url);
        if (!response.ok) return res.status(500).send("Unable to download file.");
        const buffer = await response.arrayBuffer();
        res.setHeader("Content-Disposition", `attachment; filename="${file.file_name.replace(/"/g, "")}"`);
        res.setHeader("Content-Type", response.headers.get("content-type") || "application/octet-stream");
        await recordAudit(req, "FILE_DOWNLOADED", file.file_name);
        res.send(Buffer.from(buffer));
    } catch (err) {
        console.log(err);
        res.status(500).send("Download failed.");
    }
});

// ======================================================
// DELETE FILE
// ======================================================
app.post("/delete/:id", requireAuth, async (req, res) => {
    try {
        const result = await db.query(`SELECT * FROM media WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).send("File not found.");
        const file = result.rows[0];
        await deleteCloudinaryFile(file);
        await db.query(`DELETE FROM media WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
        await recordAudit(req, "FILE_DELETED", file.file_name);
        res.redirect("/files/" + file.file_type);
    } catch (err) {
        console.log(err);
        res.status(500).send("Delete failed.");
    }
});

// ======================================================
// SECURE SHARING ENTRY
// ======================================================
// Old Tools URLs are kept only as compatibility redirects.
app.get("/tools", requireAuth, (req, res) => res.redirect("/sharing"));
app.get("/tools/sharing", requireAuth, (req, res) => res.redirect("/sharing"));

// ======================================================
// SECURE SHARING
// ======================================================
app.get("/sharing", requireAuth, async (req, res) => {
    const [files, shares] = await Promise.all([
        db.query(`SELECT id,file_name,file_type FROM media WHERE user_id=$1 ORDER BY uploaded_at DESC`, [req.user.id]),
        db.query(`SELECT s.*,m.file_name FROM secure_shares s JOIN media m ON m.id=s.media_id WHERE s.user_id=$1 ORDER BY s.created_at DESC`, [req.user.id])
    ]);
    const shareUrl = req.query.created ? `${getAppUrl(req)}/share/${req.query.created}` : null;
    res.render("sharing.ejs", {
        files: files.rows,
        shares: shares.rows,
        created: req.query.created || null,
        shareUrl,
        selectedFileId: req.query.fileId || ""
    });
});

app.post("/share/create", requireAuth, async (req, res) => {
    try {
        const { mediaId, password, expiry, maxDownloads, allowDownload } = req.body;
        const file = await db.query(`SELECT * FROM media WHERE id=$1 AND user_id=$2`, [mediaId, req.user.id]);
        if (!file.rows.length) return res.status(404).send("File not found.");

        const token = crypto.randomBytes(32).toString("hex");
        const passwordHash = password ? await bcrypt.hash(password, saltRounds) : null;
        const expiresAt = expiryToDate(expiry);
        const max = maxDownloads ? Math.max(1, parseInt(maxDownloads, 10)) : null;
        const canDownload = allowDownload === "true";

        await db.query(
            `INSERT INTO secure_shares
             (media_id,user_id,token,password_hash,expires_at,max_downloads,allow_download)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [mediaId, req.user.id, token, passwordHash, expiresAt, max, canDownload]
        );
        await recordAudit(req, "SECURE_SHARE_CREATED", file.rows[0].file_name);
        res.redirect(`/sharing?created=${encodeURIComponent(token)}`);
    } catch (err) {
        console.log(err);
        res.status(500).send("Unable to create secure share.");
    }
});

app.post("/share/revoke/:id", requireAuth, async (req, res) => {
    const result = await db.query(
        `UPDATE secure_shares SET revoked=TRUE WHERE id=$1 AND user_id=$2 RETURNING *`,
        [req.params.id, req.user.id]
    );
    if (result.rows.length) await recordAudit(req, "SECURE_SHARE_REVOKED", `Share #${req.params.id}`);
    res.redirect("/sharing");
});

function shareIsExpired(share) {
    return Boolean(
        share.revoked ||
        (share.expires_at && new Date(share.expires_at) <= new Date())
    );
}

function shareAccessGranted(req, token) {
    const access = req.session?.shareAccess?.[token];
    if (!access) return false;
    return Date.now() - access < 30 * 60 * 1000;
}

async function getShare(token) {
    const result = await db.query(
        `SELECT s.*,m.file_name,m.file_type,m.file_url,m.file_size
         FROM secure_shares s
         JOIN media m ON m.id=s.media_id
         WHERE s.token=$1`,
        [token]
    );
    return result.rows[0] || null;
}

function shareRenderData(share, req, extra = {}) {
    const needsPassword = Boolean(share.password_hash);
    const authorized = !needsPassword || shareAccessGranted(req, share.token);
    const limitReached =
        share.max_downloads !== null &&
        share.download_count >= share.max_downloads;

    return {
        share,
        needsPassword: needsPassword && !authorized,
        authorized,
        limitReached,
        error: null,
        expired: false,
        ...extra
    };
}

app.get("/share/:token", async (req, res) => {
    try {
        const share = await getShare(req.params.token);

        if (!share) {
            return res.status(404).render("public-share.ejs", {
                share: null,
                needsPassword: false,
                authorized: false,
                limitReached: false,
                expired: true,
                error: "This secure share link was not found."
            });
        }

        if (shareIsExpired(share)) {
            return res.status(410).render("public-share.ejs", {
                share,
                needsPassword: false,
                authorized: false,
                limitReached: false,
                expired: true,
                error: share.revoked
                    ? "This secure share has been revoked by the owner."
                    : "This secure share has expired."
            });
        }

        res.render("public-share.ejs", shareRenderData(share, req));
    } catch (err) {
        console.log("PUBLIC SHARE ERROR:", err.message);
        res.status(500).render("public-share.ejs", {
            share: null,
            needsPassword: false,
            authorized: false,
            limitReached: false,
            expired: true,
            error: "Unable to open this secure share right now."
        });
    }
});

app.post("/share/:token/access", async (req, res) => {
    try {
        const share = await getShare(req.params.token);

        if (!share) {
            return res.status(404).render("public-share.ejs", {
                share: null,
                needsPassword: false,
                authorized: false,
                limitReached: false,
                expired: true,
                error: "This secure share link was not found."
            });
        }

        if (shareIsExpired(share)) {
            return res.status(410).render("public-share.ejs", {
                share,
                needsPassword: false,
                authorized: false,
                limitReached: false,
                expired: true,
                error: share.revoked
                    ? "This secure share has been revoked by the owner."
                    : "This secure share has expired."
            });
        }

        if (share.password_hash) {
            const valid = await bcrypt.compare(
                req.body.password || "",
                share.password_hash
            );

            if (!valid) {
                return res.status(401).render(
                    "public-share.ejs",
                    shareRenderData(share, req, {
                        error: "Incorrect share password."
                    })
                );
            }

            if (!req.session.shareAccess) req.session.shareAccess = {};
            req.session.shareAccess[share.token] = Date.now();
        }

        res.redirect(`/share/${share.token}`);
    } catch (err) {
        console.log("SHARE ACCESS ERROR:", err.message);
        res.status(500).send("Unable to access this secure share.");
    }
});

async function sendSharedFile(req, res, inline = false) {
    try {
        const share = await getShare(req.params.token);

        if (!share) return res.status(404).send("Share link not found.");

        if (shareIsExpired(share)) {
            return res.status(410).send("This secure share has expired or been revoked.");
        }

        if (share.password_hash && !shareAccessGranted(req, share.token)) {
            return res.status(401).send("Share password required.");
        }

        if (!inline) {
            if (!share.allow_download) {
                return res.status(403).send("Downloads are disabled for this share.");
            }

            if (share.max_downloads !== null) {
                const reserved = await db.query(
                    `UPDATE secure_shares
                     SET download_count = download_count + 1
                     WHERE id=$1
                       AND revoked=FALSE
                       AND (expires_at IS NULL OR expires_at>NOW())
                       AND download_count < max_downloads
                     RETURNING download_count`,
                    [share.id]
                );

                if (!reserved.rows.length) {
                    return res.status(403).send("Download limit reached.");
                }
            } else {
                await db.query(
                    `UPDATE secure_shares
                     SET download_count=download_count+1
                     WHERE id=$1`,
                    [share.id]
                );
            }
        }

        const response = await fetch(share.file_url);
        if (!response.ok) {
            return res.status(502).send("Unable to fetch the shared file.");
        }

        const contentType =
            response.headers.get("content-type") || "application/octet-stream";

        res.setHeader("Content-Type", contentType);
        res.setHeader(
            "Content-Disposition",
            `${inline ? "inline" : "attachment"}; filename="${share.file_name.replace(/"/g, "")}"`
        );

        res.send(Buffer.from(await response.arrayBuffer()));
    } catch (err) {
        console.log("SHARED FILE ERROR:", err.message);
        res.status(500).send("Unable to open the shared file.");
    }
}

app.get("/share/:token/file", async (req, res) => {
    await sendSharedFile(req, res, true);
});

app.get("/share/:token/download", async (req, res) => {
    await sendSharedFile(req, res, false);
});

// ======================================================
// PASSPORT LOCAL STRATEGY
// ======================================================
passport.use("local", new Strategy(async (username, password, cb) => {
    try {
        const result = await db.query(`SELECT * FROM users WHERE email=$1`, [username]);
        if (!result.rows.length) return cb(null, false);
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return cb(null, false);
        return cb(null, user);
    } catch (err) { return cb(err); }
}));

// ======================================================
// PASSPORT GOOGLE STRATEGY
// ======================================================
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const result = await db.query(`SELECT * FROM users WHERE email=$1`, [profile.email]);
        if (!result.rows.length) {
            const newUser = await db.query(
                `INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *`,
                [profile.email, "google"]
            );
            return cb(null, newUser.rows[0]);
        }
        return cb(null, result.rows[0]);
    } catch (err) { return cb(err); }
}));

passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
    try {
        const result = await db.query(`SELECT * FROM users WHERE id=$1`, [id]);
        if (!result.rows.length) return cb(null, false);
        cb(null, result.rows[0]);
    } catch (err) { cb(err); }
});

// ======================================================
// SERVER
// ======================================================
app.listen(port, () => console.log(`Server running on port ${port}`));
