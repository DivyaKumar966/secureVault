-- Secure Vault feature tables.
-- The application also creates these automatically on startup.
ALTER TABLE media
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL,
ADD COLUMN IF NOT EXISTS is_self_destruct BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(80) NOT NULL,
    details TEXT,
    ip_address VARCHAR(100),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_events (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL DEFAULT 'local',
    ip_address VARCHAR(100),
    user_agent TEXT,
    fingerprint VARCHAR(128),
    suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
);

CREATE TABLE IF NOT EXISTS identity_items (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    media_id INT NOT NULL REFERENCES media(id) ON DELETE CASCADE,
    label VARCHAR(120) NOT NULL,
    category VARCHAR(80) NOT NULL DEFAULT 'Identity',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, media_id, label)
);
