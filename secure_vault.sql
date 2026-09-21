-- Secure Vault database schema (safe to commit; contains no user data or credentials).
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS media (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(20) NOT NULL,
    file_extension VARCHAR(20),
    file_size BIGINT,
    file_url TEXT NOT NULL,
    public_id TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_self_destruct BOOLEAN NOT NULL DEFAULT FALSE
);

-- The remaining feature tables are also available in secure_vault_upgrade.sql.
