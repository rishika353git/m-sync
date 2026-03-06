-- =============================================================================
-- M-Sync: All table creation and migration queries (MySQL)
-- Run in order. Replace `your_db_name` with your DB_NAME from .env if needed.
-- On first run: use full file. If a column already exists, that ALTER will error;
--   you can ignore or comment out that line.
-- =============================================================================

-- 1) Database (optional; skip if DB already exists or user can't CREATE DATABASE)
CREATE DATABASE IF NOT EXISTS `your_db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `your_db_name`;

-- -----------------------------------------------------------------------------
-- 2) Base tables (order matters: plans first, then users, then tables with FK to users)
-- -----------------------------------------------------------------------------

-- Plans: free and paid
CREATE TABLE IF NOT EXISTS plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  slug VARCHAR(50) NOT NULL UNIQUE,
  credits_per_month INT NOT NULL DEFAULT 0,
  is_paid TINYINT(1) NOT NULL DEFAULT 0,
  price_cents INT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO plans (id, name, slug, credits_per_month, is_paid) VALUES (1, 'Free', 'free', 50, 0);

-- Users (google_id + nullable password_hash for Google OAuth)
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  google_id VARCHAR(255) NULL UNIQUE,
  password_hash VARCHAR(255) NULL,
  full_name VARCHAR(255) DEFAULT NULL,
  plan_id INT NOT NULL DEFAULT 1,
  role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  credits_remaining INT NOT NULL DEFAULT 0,
  credits_reset_at DATE DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);
CREATE INDEX idx_users_email ON users(email);
-- If users table already exists without google_id, run:
-- ALTER TABLE users ADD COLUMN google_id VARCHAR(255) NULL UNIQUE AFTER email;
-- ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL;

-- GHL connection per user
CREATE TABLE IF NOT EXISTS ghl_connections (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  access_token TEXT NOT NULL,
  refresh_token TEXT DEFAULT NULL,
  location_id VARCHAR(100) DEFAULT NULL,
  subdomain VARCHAR(100) DEFAULT NULL,
  token_expires_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_ghl_connections_user ON ghl_connections(user_id);

-- Synced emails
CREATE TABLE IF NOT EXISTS synced_emails (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  gmail_message_id VARCHAR(255) NOT NULL,
  ghl_contact_id VARCHAR(100) DEFAULT NULL,
  subject VARCHAR(500) DEFAULT NULL,
  email_body TEXT DEFAULT NULL,
  synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_user_gmail (user_id, gmail_message_id)
);
CREATE INDEX idx_synced_emails_user ON synced_emails(user_id);
CREATE INDEX idx_synced_emails_gmail ON synced_emails(gmail_message_id);

-- Parsed signatures
CREATE TABLE IF NOT EXISTS parsed_signatures (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  email_message_id VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) DEFAULT NULL,
  company VARCHAR(255) DEFAULT NULL,
  phone VARCHAR(100) DEFAULT NULL,
  raw_text TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_user_message (user_id, email_message_id)
);

-- Sync logs
CREATE TABLE IF NOT EXISTS sync_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  gmail_message_id VARCHAR(255) DEFAULT NULL,
  ghl_contact_id VARCHAR(100) DEFAULT NULL,
  subject VARCHAR(500) DEFAULT NULL,
  synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  error_message TEXT DEFAULT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_sync_logs_user ON sync_logs(user_id);
CREATE INDEX idx_sync_logs_synced_at ON sync_logs(synced_at);

-- Feature flags
CREATE TABLE IF NOT EXISTS feature_flags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  flag_key VARCHAR(100) NOT NULL UNIQUE,
  enabled TINYINT(1) NOT NULL DEFAULT 0,
  description VARCHAR(500) DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO feature_flags (flag_key, enabled, description) VALUES
  ('auto_save_on_send', 0, 'When on, extension can auto-sync email to CRM when user sends and Save to CRM is enabled');

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  key_prefix VARCHAR(20) NOT NULL,
  key_hash VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_key_hash (key_hash)
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- Purchases
CREATE TABLE IF NOT EXISTS purchases (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  plan_id INT NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  amount_cents INT DEFAULT NULL,
  stripe_session_id VARCHAR(255) DEFAULT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);
CREATE INDEX idx_purchases_user ON purchases(user_id);
CREATE INDEX idx_purchases_stripe ON purchases(stripe_session_id);

-- Licenses
CREATE TABLE IF NOT EXISTS licenses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  key_prefix VARCHAR(16) NOT NULL,
  key_hash VARCHAR(64) NOT NULL,
  status ENUM('active','expired','cancelled') NOT NULL DEFAULT 'active',
  stripe_customer_id VARCHAR(255) DEFAULT NULL,
  stripe_subscription_id VARCHAR(255) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NULL DEFAULT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_licenses_hash (key_hash),
  KEY idx_licenses_user (user_id),
  KEY idx_licenses_customer (stripe_customer_id),
  KEY idx_licenses_subscription (stripe_subscription_id)
);

-- -----------------------------------------------------------------------------
-- 3) Alter users: license_count + Stripe columns (run once; ignore if column exists)
-- -----------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN license_count INT NOT NULL DEFAULT 1 AFTER credits_reset_at;
ALTER TABLE users ADD COLUMN stripe_customer_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE users ADD COLUMN stripe_subscription_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE users ADD COLUMN subscription_status VARCHAR(50) DEFAULT NULL;

-- -----------------------------------------------------------------------------
-- 4) GHL token columns as TEXT (tokens can exceed 512 chars)
-- -----------------------------------------------------------------------------
ALTER TABLE ghl_connections MODIFY COLUMN access_token TEXT NOT NULL;
ALTER TABLE ghl_connections MODIFY COLUMN refresh_token TEXT DEFAULT NULL;
