-- M-Sync Database Schema (MySQL)
-- Run this via init-db.js or import into MySQL manually.

-- Plans: free (limited credits) and paid
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

-- Users: dashboard/extension users (email + password for our app)
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) DEFAULT NULL,
  plan_id INT NOT NULL DEFAULT 1,
  role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  credits_remaining INT NOT NULL DEFAULT 0,
  credits_reset_at DATE DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);

-- GHL connection per user (one GHL account per user for now)
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

-- Synced emails: log of emails we pushed to GHL (for history / dedup)
CREATE TABLE IF NOT EXISTS synced_emails (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  gmail_message_id VARCHAR(255) NOT NULL,
  ghl_contact_id VARCHAR(100) DEFAULT NULL,
  subject VARCHAR(500) DEFAULT NULL,
  synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_user_gmail (user_id, gmail_message_id)
);

-- Parsed signatures: cache parsed email signature data
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

-- Sync logs: every sync-email attempt (success or failure) for admin
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

-- Feature flags (admin toggles; extension reads via API)
CREATE TABLE IF NOT EXISTS feature_flags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  flag_key VARCHAR(100) NOT NULL UNIQUE,
  enabled TINYINT(1) NOT NULL DEFAULT 0,
  description VARCHAR(500) DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO feature_flags (flag_key, enabled, description) VALUES
  ('auto_save_on_send', 0, 'When on, extension can auto-sync email to CRM when user sends and Save to CRM is enabled');

-- Indexes for common lookups
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_synced_emails_user ON synced_emails(user_id);
CREATE INDEX idx_synced_emails_gmail ON synced_emails(gmail_message_id);
CREATE INDEX idx_ghl_connections_user ON ghl_connections(user_id);
CREATE INDEX idx_sync_logs_user ON sync_logs(user_id);
CREATE INDEX idx_sync_logs_synced_at ON sync_logs(synced_at);
