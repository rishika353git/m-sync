-- Feature flags for admin toggles (e.g. auto-save on send in extension)
-- Run once. Creates feature_flags table and default row.
CREATE TABLE IF NOT EXISTS feature_flags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  flag_key VARCHAR(100) NOT NULL UNIQUE,
  enabled TINYINT(1) NOT NULL DEFAULT 0,
  description VARCHAR(500) DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT IGNORE INTO feature_flags (flag_key, enabled, description) VALUES
  ('auto_save_on_send', 0, 'When on, extension can auto-sync email to CRM when user sends and Save to CRM is enabled');
