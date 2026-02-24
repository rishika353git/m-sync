-- Sync logs: every sync-email attempt (success or failure) for admin debugging
-- Run once. Creates sync_logs table.
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
