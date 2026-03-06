-- Purchases: record of Stripe (or other) payments for license activation
-- Run once. If tables/columns already exist, ignore errors.

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

-- Multiple licenses (seats) per user
ALTER TABLE users ADD COLUMN license_count INT NOT NULL DEFAULT 1 AFTER credits_reset_at;
