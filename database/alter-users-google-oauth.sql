-- Add Google OAuth support: google_id for linking accounts; allow NULL password for Google-only sign-in.
-- Run this before using "Continue with Google". If google_id already exists, skip the first statement.

ALTER TABLE users ADD COLUMN google_id VARCHAR(255) NULL UNIQUE AFTER email;
ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL;
