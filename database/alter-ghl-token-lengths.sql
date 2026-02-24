-- Fix: GHL access tokens can exceed VARCHAR(1024).
-- This alters both token columns to TEXT to prevent truncation / "Data too long" errors.
-- Run once: mysql -u root msync < backend/database/alter-ghl-token-lengths.sql

ALTER TABLE ghl_connections MODIFY COLUMN access_token TEXT NOT NULL;
ALTER TABLE ghl_connections MODIFY COLUMN refresh_token TEXT DEFAULT NULL;
