-- Fix: GHL refresh tokens are often longer than 512 chars. VARCHAR(512) was truncating them,
-- causing "Invalid refresh token" when refreshing. This alters the column to TEXT.
-- Run once: mysql -u root msync < backend/database/alter-ghl-refresh-token-length.sql
-- Or in MySQL client: source path/to/alter-ghl-refresh-token-length.sql

ALTER TABLE ghl_connections MODIFY COLUMN refresh_token TEXT DEFAULT NULL;
