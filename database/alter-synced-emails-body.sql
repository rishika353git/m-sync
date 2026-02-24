-- Add email_body to synced_emails for displaying in dashboard/CRM
-- Run once. If column already exists, ignore the error.
ALTER TABLE synced_emails ADD COLUMN email_body TEXT DEFAULT NULL AFTER subject;
