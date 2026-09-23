ALTER TABLE licenses ADD COLUMN device_mode TEXT NOT NULL DEFAULT 'unlimited_devices';
ALTER TABLE licenses ADD COLUMN device_hash TEXT;
ALTER TABLE licenses ADD COLUMN duration_value INTEGER NOT NULL DEFAULT 30;
ALTER TABLE licenses ADD COLUMN duration_unit TEXT NOT NULL DEFAULT 'days';

CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key);
CREATE INDEX IF NOT EXISTS idx_licenses_expires_at ON licenses(expires_at);
