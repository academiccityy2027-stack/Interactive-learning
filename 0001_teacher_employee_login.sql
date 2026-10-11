-- Run ONCE after taking a Cloudflare D1 backup.
ALTER TABLE users ADD COLUMN employee_number TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_employee_number ON users(employee_number);
