-- BillionMail CRM Database Initialization
-- Create main database and user

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS billionmail;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE billionmail TO billionmail_user;