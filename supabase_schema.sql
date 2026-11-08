-- Supabase PostgreSQL Schema for Gmail Spam Deleter
-- Optional: Use this if hosting in the cloud with Supabase database

CREATE TABLE IF NOT EXISTS connected_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    token_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_batches (
    batch_id TEXT PRIMARY KEY,
    account_email TEXT NOT NULL,
    total_messages INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_entries (
    id BIGSERIAL PRIMARY KEY,
    batch_id TEXT REFERENCES audit_batches(batch_id) ON DELETE CASCADE,
    account_email TEXT NOT NULL,
    message_id TEXT NOT NULL,
    thread_id TEXT,
    sender TEXT,
    sender_email TEXT,
    subject TEXT,
    date_str TEXT,
    score NUMERIC,
    action TEXT NOT NULL,
    reason TEXT,
    trashed_at TIMESTAMPTZ DEFAULT NOW(),
    restored_at TIMESTAMPTZ
);

-- Indexes for lightning fast lookups
CREATE INDEX IF NOT EXISTS idx_audit_entries_batch_id ON audit_entries(batch_id);
CREATE INDEX IF NOT EXISTS idx_audit_entries_account ON audit_entries(account_email);
