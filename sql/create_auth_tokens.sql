CREATE TABLE IF NOT EXISTS auth_tokens (
  user_id TEXT PRIMARY KEY,
  user_login TEXT NOT NULL,
  encrypted_token TEXT NOT NULL,
  token_hash TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_login ON auth_tokens(user_login);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_updated_at ON auth_tokens(updated_at);
