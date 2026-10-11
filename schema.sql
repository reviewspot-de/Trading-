CREATE TABLE IF NOT EXISTS reviewspot_state (
  scope TEXT NOT NULL,
  key TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT,
  PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS reviewspot_docs (
  scope TEXT NOT NULL,
  collection TEXT NOT NULL,
  id TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT,
  PRIMARY KEY (scope, collection, id)
);

CREATE INDEX IF NOT EXISTS idx_reviewspot_docs_lookup
  ON reviewspot_docs(scope, collection, updated_at);
