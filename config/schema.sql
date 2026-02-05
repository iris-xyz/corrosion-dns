-- Schema for corrosion-dns
-- Apps and machines tables for DNS resolution

CREATE TABLE IF NOT EXISTS apps (
    app_id TEXT PRIMARY KEY NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL DEFAULT 'http',
    external_port INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_apps_domain ON apps(domain);

CREATE TABLE IF NOT EXISTS machines (
    machine_id TEXT PRIMARY KEY NOT NULL,
    app_id TEXT,
    ipv6_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    region TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (app_id) REFERENCES apps(app_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_machines_app_id ON machines(app_id);
CREATE INDEX IF NOT EXISTS idx_machines_status ON machines(status);
CREATE INDEX IF NOT EXISTS idx_machines_app_status ON machines(app_id, status);
