'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// Store the SQLite file in a local ./data directory (created if missing).
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.join(dataDir, 'app.db'));

// Recommended pragmas for reliability and integrity.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Schema. Passwords are NEVER stored in plain text  only the bcrypt hash.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    UNIQUE NOT NULL,
    email           TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    totp_secret     TEXT,
    is_2fa_enabled  INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

module.exports = db;
