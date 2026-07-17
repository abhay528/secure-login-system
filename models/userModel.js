'use strict';

const db = require('../db/database');

/*
 * All queries use prepared statements with bound parameters (the `?`
 * placeholders). User input is passed as data, never concatenated into the SQL
 * string, which is what protects the app against SQL injection.
 */
const statements = {
  insert: db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  ),
  byUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  byEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  byId: db.prepare('SELECT * FROM users WHERE id = ?'),
  enable2fa: db.prepare(
    'UPDATE users SET totp_secret = ?, is_2fa_enabled = 1 WHERE id = ?'
  ),
  disable2fa: db.prepare(
    'UPDATE users SET totp_secret = NULL, is_2fa_enabled = 0 WHERE id = ?'
  ),
  setLockState: db.prepare(
    'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?'
  ),
};

module.exports = {
  create: (username, email, passwordHash) =>
    statements.insert.run(username, email, passwordHash),
  findByUsername: (username) => statements.byUsername.get(username),
  findByEmail: (email) => statements.byEmail.get(email),
  findById: (id) => statements.byId.get(id),
  enable2fa: (id, secret) => statements.enable2fa.run(secret, id),
  disable2fa: (id) => statements.disable2fa.run(id),
  setLockState: (id, attempts, lockedUntil) =>
    statements.setLockState.run(attempts, lockedUntil, id),
};
