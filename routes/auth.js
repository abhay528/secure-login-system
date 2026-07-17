'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const User = require('../models/userModel');
const { requireAuth, requireGuest } = require('../middleware/authMiddleware');
const { registerValidator, loginValidator } = require('../middleware/validators');

const router = express.Router();

const SALT_ROUNDS = 12;
const MAX_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes

// A valid dummy hash. We compare against it when a username does not exist so
// that both branches take a similar amount of time, mitigating user enumeration
// via timing and keeping the error message generic.
const DUMMY_HASH = bcrypt.hashSync('unused-placeholder-value', SALT_ROUNDS);

// ---------------------------------------------------------------- Register
router.get('/register', requireGuest, (req, res) => {
  res.render('register', { title: 'Create account', errors: [], values: {} });
});

router.post('/register', requireGuest, registerValidator, async (req, res) => {
  const { username, email, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('register', {
      title: 'Create account',
      errors: errors.array(),
      values: { username, email },
    });
  }

  try {
    if (User.findByUsername(username)) {
      return res.status(400).render('register', {
        title: 'Create account',
        errors: [{ msg: 'That username is already taken.' }],
        values: { username, email },
      });
    }
    if (User.findByEmail(email)) {
      return res.status(400).render('register', {
        title: 'Create account',
        errors: [{ msg: 'That email is already registered.' }],
        values: { username, email },
      });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    User.create(username, email, passwordHash);

    req.session.flash = { type: 'success', message: 'Account created. Please log in.' };
    res.redirect('/login');
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).render('register', {
      title: 'Create account',
      errors: [{ msg: 'Something went wrong. Please try again.' }],
      values: { username, email },
    });
  }
});

// ------------------------------------------------------------------- Login
router.get('/login', requireGuest, (req, res) => {
  res.render('login', { title: 'Log in', errors: [], values: {} });
});

router.post('/login', requireGuest, loginValidator, async (req, res) => {
  const { username, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', {
      title: 'Log in',
      errors: errors.array(),
      values: { username },
    });
  }

  const genericError = [{ msg: 'Invalid username or password.' }];
  const user = User.findByUsername(username);

  // Unknown user: run a dummy compare so timing looks similar, then fail.
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH);
    return res.status(401).render('login', {
      title: 'Log in',
      errors: genericError,
      values: { username },
    });
  }

  // Account lockout after too many failed attempts (brute-force protection).
  if (user.locked_until && user.locked_until > Date.now()) {
    const minutes = Math.ceil((user.locked_until - Date.now()) / 60000);
    return res.status(429).render('login', {
      title: 'Log in',
      errors: [{ msg: `Account locked. Try again in ${minutes} minute(s).` }],
      values: { username },
    });
  }

  const passwordMatches = await bcrypt.compare(password, user.password_hash);
  if (!passwordMatches) {
    const attempts = user.failed_attempts + 1;
    const lockedUntil = attempts >= MAX_ATTEMPTS ? Date.now() + LOCK_TIME_MS : null;
    User.setLockState(user.id, attempts, lockedUntil);
    return res.status(401).render('login', {
      title: 'Log in',
      errors: genericError,
      values: { username },
    });
  }

  // Success: reset the failed-attempt counter.
  User.setLockState(user.id, 0, null);

  // If 2FA is on, defer the real login until the TOTP code is verified.
  if (user.is_2fa_enabled) {
    req.session.pending2faUserId = user.id;
    return res.redirect('/login/2fa');
  }

  establishSession(req, res, user, '/dashboard');
});

// -------------------------------------------------- 2FA challenge at login
router.get('/login/2fa', (req, res) => {
  if (!req.session.pending2faUserId) return res.redirect('/login');
  res.render('verify-2fa', { title: 'Two-factor authentication', errors: [] });
});

router.post('/login/2fa', (req, res) => {
  const pendingId = req.session.pending2faUserId;
  if (!pendingId) return res.redirect('/login');

  const user = User.findById(pendingId);
  if (!user) {
    delete req.session.pending2faUserId;
    return res.redirect('/login');
  }

  const token = String(req.body.token || '').replace(/\s/g, '');
  const verified = speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!verified) {
    return res.status(401).render('verify-2fa', {
      title: 'Two-factor authentication',
      errors: [{ msg: 'Invalid code. Please try again.' }],
    });
  }

  delete req.session.pending2faUserId;
  establishSession(req, res, user, '/dashboard');
});

// -------------------------------------------------------------- Dashboard
router.get('/dashboard', requireAuth, (req, res) => {
  const user = User.findById(req.session.userId);
  res.render('dashboard', { title: 'Dashboard', user });
});

// ---------------------------------------------------------- 2FA management
router.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = User.findById(req.session.userId);
  if (user.is_2fa_enabled) {
    return res.render('setup-2fa', {
      title: 'Two-factor authentication',
      enabled: true,
      qr: null,
      secret: null,
      errors: [],
    });
  }

  const secret = speakeasy.generateSecret({ name: `SecureLogin (${user.username})` });
  req.session.temp2faSecret = secret.base32;
  const qr = await qrcode.toDataURL(secret.otpauth_url);

  res.render('setup-2fa', {
    title: 'Two-factor authentication',
    enabled: false,
    qr,
    secret: secret.base32,
    errors: [],
  });
});

router.post('/2fa/setup', requireAuth, async (req, res) => {
  const secret = req.session.temp2faSecret;
  if (!secret) return res.redirect('/2fa/setup');

  const token = String(req.body.token || '').replace(/\s/g, '');
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

  if (!verified) {
    const otpauthUrl = speakeasy.otpauthURL({
      secret,
      label: 'SecureLogin',
      encoding: 'base32',
    });
    const qr = await qrcode.toDataURL(otpauthUrl);
    return res.status(400).render('setup-2fa', {
      title: 'Two-factor authentication',
      enabled: false,
      qr,
      secret,
      errors: [{ msg: 'Invalid code. Scan the QR code and try again.' }],
    });
  }

  User.enable2fa(req.session.userId, secret);
  delete req.session.temp2faSecret;
  req.session.flash = { type: 'success', message: 'Two-factor authentication enabled.' };
  res.redirect('/dashboard');
});

router.post('/2fa/disable', requireAuth, (req, res) => {
  User.disable2fa(req.session.userId);
  req.session.flash = { type: 'success', message: 'Two-factor authentication disabled.' };
  res.redirect('/dashboard');
});

// ---------------------------------------------------------------- Logout
router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Regenerate the session ID on login to prevent session fixation.
function establishSession(req, res, user, redirectTo) {
  req.session.regenerate((err) => {
    if (err) {
      console.error('Session error:', err);
      return res.status(500).send('Session error');
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect(redirectTo);
  });
}

module.exports = router;
