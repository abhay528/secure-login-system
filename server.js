'use strict';

require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Initialize the database (creates the schema on first run).
require('./db/database');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust the first proxy so "secure" cookies work behind a reverse proxy.
app.set('trust proxy', 1);

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security HTTP headers
app.use(helmet());

// Parse form submissions
app.use(express.urlencoded({ extended: false }));

// Static assets
app.use(express.static(path.join(__dirname, 'public')));

// Sessions, persisted in SQLite so they survive restarts.
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
    secret: process.env.SESSION_SECRET || 'insecure-dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // not readable by JavaScript (mitigates XSS cookie theft)
      sameSite: 'lax', // mitigates CSRF
      secure: process.env.NODE_ENV === 'production', // HTTPS-only in production
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// Expose the current user and one-time flash messages to all views.
app.use((req, res, next) => {
  res.locals.currentUser = req.session.username || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

// Rate limit authentication traffic (brute-force / abuse protection).
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(authLimiter, authRoutes);

// Home redirects based on auth state.
app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/dashboard' : '/login');
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', { title: 'Not found', message: 'Page not found.' });
});

app.listen(PORT, () => {
  console.log(`Secure login system running at http://localhost:${PORT}`);
});
