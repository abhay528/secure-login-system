'use strict';

// Blocks access to protected pages unless a valid session exists.
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    req.session.flash = { type: 'error', message: 'Please log in to continue.' };
    return res.redirect('/login');
  }
  next();
}

// Redirects already-logged-in users away from login/register pages.
function requireGuest(req, res, next) {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  next();
}

module.exports = { requireAuth, requireGuest };
