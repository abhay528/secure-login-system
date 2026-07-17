'use strict';

const { body } = require('express-validator');

// Server-side input validation & sanitization for registration.
const registerValidator = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters.')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username may only contain letters, numbers, and underscores.'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Enter a valid email address.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters.')
    .matches(/[a-z]/)
    .withMessage('Password must contain a lowercase letter.')
    .matches(/[A-Z]/)
    .withMessage('Password must contain an uppercase letter.')
    .matches(/[0-9]/)
    .withMessage('Password must contain a number.'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match.');
    }
    return true;
  }),
];

// Validation for login.
const loginValidator = [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
];

module.exports = { registerValidator, loginValidator };
