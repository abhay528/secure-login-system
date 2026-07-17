# 🔐 Secure Login System

A secure authentication web application built with **Node.js**, **Express**, and **SQLite**. It demonstrates the security fundamentals every real-world login system needs: hashed passwords, server-side input validation, SQL-injection-safe queries, secure session management, and optional **Two-Factor Authentication (TOTP)**.

![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4-000000?logo=express&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

---

## ✨ Features

| Feature | How it's implemented |
| --- | --- |
| **Password hashing** | Passwords are hashed with **bcrypt** (cost factor 12). Plain-text passwords are never stored. |
| **Input validation** | Server-side validation & sanitization with **express-validator** (username rules, email format, strong-password policy). |
| **SQL injection protection** | All database access uses **parameterized prepared statements** — user input is never concatenated into SQL. |
| **Session management** | Signed, HTTP-only cookies via **express-session**, persisted in SQLite. Session ID is regenerated on login to prevent fixation. |
| **Logout** | Destroys the server session and clears the cookie. |
| **Two-Factor Auth (2FA)** | Optional TOTP 2FA (Google Authenticator / Authy) using **speakeasy** + a scannable **QR code**. |
| **Brute-force protection** | Account lockout after 5 failed attempts + global rate limiting. |
| **Secure HTTP headers** | Set automatically with **helmet**. |

---

## 🧱 Tech Stack

- **Runtime:** Node.js
- **Server:** Express
- **Database:** SQLite (`better-sqlite3`)
- **Auth:** bcrypt, express-session, speakeasy (TOTP)
- **Security:** helmet, express-rate-limit, express-validator
- **Views:** EJS templates + vanilla CSS

---

## 📂 Project Structure

```
secure-login-system/
├── server.js               # App entry point & middleware setup
├── db/
│   └── database.js         # SQLite connection + schema
├── models/
│   └── userModel.js        # Prepared-statement data access (SQLi-safe)
├── middleware/
│   ├── authMiddleware.js   # requireAuth / requireGuest guards
│   └── validators.js       # express-validator rules
├── routes/
│   └── auth.js             # register / login / 2FA / logout logic
├── views/                  # EJS templates
│   ├── partials/
│   ├── register.ejs
│   ├── login.ejs
│   ├── verify-2fa.ejs
│   ├── setup-2fa.ejs
│   ├── dashboard.ejs
│   └── error.ejs
├── public/css/style.css    # Styling
├── .env.example            # Environment variable template
├── .gitignore
├── LICENSE
└── package.json
```

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) 18 or newer

### Installation

```bash
# 1. Install dependencies
npm install

# 2. Create your environment file
cp .env.example .env

# 3. Set a strong session secret inside .env
#    (generate one with the command below and paste the output)
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"

# 4. Start the server
npm start
```

Then open **http://localhost:3000** in your browser.

> Uses `better-sqlite3`, which compiles a small native module during `npm install`. On most systems this works out of the box; on Windows you may need the “Desktop development with C++” build tools.

---

## 🔒 How the Security Works

### 1. Password hashing (bcrypt)
During registration the password is hashed with bcrypt and a per-user salt (cost factor 12). Only the hash is stored. At login, `bcrypt.compare()` checks the submitted password against the stored hash.

### 2. SQL injection protection
Every query is a **prepared statement** with bound `?` parameters, e.g.:
```js
db.prepare('SELECT * FROM users WHERE username = ?').get(username);
```
Input is treated strictly as data, so classic payloads like `' OR 1=1 --` cannot alter the query.

### 3. Input validation
`express-validator` enforces a username pattern, valid email, and a strong password (min 8 chars, upper + lower + number) before anything touches the database.

### 4. Session management
Sessions use signed, **HTTP-only** cookies (`sameSite=lax`, `secure` in production). The session ID is **regenerated on login** to prevent session fixation, and fully destroyed on logout.

### 5. Two-Factor Authentication (optional)
After logging in, a user can enable 2FA: the server generates a TOTP secret, shows a QR code, and requires a valid 6-digit code to activate. On future logins, the password step is followed by a TOTP challenge.

### 6. Brute-force defense
Five consecutive failed logins lock the account for 15 minutes, and `express-rate-limit` caps overall auth requests.

---

## 🧪 Try It Out
1. Register a new account.
2. Log in — you'll land on a protected dashboard.
3. (Optional) Enable 2FA and scan the QR code with an authenticator app.
4. Log out and confirm the dashboard is no longer accessible.

---

## ⚠️ Notes
This is an educational/portfolio project. For production you would additionally add: HTTPS, CSRF tokens, email verification, password reset, backup 2FA codes, and audit logging.

---

## 📄 License
MIT © Jual Coco
