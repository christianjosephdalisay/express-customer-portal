var express = require('express');
var router = express.Router();
var { body, validationResult } = require('express-validator');
var { nanoid } = require('nanoid');
var path = require('path');
var fs = require('fs');

const SESSIONS_FILE = path.join(__dirname, '..', 'data', 'sessions.json');

function readSessions() {
  try {
    const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch (err) {
    return {};
  }
}

function writeSessions(sessions) {
  fs.mkdirSync(path.dirname(SESSIONS_FILE), { recursive: true });
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2), 'utf8');
}

// POST /api/login
router.post(
  '/login',
  // validator chain: single `user` field (email or phone)
  [body('user').trim().notEmpty().withMessage('user required')],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { user } = req.body;

    // detect type and validate
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    const phoneRegex = /^\+?[0-9]{7,15}$/;

    let type = null;
    if (emailRegex.test(user)) {
      type = 'email';
    } else if (phoneRegex.test(user)) {
      type = 'phone';
    } else {
      return res.status(400).json({ error: 'identifier must be a valid email or international phone number' });
    }

    // create session
    const sessions = readSessions();
    const token = nanoid(32);
    const expiry = Date.now() + 1000 * 60 * 60 * 24; // 24h
    sessions[token] = { identifier: user, type, expiry };
    writeSessions(sessions);

    // set httpOnly cookie
    res.cookie('session', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // set to true in production with HTTPS
      maxAge: 1000 * 60 * 60 * 24,
    });

    return res.json({ ok: true });
  }
);

// GET /api/session
router.get('/session', (req, res) => {
  const token = req.cookies && req.cookies.session;
  if (!token) return res.json({ authenticated: false });
  const sessions = readSessions();
  const s = sessions[token];
  if (!s || s.expiry < Date.now()) {
    return res.json({ authenticated: false });
  }
  return res.json({ authenticated: true, identifier: s.identifier, type: s.type });
});

// POST /api/logout
router.post('/logout', (req, res) => {
  const token = req.cookies && req.cookies.session;
  if (token) {
    const sessions = readSessions();
    delete sessions[token];
    writeSessions(sessions);
    res.clearCookie('session');
  }
  res.json({ ok: true });
});

module.exports = router;
