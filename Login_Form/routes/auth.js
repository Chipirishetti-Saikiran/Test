const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');

const router = express.Router();

// POST /auth/register
router.post('/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  if (!email || !password) return res.status(400).send('Email and password are required');
  if (password !== confirmPassword) return res.status(400).send('Passwords do not match');

  try {
    const [exist] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (exist.length) return res.status(409).send('Email already registered');

    const hash = await bcrypt.hash(password, 12);
    await pool.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name || null, email, hash]
    );

    return res.redirect('/login.html?registered=1');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error');
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password are required');

  try {
    const [rows] = await pool.execute(
      'SELECT id, name, email, password_hash FROM users WHERE email = ? AND is_active = 1',
      [email]
    );
    if (!rows.length) return res.status(401).send('Invalid credentials');

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send('Invalid credentials');

    // Update last login timestamp
    await pool.execute('UPDATE users SET last_login_at = NOW() WHERE id = ?', [user.id]);

    // Set session
    req.session.user = { id: user.id, email: user.email, name: user.name };
    return res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error');
  }
});

// POST /auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Could not log out');
    }
    res.clearCookie('sid');
    return res.redirect('/login.html?logged_out=1');
  });
});

// GET /auth/me (optional helper for frontend)
router.get('/me', (req, res) => {
  if (req.session && req.session.user) return res.json(req.session.user);
  return res.status(401).json({ error: 'Not authenticated' });
});

module.exports = router;
