require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');

const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();

// Security headers
app.use(helmet());

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static assets (HTML/CSS)
app.use(express.static(path.join(__dirname, 'public')));

// Sessions (MemoryStore: fine for dev; use a store like Redis/MySQL in production)
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // set true behind HTTPS in production
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// Routes
app.use('/auth', authRoutes);

// Protected dashboard route serves the HTML
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Default → login
app.get('/', (_req, res) => res.redirect('/login.html'));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
