const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const pool = require('./db');

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Register ---
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    res.status(201).json({ message: 'User registered', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ message: 'Email already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// --- Login ---
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Protected Route Example ---
app.get('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing token' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pool.query('SELECT id, email FROM users WHERE id = $1', [decoded.id]);
    res.json({ profile: user.rows[0] });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
