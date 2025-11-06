const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = 'replace_this_with_a_strong_secret'; // change in production
const DB_FILE = path.join(__dirname, 'eduplanner.db');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Could not open DB', err);
    process.exit(1);
  }
});

const initSql = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  exam TEXT,
  subject TEXT,
  completed_units INTEGER DEFAULT 0,
  total_units INTEGER DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam TEXT,
  week INTEGER,
  questions TEXT -- JSON string [{q, options, answerIndex}]
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  test_id INTEGER,
  user_id INTEGER,
  score REAL,
  submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(test_id) REFERENCES tests(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`;

db.exec(initSql, (err) => {
  if (err) console.error('DB init error', err);
  else seedData();
});

function seedData() {
  // Seed a sample weekly test for KCET if not present
  db.get("SELECT COUNT(*) as cnt FROM tests WHERE exam = ?", ['KCET'], (err, row) => {
    if (err) return console.error(err);
    if (row.cnt === 0) {
      const questions = JSON.stringify([
        { q: 'What is the SI unit of force?', options: ['Newton', 'Joule', 'Watt', 'Pascal'], a: 0 },
        { q: 'Which is an alkali metal?', options: ['Oxygen','Sodium','Chlorine','Nitrogen'], a: 1 }
      ]);
      db.run('INSERT INTO tests (exam, week, questions) VALUES (?,?,?)', ['KCET', 1, questions]);
    }
  });
}

// Helpers
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '7d' });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing authorization header' });
  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid authorization header' });
  jwt.verify(token, SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

// Routes
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (name, email, password_hash) VALUES (?,?,?)', [name || '', email, hash], function(err) {
    if (err) return res.status(400).json({ error: 'User exists or DB error' });
    const token = generateToken({ id: this.lastID, email });
    res.json({ token });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.get('SELECT id, email, password_hash FROM users WHERE email = ?', [email], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, row.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = generateToken(row);
    res.json({ token });
  });
});

// Get progress summary (percentage) for user
app.get('/api/progress', authenticate, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT exam, SUM(completed_units) as completed, SUM(total_units) as total FROM progress WHERE user_id = ? GROUP BY exam', [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const result = rows.map(r => ({ exam: r.exam, completed: r.completed || 0, total: r.total || 0, percentage: r.total ? Math.round((r.completed / r.total) * 100) : 0 }));
    res.json({ progress: result });
  });
});

// Update progress for a subject (post {exam, subject, completed_units, total_units})
app.post('/api/progress', authenticate, (req, res) => {
  const userId = req.user.id;
  const { exam, subject, completed_units, total_units } = req.body;
  if (!exam || !subject) return res.status(400).json({ error: 'exam and subject required' });
  db.get('SELECT id FROM progress WHERE user_id = ? AND exam = ? AND subject = ?', [userId, exam, subject], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (row) {
      db.run('UPDATE progress SET completed_units = ?, total_units = ? WHERE id = ?', [completed_units || 0, total_units || 0, row.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ ok: true });
      });
    } else {
      db.run('INSERT INTO progress (user_id, exam, subject, completed_units, total_units) VALUES (?,?,?,?,?)', [userId, exam, subject, completed_units || 0, total_units || 0], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ ok: true });
      });
    }
  });
});

// Get weekly test for an exam (e.g., /api/tests/weekly?exam=KCET)
app.get('/api/tests/weekly', authenticate, (req, res) => {
  const exam = req.query.exam;
  if (!exam) return res.status(400).json({ error: 'exam required' });
  db.get('SELECT id, exam, week, questions FROM tests WHERE exam = ? ORDER BY week LIMIT 1', [exam], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.json({ test: null });
    res.json({ test: { id: row.id, exam: row.exam, week: row.week, questions: JSON.parse(row.questions) } });
  });
});

// Submit test answers {test_id, answers: [index,...]}
app.post('/api/tests/submit', authenticate, (req, res) => {
  const userId = req.user.id;
  const { test_id, answers } = req.body;
  if (!test_id || !Array.isArray(answers)) return res.status(400).json({ error: 'test_id and answers required' });
  db.get('SELECT questions, exam FROM tests WHERE id = ?', [test_id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: 'Test not found' });
    const questions = JSON.parse(row.questions);
    let correct = 0;
    questions.forEach((q, idx) => { if (q.a === answers[idx]) correct++; });
    const score = Math.round((correct / questions.length) * 100);
    db.run('INSERT INTO submissions (test_id, user_id, score) VALUES (?,?,?)', [test_id, userId, score], function(err) {
      if (err) console.error(err);
      // Optionally update progress: increment completed_units
      // For demo: increment a generic counter per exam
      // We'll increment a "weekly_tests_completed" subject
      db.get('SELECT id, completed_units, total_units FROM progress WHERE user_id = ? AND exam = ? AND subject = ?', [userId, row.exam, 'WeeklyTests'], (err, p) => {
        if (p) {
          const newCompleted = (p.completed_units || 0) + 1;
          db.run('UPDATE progress SET completed_units = ?, total_units = ? WHERE id = ?', [newCompleted, p.total_units || 10, p.id]);
        } else {
          db.run('INSERT INTO progress (user_id, exam, subject, completed_units, total_units) VALUES (?,?,?,?,?)', [userId, row.exam, 'WeeklyTests', 1, 10]);
        }
      });

      res.json({ score });
    });
  });
});

// Public route to get resourceDB from admin localStorage: for demo we also allow a simple resources table
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
