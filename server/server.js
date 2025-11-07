const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
// Add axios when you install it: const axios = require('axios');

const SECRET = 'replace_this_with_a_strong_secret'; // change in production
const UIPATH_CONFIG = {
  orchestratorUrl: process.env.UIPATH_ORCHESTRATOR_URL || 'https://cloud.uipath.com',
  clientId: process.env.UIPATH_CLIENT_ID,
  clientSecret: process.env.UIPATH_CLIENT_SECRET,
  processName: process.env.UIPATH_PROCESS_NAME || 'GenerateStudentReport'
};
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
  console.log('Successfully connected to database');
  
  // Initialize tables
  db.serialize(() => {
    db.run(initSql, (err) => {
      if (err) {
        console.error('Error initializing database tables:', err);
        process.exit(1);
      }
      console.log('Database tables initialized successfully');
      
      // Create a test user if none exists
      db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        if (err) {
          console.error('Error checking users:', err);
          return;
        }
        if (row.count === 0) {
          const testPassword = bcrypt.hashSync('test123', 10);
          db.run(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            ['Test User', 'test@example.com', testPassword],
            (err) => {
              if (err) {
                console.error('Error creating test user:', err);
                return;
              }
              console.log('Test user created: test@example.com / test123');
            }
          );
        }
      });
    });
  });
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

// All routes are public - no auth needed
function authenticate(req, res, next) {
  // Guest user for public access
  req.user = { id: 1, email: 'guest@example.com' };
  next();
}

// Remove auth middleware from routes
app.use((req, res, next) => {
  req.user = { id: 1, email: 'guest@example.com' };
  next();
});

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
app.get('/api/progress', (req, res) => {
  const userId = req.user.id;
  db.all('SELECT exam, SUM(completed_units) as completed, SUM(total_units) as total FROM progress WHERE user_id = ? GROUP BY exam', [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const result = rows.map(r => ({ exam: r.exam, completed: r.completed || 0, total: r.total || 0, percentage: r.total ? Math.round((r.completed / r.total) * 100) : 0 }));
    res.json({ progress: result });
  });
});

// Update progress for a subject (post {exam, subject, completed_units, total_units})
app.post('/api/progress', (req, res) => {
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
app.get('/api/tests/weekly', (req, res) => {
  const exam = req.query.exam;
  if (!exam) return res.status(400).json({ error: 'exam required' });
  db.get('SELECT id, exam, week, questions FROM tests WHERE exam = ? ORDER BY week LIMIT 1', [exam], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.json({ test: null });
    res.json({ test: { id: row.id, exam: row.exam, week: row.week, questions: JSON.parse(row.questions) } });
  });
});

// Submit test answers {test_id, answers: [index,...]}
app.post('/api/tests/submit', (req, res) => {
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

// Progress Tracking Endpoints
app.get('/api/progress/weekly', (req, res) => {
  const userId = req.user.id;
  const exam = req.query.exam;
  
  // Get progress for the last 8 weeks
  db.all(`
    SELECT strftime('%W', created_at) as week,
           avg(score) as avg_score,
           count(*) as tests_taken,
           sum(case when score >= 70 then 1 else 0 end) as tests_passed
    FROM submissions 
    WHERE user_id = ? 
    AND created_at >= date('now', '-8 weeks')
    GROUP BY week
    ORDER BY week ASC
  `, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    
    // Format data for the chart
    const weeks = rows.map(r => 'Week ' + r.week);
    const progress = rows.map(r => Math.round((r.tests_passed / r.tests_taken) * 100) || 0);
    
    res.json({
      labels: weeks,
      progress: progress
    });
  });
});

// Weekly Topic Planning Endpoints
app.get('/api/planner/weekly-topics', (req, res) => {
  const userId = req.user.id;
  const exam = req.query.exam || 'KCET'; // Default to KCET if not specified
  
  // Get user's progress and generate personalized weekly plan
  db.all(`
    SELECT subject, completed_units, total_units 
    FROM progress 
    WHERE user_id = ? AND exam = ?
  `, [userId, exam], (err, progress) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    
    // Generate 4-week plan based on progress
    const weeks = generateWeeklyPlan(progress, exam);
    res.json({ weeks });
  });
});

function generateWeeklyPlan(progress, exam) {
  const subjectWeeks = {
    'KCET': [
      { name: 'Physics Mechanics', topics: ['Kinematics', 'Forces', 'Energy', 'Momentum'] },
      { name: 'Chemistry Basics', topics: ['Atomic Structure', 'Chemical Bonding', 'States of Matter'] },
      { name: 'Mathematics', topics: ['Algebra', 'Calculus', 'Trigonometry', 'Vectors'] },
      { name: 'Test Preparation', topics: ['Mock Tests', 'Previous Papers', 'Quick Revision'] }
    ],
    'NEET': [
      { name: 'Biology Focus', topics: ['Cell Biology', 'Genetics', 'Human Physiology'] },
      { name: 'Physics Core', topics: ['Mechanics', 'Thermodynamics', 'Optics'] },
      { name: 'Chemistry Essential', topics: ['Organic Chemistry', 'Inorganic Chemistry'] },
      { name: 'Final Preparation', topics: ['Full Tests', 'Topic Revisions', 'Quick Reviews'] }
    ]
  };

  const plan = subjectWeeks[exam] || subjectWeeks['KCET'];
  return plan.map((week, index) => {
    const weekProgress = progress.find(p => p.subject === week.name);
    const completed = weekProgress ? (weekProgress.completed_units / weekProgress.total_units) * 100 : 0;
    
    return {
      topics: week.topics.map((topic, i) => ({
        id: `week${index}_topic${i}`,
        name: topic,
        completed: i < (completed / 25) // Each topic represents 25% of weekly progress
      })),
      progress: Math.round(completed)
    };
  });
}

// Generate personalized weekly test based on progress
app.get('/api/tests/generate-weekly', (req, res) => {
  const userId = req.user.id;
  const exam = req.query.exam || 'KCET';

  // Get user's progress to determine test difficulty and topics
  db.all(`
    SELECT subject, completed_units, total_units 
    FROM progress 
    WHERE user_id = ? AND exam = ?
  `, [userId, exam], (err, progress) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    
    // Generate test questions based on progress
    const test = generatePersonalizedTest(progress, exam);
    
    // Save the generated test
    db.run(`
      INSERT INTO tests (exam, week, questions) 
      VALUES (?, ?, ?)
    `, [exam, test.week, JSON.stringify(test.questions)], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      
      test.id = this.lastID;
      res.json({ test });
    });
  });
});

function generatePersonalizedTest(progress, exam) {
  // Calculate overall progress
  const totalProgress = progress.reduce((sum, p) => sum + (p.completed_units / p.total_units), 0) / progress.length;
  
  // Adjust difficulty based on progress
  const difficulty = Math.min(Math.floor(totalProgress * 3), 2); // 0=easy, 1=medium, 2=hard
  
  // Get current week number
  const week = Math.floor(progress[0]?.completed_units || 0);
  
  // Generate questions (simplified example)
  const questions = getQuestionBank(exam, difficulty).slice(0, 10);
  
  return {
    week,
    questions
  };
}

function getQuestionBank(exam, difficulty) {
  // This would typically fetch from a real question bank
  // For demonstration, returning sample questions
  const difficulties = ['Easy', 'Medium', 'Hard'];
  return [
    {
      q: `${difficulties[difficulty]} question about Newton's Laws`,
      options: ['Option A', 'Option B', 'Option C', 'Option D'],
      a: Math.floor(Math.random() * 4)
    },
    // Add more questions here
  ];
}

// UiPath Integration Endpoints
app.post('/api/uipath/generate-report', async (req, res) => {
  try {
    // NOTE: This is a mock implementation until you set up UiPath Orchestrator
    // When you're ready to integrate with UiPath:
    // 1. Install axios: npm install axios
    // 2. Uncomment the axios code below
    // 3. Set up your environment variables with UiPath credentials

    /* Real UiPath integration code - uncomment when ready:
    const axios = require('axios');
    
    // Get OAuth token from UiPath
    const authResponse = await axios.post(`${UIPATH_CONFIG.orchestratorUrl}/oauth/token`, {
      grant_type: 'client_credentials',
      client_id: UIPATH_CONFIG.clientId,
      client_secret: UIPATH_CONFIG.clientSecret
    });

    const token = authResponse.data.access_token;

    // Start the UiPath process
    const startJobResponse = await axios.post(
      `${UIPATH_CONFIG.orchestratorUrl}/odata/Jobs/UiPath.Server.Configuration.OData.StartJobs`,
      {
        startInfo: {
          ReleaseKey: UIPATH_CONFIG.processName,
          Strategy: 'All',
          InputArguments: JSON.stringify({
            userId: req.user.id,
            userName: req.user.name,
            userEmail: req.user.email
          })
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const jobId = startJobResponse.data.value[0].Id;
    */

    // For now, we'll just mock a successful response
    setTimeout(() => {
      // This would be replaced by actual UiPath webhook callback
      console.log('Mock report generated for user:', req.user.id);
    }, 5000);

    res.json({ 
      success: true, 
      message: 'Report generation started',
      // jobId: jobId // Uncomment when using real UiPath integration
    });

  } catch (error) {
    console.error('UiPath automation error:', error);
    res.status(500).json({ 
      error: 'Failed to start report generation',
      details: error.message 
    });
  }
});
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
