const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));
// ── Database pool ─────────────────────────────────────────────────────────────
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'adaptive_learning',
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'studyiq_secret';

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.send('StudyIQ Backend Running ✅'));

// ── POST /register ────────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { name, email, password, department, semester } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO students (name, email, password_hash, department, semester) VALUES (?, ?, ?, ?, ?)',
      [name, email, hash, department || '', semester || 1]
    );
    res.status(201).json({ message: 'Registered successfully', student_id: result.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: e.message });
  }
});

// ── POST /login ───────────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.execute(
      'SELECT * FROM students WHERE email = ?', [email]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password' });

    const student = rows[0];
    const match = await bcrypt.compare(password, student.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign(
      { student_id: student.student_id, name: student.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      student_id: student.student_id,
      name: student.name,
      email: student.email,
      department: student.department,
      semester: student.semester
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /students ─────────────────────────────────────────────────────────────
app.get('/students', auth, async (req, res) => {
  const [rows] = await db.execute('SELECT student_id, name, email FROM students');
  res.json(rows);
});

// ── PUT /students/:id ─────────────────────────────────────────────────────────
app.put('/students/:id', auth, async (req, res) => {
  const { name, department, semester } = req.body;
  await db.execute(
    'UPDATE students SET name=?, department=?, semester=? WHERE student_id=?',
    [name, department, semester, req.params.id]
  );
  res.json({ message: 'Profile updated' });
});

// ── GET /performance ──────────────────────────────────────────────────────────
app.get('/performance', auth, async (req, res) => {
  try {
    const sql = `
      SELECT
        s.student_id,
        st.name        AS student_name,
        sub.name       AS subject_name,
        t.topic_id,
        t.topic_name,
        t.weightage,
        s.marks_obtained,
        s.max_marks,
        ROUND((s.marks_obtained * 100.0 / s.max_marks), 2) AS score_pct,
        s.exam_date,
        CASE
          WHEN (s.marks_obtained * 100.0 / s.max_marks) < 40 THEN 'critical'
          WHEN (s.marks_obtained * 100.0 / s.max_marks) < 60 THEN 'weak'
          WHEN (s.marks_obtained * 100.0 / s.max_marks) < 75 THEN 'average'
          ELSE 'strong'
        END AS performance_band
      FROM (
        SELECT *,
          ROW_NUMBER() OVER (PARTITION BY student_id, topic_id ORDER BY exam_date DESC) AS rn
        FROM scores
      ) s
      JOIN students  st  ON s.student_id = st.student_id
      JOIN topics     t  ON s.topic_id   = t.topic_id
      JOIN subjects  sub ON t.subject_id = sub.subject_id
      WHERE s.rn = 1
    `;
    const [rows] = await db.execute(sql);
    // Return as array of arrays (indexed) for frontend compatibility
    res.json(rows.map(r => Object.values(r)));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /scores ──────────────────────────────────────────────────────────────
app.post('/scores', auth, async (req, res) => {
  const { student_id, topic_id, marks, max_marks, exam_date } = req.body;
  if (!student_id || !topic_id)
    return res.status(400).json({ error: 'student_id and topic_id required' });

  await db.execute(
    'INSERT INTO scores (student_id, topic_id, marks_obtained, max_marks, exam_date) VALUES (?, ?, ?, ?, ?)',
    [student_id, topic_id, marks, max_marks || 100, exam_date || new Date().toISOString().split('T')[0]]
  );
  res.json({ message: 'Score added successfully' });
});

// ── GET /subjects ─────────────────────────────────────────────────────────────
app.get('/subjects', auth, async (req, res) => {
  const [rows] = await db.execute('SELECT subject_id, name FROM subjects ORDER BY name');
  res.json(rows);
});

// ── POST /subjects ────────────────────────────────────────────────────────────
app.post('/subjects', auth, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const [result] = await db.execute('INSERT INTO subjects (name) VALUES (?)', [name]);
  res.status(201).json({ subject_id: result.insertId, name });
});

// ── GET /topics ───────────────────────────────────────────────────────────────
app.get('/topics', auth, async (req, res) => {
  const { subject_id } = req.query;
  if (subject_id) {
    const [rows] = await db.execute(
      'SELECT topic_id, topic_name FROM topics WHERE subject_id = ? ORDER BY topic_name',
      [subject_id]
    );
    return res.json(rows);
  }
  const [rows] = await db.execute('SELECT topic_id, topic_name FROM topics ORDER BY topic_name');
  res.json(rows);
});

// ── POST /topics ──────────────────────────────────────────────────────────────
app.post('/topics', auth, async (req, res) => {
  const { subject_id, topic_name } = req.body;
  if (!subject_id || !topic_name)
    return res.status(400).json({ error: 'subject_id and topic_name required' });
  const [result] = await db.execute(
    'INSERT INTO topics (subject_id, topic_name) VALUES (?, ?)',
    [subject_id, topic_name]
  );
  res.status(201).json({ topic_id: result.insertId, topic_name });
});

// ── POST /api/chat — AI Tutor via Groq ───────────────────────────────────────
app.post('/api/chat', auth, async (req, res) => {
  const { message, history = [], systemInstruction } = req.body;
  const groqKey = process.env.GROQ_API_KEY;

  if (!groqKey || groqKey === 'your_groq_key_here') {
    return res.status(500).json({ error: 'GROQ_API_KEY not set in .env' });
  }

  try {
    const messages = [];
    if (systemInstruction) messages.push({ role: 'system', content: systemInstruction });

    history.forEach(h => messages.push({
      role: h.role === 'model' ? 'assistant' : 'user',
      content: h.parts[0].text
    }));
    messages.push({ role: 'user', content: message });

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${groqKey}`
      },
      body: JSON.stringify({
        model: 'llama-3.1-8b-instant',
        messages,
        max_tokens: 1024
      })
    });

    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || 'Groq error' });

    const reply = data.choices?.[0]?.message?.content;
    if (!reply) return res.status(500).json({ error: 'Empty response from AI' });

    res.json({ status: 'success', reply });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/extract-marks — AI extracts marks from image/PDF ────────────────
app.post('/api/extract-marks', auth, async (req, res) => {
  const { base64, mimeType, prompt } = req.body;
  const groqKey = process.env.GROQ_API_KEY;

  if (!groqKey || groqKey === 'your_groq_key_here') {
    return res.status(500).json({ error: 'GROQ_API_KEY not set in .env' });
  }

  if (!base64 || !mimeType) {
    return res.status(400).json({ error: 'base64 and mimeType required' });
  }

  try {
    // Use llama-3.2-11b-vision-preview for image/PDF extraction
    const isImage = mimeType.startsWith('image/');

    let messages;
    if (isImage) {
      // Vision model for images
      messages = [{
        role: 'user',
        content: [
          { type: 'text', text: prompt },
          { type: 'image_url', image_url: { url: `data:${mimeType};base64,${base64}` } }
        ]
      }];
    } else {
      // For PDF — use text model with instruction to extract from document description
      messages = [{
        role: 'system',
        content: 'You are an expert at extracting academic marks from documents. Always return valid JSON only.'
      }, {
        role: 'user',
        content: prompt + '\n\nNote: The document is a PDF. Extract any visible marks/scores and return JSON array.'
      }];
    }

    const model = isImage ? 'meta-llama/llama-4-scout-17b-16e-instruct' : 'llama-3.1-8b-instant';

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${groqKey}`
      },
      body: JSON.stringify({ model, messages, max_tokens: 1024 })
    });

    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || 'Groq error' });

    const result = data.choices?.[0]?.message?.content;
    if (!result) return res.status(500).json({ error: 'Empty response from AI' });

    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ StudyIQ backend running on http://localhost:${PORT}`));
