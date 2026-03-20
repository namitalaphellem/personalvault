const express = require('express');
const session = require('express-session');
const multer  = require('multer');
const Database = require('better-sqlite3');
const bcrypt  = require('bcryptjs');
const path    = require('path');
const fs      = require('fs');

// ── Setup ─────────────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

// Persistent data directory (Railway mounts /data as persistent volume)
const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH     = path.join(DATA_DIR, 'vault.db');

if (!fs.existsSync(DATA_DIR))    fs.mkdirSync(DATA_DIR,    { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notes (
    id       TEXT PRIMARY KEY,
    title    TEXT,
    body     TEXT,
    created  INTEGER,
    updated  INTEGER
  );

  CREATE TABLE IF NOT EXISTS files (
    id        TEXT PRIMARY KEY,
    name      TEXT,
    size      INTEGER,
    mimetype  TEXT,
    filename  TEXT,
    date      INTEGER
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id      TEXT PRIMARY KEY,
    name    TEXT,
    email   TEXT,
    phone   TEXT,
    role    TEXT,
    company TEXT,
    address TEXT,
    notes   TEXT
  );
`);

// Seed default admin user if none exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync(process.env.VAULT_PASSWORD || 'vault2024', 10);
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('admin', hash);
  console.log('Default user created: admin / vault2024');
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'personalvault-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: 1000000 * 1024 * 1024 } // 50MB limit
});

// Auth guard
function auth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Not logged in' });
}

function uid() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ ok: true });
});

app.post('/api/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

// ── Notes Routes ──────────────────────────────────────────────────────────────
app.get('/api/notes', auth, (req, res) => {
  const notes = db.prepare('SELECT * FROM notes ORDER BY updated DESC').all();
  res.json(notes);
});

app.post('/api/notes', auth, (req, res) => {
  const { title, body } = req.body;
  const note = { id: uid(), title: title || '', body: body || '', created: Date.now(), updated: Date.now() };
  db.prepare('INSERT INTO notes (id, title, body, created, updated) VALUES (?, ?, ?, ?, ?)').run(note.id, note.title, note.body, note.created, note.updated);
  res.json(note);
});

app.put('/api/notes/:id', auth, (req, res) => {
  const { title, body } = req.body;
  const updated = Date.now();
  db.prepare('UPDATE notes SET title = ?, body = ?, updated = ? WHERE id = ?').run(title || '', body || '', updated, req.params.id);
  res.json({ ok: true, updated });
});

app.delete('/api/notes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Files Routes ──────────────────────────────────────────────────────────────
app.get('/api/files', auth, (req, res) => {
  const files = db.prepare('SELECT id, name, size, mimetype, date FROM files ORDER BY date DESC').all();
  res.json(files);
});

app.post('/api/files', auth, upload.array('files'), (req, res) => {
  const saved = req.files.map(f => {
    const entry = { id: uid(), name: f.originalname, size: f.size, mimetype: f.mimetype, filename: f.filename, date: Date.now() };
    db.prepare('INSERT INTO files (id, name, size, mimetype, filename, date) VALUES (?, ?, ?, ?, ?, ?)').run(entry.id, entry.name, entry.size, entry.mimetype, entry.filename, entry.date);
    return { id: entry.id, name: entry.name, size: entry.size, mimetype: entry.mimetype, date: entry.date };
  });
  res.json(saved);
});

app.get('/api/files/:id/download', auth, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found' });
  const filePath = path.join(UPLOADS_DIR, file.filename);
  res.download(filePath, file.name);
});

app.get('/api/files/:id/preview', auth, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found' });
  const filePath = path.join(UPLOADS_DIR, file.filename);
  res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${file.name}"`);
  fs.createReadStream(filePath).pipe(res);
});

app.delete('/api/files/:id', auth, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (file) {
    const filePath = path.join(UPLOADS_DIR, file.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
  }
  res.json({ ok: true });
});

// ── Contacts Routes ───────────────────────────────────────────────────────────
app.get('/api/contacts', auth, (req, res) => {
  const contacts = db.prepare('SELECT * FROM contacts ORDER BY name ASC').all();
  res.json(contacts);
});

app.post('/api/contacts', auth, (req, res) => {
  const { name, email, phone, role, company, address, notes } = req.body;
  const contact = { id: uid(), name: name || '', email: email || '', phone: phone || '', role: role || '', company: company || '', address: address || '', notes: notes || '' };
  db.prepare('INSERT INTO contacts (id, name, email, phone, role, company, address, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(contact.id, contact.name, contact.email, contact.phone, contact.role, contact.company, contact.address, contact.notes);
  res.json(contact);
});

app.put('/api/contacts/:id', auth, (req, res) => {
  const { name, email, phone, role, company, address, notes } = req.body;
  db.prepare('UPDATE contacts SET name=?, email=?, phone=?, role=?, company=?, address=?, notes=? WHERE id=?').run(name||'', email||'', phone||'', role||'', company||'', address||'', notes||'', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/contacts/:id', auth, (req, res) => {
  db.prepare('DELETE FROM contacts WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`PersonalVault running on http://localhost:${PORT}`));
