// server.js (paste entire file into mail-app/server.js)
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';

// files
const usersFile = path.join(__dirname, 'users.json');
const mailsFile = path.join(__dirname, 'mails.json');
const uploadsDir = path.join(__dirname, 'uploads');

// ensure files/dirs
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, JSON.stringify([], null, 2));
if (!fs.existsSync(mailsFile)) fs.writeFileSync(mailsFile, JSON.stringify([], null, 2));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// load data helpers
function readUsers() {
  try { return JSON.parse(fs.readFileSync(usersFile, 'utf8') || '[]'); }
  catch { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}
function readMails() {
  try { return JSON.parse(fs.readFileSync(mailsFile, 'utf8') || '[]'); }
  catch { return []; }
}
function writeMails(mails) {
  fs.writeFileSync(mailsFile, JSON.stringify(mails, null, 2));
}

// helper: auth middleware
function authenticate(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ message: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Invalid auth format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { email }
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

/**
 * Register
 * Expects JSON: { email, password, publicKeyPem }
 * - password is hashed (bcrypt)
 * - publicKeyPem is stored (string)
 */
app.post('/register', (req, res) => {
  const { email, password, publicKeyPem } = req.body;
  if (!email || !password || !publicKeyPem) {
    return res.status(400).json({ message: 'email, password and publicKeyPem required' });
  }
  const users = readUsers();
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  users.push({ email, passwordHash: hash, publicKeyPem });
  writeUsers(users);
  return res.json({ message: 'Registered' });
});

/**
 * Login
 * Expects JSON: { email, password }
 * Returns: { token }
 */
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'email+password required' });
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '12h' });
  return res.json({ token });
});

/**
 * Fetch public key of a user
 * GET /pubkey/:email
 * Returns { publicKeyPem }
 */
app.get('/pubkey/:email', (req, res) => {
  const email = req.params.email;
  const users = readUsers();
  const u = users.find(x => x.email === email);
  if (!u) return res.status(404).json({ message: 'User not found' });
  return res.json({ publicKeyPem: u.publicKeyPem });
});

/**
 * Send an encrypted message bundle
 * Protected - sender must be authenticated
 * Expects multipart/form-data (to allow attachment) or JSON:
 * For JSON: { to, subject, bundle }
 * bundle = {
 *   ciphertext: base64,
 *   iv: base64,
 *   encKey: base64,        // AES key encrypted with recipient RSA-OAEP
 *   signature: base64,     // signature over ciphertext (by sender private key)
 *   hash?: hex (optional)
 * }
 */
app.post('/send', upload.single('attachment'), authenticate, (req, res) => {
  // accept either JSON body or form-data
  const from = req.user.email;
  let to, subject, bundle;
  if (req.is('multipart/form-data')) {
    to = req.body.to;
    subject = req.body.subject;
    // bundle sent as JSON string field
    try { bundle = req.body.bundle ? JSON.parse(req.body.bundle) : null; } catch { bundle = null; }
  } else {
    ({ to, subject, bundle } = req.body || {});
  }
  if (!to || !subject || !bundle) return res.status(400).json({ message: 'to, subject and bundle required' });

  // verify recipient exists
  const users = readUsers();
  const recipient = users.find(u => u.email === to);
  if (!recipient) return res.status(400).json({ message: 'Recipient does not exist' });

  const mails = readMails();
  const newMail = {
    id: Date.now() + '-' + Math.floor(Math.random()*10000),
    from,
    to,
    subject,
    bundle,
    date: new Date().toISOString(),
    attachment: req.file ? req.file.filename : null
  };
  mails.push(newMail);
  writeMails(mails);
  return res.json({ message: 'Mail stored' });
});

/**
 * Inbox for the authenticated user
 * GET /inbox
 * Returns list of message objects (encrypted bundles) for the user (do NOT decrypt on server)
 */
app.get('/inbox', authenticate, (req, res) => {
  const email = req.user.email;
  const mails = readMails().filter(m => m.to === email).map(m => ({
    id: m.id,
    from: m.from,
    subject: m.subject,
    bundle: m.bundle,
    date: m.date,
    attachment: m.attachment
  }));
  return res.json(mails);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
