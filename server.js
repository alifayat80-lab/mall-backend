/**
 * Mall backend (CommonJS)
 * Simple file-based DB using db.json
 * - default admin password: 123456
 * - endpoints: invite check, register, login, admin login, admin invite management, block/unlock
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');

const DB_PATH = path.join(__dirname, 'db.json');
const JWT_SECRET = 'replace_with_a_long_secret_change_me';
const ADMIN_INIT_PASSWORD = '123456';

function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Ensure admin has password hash at startup
(async function ensureAdmin() {
  const db = readDB();
  let admin = db.users.find(u => u.role === 'admin');
  if (!admin) {
    const pwHash = await bcrypt.hash(ADMIN_INIT_PASSWORD, 10);
    admin = {
      id: 'u_' + nanoid(6),
      username: 'admin',
      passwordHash: pwHash,
      name: 'Administrator',
      role: 'admin',
      invite: '000000',
      balance: 0,
      vip: 0,
      device: null,
      blocked: false,
      walletAddress: null
    };
    db.users.push(admin);
    writeDB(db);
    console.log('Admin created with username=admin password=' + ADMIN_INIT_PASSWORD);
  } else {
    if (!admin.passwordHash || admin.passwordHash.length < 10) {
      admin.passwordHash = await bcrypt.hash(ADMIN_INIT_PASSWORD, 10);
      writeDB(db);
      console.log('Admin password hash set to default (admin / ' + ADMIN_INIT_PASSWORD + ')');
    }
  }
})();

const app = express();
app.use(cors());
app.use(bodyParser.json());

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---- Public endpoints ----
app.post('/api/invite/check', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ ok: false, msg: 'No code' });
  const db = readDB();
  const inv = db.invites.find(i => i.code === code);
  if (!inv) return res.json({ ok: false, msg: 'Invalid code' });
  if (inv.used) return res.json({ ok: false, msg: 'Already used' });
  return res.json({ ok: true });
});

app.post('/api/auth/register', async (req, res) => {
  const { username, password, inviteCode, name } = req.body;
  if (!username || !password || !inviteCode) return res.status(400).json({ error: 'Missing fields' });
  const db = readDB();
  const inv = db.invites.find(i => i.code === inviteCode);
  if (!inv) return res.status(400).json({ error: 'Invalid invite' });
  if (inv.used) return res.status(400).json({ error: 'Invite used' });
  if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Username exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: 'u_' + nanoid(8),
    username,
    passwordHash: hash,
    name: name || username,
    role: 'user',
    invite: inviteCode,
    balance: 0,
    vip: 1,
    device: null,
    blocked: false,
    walletAddress: null
  };
  db.users.push(user);
  inv.used = true;
  writeDB(db);
  return res.json({ ok: true, msg: 'Registered' });
});

// login with deviceId
app.post('/api/auth/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) return res.status(400).json({ error: 'Missing credentials or deviceId' });
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.blocked) return res.status(403).json({ error: 'User blocked by admin' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.device) {
    user.device = deviceId;
    writeDB(db);
  } else {
    if (user.device !== deviceId) {
      return res.status(403).json({ error: 'This account is locked to another device' });
    }
  }
  const token = generateToken(user);
  return res.json({ ok: true, token, user: { username: user.username, name: user.name, role: user.role, balance: user.balance, vip: user.vip } });
});

app.get('/api/config', (req, res) => {
  const db = readDB();
  res.json(db.config || {});
});

// ---- Admin endpoints ----
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const admin = db.users.find(u => u.username === username && u.role === 'admin');
  if (!admin) return res.status(401).json({ error: 'Invalid admin' });
  const ok = await bcrypt.compare(password, admin.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid admin' });
  const token = generateToken(admin);
  return res.json({ ok: true, token });
});

app.get('/api/admin/invites', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  res.json(db.invites);
});

app.post('/api/admin/invites/create', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { count } = req.body;
  const db = readDB();
  for (let i = 0; i < (count || 10); i++) {
    db.invites.push({ code: 'INV' + Math.floor(10000 + Math.random() * 90000), used: false });
  }
  writeDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/config', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  db.config = { ...db.config, ...req.body };
  writeDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  res.json(db.users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, blocked: u.blocked, device: u.device, balance: u.balance })));
});

app.post('/api/admin/users/block', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { username, block } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.blocked = !!block;
  if (block) {
    user.device = '__BLOCKED__';
  } else {
    user.device = null;
  }
  writeDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/users/unlock', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { username } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.device = null;
  writeDB(db);
  res.json({ ok: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ username: user.username, name: user.name, role: user.role, balance: user.balance, vip: user.vip, blocked: user.blocked });
});

// ✅ Root route (Render এ খুললে এটা দেখাবে)
app.get('/', (req, res) => {
  res.send('✅ Server is running successfully!');
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Backend running on port ' + PORT));
