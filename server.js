const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ExcelJS = require('exceljs');

const app = express();
const PORT = 4100;

const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const BREAKDOWNS_FILE = path.join(DATA_DIR, 'breakdowns.json');
const MASTER_DATA_FILE = path.join(DATA_DIR, 'master_data.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSION_SECRET_FILE = path.join(DATA_DIR, 'session_secret.txt');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

function getSessionSecret() {
  if (fs.existsSync(SESSION_SECRET_FILE)) return fs.readFileSync(SESSION_SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SESSION_SECRET_FILE, secret, 'utf8');
  return secret;
}

app.use(express.json());
app.use(session({
  store: new FileStore({ path: SESSIONS_DIR, ttl: 7 * 24 * 60 * 60, retries: 1, logFn: () => {} }),
  secret: getSessionSecret(),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ---------- File helpers ----------
function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8').trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.error(`Failed to read ${file}:`, e.message);
    return fallback;
  }
}

function writeJson(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

function readBreakdowns() {
  return readJson(BREAKDOWNS_FILE, []);
}

function writeBreakdowns(rows) {
  writeJson(BREAKDOWNS_FILE, rows);
}

function readMasterData() {
  return readJson(MASTER_DATA_FILE, {
    units: [], userDepartments: [], maintenanceDepartments: [],
    breakdownTypes: [], statuses: [], recurringOptions: [], personnel: [], equipment: [], materials: []
  });
}

function writeMasterData(data) {
  writeJson(MASTER_DATA_FILE, data);
}

function readUsers() {
  return readJson(USERS_FILE, []);
}

function writeUsers(users) {
  writeJson(USERS_FILE, users);
}

// ---------- Auth helpers ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  const hashBuffer = Buffer.from(hash, 'hex');
  const suppliedBuffer = crypto.scryptSync(password, salt, 64);
  return hashBuffer.length === suppliedBuffer.length && crypto.timingSafeEqual(hashBuffer, suppliedBuffer);
}

const ROLES = ['admin', 'viewer', 'editor'];

function publicUser(u) {
  return { id: u.id, email: u.email, role: u.role || 'editor', createdAt: u.createdAt };
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

function currentUserRole(req) {
  if (!req.session || !req.session.userId) return null;
  const user = readUsers().find(u => u.id === req.session.userId);
  return user ? (user.role || 'editor') : null;
}

// admin: unrestricted. viewer: read-only everywhere (no writes at all).
// editor: can create/edit/delete breakdowns only — no master data, no user
// management.
function requireRole(...roles) {
  return (req, res, next) => {
    const role = currentUserRole(req);
    if (!role || !roles.includes(role)) return res.status(403).json({ error: 'Not authorized for this action' });
    next();
  };
}

const PUBLIC_API_PATHS = ['/api/auth/status', '/api/auth/setup', '/api/auth/login', '/api/auth/logout'];
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/') || req.path === '/health' || PUBLIC_API_PATHS.includes(req.path)) return next();
  return requireAuth(req, res, next);
});

// no-cache (not no-store) so the browser always revalidates with the server
// before reusing a cached copy — avoids "I don't see the update" confusion
// after a deploy without needing a hard refresh, while still allowing fast
// 304 responses when nothing changed.
app.use(express.static(PUBLIC_DIR, {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

// ---------- Auth routes ----------
app.get('/api/auth/status', (req, res) => {
  const users = readUsers();
  if (req.session && req.session.userId) {
    const user = users.find(u => u.id === req.session.userId);
    if (user) return res.json({ setupNeeded: false, user: publicUser(user) });
  }
  res.json({ setupNeeded: users.length === 0, user: null });
});

app.post('/api/auth/setup', (req, res) => {
  const users = readUsers();
  if (users.length > 0) return res.status(400).json({ error: 'Setup already completed' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const user = {
    id: crypto.randomUUID(),
    email: String(email).toLowerCase().trim(),
    passwordHash: hashPassword(password),
    role: 'admin',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeUsers(users);
  req.session.userId = user.id;
  res.status(201).json(publicUser(user));
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.email === String(email || '').toLowerCase().trim());
  if (!user || !verifyPassword(password || '', user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  req.session.userId = user.id;
  res.json(publicUser(user));
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.post('/api/auth/change-password', (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!verifyPassword(currentPassword, user.passwordHash)) return res.status(401).json({ error: 'Current password is incorrect' });
  user.passwordHash = hashPassword(newPassword);
  writeUsers(users);
  res.json({ success: true });
});

// ---------- Users management (admin only) ----------
app.get('/api/users', requireRole('admin'), (req, res) => {
  res.json(readUsers().map(publicUser));
});

app.post('/api/users', requireRole('admin'), (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (role && !ROLES.includes(role)) return res.status(400).json({ error: 'Role must be one of: ' + ROLES.join(', ') });
  const users = readUsers();
  const normEmail = String(email).toLowerCase().trim();
  if (users.some(u => u.email === normEmail)) return res.status(400).json({ error: 'A user with this email already exists' });
  const user = { id: crypto.randomUUID(), email: normEmail, passwordHash: hashPassword(password), role: role || 'editor', createdAt: new Date().toISOString() };
  users.push(user);
  writeUsers(users);
  res.status(201).json(publicUser(user));
});

app.put('/api/users/:id/role', requireRole('admin'), (req, res) => {
  const { role } = req.body;
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Role must be one of: ' + ROLES.join(', ') });
  const users = readUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  user.role = role;
  writeUsers(users);
  res.json(publicUser(user));
});

app.delete('/api/users/:id', requireRole('admin'), (req, res) => {
  const users = readUsers();
  if (users.length <= 1) return res.status(400).json({ error: 'Cannot delete the last remaining user' });
  const next = users.filter(u => u.id !== req.params.id);
  if (next.length === users.length) return res.status(404).json({ error: 'Not found' });
  writeUsers(next);
  if (req.session.userId === req.params.id) {
    return req.session.destroy(() => res.json({ success: true, selfDeleted: true }));
  }
  res.json({ success: true });
});

// ---------- Derived-field computation ----------
function minutesBetween(a, b) {
  if (!a || !b) return null;
  const ta = new Date(a).getTime();
  const tb = new Date(b).getTime();
  if (isNaN(ta) || isNaN(tb)) return null;
  return Math.round((tb - ta) / 60000);
}

function dateOnly(dt) {
  if (!dt) return null;
  const d = new Date(dt);
  if (isNaN(d.getTime())) return null;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function computeDerived(rec) {
  const responseTimeMin = minutesBetween(rec.intimationDateTime, rec.attendedDateTime);
  const repairTimeMin = minutesBetween(rec.attendedDateTime, rec.restorationDateTime);
  const totalDowntimeMin = minutesBetween(rec.intimationDateTime, rec.restorationDateTime);
  return {
    date: dateOnly(rec.intimationDateTime),
    responseTimeMin,
    repairTimeMin,
    totalDowntimeMin,
    totalDowntimeHrs: totalDowntimeMin != null ? Math.round((totalDowntimeMin / 60) * 100) / 100 : null
  };
}

function nextBreakdownId(rows, intimationDateTime) {
  const d = new Date(intimationDateTime);
  if (isNaN(d.getTime())) return null;
  const yy = String(d.getFullYear()).slice(-2);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const prefix = `BD-${yy}${mm}-`;
  let maxSeq = 0;
  for (const r of rows) {
    if (r.breakdownId && r.breakdownId.startsWith(prefix)) {
      const seq = parseInt(r.breakdownId.slice(prefix.length), 10);
      if (!isNaN(seq) && seq > maxSeq) maxSeq = seq;
    }
  }
  return `${prefix}${String(maxSeq + 1).padStart(3, '0')}`;
}

const EDITABLE_FIELDS = [
  'unit', 'userDepartment', 'equipment', 'equipmentCode', 'breakdownType', 'problem',
  'intimationDateTime', 'attendedDateTime', 'restorationDateTime', 'maintenanceDept',
  'personnelNames', 'noOfPersonnel', 'rootCause', 'correctiveAction', 'spareUsed',
  'materialUsed', 'cost',
  'status', 'recurring', 'attendedBy', 'verifiedBy', 'remarks'
];

function pickEditable(body) {
  const out = {};
  for (const f of EDITABLE_FIELDS) {
    if (body[f] !== undefined) out[f] = body[f];
  }
  return out;
}

const REQUIRED_FIELDS = ['unit', 'userDepartment', 'equipment', 'breakdownType', 'maintenanceDept', 'status', 'intimationDateTime'];

function validateBreakdown(fields) {
  for (const f of REQUIRED_FIELDS) {
    if (!fields[f]) return `${f} is required`;
  }
  const intimation = new Date(fields.intimationDateTime).getTime();
  if (isNaN(intimation)) return 'intimationDateTime is invalid';

  if (fields.attendedDateTime) {
    const attended = new Date(fields.attendedDateTime).getTime();
    if (isNaN(attended)) return 'attendedDateTime is invalid';
    if (attended < intimation) return 'Attended Date & Time cannot be before Intimation Date & Time';

    if (fields.restorationDateTime) {
      const restoration = new Date(fields.restorationDateTime).getTime();
      if (isNaN(restoration)) return 'restorationDateTime is invalid';
      if (restoration < attended) return 'Restoration Date & Time cannot be before Attended Date & Time';
    }
  } else if (fields.restorationDateTime) {
    const restoration = new Date(fields.restorationDateTime).getTime();
    if (isNaN(restoration)) return 'restorationDateTime is invalid';
    if (restoration < intimation) return 'Restoration Date & Time cannot be before Intimation Date & Time';
  }

  if (fields.noOfPersonnel != null && fields.noOfPersonnel !== '' && (isNaN(fields.noOfPersonnel) || fields.noOfPersonnel < 0)) {
    return 'No. of Personnel must be a non-negative number';
  }
  return null;
}

// ---------- Breakdown Log API ----------
app.get('/api/breakdowns', (req, res) => {
  res.json(readBreakdowns());
});

app.post('/api/breakdowns', requireRole('admin', 'editor'), (req, res) => {
  const rows = readBreakdowns();
  const fields = pickEditable(req.body);
  const error = validateBreakdown(fields);
  if (error) return res.status(400).json({ error });
  const now = new Date().toISOString();
  const rec = {
    id: crypto.randomUUID(),
    breakdownId: nextBreakdownId(rows, fields.intimationDateTime),
    ...fields,
    ...computeDerived(fields),
    createdAt: now,
    updatedAt: now
  };
  rows.push(rec);
  writeBreakdowns(rows);
  res.status(201).json(rec);
});

app.put('/api/breakdowns/:id', requireRole('admin', 'editor'), (req, res) => {
  const rows = readBreakdowns();
  const idx = rows.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const fields = pickEditable(req.body);
  const merged = { ...rows[idx], ...fields };
  const error = validateBreakdown(merged);
  if (error) return res.status(400).json({ error });
  merged.updatedAt = new Date().toISOString();
  Object.assign(merged, computeDerived(merged));
  rows[idx] = merged;
  writeBreakdowns(rows);
  res.json(merged);
});

app.delete('/api/breakdowns/:id', requireRole('admin', 'editor'), (req, res) => {
  const rows = readBreakdowns();
  const next = rows.filter(r => r.id !== req.params.id);
  if (next.length === rows.length) return res.status(404).json({ error: 'Not found' });
  writeBreakdowns(next);
  res.json({ success: true });
});

// ---------- Master Data API ----------
app.get('/api/master-data', (req, res) => {
  res.json(readMasterData());
});

app.put('/api/master-data', requireRole('admin'), (req, res) => {
  writeMasterData(req.body);
  res.json(req.body);
});

// ---------- Daily Monitoring ----------
function avg(nums) {
  const valid = nums.filter(n => n != null);
  if (!valid.length) return null;
  return valid.reduce((a, b) => a + b, 0) / valid.length;
}
function sum(nums) {
  return nums.filter(n => n != null).reduce((a, b) => a + b, 0);
}
function round2(n) {
  return n == null ? null : Math.round(n * 100) / 100;
}

app.get('/api/daily-monitoring', (req, res) => {
  const startStr = req.query.start;
  const target = parseFloat(req.query.target) || 120;
  const start = startStr ? new Date(startStr) : new Date();
  if (isNaN(start.getTime())) return res.status(400).json({ error: 'Invalid start date' });

  const rows = readBreakdowns();
  const days = [];
  for (let i = 0; i < 31; i++) {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    const dayStr = dateOnly(d);
    const dayRecords = rows.filter(r => r.date === dayStr);
    const totalBreakdowns = dayRecords.length;
    const closed = dayRecords.filter(r => r.status === 'Closed').length;
    const pending = totalBreakdowns - closed;
    const totalDowntimeMin = sum(dayRecords.map(r => r.totalDowntimeMin));
    const mttrTotalMin = avg(dayRecords.map(r => r.totalDowntimeMin));
    const manpower = sum(dayRecords.map(r => r.noOfPersonnel));
    const totalMaterialCost = sum(dayRecords.map(r => r.cost));
    days.push({
      date: dayStr,
      totalBreakdowns,
      closed,
      pending,
      totalDowntimeMin,
      totalDowntimeHrs: round2(totalDowntimeMin / 60),
      avgResponseTimeMin: round2(avg(dayRecords.map(r => r.responseTimeMin))),
      mttrTotalMin: round2(mttrTotalMin),
      mttrRepairOnlyMin: round2(avg(dayRecords.map(r => r.repairTimeMin))),
      mttrTotalHrs: totalBreakdowns ? round2(mttrTotalMin / 60) : null,
      manpowerDeputed: manpower,
      totalMaterialCost: round2(totalMaterialCost),
      mttrVsTarget: totalBreakdowns === 0 ? '-' : (mttrTotalMin <= target ? 'OK' : 'HIGH')
    });
  }

  const monthDayStrs = days.map(d => d.date);
  const monthRecords = rows.filter(r => monthDayStrs.includes(r.date));
  const monthTotalDowntimeMin = sum(monthRecords.map(r => r.totalDowntimeMin));
  const monthMttrTotalMin = avg(monthRecords.map(r => r.totalDowntimeMin));
  const monthTotal = {
    totalBreakdowns: monthRecords.length,
    closed: monthRecords.filter(r => r.status === 'Closed').length,
    pending: monthRecords.filter(r => r.status !== 'Closed').length,
    totalDowntimeMin: monthTotalDowntimeMin,
    totalDowntimeHrs: round2(monthTotalDowntimeMin / 60),
    avgResponseTimeMin: round2(avg(monthRecords.map(r => r.responseTimeMin))),
    mttrTotalMin: round2(monthMttrTotalMin),
    mttrRepairOnlyMin: round2(avg(monthRecords.map(r => r.repairTimeMin))),
    mttrTotalHrs: monthRecords.length ? round2(monthMttrTotalMin / 60) : null,
    manpowerDeputed: sum(monthRecords.map(r => r.noOfPersonnel)),
    totalMaterialCost: round2(sum(monthRecords.map(r => r.cost))),
    mttrVsTarget: monthRecords.length === 0 ? '-' : (monthMttrTotalMin <= target ? 'OK' : 'HIGH')
  };

  res.json({ target, days, monthTotal });
});

// ---------- Dept & Equipment Summary ----------
function groupSummary(records, groupField, fixedGroups) {
  const totalDowntimeAll = sum(records.map(r => r.totalDowntimeMin));
  const groups = fixedGroups && fixedGroups.length
    ? fixedGroups
    : [...new Set(records.map(r => r[groupField]).filter(Boolean))].sort();

  return groups.map(name => {
    const groupRecords = records.filter(r => r[groupField] === name);
    const totalDowntimeMin = sum(groupRecords.map(r => r.totalDowntimeMin));
    const mttrTotalMin = avg(groupRecords.map(r => r.totalDowntimeMin));
    return {
      name,
      breakdowns: groupRecords.length,
      totalDowntimeMin,
      totalDowntimeHrs: round2(totalDowntimeMin / 60),
      mttrTotalMin: groupRecords.length ? round2(mttrTotalMin) : null,
      avgResponseMin: groupRecords.length ? round2(avg(groupRecords.map(r => r.responseTimeMin))) : null,
      pending: groupRecords.filter(r => r.status !== 'Closed').length,
      pctOfTotalDowntime: totalDowntimeAll ? round2((totalDowntimeMin / totalDowntimeAll) * 100) : 0
    };
  });
}

app.get('/api/dept-summary', (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: 'from and to are required' });
  const rows = readBreakdowns();
  const records = rows.filter(r => r.date && r.date >= from && r.date <= to);
  const master = readMasterData();

  res.json({
    from, to,
    byMaintenanceDept: groupSummary(records, 'maintenanceDept', master.maintenanceDepartments),
    byUserDept: groupSummary(records, 'userDepartment', master.userDepartments),
    byBreakdownType: groupSummary(records, 'breakdownType', master.breakdownTypes),
    byEquipment: groupSummary(records, 'equipment', null)
  });
});

// ---------- Excel Export ----------
app.get('/api/export', async (req, res) => {
  const { from, to } = req.query;
  let rows = readBreakdowns();
  if (from) rows = rows.filter(r => r.date && r.date >= from);
  if (to) rows = rows.filter(r => r.date && r.date <= to);
  rows.sort((a, b) => (a.intimationDateTime || '').localeCompare(b.intimationDateTime || ''));

  const wb = new ExcelJS.Workbook();
  const sheet = wb.addWorksheet('Breakdown Log');
  sheet.columns = [
    { header: 'S.No.', key: 'sno', width: 6 },
    { header: 'Date', key: 'date', width: 12 },
    { header: 'Breakdown ID', key: 'breakdownId', width: 16 },
    { header: 'Unit / Plant', key: 'unit', width: 14 },
    { header: 'User Department', key: 'userDepartment', width: 18 },
    { header: 'Equipment / Machine', key: 'equipment', width: 20 },
    { header: 'Equipment Code', key: 'equipmentCode', width: 14 },
    { header: 'Breakdown Type', key: 'breakdownType', width: 16 },
    { header: 'Problem / Nature of Breakdown', key: 'problem', width: 30 },
    { header: 'Intimation Date & Time', key: 'intimationDateTime', width: 20 },
    { header: 'Attended Date & Time', key: 'attendedDateTime', width: 20 },
    { header: 'Restoration Date & Time', key: 'restorationDateTime', width: 20 },
    { header: 'Response Time (Min)', key: 'responseTimeMin', width: 14 },
    { header: 'Repair Time (Min)', key: 'repairTimeMin', width: 14 },
    { header: 'Total Downtime (Min)', key: 'totalDowntimeMin', width: 16 },
    { header: 'Total Downtime (Hrs)', key: 'totalDowntimeHrs', width: 16 },
    { header: 'Maintenance Dept', key: 'maintenanceDept', width: 16 },
    { header: 'Personnel Deputed (Names)', key: 'personnelNames', width: 22 },
    { header: 'No. of Personnel', key: 'noOfPersonnel', width: 12 },
    { header: 'Root Cause', key: 'rootCause', width: 26 },
    { header: 'Corrective Action Taken', key: 'correctiveAction', width: 26 },
    { header: 'Spare / Material Used', key: 'spareUsed', width: 22 },
    { header: 'Material Used (Master)', key: 'materialUsed', width: 22 },
    { header: 'Cost (₹)', key: 'cost', width: 12 },
    { header: 'Status', key: 'status', width: 12 },
    { header: 'Recurring?', key: 'recurring', width: 10 },
    { header: 'Attended By / Shift Incharge', key: 'attendedBy', width: 20 },
    { header: 'Verified By', key: 'verifiedBy', width: 16 },
    { header: 'Remarks', key: 'remarks', width: 20 }
  ];
  sheet.getRow(1).font = { bold: true };
  sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE8F0FB' } };

  rows.forEach((r, i) => {
    sheet.addRow({
      sno: i + 1,
      date: fmtDMY(r.date),
      breakdownId: r.breakdownId,
      unit: r.unit,
      userDepartment: r.userDepartment,
      equipment: r.equipment,
      equipmentCode: r.equipmentCode,
      breakdownType: r.breakdownType,
      problem: r.problem,
      intimationDateTime: fmtDMYHM(r.intimationDateTime),
      attendedDateTime: fmtDMYHM(r.attendedDateTime),
      restorationDateTime: fmtDMYHM(r.restorationDateTime),
      responseTimeMin: r.responseTimeMin,
      repairTimeMin: r.repairTimeMin,
      totalDowntimeMin: r.totalDowntimeMin,
      totalDowntimeHrs: r.totalDowntimeHrs,
      maintenanceDept: r.maintenanceDept,
      personnelNames: r.personnelNames,
      noOfPersonnel: r.noOfPersonnel,
      rootCause: r.rootCause,
      correctiveAction: r.correctiveAction,
      spareUsed: r.spareUsed,
      materialUsed: r.materialUsed,
      cost: r.cost,
      status: r.status,
      recurring: r.recurring,
      attendedBy: r.attendedBy,
      verifiedBy: r.verifiedBy,
      remarks: r.remarks
    });
  });

  const fileName = `MTTR_Breakdown_Log_${dateOnly(new Date())}.xlsx`;
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
  await wb.xlsx.write(res);
  res.end();
});

function fmtDMY(dateStr) {
  if (!dateStr) return '';
  const [y, m, d] = dateStr.split('-');
  return `${d}-${m}-${y}`;
}
function fmtDMYHM(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getDate())}-${pad(d.getMonth() + 1)}-${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// ---------- Dashboard ----------
app.get('/api/dashboard', (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error: 'from and to are required' });
  const rows = readBreakdowns().filter(r => r.date && r.date >= from && r.date <= to);

  const closed = rows.filter(r => r.status === 'Closed').length;
  const open = rows.length - closed;
  const avgMttrMin = avg(rows.map(r => r.totalDowntimeMin));
  const avgResponseMin = avg(rows.map(r => r.responseTimeMin));

  const byDate = {};
  for (const r of rows) {
    if (!r.date) continue;
    if (!byDate[r.date]) byDate[r.date] = [];
    byDate[r.date].push(r.totalDowntimeMin);
  }
  const trend = Object.keys(byDate).sort().map(date => ({
    date,
    mttrMin: round2(avg(byDate[date]))
  }));

  const byEquipment = {};
  for (const r of rows) {
    if (!r.equipment) continue;
    byEquipment[r.equipment] = (byEquipment[r.equipment] || 0) + (r.totalDowntimeMin || 0);
  }
  const topEquipment = Object.entries(byEquipment)
    .map(([name, totalDowntimeMin]) => ({ name, totalDowntimeMin }))
    .sort((a, b) => b.totalDowntimeMin - a.totalDowntimeMin)
    .slice(0, 5);

  res.json({
    kpis: {
      total: rows.length,
      open,
      closed,
      avgMttrMin: round2(avgMttrMin),
      avgResponseMin: round2(avgResponseMin)
    },
    trend,
    topEquipment
  });
});

// ---------- Daily Backup ----------
// Backs up outside the project folder so an accidental delete of MTTR_Tracker
// (or a full PC issue) doesn't take the backups down with it too.
// Every day's backup is kept forever (no auto-delete) - files are tiny (KBs),
// so even years of daily backups stay a trivial amount of disk space, and any
// past day's data stays recoverable.
const BACKUP_DIR = path.join('C:\\Users\\LENOVO\\Desktop', 'MTTR_Tracker_Backups');
const BACKUP_FILES = ['breakdowns.json', 'master_data.json', 'users.json'];

function runDailyBackup() {
  try {
    const todayStr = dateOnly(new Date());
    const destDir = path.join(BACKUP_DIR, todayStr);
    if (fs.existsSync(destDir)) return;
    fs.mkdirSync(destDir, { recursive: true });
    for (const file of BACKUP_FILES) {
      const src = path.join(DATA_DIR, file);
      if (fs.existsSync(src)) fs.copyFileSync(src, path.join(destDir, file));
    }
    console.log(`Backup completed: ${destDir}`);
  } catch (e) {
    console.error('Backup failed:', e.message);
  }
}

app.get('/api/backup-status', (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.json({ lastBackup: null, count: 0, location: BACKUP_DIR });
    const entries = fs.readdirSync(BACKUP_DIR, { withFileTypes: true })
      .filter(e => e.isDirectory())
      .map(e => e.name)
      .sort();
    res.json({ lastBackup: entries.length ? entries[entries.length - 1] : null, count: entries.length, location: BACKUP_DIR });
  } catch (e) {
    res.json({ lastBackup: null, count: 0, location: BACKUP_DIR, error: e.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`MTTR Tracker running at http://localhost:${PORT}`);
  runDailyBackup();
  setInterval(runDailyBackup, 24 * 60 * 60 * 1000);
});
