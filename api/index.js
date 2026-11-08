'use strict';
/**
 * Esports tournament backend — single file (Node 18+, Express, Firebase Admin, Cloud Firestore, Cashfree PG)
 *
 * npm i express firebase-admin
 *
 * ENV
 *   FIREBASE_SERVICE_ACCOUNT  service-account JSON (raw or base64). Omit on GCP to use default credentials.
 *   CASHFREE_APP_ID, CASHFREE_SECRET_KEY, CASHFREE_ENV (sandbox|production, default sandbox)
 *   PUBLIC_URL                public URL of this server (used for Cashfree notify_url -> /webhook/cashfree)
 *   RETURN_URL                optional checkout return URL
 *   ADMIN_EMAILS              comma separated admin emails (default admin123@gmail.com); custom claim isAdmin=true also works
 *   CRON_SECRET               optional; lets a cron job call POST /admin/sweep with header x-cron-secret
 *   ALLOWED_ORIGIN            CORS origin (default *)
 *   MIN_WITHDRAW (50), MAX_WITHDRAW (10000), MIN_TOPUP (10), MAX_TOPUP (50000), SWEEP_MS (30000, 0 = off)
 *
 * Compatibility with the admin panel:
 *   - Withdrawals use status "Pending" (admin panel + Firestore rules query/update exactly that value).
 *     Cashfree top-ups use "PENDING" | "SUCCESS" | "FAILED".
 *   - Admin panel writes matches/{id}/results/{gameUid} {rank,kills,distributed:false}; the sweep (and
 *     POST /admin/match/distribute) credits prize + XP exactly once and flips distributed/prizeDistributed.
 *   - Rejected withdrawals are refunded once by the sweep (wallet is only ever changed by this server).
 *   - Collection-group query on `results.distributed` needs a single-field index exemption (Firestore logs a link).
 */
const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

// ---------- config ----------
const env = process.env;
const PORT = Number(env.PORT) || 3000;
const ADMIN_EMAILS = (env.ADMIN_EMAILS || 'admin123@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const CF_BASE = (env.CASHFREE_ENV || 'sandbox').toLowerCase() === 'production' ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg';
const CF_ID = env.CASHFREE_APP_ID, CF_SECRET = env.CASHFREE_SECRET_KEY;
const MIN_WITHDRAW = Number(env.MIN_WITHDRAW) || 50, MAX_WITHDRAW = Number(env.MAX_WITHDRAW) || 10000;
const MIN_TOPUP = Number(env.MIN_TOPUP) || 10, MAX_TOPUP = Number(env.MAX_TOPUP) || 50000;
const WITHDRAW_PENDING = 'Pending';
const DAY = 864e5;
const XP = { PARTICIPATION: 10, PER_KILL: 5, RANK_BONUS: r => (r === 1 ? 50 : r === 2 ? 30 : r === 3 ? 20 : r <= 10 ? 10 : 0) };
const MODE_SIZE = { solo: 1, duo: 2, squad: 4 };

// ---------- firebase ----------
(function initFirebase() {
  let cred;
  const raw = env.FIREBASE_SERVICE_ACCOUNT;
  if (raw) {
    const txt = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
    cred = admin.credential.cert(JSON.parse(txt));
  } else cred = admin.credential.applicationDefault();
  admin.initializeApp({ credential: cred });
})();
const db = admin.firestore();
const FV = admin.firestore.FieldValue;

// ---------- helpers ----------
class AppError extends Error { constructor(status, code, msg) { super(msg || code); this.status = status; this.code = code; } }
const r2 = n => Math.round(n * 100) / 100;
const low = s => String(s || '').toLowerCase();
const isNum = v => typeof v === 'number' && Number.isFinite(v);
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (e instanceof AppError) return res.status(e.status).json({ success: false, error: e.code, message: e.message });
  console.error(`[${req.method} ${req.path}]`, e);
  res.status(500).json({ success: false, error: 'INTERNAL_ERROR' });
});
const isAdminToken = u => u.claims.isAdmin === true || ADMIN_EMAILS.includes(low(u.email));

// ---------- app / middleware ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'X-Content-Type-Options': 'nosniff'
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
const hits = new Map();
setInterval(() => hits.clear(), 60e3).unref();
app.use((req, res, next) => {
  if (req.path === '/webhook/cashfree') return next();
  const k = req.ip + req.path, n = (hits.get(k) || 0) + 1;
  hits.set(k, n);
  if (n > 60) return res.status(429).json({ success: false, error: 'RATE_LIMITED' });
  next();
});

// Webhook needs the RAW body for signature verification — mount before express.json()
app.post('/webhook/cashfree', express.raw({ type: '*/*', limit: '256kb' }), wrap(cashfreeWebhook));
app.use(express.json({ limit: '20kb' }));

function requireAuth(adminOnly) {
  return async (req, res, next) => {
    try {
      if (adminOnly && env.CRON_SECRET && req.get('x-cron-secret') === env.CRON_SECRET) { req.user = { uid: 'cron', email: 'cron', cron: true }; return next(); }
      const m = /^Bearer (.+)$/.exec(req.get('Authorization') || '');
      if (!m) throw new AppError(401, 'UNAUTHENTICATED');
      let decoded;
      try { decoded = await admin.auth().verifyIdToken(m[1]); } catch { throw new AppError(401, 'INVALID_TOKEN'); }
      req.user = { uid: decoded.uid, email: decoded.email || '', claims: decoded };
      if (adminOnly && !isAdminToken({ claims: decoded, email: decoded.email })) throw new AppError(403, 'FORBIDDEN');
      next();
    } catch (e) {
      if (e instanceof AppError) return res.status(e.status).json({ success: false, error: e.code });
      console.error(e); res.status(500).json({ success: false, error: 'INTERNAL_ERROR' });
    }
  };
}
async function activeUser(t, uid) {
  const ref = db.doc(`users/${uid}`), snap = await t.get(ref);
  if (!snap.exists) throw new AppError(404, 'USER_NOT_FOUND');
  if (snap.data().status === 'banned') throw new AppError(403, 'USER_BANNED');
  return { ref, data: snap.data() };
}

app.get('/', (req, res) => res.json({ success: true, service: 'esports-backend' }));
app.get('/health', (req, res) => res.json({ success: true }));

// ---------- POST /auth/signup ----------
app.post('/auth/signup', requireAuth(false), wrap(async (req, res) => {
  const { uid, username, email, referralCode } = req.body || {};
  if (uid !== req.user.uid) throw new AppError(403, 'UID_MISMATCH');
  if (typeof username !== 'string' || !/^[A-Za-z0-9_ ]{3,20}$/.test(username.trim())) throw new AppError(400, 'INVALID_USERNAME');
  const mail = String(req.user.email || email || '').trim().toLowerCase();
  if (!/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(mail)) throw new AppError(400, 'INVALID_EMAIL');
  if (referralCode != null && !/^[A-Za-z0-9]{4,12}$/.test(String(referralCode))) throw new AppError(400, 'INVALID_REFERRAL');

  const userRef = db.doc(`users/${uid}`);
  let myCode = null, referredBy = null;
  const pre = await userRef.get();
  if (!pre.exists || !pre.data().referralCode) {
    for (let i = 0; i < 6 && !myCode; i++) {
      const c = 'BX' + crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 6);
      if ((await db.collection('users').where('referralCode', '==', c).limit(1).get()).empty) myCode = c;
    }
    if (!myCode) throw new AppError(500, 'REFERRAL_GEN_FAILED');
  }
  if (!pre.exists && referralCode) {
    const q = await db.collection('users').where('referralCode', '==', String(referralCode).toUpperCase()).limit(1).get();
    if (!q.empty && q.docs[0].id !== uid) referredBy = q.docs[0].id;
  }
  const out = await db.runTransaction(async t => {
    const s = await t.get(userRef);
    if (s.exists) {
      const d = s.data();
      if (!d.referralCode) { t.update(userRef, { referralCode: myCode }); return { created: false, referralCode: myCode }; }
      return { created: false, referralCode: d.referralCode };
    }
    t.set(userRef, {
      username: username.trim(), email: mail, wallet: 0, totalXP: 0, joinedMatches: [],
      referralCode: myCode, referredBy, matchesPlayed: 0, totalKills: 0, dailyStreak: 0, isVIP: false,
      status: 'active', createdAt: Date.now()
    });
    return { created: true, referralCode: myCode };
  });
  res.json({ success: true, ...out });
}));

// ---------- POST /match/join ----------
app.post('/match/join', requireAuth(false), wrap(async (req, res) => {
  const { matchId, gameUids } = req.body || {};
  const uid = req.user.uid;
  if (typeof matchId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(matchId)) throw new AppError(400, 'INVALID_MATCH');
  if (!Array.isArray(gameUids) || ![1, 2, 4].includes(gameUids.length)) throw new AppError(400, 'INVALID_GAME_UIDS', 'gameUids must contain 1, 2 or 4 ids');
  const uids = gameUids.map(String).map(s => s.trim());
  if (uids.some(u => !/^[0-9]{5,15}$/.test(u)) || new Set(uids).size !== uids.length) throw new AppError(400, 'INVALID_GAME_UIDS');

  const matchRef = db.doc(`matches/${matchId}`), teamRef = matchRef.collection('teams').doc(uid);
  const idxRefs = uids.map(u => matchRef.collection('gameUidIndex').doc(u));
  const result = await db.runTransaction(async t => {
    const [mSnap, tSnap, user, ...idx] = await Promise.all([t.get(matchRef), t.get(teamRef), activeUser(t, uid), ...idxRefs.map(r => t.get(r))]);
    if (!mSnap.exists) throw new AppError(404, 'MATCH_NOT_FOUND');
    const m = mSnap.data();
    if (low(m.status) !== 'upcoming') throw new AppError(409, 'MATCH_NOT_UPCOMING');
    const size = Number(m.teamSize) || MODE_SIZE[low(m.mode)];
    if (size && size !== uids.length) throw new AppError(400, 'TEAM_SIZE_MISMATCH', `This match needs ${size} game UID(s)`);
    if (tSnap.exists) throw new AppError(409, 'ALREADY_JOINED');
    if (idx.some(s => s.exists)) throw new AppError(409, 'GAME_UID_ALREADY_USED');
    const max = Number(m.maxPlayers ?? m.maxSlots) || 0, joined = Number(m.joinedCount) || 0;
    if (!max || joined >= max) throw new AppError(409, 'MATCH_FULL');
    const fee = r2(Number(m.entryFee) || 0);
    if (fee < 0) throw new AppError(500, 'BAD_ENTRY_FEE');
    if (r2(Number(user.data.wallet) || 0) < fee) throw new AppError(402, 'INSUFFICIENT_BALANCE');

    t.update(matchRef, { joinedCount: FV.increment(1) });
    t.set(teamRef, { ownerUid: uid, ownerUsername: user.data.username || '', gameUids: uids, joinedAt: Date.now() });
    idxRefs.forEach(r => t.set(r, { ownerUid: uid }));
    t.update(user.ref, { wallet: FV.increment(-fee), joinedMatches: FV.arrayUnion(matchId) });
    if (fee > 0) t.set(db.collection('transactions').doc(`entry_${matchId}_${uid}`), {
      userId: uid, type: 'entry_fee', amount: fee, status: 'SUCCESS', matchId, matchTitle: m.title || '', timestamp: Date.now()
    });
    return { fee, slot: joined + 1 };
  });
  res.json({ success: true, matchId, ...result });
}));

// ---------- POST /rewards/daily ----------
app.post('/rewards/daily', requireAuth(false), wrap(async (req, res) => {
  const uid = req.user.uid, now = Date.now();
  const out = await db.runTransaction(async t => {
    const u = await activeUser(t, uid), d = u.data, last = Number(d.lastDailyAt) || 0;
    if (last && now - last < DAY) throw new AppError(429, 'ALREADY_CLAIMED', 'Come back after 24 hours');
    const streak = last && now - last < 2 * DAY ? (Number(d.dailyStreak) || 0) + 1 : 1;
    const reward = Math.min(streak, 7);
    t.update(u.ref, { wallet: FV.increment(reward), dailyStreak: streak, lastDailyAt: now });
    t.set(db.collection('transactions').doc(), { userId: uid, type: 'daily_reward', amount: reward, status: 'SUCCESS', timestamp: now });
    return { reward, dailyStreak: streak, nextClaimAt: now + DAY };
  });
  res.json({ success: true, ...out });
}));

// ---------- POST /wallet/createOrder ----------
app.post('/wallet/createOrder', requireAuth(false), wrap(async (req, res) => {
  if (!CF_ID || !CF_SECRET) throw new AppError(503, 'PAYMENTS_NOT_CONFIGURED');
  const uid = req.user.uid, amount = r2(Number((req.body || {}).amount));
  if (!isNum(amount) || amount < MIN_TOPUP || amount > MAX_TOPUP) throw new AppError(400, 'INVALID_AMOUNT', `Amount must be ${MIN_TOPUP}-${MAX_TOPUP}`);
  const uSnap = await db.doc(`users/${uid}`).get();
  if (!uSnap.exists) throw new AppError(404, 'USER_NOT_FOUND');
  const u = uSnap.data();
  if (u.status === 'banned') throw new AppError(403, 'USER_BANNED');
  const reqPhone = String((req.body || {}).phone || u.phone || '');
  const phone = /^[6-9][0-9]{9}$/.test(reqPhone) ? reqPhone : (env.CASHFREE_DEFAULT_PHONE || '9999999999');
  const orderId = `ord_${uid.slice(0, 8)}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`.replace(/[^A-Za-z0-9_-]/g, '');

  const body = {
    order_id: orderId, order_amount: amount, order_currency: 'INR',
    customer_details: { customer_id: uid.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 50), customer_phone: phone, customer_email: u.email || req.user.email || 'user@example.com' },
    order_meta: { notify_url: env.PUBLIC_URL ? `${env.PUBLIC_URL.replace(/\/$/, '')}/webhook/cashfree` : undefined, return_url: env.RETURN_URL ? `${env.RETURN_URL}${env.RETURN_URL.includes('?') ? '&' : '?'}order_id={order_id}` : undefined }
  };
  const cf = await cashfree('POST', '/orders', body);
  if (!cf.payment_session_id) throw new AppError(502, 'GATEWAY_ERROR');
  const now = Date.now(), b = db.batch();
  b.set(db.doc(`transactions/${orderId}`), { userId: uid, type: 'deposit', amount, status: 'PENDING', orderId, timestamp: now });
  b.set(db.doc(`payments/${orderId}`), { userId: uid, orderId, amount, status: 'PENDING', createdAt: now });
  await b.commit(); // wallet is NOT touched here
  res.json({ success: true, orderId, paymentSessionId: cf.payment_session_id, payment_session_id: cf.payment_session_id, amount });
}));

async function cashfree(method, path, body) {
  const ac = new AbortController(), to = setTimeout(() => ac.abort(), 15000);
  try {
    const r = await fetch(CF_BASE + path, {
      method, signal: ac.signal,
      headers: { 'x-client-id': CF_ID, 'x-client-secret': CF_SECRET, 'x-api-version': '2023-08-01', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { console.error('Cashfree error', r.status, j); throw new AppError(502, 'GATEWAY_ERROR', j.message); }
    return j;
  } catch (e) {
    if (e instanceof AppError) throw e;
    throw new AppError(502, 'GATEWAY_UNREACHABLE');
  } finally { clearTimeout(to); }
}

// ---------- POST /webhook/cashfree (ONLY place deposits credit the wallet) ----------
async function cashfreeWebhook(req, res) {
  if (!CF_SECRET) return res.status(503).json({ success: false });
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  const sig = req.get('x-webhook-signature') || '', ts = req.get('x-webhook-timestamp') || '';
  const expected = crypto.createHmac('sha256', CF_SECRET).update(ts + raw).digest('base64');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (!sig || !ts || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ success: false, error: 'BAD_SIGNATURE' });

  let ev; try { ev = JSON.parse(raw); } catch { return res.status(400).json({ success: false }); }
  const orderId = ev && ev.data && ev.data.order && ev.data.order.order_id;
  const paidAmt = Number(ev && ev.data && ev.data.order && ev.data.order.order_amount);
  const pStatus = String((ev && ev.data && ev.data.payment && ev.data.payment.payment_status) || '').toUpperCase();
  if (!orderId) return res.json({ success: true, ignored: true });
  const success = ev.type === 'PAYMENT_SUCCESS_WEBHOOK' && pStatus === 'SUCCESS';
  const failed = ev.type === 'PAYMENT_FAILED_WEBHOOK' || ev.type === 'PAYMENT_USER_DROPPED_WEBHOOK' || pStatus === 'FAILED';
  if (!success && !failed) return res.json({ success: true, ignored: true });

  const txRef = db.doc(`transactions/${orderId}`), payRef = db.doc(`payments/${orderId}`);
  if (success) { // never trust the payload alone: confirm with Cashfree (5xx -> Cashfree retries)
    const o = await cashfree('GET', `/orders/${encodeURIComponent(orderId)}`);
    if (o.order_status !== 'PAID' || Math.abs(Number(o.order_amount) - paidAmt) > 0.001) {
      console.error('Webhook/order mismatch', orderId, o.order_status, o.order_amount, paidAmt);
      return res.json({ success: true, ignored: true });
    }
  }
  const outcome = await db.runTransaction(async t => {
    const tSnap = await t.get(txRef);
    if (!tSnap.exists || tSnap.data().type !== 'deposit') return 'unknown_order';
    const tx = tSnap.data();
    if (tx.status === 'SUCCESS') return 'duplicate'; // idempotent
    if (Math.abs(Number(tx.amount) - paidAmt) > 0.001) {
      t.update(txRef, { status: 'FLAGGED', reason: 'AMOUNT_MISMATCH' }); t.set(payRef, { status: 'FLAGGED' }, { merge: true });
      return 'amount_mismatch';
    }
    if (success) {
      const uRef = db.doc(`users/${tx.userId}`), uSnap = await t.get(uRef);
      if (!uSnap.exists) { t.update(txRef, { status: 'FLAGGED', reason: 'NO_USER' }); return 'no_user'; }
      t.update(uRef, { wallet: FV.increment(r2(Number(tx.amount))) });
      t.update(txRef, { status: 'SUCCESS', completedAt: Date.now() });
      t.set(payRef, { status: 'SUCCESS', completedAt: Date.now() }, { merge: true });
      return 'credited';
    }
    if (tx.status === 'PENDING') { // a FAILED attempt can still be retried and succeed later on the same order
      t.update(txRef, { status: 'FAILED', completedAt: Date.now() });
      t.set(payRef, { status: 'FAILED', completedAt: Date.now() }, { merge: true });
    }
    return 'failed';
  });
  res.json({ success: true, outcome });
}

// ---------- POST /wallet/withdraw ----------
app.post('/wallet/withdraw', requireAuth(false), wrap(async (req, res) => {
  const uid = req.user.uid, amount = r2(Number((req.body || {}).amount)), upiId = String((req.body || {}).upiId || '').trim();
  if (!isNum(amount) || amount < MIN_WITHDRAW || amount > MAX_WITHDRAW) throw new AppError(400, 'INVALID_AMOUNT', `Amount must be ${MIN_WITHDRAW}-${MAX_WITHDRAW}`);
  if (!/^[A-Za-z0-9._-]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}$/.test(upiId)) throw new AppError(400, 'INVALID_UPI');
  const txRef = db.collection('transactions').doc();
  await db.runTransaction(async t => {
    const u = await activeUser(t, uid);
    if (r2(Number(u.data.wallet) || 0) < amount) throw new AppError(402, 'INSUFFICIENT_BALANCE');
    t.update(u.ref, { wallet: FV.increment(-amount) }); // funds held immediately
    t.set(txRef, { userId: uid, type: 'withdraw', amount, upi: upiId, upiId, status: WITHDRAW_PENDING, refunded: false, timestamp: Date.now() });
  });
  res.json({ success: true, transactionId: txRef.id, status: WITHDRAW_PENDING });
}));

// ---------- prize distribution (exactly once per game UID) ----------
function rankPrizeOf(rp, rank) {
  if (Array.isArray(rp)) { const e = rp.find(x => x && Number(x.rank) === rank); return e ? Number(e.prize) || 0 : 0; }
  if (rp && typeof rp === 'object') return Number(rp[rank] ?? rp[String(rank)]) || 0;
  return 0;
}
async function distribute(matchId, gameUid, rank, kills, by) {
  const matchRef = db.doc(`matches/${matchId}`), resRef = matchRef.collection('results').doc(gameUid);
  return db.runTransaction(async t => {
    const [mSnap, rSnap] = await Promise.all([t.get(matchRef), t.get(resRef)]);
    if (!mSnap.exists) throw new AppError(404, 'MATCH_NOT_FOUND');
    const m = mSnap.data();
    if (low(m.status) !== 'ended') throw new AppError(409, 'MATCH_NOT_ENDED');
    if (rSnap.exists && (rSnap.data().distributed === true || rSnap.data().prizeDistributed === true)) return { duplicate: true };
    const tq = await t.get(matchRef.collection('teams').where('gameUids', 'array-contains', gameUid).limit(1));
    if (tq.empty) throw new AppError(404, 'TEAM_NOT_FOUND');
    const teamSnap = tq.docs[0], team = teamSnap.data(), ownerUid = team.ownerUid || teamSnap.id;
    const userRef = db.doc(`users/${ownerUid}`),
