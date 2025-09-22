'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ===== Env =====
const PORT = process.env.PORT || 3000;
const CRON_SECRET = process.env.CRON_SECRET || '';
const PROBE_SECRET = process.env.PROBE_SECRET || '';

const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

// 運用パラメータ
const STALE_MINUTES = Number(process.env.STALE_MINUTES || 20);
const LONG_OFFLINE_MIN = Number(process.env.LONG_OFFLINE_MIN || 1440);
const PING_TTL_MS = Number(process.env.PING_TTL_MS || (2 * 60 * 1000));
const PING_ACK_WINDOW_MS = Number(process.env.PING_ACK_WINDOW_MS || PING_TTL_MS);
const FCM_FAIL_THRESHOLD = Number(process.env.FCM_FAIL_THRESHOLD || 3);

// ===== Firebase Admin =====
let db = null;
async function initAsync() {
  if (admin.apps.length) { db = admin.firestore(); return; }
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (sa) admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
  else admin.initializeApp();
  db = admin.firestore();
  console.log('[init] Firestore handle obtained');
}
const getDb = () => {
  if (!db) throw new Error('Firestore not initialized yet');
  return db;
};

// ===== Express =====
const app = express();
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

// ===== LINE =====
const client = new line.Client(lineConfig);

// ===== Firebase Auth MW =====
const firebaseAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const idToken = authHeader.substring('Bearer '.length);
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.auth = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (error) {
    console.error('[auth] verifyIdToken error:', error);
    return res.status(403).json({ error: 'Unauthorized: Invalid token' });
  }
};

// ===== Utils =====
const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const hours = (n) => n * 60 * 60 * 1000;

function formatTs(ts) {
  const d = (ts && typeof ts.toDate === 'function') ? ts.toDate() : ts;
  const dateTimeString = d.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  });
  return dateTimeString.replace(/\//g, '-').replace(' ', '-');
}
function shortId(uuid) { return uuid.replace(/-/g, '').slice(0, 6).toUpperCase(); }
function makeDocId(formattedTsStr, uuid) { return `${formattedTsStr}-${shortId(uuid)}`; }
function genCode() { return String(Math.floor(Math.random() * 90000) + 10000); } // 5桁数字
function reply(replyToken, text) { return client.replyMessage(replyToken, { type: 'text', text }); }

// ===== 表示情報ヘルパー =====
async function getUserDisplayInfo(uid) {
  const dbx = getDb();
  const ref = dbx.collection('users').doc(uid);
  const snap = await ref.get();

  let displayName = null;
  let photoUrl = null;

  if (snap.exists) {
    const d = snap.data() || {};
    displayName =
      d.displayName ||
      (d.lineProfile && d.lineProfile.displayName) ||
      null;

    photoUrl =
      d.photoUrl ||
      (d.lineProfile && d.lineProfile.pictureUrl) ||
      null;
  }

  if (!displayName || !photoUrl) {
    try {
      const authUser = await admin.auth().getUser(uid);
      if (!displayName) displayName = authUser.displayName || null;
      if (!photoUrl)    photoUrl = authUser.photoURL || null;
    } catch (_) {
      // ignore
    }
  }

  return { displayName, photoUrl };
}

async function writeCrossPairProfiles(actorUid, partnerUid) {
  const dbx = getDb();
  const actorRef   = dbx.collection('users').doc(actorUid);
  const partnerRef = dbx.collection('users').doc(partnerUid);

  const [actorInfo, partnerInfo] = await Promise.all([
    getUserDisplayInfo(actorUid),
    getUserDisplayInfo(partnerUid),
  ]);

  await Promise.all([
    actorRef.set({
      pairingStatus: {
        partnerUid: partnerUid,
        partnerDisplayName: partnerInfo.displayName || '',
        partnerPhotoUrl: partnerInfo.photoUrl || '',
      }
    }, { merge: true }),

    partnerRef.set({
      pairingStatus: {
        partnerUid: actorUid,
        partnerDisplayName: actorInfo.displayName || '',
        partnerPhotoUrl: actorInfo.photoUrl || '',
      }
    }, { merge: true }),
  ]);
}

// ===== LINE webhook =====
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  try { await Promise.all((req.body.events || []).map(handleEvent)); }
  catch (e) { console.error('[webhook] error', e); }
});

// 以降のAPIは JSON ボディをパース
app.use(express.json());

// ===== 共通：ペア確定ロジック =====
async function acceptPairingWithCode({ code, partnerUid, partnerLineUserId }) {
  const dbx = getDb();
  const snap = await dbx.collection('users')
    .where('pairingStatus.code', '==', code)
    .limit(1)
    .get();
  if (snap.empty) throw new Error('invalid code');

  const userDoc = snap.docs[0];           // ← code を持っていた「当事者」doc
  const actorUid = userDoc.id;

  const pairing = userDoc.data().pairingStatus || {};
  const expMs = (pairing.expiresAt?.toMillis?.()
    ? pairing.expiresAt.toMillis()
    : (typeof pairing.expiresAt === 'number' ? pairing.expiresAt : 0));
  if (!expMs || Date.now() > expMs) throw new Error('expired');

  await dbx.runTransaction(async (tx) => {
    const ref = userDoc.ref;
    const fresh = await tx.get(ref);
    const cur = fresh.data().pairingStatus || {};
    const exp2 = (cur.expiresAt?.toMillis?.()
      ? cur.expiresAt.toMillis()
      : (typeof cur.expiresAt === 'number' ? cur.expiresAt : 0));
    if (!exp2 || Date.now() > exp2) throw new Error('expired');
    if (cur.status === 'paired') return;

    const updates = {
      'pairingStatus.status': 'paired',
      'pairingStatus.pairedAt': admin.firestore.FieldValue.serverTimestamp(),
      'pairingStatus.code': admin.firestore.FieldValue.delete(),
      'pairingStatus.expiresAt': admin.firestore.FieldValue.delete(),
    };
    if (partnerUid) updates['pairingStatus.partnerUid'] = partnerUid;
    if (partnerLineUserId) updates['pairingStatus.partnerLineUserId'] = partnerLineUserId;

    tx.update(ref, updates);
  });

  // ▼ ここから：相互プロフィール書き込み/LINEプロフィール反映
  try {
    if (partnerUid) {
      // アプリ→アプリのペア確定：双方に相手の表示名・写真URLをコピー
      await writeCrossPairProfiles(actorUid, partnerUid);
    } else if (partnerLineUserId) {
      // LINEからのペア確定：少なくとも当事者側にLINEプロフィールを保存しておく
      try {
        const prof = await client.getProfile(partnerLineUserId);
        await userDoc.ref.set({
          pairingStatus: {
            partnerDisplayName: prof?.displayName || '',
            partnerPhotoUrl: prof?.pictureUrl || '',
          }
        }, { merge: true });
      } catch (e) {
        console.warn('[pair] getProfile failed (non-fatal):', e?.message || e);
      }
    }
  } catch (e) {
    console.error('[pair] cross profile write failed (non-fatal):', e);
  }

  return { ok: true };
}

async function handleEvent(event) {
  // 1) LINEメッセージでのコード受領
  if (event.type === 'message' && event.message?.type === 'text' && event.source?.userId) {
    const text = (event.message.text || '').trim();
    const partnerLineUserId = event.source.userId;
    let pairingCode = null;

    if (/^\d{5}$/.test(text)) pairingCode = text;
    else {
      const m = /^pair\s+([A-Z0-9]{5,10})$/i.exec(text);
      if (m) pairingCode = m[1].toUpperCase();
    }

    if (pairingCode) {
      try {
        await acceptPairingWithCode({ code: pairingCode, partnerLineUserId });
        return reply(event.replyToken, 'ペアリングが完了しました ✅');
      } catch (error) {
        const msg = String(error.message || error);
        console.error('[webhook/pair] error', msg);
        if (/invalid/.test(msg)) return reply(event.replyToken, `コード ${pairingCode} は無効です。`);
        if (/expired/.test(msg)) return reply(event.replyToken, `コード ${pairingCode} は有効期限切れです。`);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }
  }

  // 2) 解除ポストバック
  if (event.type === 'postback') {
    const data = event.postback?.data || '';
    const ap = /^approve:(.+)$/i.exec(data);
    const rj = /^reject:(.+)$/i.exec(data);
    if (ap) {
      const appUserUid = ap[1];
      try {
        const userRef = getDb().collection('users').doc(appUserUid);
        await userRef.update({ 'blockStatus.isActive': false, 'blockStatus.activatedAt': null });
        if (event.source?.userId) await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。' });
      } catch (err) { console.error('[webhook/approve] failed:', err); }
      return;
    }
    if (rj) {
      if (event.source?.userId) await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
      return;
    }
  }
}

// ===== App APIs =====

// 当事者：コード発行
app.post('/pair/create', firebaseAuthMiddleware, async (req, res) => {
  const appUserUid = req.auth.uid;
  const code = genCode();
  const expiresAtMs = now() + minutes(30);
  const expiresAtSec = Math.floor(expiresAtMs / 1000);
  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(appUserUid);
    await userRef.set({
      pairingStatus: {
        code,
        expiresAt: admin.firestore.Timestamp.fromMillis(expiresAtMs),
        status: 'waiting'
      }
    }, { merge: true });
    res.json({ code, expiresAt: expiresAtSec });
  } catch (e) {
    console.error('[pair/create] failed:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

// パートナー：コード入力（アプリ間ペアリング）
app.post('/pair/accept', firebaseAuthMiddleware, async (req, res) => {
  try {
    const partnerUid = req.auth.uid;
    const code = String(req.body?.code || '').trim();
    if (!/^\d{5}$/.test(code)) return res.status(400).json({ message: 'bad code' });
    await acceptPairingWithCode({ code, partnerUid });
    res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    const status = /invalid|expired|bad code/i.test(msg) ? 400 : 500;
    console.error('[pair/accept] failed:', msg);
    res.status(status).json({ message: msg });
  }
});

app.post('/request-partner-unlock', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  const email = req.auth.email;
  const dbx = getDb();
  try {
    if (email === 'nomorebettest@gmail.com') {
      const userRef = dbx.collection('users').doc(uid);
      await userRef.update({ 'blockStatus.isActive': false, 'blockStatus.activatedAt': null });
      console.log(`[test-unlock] Auto-unlocked: user=${uid}`);
      return res.json({ ok: true, message: 'Auto-unlocked for test user.' });
    }
    const userRef = dbx.collection('users').doc(uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) return res.status(404).json({ error: 'User not found' });

    const pairingStatus = userSnap.data().pairingStatus || {};
    const partnerLineUserId = pairingStatus.partnerLineUserId;
    if (!partnerLineUserId || pairingStatus.status !== 'paired') {
      return res.status(400).json({ error: 'Partner is not configured.' });
    }
    await client.pushMessage(partnerLineUserId, {
      type: 'template',
      altText: '解除申請が届きました',
      template: {
        type: 'confirm',
        text: 'パートナーからブロック解除の申請が届きました。承認しますか？',
        actions: [
          { type: 'postback', label: '承認する', data: `approve:${uid}` },
          { type: 'postback', label: '拒否する', data: `reject:${uid}` },
        ],
      },
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('[request-partner-unlock] failed:', e);
    res.status(500).json({ error: 'Failed to process unlock request.' });
  }
});

// 強制解除の通知API
app.post('/force-unlock-notify', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const dbx = getDb();
    const userSnap = await dbx.collection('users').doc(uid).get();
    if (!userSnap.exists) return res.status(404).json({ error: 'User not found' });

    const pairingStatus = userSnap.data().pairingStatus || {};
    const partnerLineUserId = pairingStatus.partnerLineUserId;
    if (partnerLineUserId && pairingStatus.status === 'paired') {
      await client.pushMessage(partnerLineUserId, {
        type: 'text',
        text: '【nomoreBET お知らせ】\nパートナーが強制解除機能を使用しました。'
      });
      console.log(`[force-unlock] 通知送信: user=${uid}, partner=${partnerLineUserId}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[force-unlock-notify] failed:', e);
    res.status(500).json({ error: 'Failed to send notification.' });
  }
});

// Heartbeat
app.post('/heartbeat', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const userRef = getDb().collection('users').doc(uid);
    await userRef.update({ 'blockStatus.lastHeartbeat': admin.firestore.FieldValue.serverTimestamp() });
    res.json({ ok: true });
  } catch (e) {
    console.error(`[heartbeat] failed for user ${uid}`, e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ACK: waiting→replied
app.post('/ack-ping', async (req, res) => {
  const uid = req.body?.uid;
  const fcmTokenFromApp = req.body?.fcmToken;
  const pingId = req.body?.pingId;
  if (!pingId || !uid || !fcmTokenFromApp) {
    console.warn('[ack-ping] 400 Bad Request', req.body);
    return res.status(400).json({ error: 'pingId, uid, and fcmToken are required' });
  }
  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) return res.status(404).json({ error: 'User not found' });

    const storedFcmToken = userSnap.data()?.deviceStatus?.fcmToken;
    if (storedFcmToken !== fcmTokenFromApp) {
      console.warn('[ack-ping] FCM token mismatch', { uid });
      return res.status(403).json({ error: 'Unauthorized: Invalid device token' });
    }

    const q = await userRef.collection('pendingPings').where('id', '==', pingId).limit(1).get();
    if (q.empty) return res.json({ ok: true, message: 'not found' });
    const snap = q.docs[0];
    const data = snap.data();
    if (data.status !== 'waiting') return res.json({ ok: true, message: `ignored (${data.status})` });

    const deadlineMs = (data.expiresAt?.toMillis?.() ?? (data.sentAt?.toMillis?.() + PING_ACK_WINDOW_MS));
    const newStatus = (Date.now() <= deadlineMs) ? 'replied' : 'replied_late';
    await snap.ref.set({ status: newStatus, repliedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    res.json({ ok: true });
  } catch (e) {
    console.error('[ack-ping] failed', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== Cron
app.get('/cron/check-heartbeats', async (req, res) => {
  if (!CRON_SECRET || req.query.secret !== CRON_SECRET) {
    console.warn('[cron] 403 secret mismatch');
    return res.status(403).json({ error: 'Forbidden' });
  }

  const dbx = getDb();
  const nowTs = admin.firestore.Timestamp.now();
  const staleCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(STALE_MINUTES));
  const longOfflineCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(LONG_OFFLINE_MIN));

  try {
    // 1) waiting期限切れ
    const allUsers = await dbx.collection('users').get();
    for (const userDoc of allUsers.docs) {
      const userRef = userDoc.ref;
      const pairingStatus = userDoc.data()?.pairingStatus || {};
      const partnerLineUserId = pairingStatus.partnerLineUserId;

      const overdue = await userRef.collection('pendingPings')
        .where('status', '==', 'waiting')
        .where('expiresAt', '<', nowTs)
        .get();

      if (!overdue.empty) {
        const batch = dbx.batch();
        for (const ping of overdue.docs) {
          batch.set(ping.ref, { status: 'expired', expiredAt: nowTs }, { merge: true });

          if (partnerLineUserId) {
            const sentAt = ping.data().sentAt;
            let timeString = '一定時間';
            if (sentAt) {
              const date = sentAt.toDate();
              timeString = new Intl.DateTimeFormat('ja-JP', {
                month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo'
              }).format(date);
            }
            try {
              await client.pushMessage(partnerLineUserId, {
                type: 'text',
                text:
                  `【nomoreBET お知らせ】\n` +
                  `パートナーの端末から、ブロック機能が有効であることを示す定期的な信号が途絶えています。\n\n` +
                  `${timeString}ごろ、ブロック機能が一時的に無効になっていた可能性があります。パートナーの方にご確認ください。\n\n` +
                  `※端末の電源OFF、圏外、設定変更などが原因の場合もあります。`
              });
            } catch (e) { console.error('[cron] LINE push error:', e); }
          }
        }
        await batch.commit();
        console.log(`[cron] expired marked: user=${userDoc.id}, count=${overdue.size}`);
      }
    }

    // 2) stale への ping
    const q = await dbx.collection('users')
      .where('blockStatus.isActive', '==', true)
      .where('blockStatus.lastHeartbeat', '<', staleCutoff)
      .where('blockStatus.lastHeartbeat', '>', longOfflineCutoff)
      .get();

    console.log('[cron] run', { at: new Date().toISOString(), staleCandidates: q.size });

    for (const userDoc of q.docs) {
      const uid = userDoc.id;
      const userRef = userDoc.ref;
      const fcmToken = userDoc.data().deviceStatus?.fcmToken;
      if (!fcmToken) { console.warn('[cron] skip (no fcmToken)', uid); continue; }

      const waitingExists = await userRef.collection('pendingPings')
        .where('status', '==', 'waiting')
        .limit(1)
        .get();
      if (!waitingExists.empty) { console.log('[cron] skip (waiting exists)', uid); continue; }

      const pingUuid = crypto.randomUUID();
      const japanFormattedNow = formatTs(nowTs);
      const docId = makeDocId(japanFormattedNow, pingUuid);
      const expiresAt = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() + PING_ACK_WINDOW_MS);

      await userRef.collection('pendingPings').doc(docId).set({
        id: pingUuid, readableId: docId, status: 'waiting',
        sentAt: nowTs, expiresAt, by: 'cron'
      });

      try {
        await admin.messaging().send({
          token: fcmToken,
          data: { action: 'ping_challenge', pingId: pingUuid, uid },
          android: { priority: 'high', ttl: PING_TTL_MS },
        });

        await userRef.set({
          deviceStatus: {
            lastFcmOkAt: admin.firestore.FieldValue.serverTimestamp(),
            fcmConsecutiveFails: 0,
            gmsIssueSuspected: false
          }
        }, { merge: true });

        console.log('[cron] ping queued', { uid, pingUuid, docId });
      } catch (sendErr) {
        const code = sendErr?.errorInfo?.code || sendErr?.code || 'unknown';
        console.error('[cron] FCM send error', uid, code, sendErr?.message);

        try {
          await userRef.collection('fcmSendLogs').add({
            token: fcmToken, code, message: sendErr?.message || '',
            at: admin.firestore.FieldValue.serverTimestamp()
          });
        } catch (logErr) { console.error('[cron] fcmSendLogs add error:', logErr); }

        if (code === 'messaging/registration-token-not-registered') {
          await userRef.set({
            deviceStatus: {
              fcmToken: admin.firestore.FieldValue.delete(),
              fcmConsecutiveFails: admin.firestore.FieldValue.increment(1),
              gmsIssueSuspected: false
            }
          }, { merge: true });
        } else {
          await userRef.set({
            deviceStatus: { fcmConsecutiveFails: admin.firestore.FieldValue.increment(1) }
          }, { merge: true });
        }

        try {
          const fresh = await userRef.get();
          const dev = fresh.data()?.deviceStatus || {};
          if ((dev.fcmConsecutiveFails || 0) >= FCM_FAIL_THRESHOLD) {
            await userRef.set({ deviceStatus: { gmsIssueSuspected: true } }, { merge: true });
          }
        } catch (readErr) { console.error('[cron] read-after-fail error:', readErr); }
      }
    }

    // 3) 古い ping の掃除（48h）
    try {
      const cleanupCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - hours(48));
      const allUsers = await dbx.collection('users').get();
      for (const userDoc of allUsers.docs) {
        const old = await userDoc.ref.collection('pendingPings').where('sentAt', '<', cleanupCutoff).get();
        if (!old.empty) {
          const batch = dbx.batch();
          old.docs.forEach(doc => batch.delete(doc.ref));
          await batch.commit();
          console.log(`[cron-cleanup] cleaned old pings: user=${userDoc.id}, count=${old.size}`);
        }
      }
    } catch (e) { console.error('[cron-cleanup] failed', e); }

    return res.json({ ok: true, staleChecked: q.size });
  } catch (e) {
    console.error('[cron] failed', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ===== Probe =====
app.get('/probe/check', (req, res) => {
  if (!PROBE_SECRET) return res.status(500).json({ error: 'PROBE_SECRET not set' });
  const nonce = String(req.query.nonce || '');
  if (!/^[A-Za-z0-9._~\-]{8,128}$/.test(nonce)) return res.status(400).json({ error: 'bad nonce' });
  const sig = crypto.createHmac('sha256', PROBE_SECRET).update(nonce, 'utf8').digest('base64');
  res.set('Cache-Control', 'no-store');
  res.json({ alg: 'HS256', sig });
});

// ===== Boot =====
(async () => {
  try {
    await initAsync();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[boot] listening on ${PORT}`);
    });
  } catch (e) {
    console.error('[boot] fatal init error, exiting', e);
    process.exit(1);
  }
})();
