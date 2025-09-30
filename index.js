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

// /webhook は署名検証のために raw を通す（ここでは line.middleware に任せる）
app.use((req, res, next) => {
  if (req.path === '/webhook') return next();
  return express.json()(req, res, next);
});

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

// ============================================================
//  ペアリング（アプリ主導）: pairingCodes コレクション方式（変更なし）
// ============================================================
app.post('/pair/create', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  const dbx = getDb();

  // 軽い衝突回避（5桁なので一応）
  let code = genCode();
  let tries = 0;
  while (tries < 5) {
    const ref = dbx.collection('pairingCodes').doc(code);
    const snap = await ref.get();
    if (!snap.exists) break;
    code = genCode();
    tries++;
  }
  if (tries >= 5) return res.status(500).json({ error: 'code generation failed' });

  const expiresAtMs = now() + minutes(30);
  const expiresAt = admin.firestore.Timestamp.fromMillis(expiresAtMs);

  try {
    await dbx.collection('pairingCodes').doc(code).set({
      ownerUid: uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt
    });

    await dbx.collection('users').doc(uid).set({
      pairingStatus: { status: 'waiting', code, expiresAt }
    }, { merge: true });

    res.json({ code, expiresAt: Math.floor(expiresAtMs / 1000) });
  } catch (e) {
    console.error('[pair/create] failed:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

app.post('/pair/accept', firebaseAuthMiddleware, async (req, res) => {
  const partnerUid = req.auth.uid; // B
  const code = String(req.body?.code || '').trim();
  if (!/^\d{5}$/.test(code)) return res.status(400).json({ message: 'bad code' });

  const dbx = getDb();
  const codeRef = dbx.collection('pairingCodes').doc(code);

  try {
    await dbx.runTransaction(async (tx) => {
      const codeSnap = await tx.get(codeRef);
      if (!codeSnap.exists) throw new Error('invalid');
      const { ownerUid, expiresAt } = codeSnap.data() || {};
      if (!ownerUid) throw new Error('invalid');
      if (ownerUid === partnerUid) throw new Error('self_pair');

      const expMs = expiresAt?.toMillis?.() ?? 0;
      if (!expMs || Date.now() > expMs) throw new Error('expired');

      const actorRef = dbx.collection('users').doc(ownerUid);   // A
      const partnerRef = dbx.collection('users').doc(partnerUid); // B

      const [aSnap, pSnap] = await Promise.all([tx.get(actorRef), tx.get(partnerRef)]);
      const a = aSnap.data()?.pairingStatus || {};
      const p = pSnap.data()?.pairingStatus || {};

      if (a.status === 'paired' && a.partnerUid && a.partnerUid !== partnerUid) throw new Error('actor_already_paired');
      if (p.status === 'paired' && p.partnerUid && p.partnerUid !== ownerUid) throw new Error('partner_already_paired');

      const nowTs = admin.firestore.FieldValue.serverTimestamp();

      tx.set(actorRef, {
        pairingStatus: {
          status: 'paired',
          partnerUid: partnerUid,
          pairedAt: nowTs,
          code: admin.firestore.FieldValue.delete(),
          expiresAt: admin.firestore.FieldValue.delete(),
          lineAccepted: admin.firestore.FieldValue.delete()
        }
      }, { merge: true });

      tx.set(partnerRef, {
        pairingStatus: { status: 'paired', partnerUid: ownerUid, pairedAt: nowTs }
      }, { merge: true });

      tx.delete(codeRef);
    });

    res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    const status =
      /invalid|bad code|expired|self_pair/i.test(msg) ? 400 :
      /actor_already_paired|partner_already_paired/i.test(msg) ? 409 : 500;
    console.error('[pair/accept] failed:', msg);
    res.status(status).json({ message: msg });
  }
});

// ============================================================
//  LINE でコード入力 → その場で確定（paired）
// ============================================================
async function finalizePairingByLine(code, partnerLineUserId) {
  const dbx = getDb();
  const codeRef = dbx.collection('pairingCodes').doc(code);

  await dbx.runTransaction(async (tx) => {
    const codeSnap = await tx.get(codeRef);
    if (!codeSnap.exists) throw new Error('invalid');
    const { ownerUid, expiresAt } = codeSnap.data() || {};
    if (!ownerUid) throw new Error('invalid');

    const expMs = expiresAt?.toMillis?.() ?? 0;
    if (!expMs || Date.now() > expMs) throw new Error('expired');

    const actorRef = dbx.collection('users').doc(ownerUid);
    const actorSnap = await tx.get(actorRef);
    const current = actorSnap.data()?.pairingStatus || {};

    // すでに別相手と paired なら拒否（同じ相手なら冪等許容だが LINE は partnerUid を持たないのでチェックは owner 側のみ）
    if (current.status === 'paired' && current.partnerUid) {
      throw new Error('actor_already_paired');
    }

    const nowTs = admin.firestore.FieldValue.serverTimestamp();

    // LINE 方式：owner 側だけ確定（アプリを持たないパートナーのため partnerUid は無し）
    tx.set(actorRef, {
      pairingStatus: {
        status: 'paired',
        partnerUid: current.partnerUid || null, // 既に同一相手で確定していれば維持、基本は null
        partnerLineUserId,
        pairedAt: nowTs,
        code: admin.firestore.FieldValue.delete(),
        expiresAt: admin.firestore.FieldValue.delete(),
        lineAccepted: true
      }
    }, { merge: true });

    // ワンタイム消費
    tx.delete(codeRef);
  });

  return { ok: true };
}

// ===== LINE webhook =====
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  try {
    const events = req.body?.events || [];
    console.log('[webhook] events=', JSON.stringify(events));
    await Promise.all(events.map(handleEvent));
  } catch (e) {
    console.error('[webhook] error', e);
  }
});

async function handleEvent(event) {
  try {
    // 1) 5桁コード or "pair XXXXX" を受けたら即確定
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
          await finalizePairingByLine(pairingCode, partnerLineUserId);
          return reply(event.replyToken, 'ペアリングが完了しました。アプリ側に反映されます。');
        } catch (error) {
          const msg = String(error.message || error);
          console.error('[webhook/pair-finalize] error', msg);
          if (/invalid/.test(msg)) return reply(event.replyToken, `コード ${pairingCode} は無効です。`);
          if (/expired/.test(msg)) return reply(event.replyToken, `コード ${pairingCode} は有効期限切れです。`);
          if (/actor_already_paired/.test(msg)) return reply(event.replyToken, 'すでに別の相手とペアリング済みです。');
          return reply(event.replyToken, 'エラーが発生しました。');
        }
      }
    }

    // 2) 解除ポストバック（既存）
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
  } catch (err) {
    console.error('[handleEvent] failed', err);
  }
}

// ===== その他API（既存） =====

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
    console.error('[force-unlock-notify] failed', e);
    res.status(500).json({ error: 'Failed to send notification.' });
  }
});

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

// ===== Cron =====
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

    // cleanup
    try {
      const cleanupCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - hours(48));
      const allUsers2 = await dbx.collection('users').get();
      for (const userDoc of allUsers2.docs) {
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
