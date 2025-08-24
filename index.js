'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ===== Env =====
const PORT = process.env.PORT || 3000;
const CRON_SECRET = process.env.CRON_SECRET || '';
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

// 運用パラメータ（環境変数で上書き可）
const STALE_MINUTES = Number(process.env.STALE_MINUTES || 20);            // HBが来なければ ping 対象（分）
const LONG_OFFLINE_MIN = Number(process.env.LONG_OFFLINE_MIN || 1440);    // 長期離脱の上限（分）
const PING_TTL_MS = Number(process.env.PING_TTL_MS || (2 * 60 * 1000));   // FCM TTL
const PING_ACK_WINDOW_MS = Number(process.env.PING_ACK_WINDOW_MS || PING_TTL_MS); // 返信猶予
const FCM_FAIL_THRESHOLD = Number(process.env.FCM_FAIL_THRESHOLD || 3);   // 連続失敗しきい値

// ===== Firebase Admin =====
let db = null;
async function initAsync() {
  if (admin.apps.length) {
    db = admin.firestore();
    return;
  }
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (sa) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
  } else {
    admin.initializeApp();
  }
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
app.use(express.json());

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
    req.auth = { uid: decoded.uid };
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
const pad2 = (n) => String(n).padStart(2, '0');

function formatTs(ts) {
  const d = ts.toDate();
  const y = d.getFullYear();
  const M = pad2(d.getMonth() + 1);
  const D = pad2(d.getDate());
  const H = pad2(d.getHours());
  const m = pad2(d.getMinutes());
  return `${y}-${M}-${D}-${H}-${m}`;
}
function shortId(uuid) {
  return uuid.replace(/-/g, '').slice(0, 6).toUpperCase();
}
function makeDocId(ts, uuid) {
  return `${formatTs(ts)}-${shortId(uuid)}`;
}
function genCode(len = 6) {
  const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

// ===== LINE webhook =====
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  try {
    await Promise.all((req.body.events || []).map(handleEvent));
  } catch (e) {
    console.error('[webhook] error', e);
  }
});

async function handleEvent(event) {
  if (event.type === 'message' && event.message?.type === 'text') {
    const text = (event.message.text || '').trim();
    const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
    if (m && event.source?.userId) {
      const code = m[1].toUpperCase();
      const partnerLineUserId = event.source.userId;
      try {
        const dbx = getDb();
        const codeRef = dbx.collection('codes').doc(code);
        const codeSnap = await codeRef.get();
        if (!codeSnap.exists || (codeSnap.data().expiresAt.toMillis?.() || 0) < now()) {
          return reply(event.replyToken, `コード ${code} は無効か、有効期限切れです。`);
        }
        const appUserUid = codeSnap.data().appUserUid;
        const userRef = dbx.collection('users').doc(appUserUid);
        const partnerProfile = await client.getProfile(partnerLineUserId);
        await userRef.update({
          'pairingStatus.status': 'paired',
          'pairingStatus.partnerLineUserId': partnerLineUserId,
          'pairingStatus.partnerDisplayName': partnerProfile.displayName,
          'pairingStatus.pairedAt': admin.firestore.FieldValue.serverTimestamp(),
        });
        await codeRef.delete();
        return reply(event.replyToken, `ペアリングが完了しました ✅`);
      } catch (error) {
        console.error('[webhook/pair] error', error);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }
  }
  if (event.type === 'postback') {
    const data = event.postback?.data || '';
    const ap = /^approve:(.+)$/i.exec(data);
    const rj = /^reject:(.+)$/i.exec(data);
    if (ap) {
      const appUserUid = ap[1];
      try {
        const userRef = getDb().collection('users').doc(appUserUid);
        await userRef.update({
          'blockStatus.isActive': false,
          'blockStatus.activatedAt': null,
        });
        if (event.source?.userId) {
          await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。' });
        }
      } catch (err) {
        console.error('[webhook/approve] failed:', err);
      }
      return;
    }
    if (rj) {
      if (event.source?.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
      }
      return;
    }
  }
}

// ===== App APIs =====
app.post('/pair/create', firebaseAuthMiddleware, async (req, res) => {
  const appUserUid = req.auth.uid;
  const code = genCode(6).toUpperCase();
  const expiresAt = now() + minutes(30);
  try {
    const dbx = getDb();
    const batch = dbx.batch();
    const codeRef = dbx.collection('codes').doc(code);
    batch.set(codeRef, { appUserUid, expiresAt: admin.firestore.Timestamp.fromMillis(expiresAt) });
    const userRef = dbx.collection('users').doc(appUserUid);
    batch.update(userRef, {
      'pairingStatus.code': code,
      'pairingStatus.expiresAt': admin.firestore.Timestamp.fromMillis(expiresAt),
      'pairingStatus.status': 'waiting',
    });
    await batch.commit();
    res.json({ code, expiresAt });
  } catch (e) {
    console.error('[pair/create] failed:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

app.post('/request-partner-unlock', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const dbx = getDb();
    const userSnap = await dbx.collection('users').doc(uid).get();
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

// ▼▼▼ 強制解除の通知API ▼▼▼
app.post('/force-unlock-notify', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const dbx = getDb();
    const userSnap = await dbx.collection('users').doc(uid).get();
    if (!userSnap.exists) {
      // ユーザーが見つからない場合は何もしない
      return res.status(404).json({ error: 'User not found' });
    }

    const pairingStatus = userSnap.data().pairingStatus || {};
    const partnerLineUserId = pairingStatus.partnerLineUserId;

    // パートナーが設定されていれば、LINEで通知を送信
    if (partnerLineUserId && pairingStatus.status === 'paired') {
      await client.pushMessage(partnerLineUserId, {
        type: 'text',
        text: '【NoMoreBet お知らせ】\nパートナーが強制解除機能を使用しました。'
      });
      console.log(`[force-unlock] 通知を送信しました: user=${uid}, partner=${partnerLineUserId}`);
    }
    
    res.json({ ok: true });
  } catch (e) {
    console.error(`[force-unlock-notify] failed for user ${uid}:`, e);
    res.status(500).json({ error: 'Failed to send notification.' });
  }
});
// ▲▲▲ ここまで ▲▲▲

// Heartbeat: lastHeartbeat のみ更新
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

// ACK: waiting→replied（期限超過は replied_late）
app.post('/ack-ping', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  const pingId = req.body?.pingId;
  if (!pingId) return res.status(400).json({ error: 'pingId is required' });
  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(uid);
    const q = await userRef.collection('pendingPings').where('id', '==', pingId).limit(1).get();
    if (q.empty) {
      console.warn(`[ack-ping] ping not found for user ${uid}, pingId=${pingId}`);
      return res.json({ ok: true, message: 'not found' });
    }
    const snap = q.docs[0];
    const data = snap.data();
    if (data.status !== 'waiting') {
      return res.json({ ok: true, message: `ignored (${data.status})` });
    }
    const deadlineMs = (data.expiresAt?.toMillis?.() ?? (data.sentAt?.toMillis?.() + PING_ACK_WINDOW_MS));
    const newStatus = (Date.now() <= deadlineMs) ? 'replied' : 'replied_late';
    await snap.ref.set({
      status: newStatus,
      repliedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    res.json({ ok: true });
  } catch (e) {
    console.error(`[ack-ping] failed for user ${uid}, pingId: ${pingId}`, e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===== Cron：1) 期限切れ回収→通知 2) 未HBユーザーへ ping 3) 古いログ掃除 =====
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
    // 1) 期限切れ waiting → expired & パートナー通知
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
            const readableId = ping.data().readableId || '(no-id)';
            const sentAt = ping.data().sentAt;
            const sentStr = sentAt ? new Date(sentAt.toMillis()).toLocaleString('ja-JP') : '不明';
            try {
              await client.pushMessage(partnerLineUserId, {
                type: 'text',
                text:
                  `【NoMoreBet お知らせ】\n` +
                  `確認用の通知に応答がありませんでした（ID: ${readableId} / 送信: ${sentStr}）。\n` +
                  `端末の電源OFF・セーフモード・圏外・端末設定などの可能性があります。`
              });
            } catch (e) {
              console.error('[cron] LINE push error:', e);
            }
          }
        }
        await batch.commit();
        console.log(`[cron] expired marked: user=${userDoc.id}, count=${overdue.size}`);
      }
    }

    // 2) HBが途絶えたユーザーに ping 送信（既に waiting があればスキップ）
    const q = await dbx.collection('users')
      .where('blockStatus.isActive', '==', true)
      .where('blockStatus.lastHeartbeat', '<', staleCutoff)
      .where('blockStatus.lastHeartbeat', '>', longOfflineCutoff)
      .get();

    console.log(
      '[cron] run at=%s | stale candidates=%d | stale<%s longOffline>%s',
      new Date().toISOString(),
      q.size,
      new Date(staleCutoff.toMillis()).toISOString(),
      new Date(longOfflineCutoff.toMillis()).toISOString()
    );

    for (const userDoc of q.docs) {
      const uid = userDoc.id;
      const userRef = userDoc.ref;
      const fcmToken = userDoc.data().deviceStatus?.fcmToken;
      if (!fcmToken) {
        console.warn('[cron] skip (no fcmToken) -> %s', uid);
        continue;
      }

      const waitingExists = await userRef.collection('pendingPings')
        .where('status', '==', 'waiting')
        .limit(1)
        .get();
      if (!waitingExists.empty) {
        console.log('[cron] skip (waiting exists) -> %s', uid);
        continue;
      }

      const pingUuid = crypto.randomUUID();
      const docId = makeDocId(nowTs, pingUuid);
      const expiresAt = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() + PING_ACK_WINDOW_MS);

      await userRef.collection('pendingPings').doc(docId).set({
        id: pingUuid,
        readableId: docId,
        status: 'waiting',
        sentAt: nowTs,
        expiresAt,
        by: 'cron'
      });

      try {
        await admin.messaging().send({
          token: fcmToken,
          data: { action: 'ping_challenge', pingId: pingUuid },
          android: { priority: 'high', ttl: PING_TTL_MS },
        });

        // 送信成功：連続失敗をリセット
        await userRef.set({
          deviceStatus: {
            lastFcmOkAt: admin.firestore.FieldValue.serverTimestamp(),
            fcmConsecutiveFails: 0,
            gmsIssueSuspected: false
          }
        }, { merge: true });

        console.log('[cron] ping queued -> %s (%s / %s)', uid, pingUuid, docId);
      } catch (sendErr) {
        const code = sendErr?.errorInfo?.code || sendErr?.code || 'unknown';
        console.error('[cron] FCM send error -> %s : %s', uid, code, sendErr?.message);

        // ログ保存（任意）
        try {
          await userRef.collection('fcmSendLogs').add({
            token: fcmToken,
            code,
            message: sendErr?.message || '',
            at: admin.firestore.FieldValue.serverTimestamp()
          });
        } catch (logErr) {
          console.error('[cron] fcmSendLogs add error:', logErr);
        }

        // 失敗コード別の処理
        if (code === 'messaging/registration-token-not-registered') {
          // 失効したトークンを無効化
          await userRef.set({
            deviceStatus: {
              fcmToken: admin.firestore.FieldValue.delete(),
              fcmConsecutiveFails: admin.firestore.FieldValue.increment(1),
              gmsIssueSuspected: false
            }
          }, { merge: true });
        } else {
          // 一時障害 or 不明 → 連続失敗カウントを進める
          await userRef.set({
            deviceStatus: {
              fcmConsecutiveFails: admin.firestore.FieldValue.increment(1)
            }
          }, { merge: true });
        }

        // 連続失敗がしきい値を超えたら、GMS不整合の可能性をフラグで示す
        try {
          const fresh = await userRef.get();
          const dev = fresh.data()?.deviceStatus || {};
          if ((dev.fcmConsecutiveFails || 0) >= FCM_FAIL_THRESHOLD) {
            await userRef.set({
              deviceStatus: {
                gmsIssueSuspected: true
              }
            }, { merge: true });
          }
        } catch (readErr) {
          console.error('[cron] read-after-fail error:', readErr);
        }
      }
    }

    // 3) 古い ping の掃除（48h）
    try {
      const cleanupCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - hours(48));
      for (const userDoc of allUsers.docs) {
        const old = await userDoc.ref.collection('pendingPings').where('sentAt', '<', cleanupCutoff).get();
        if (!old.empty) {
          const batch = dbx.batch();
          old.docs.forEach(doc => batch.delete(doc.ref));
          await batch.commit();
          console.log(`[cron-cleanup] cleaned old pings: user=${userDoc.id}, count=${old.size}`);
        }
      }
    } catch (e) {
      console.error('[cron-cleanup] failed', e);
    }

    return res.json({ ok: true, staleChecked: q.size });
  } catch (e) {
    console.error('[cron] failed', e);
    return res.status(500).json({ error: 'Internal error' });
  }
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