'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ==============================
// 環境変数
// ==============================
const PORT = process.env.PORT || 3000;
const CRON_SECRET = process.env.CRON_SECRET || '';
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

// ==============================
// Firebase Admin 初期化
// ==============================
let db = null;
async function initAsync() {
  if (admin.apps.length) {
    db = admin.firestore();
    return;
  }
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  try {
    if (sa) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
    } else {
      admin.initializeApp();
    }
    db = admin.firestore();
    console.log('[init] Firestore handle obtained');
  } catch (e) {
    console.error('[init] Firebase init failed:', e);
    throw e;
  }
}
const getDb = () => {
  if (!db) throw new Error('Firestore not initialized yet');
  return db;
};

// ==============================
// Express 準備
// ==============================
const app = express();

app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));
app.use(express.json());

// ==============================
// LINE 設定
// ==============================
const client = new line.Client(lineConfig);

// ==============================
// Firebase 認証ミドルウェア
// ==============================
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
    console.error('[auth] Error verifying token:', error);
    return res.status(403).json({ error: 'Unauthorized: Invalid token' });
  }
};

// ==============================
// Webhook
// ==============================
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  try {
    await Promise.all((req.body.events || []).map(handleEvent));
  } catch (e) {
    console.error('[webhook] error', e);
  }
});

// ==============================
// ユーティリティ
// ==============================
const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const hours = (n) => n * 60 * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}
function pad2(n) { return String(n).padStart(2, '0'); }
/** Firestore Timestamp -> 'yyyy-MM-dd-HH-mm' */
function formatTs(ts) {
  // ts: admin.firestore.Timestamp
  const d = ts.toDate(); // JS Date (UTC→ローカルで可読化、表示目的なのでここでは簡易に)
  const y = d.getFullYear();
  const M = pad2(d.getMonth() + 1);
  const D = pad2(d.getDate());
  const H = pad2(d.getHours());
  const m = pad2(d.getMinutes());
  return `${y}-${M}-${D}-${H}-${m}`;
}
/** 短いID（衝突回避用のサフィックス） */
function shortId(uuid) {
  return uuid.replace(/-/g, '').slice(0, 6).toUpperCase();
}

// ==============================
// メインイベントハンドラ (LINEからのWebhookイベント処理)
// ==============================
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

// ==============================
// 自前 API (Androidアプリからのリクエスト処理)
// ==============================
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

app.post('/notify-partner-of-fraud', firebaseAuthMiddleware, async (req, res) => {
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
        text: '【NoMoreBet 警告】\nパートナーのアプリで不正な操作（セーフモード利用の可能性）が検知されたため、連続ブロック期間がリセットされました。',
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[notify-partner-of-fraud] failed:', e);
    res.status(500).json({ error: 'Failed to notify partner.' });
  }
});

// ★ 4) ハートビート受信 & 不正最終判断
app.post('/heartbeat', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(uid);

    // 「未返信があるか」は status == 'waiting' のみで判定
    const waitingPings = await userRef.collection('pendingPings')
      .where('status', '==', 'waiting')
      .get();

    const userSnap = await userRef.get();
    const blockStatus = userSnap.data()?.blockStatus || {};

    if (waitingPings.empty) {
      // --- ケース1: 未返信なし（正常） ---
      if (blockStatus.suspicionDetectedAt) {
        await userRef.update({ 'blockStatus.suspicionDetectedAt': null });
        console.log(`[heartbeat] User ${uid} recovered from suspicion. Flag cleared.`);
      }
    } else {
      // --- ケース2: 未返信あり（疑い or 不正） ---
      if (blockStatus.suspicionDetectedAt) {
        const suspicionTime = blockStatus.suspicionDetectedAt.toMillis();
        const nowMs = Date.now();
        const THIRTY_MINUTES_MS = 30 * 60 * 1000;

        if (nowMs - suspicionTime > THIRTY_MINUTES_MS) {
          // ** 不正確定（削除はしない） **
          console.log(`[heartbeat] Fraud confirmed for user ${uid}. Suspicion time exceeded 30 minutes.`);

          const pairingStatus = userSnap.data()?.pairingStatus || {};
          const partnerLineUserId = pairingStatus.partnerLineUserId;
          await userRef.update({
            'blockStatus.activatedAt': admin.firestore.FieldValue.serverTimestamp(),
            'blockStatus.suspicionDetectedAt': null,
            'blockStatus.fraudConfirmedAt': admin.firestore.FieldValue.serverTimestamp()
          });
          if (partnerLineUserId) {
            await client.pushMessage(partnerLineUserId, {
              type: 'text',
              text: '【NoMoreBet 警告】\nパートナーのアプリで不正な操作（セーフモード利用の可能性）が検知されたため、連続ブロック期間がリセットされました。',
            });
          }
          // ★ pendingPings は証跡として保持（削除しない）
        } else {
          console.log(`[heartbeat] User ${uid} is still under suspicion.`);
        }
      } else {
        // 初回の疑い
        console.log(`[heartbeat] Suspicion detected for user ${uid}. Setting warning timestamp.`);
        await userRef.update({
          'blockStatus.suspicionDetectedAt': admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }

    // 最後に、今回のハートビート時刻を更新
    await userRef.update({ 'blockStatus.lastHeartbeat': admin.firestore.FieldValue.serverTimestamp() });
    res.json({ ok: true });

  } catch (e) {
    console.error(`[heartbeat] processing failed for user ${uid}`, e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ★ 5) ping の ACK（削除せず、status を 'replied' に更新）
app.post('/ack-ping', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  const pingId = req.body?.pingId;
  if (!pingId) return res.status(400).json({ error: 'pingId is required' });
  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(uid);

    // 旧実装では doc(pingId) だったが、今は docId を時刻ベースにしたため検索して更新
    const q = await userRef.collection('pendingPings')
      .where('id', '==', pingId)
      .limit(1)
      .get();

    if (q.empty) {
      console.warn(`[ack-ping] ping not found for user ${uid}, pingId=${pingId}`);
      return res.json({ ok: true, message: 'not found (already handled or cleaned)' });
    }

    const docRef = q.docs[0].ref;
    await docRef.set({
      status: 'replied',
      repliedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    // まだ waiting が残っているかを確認
    const remaining = await userRef.collection('pendingPings')
      .where('status', '==', 'waiting')
      .limit(1)
      .get();

    if (remaining.empty) {
      await userRef.update({ 'blockStatus.suspicionDetectedAt': null });
      console.log(`[ack-ping] All pings replied for user ${uid}. Suspicion flag removed.`);
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(`[ack-ping] failed for user ${uid}, pingId: ${pingId}`, e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ★ 6) 定期実行：ハートビート監視 Cron
app.get('/cron/check-heartbeats', async (req, res) => {
  if (!CRON_SECRET || req.query.secret !== CRON_SECRET) {
    console.warn('[cron] 403 secret mismatch');
    return res.status(403).json({ error: 'Forbidden' });
  }

  const dbx = getDb();
  const nowTs = admin.firestore.Timestamp.now();

  // 48時間以上経過した古い pendingPings を削除するゴミ掃除処理（必要なら status 条件を追加可能）
  try {
    const cleanupCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - hours(48));
    const allUsers = await dbx.collection('users').get();
    for (const userDoc of allUsers.docs) {
      const pingsToCleanQuery = await userDoc.ref
        .collection('pendingPings')
        .where('sentAt', '<', cleanupCutoff)
        .get();
      if (!pingsToCleanQuery.empty) {
        const batch = dbx.batch();
        pingsToCleanQuery.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
        console.log(`[cron-cleanup] Cleaned ${pingsToCleanQuery.size} old pings for user ${userDoc.id}`);
      }
    }
  } catch (e) {
    console.error('[cron-cleanup] failed', e);
  }

  // ハートビートが20分以上途絶えているユーザーを探す
  const staleCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(20));
  const longOfflineCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(24 * 60));

  try {
    const q = await dbx.collection('users')
      .where('blockStatus.isActive', '==', true)
      .where('blockStatus.lastHeartbeat', '<', staleCutoff)
      .where('blockStatus.lastHeartbeat', '>', longOfflineCutoff)
      .get();

    console.log(
      '[cron] run at=%s | candidates=%d | stale<%s longOffline>%s',
      new Date().toISOString(),
      q.size,
      new Date(staleCutoff.toMillis()).toISOString(),
      new Date(longOfflineCutoff.toMillis()).toISOString()
    );

    for (const userDoc of q.docs) {
      const uid = userDoc.id;
      const fcmToken = userDoc.data().deviceStatus?.fcmToken;
      if (!fcmToken) {
        console.warn('[cron] skip (no fcmToken) -> %s', uid);
        continue;
      }

      // ping 識別用 UUID（payloadで端末に渡す ID）
      const pingUuid = crypto.randomUUID();
      const suffix = shortId(pingUuid);
      const docId = `${formatTs(nowTs)}-${suffix}`; // 例: 2025-08-24-09-15-1A2B3C

      const pingRef = userDoc.ref.collection('pendingPings').doc(docId);
      await pingRef.set({
        id: pingUuid,                 // ← 識別ID（ACKで使う）
        status: 'waiting',            // ← 返信待ち
        sentAt: nowTs,
        by: 'cron',
        readableId: docId             // （検索は id を使う。表示・監査用に残す）
      });

      try {
        await admin.messaging().send({
          token: fcmToken,
          data: { action: 'ping_challenge', pingId: pingUuid },
          android: { priority: 'high' },
        });
        console.log('[cron] ping queued -> %s (%s / %s)', uid, pingUuid, docId);
      } catch (sendErr) {
        console.error('[cron] FCM send error -> %s :', uid, sendErr);
      }
    }
    return res.json({ ok: true, checked: q.size });
  } catch (e) {
    console.error('[cron] failed', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ==============================
// サーバー起動（初期化を待ってから listen）
// ==============================
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
