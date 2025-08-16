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
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  try {
    if (sa) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
    } else {
      admin.initializeApp();
    }
    db = admin.firestore();
    console.log('Firestore handle obtained');
  } catch (e) {
    console.error('Firebase init failed:', e);
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

// ---- health (監視用)
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

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
    console.error('Error verifying token:', error);
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
  } catch (e) { console.error('webhook error', e); }
});

// ==============================
// API用 Body Parser
// ==============================
app.use(express.json());

// ==============================
// ユーティリティ
// ==============================
const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

// ==============================
// メインイベントハンドラ (LINEからのWebhookイベント処理)
// ==============================
async function handleEvent(event) {
    // 1) パートナーがペアコードを送信した時
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
    
            if (!codeSnap.exists || (codeSnap.data().expiresAt.toMillis() || 0) < now()) {
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
            console.error('pair webhook error', error);
            return reply(event.replyToken, 'エラーが発生しました。');
          }
        }
    }
    // 2) パートナーが解除申請を承認/拒否した時
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
          } catch (err) { console.error('Approval failed:', err); }
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

// 1) ペアコード発行 API
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
      console.error('Failed to create pair code:', e);
      res.status(500).json({ error: 'Failed to issue a pair code.' });
    }
});

// 2) パートナーへの解除申請 API
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
        type: 'template', altText: '解除申請が届きました',
        template: {
          type: 'confirm', text: 'パートナーからブロック解除の申請が届きました。承認しますか？',
          actions: [
            { type: 'postback', label: '承認する', data: `approve:${uid}` },
            { type: 'postback', label: '拒否する', data: `reject:${uid}` },
          ],
        },
      });
      res.json({ ok: true });
    } catch (e) {
      console.error('Unlock request failed:', e);
      res.status(500).json({ error: 'Failed to process unlock request.' });
    }
});

// 3) 不正検知をパートナーに通知するAPI
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
          text: '【NoMoreBet 警告】\nパートナーのアプリで、ブロック機能の不正な操作が検知されました。現在、ブロック機能は解除されています。'
        });
      }
      res.json({ ok: true });
    } catch (e) {
      console.error('Failed to notify partner of fraud:', e);
      res.status(500).json({ error: 'Failed to notify partner.' });
    }
});

// ★ 4) アプリからの通常のハートビートを受け取り、不正を最終判断するAPI
app.post('/heartbeat', firebaseAuthMiddleware, async (req, res) => {
    const uid = req.auth.uid;
    try {
        const dbx = getDb();
        const userRef = dbx.collection('users').doc(uid);

        const pendingPingsQuery = await userRef.collection('pendingPings').limit(1).get();
        if (!pendingPingsQuery.empty) {
            // 不正確定！
            console.log(`Fraud detected for user ${uid}. Heartbeat received while pings are pending.`);
            const pairingStatus = (await userRef.get()).data()?.pairingStatus || {};
            const partnerLineUserId = pairingStatus.partnerLineUserId;

            await userRef.update({
                'blockStatus.isActive': false,
                'blockStatus.activatedAt': null
            });

            if (partnerLineUserId) {
                await client.pushMessage(partnerLineUserId, {
                    type: 'text',
                    text: '【NoMoreBet 警告】\nパートナーのアプリで不正な操作（セーフモード利用の可能性）が検知されました。ブロックは解除されています。'
                });
            }
            const allPings = await userRef.collection('pendingPings').get();
            const batch = dbx.batch();
            allPings.docs.forEach(doc => batch.delete(doc.ref));
            await batch.commit();
        }

        await userRef.update({ 'blockStatus.lastHeartbeat': admin.firestore.FieldValue.serverTimestamp() });
        res.json({ ok: true });
    } catch (e) {
        console.error(`Heartbeat processing failed for user ${uid}`, e);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ★ 5) アプリからの応答確認への「返信」を受け取るAPI
app.post('/ack-ping', firebaseAuthMiddleware, async (req, res) => {
    const uid = req.auth.uid;
    const pingId = req.body?.pingId;
    if (!pingId) return res.status(400).json({ error: 'pingId is required' });
    try {
      const pingRef = getDb().collection('users').doc(uid).collection('pendingPings').doc(pingId);
      await pingRef.delete();
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
});
  
// ★ 6) 定期実行されるハートビート監視 Cronジョブ
app.get('/cron/check-heartbeats', async (req, res) => {
    if (!CRON_SECRET || req.query.secret !== CRON_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  
    const dbx = getDb();
    const now = admin.firestore.Timestamp.now();
    const staleCutoff = admin.firestore.Timestamp.fromMillis(now.toMillis() - minutes(20));
    const longOfflineCutoff = admin.firestore.Timestamp.fromMillis(now.toMillis() - minutes(24 * 60));
  
    try {
      const staleUsersQuery = await dbx.collection('users')
        .where('blockStatus.isActive', '==', true)
        .where('blockStatus.lastHeartbeat', '<', staleCutoff)
        .where('blockStatus.lastHeartbeat', '>', longOfflineCutoff)
        .get();
  
      for (const userDoc of staleUsersQuery.docs) {
        const uid = userDoc.id;
        const userData = userDoc.data();
        const fcmToken = userData.deviceStatus?.fcmToken; // fcmTokenはdeviceStatusにあると仮定
  
        if (fcmToken) {
          const pingId = crypto.randomUUID();
          const pingRef = userDoc.ref.collection('pendingPings').doc(pingId);
          await pingRef.set({ sentAt: now });
  
          await admin.messaging().send({
            token: fcmToken,
            data: { action: 'ping_challenge', pingId: pingId },
            android: { priority: 'high' },
          });
        }
      }
      res.json({ ok: true, checked: staleUsersQuery.size });
    } catch (e) {
      console.error('Cron job failed', e);
      res.status(500).json({ error: 'Internal error' });
    }
});

// ==============================
// サーバー起動
// ==============================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on ${PORT}`);
  initAsync();
});