'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ==============================
// 環境変数
// ==============================
const PORT = process.env.PORT || 3000;
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

// ==============================
// Firebase Admin 初期化
// ==============================
let db = null;
try {
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (sa) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
  } else {
    admin.initializeApp();
  }
  db = admin.firestore();
} catch (e) {
  console.error('Firebase init failed:', e);
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
  res.sendStatus(200); // 先に成功応答を返す
  try {
    await Promise.all((req.body.events || []).map(handleEvent));
  } catch (e) {
    console.error('webhook error', e);
  }
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
        // ★ codesコレクションから逆引き
        const codeRef = dbx.collection('codes').doc(code);
        const codeSnap = await codeRef.get();

        if (!codeSnap.exists || (codeSnap.data().expiresAt || 0) < now()) {
          return reply(event.replyToken, `コード ${code} は無効か、有効期限切れです。`);
        }
        const appUserUid = codeSnap.data().appUserUid;

        // userドキュメントを更新してペアリングを完了
        const userRef = dbx.collection('users').doc(appUserUid);
        const partnerProfile = await client.getProfile(partnerLineUserId);
        await userRef.update({
          'pairingStatus.status': 'paired',
          'pairingStatus.partnerLineUserId': partnerLineUserId,
          'pairingStatus.partnerDisplayName': partnerProfile.displayName,
          'pairingStatus.pairedAt': admin.firestore.FieldValue.serverTimestamp(),
        });
        
        await codeRef.delete(); // 完了したので逆引きコードを削除
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
    const ap = /^approve:(.+)$/i.exec(data); // approve:{uid}
    const rj = /^reject:(.+)$/i.exec(data);  // reject:{uid}

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
    batch.set(codeRef, { appUserUid, expiresAt });

    const userRef = dbx.collection('users').doc(appUserUid);
    batch.update(userRef, {
      'pairingStatus.code': code,
      'pairingStatus.expiresAt': expiresAt,
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

// ★ 3) 不正検知をパートナーに通知するAPI
app.post('/notify-partner-of-fraud', firebaseAuthMiddleware, async (req, res) => {
    const uid = req.auth.uid;
    try {
      const dbx = getDb();
      const userSnap = await dbx.collection('users').doc(uid).get();
      if (!userSnap.exists) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const pairingStatus = userSnap.data().pairingStatus || {};
      const partnerLineUserId = pairingStatus.partnerLineUserId;
  
      if (partnerLineUserId && pairingStatus.status === 'paired') {
        const message = {
          type: 'text',
          text: '【NoMoreBet 警告】\nパートナーのアプリで、ブロック機能の不正な操作（アプリの再インストールなど）が検知されました。現在、ブロック機能は解除されています。'
        };
        await client.pushMessage(partnerLineUserId, message);
      }
      
      res.json({ ok: true });
  
    } catch (e) {
      console.error('Failed to notify partner of fraud:', e);
      res.status(500).json({ error: 'Failed to notify partner.' });
    }
});

// ==============================
// 4) ハートビート監視用 Cron エンドポイント
// GET /cron/check-heartbeats?secret=xxxxx
// ==============================
const CRON_SECRET = process.env.CRON_SECRET || '';
const STALE_MINUTES = parseInt(process.env.HEARTBEAT_STALE_MINUTES || '20', 10);   // 20分以上無通信でstale扱い
const PARTNER_NOTIFY_COOLDOWN_MIN = parseInt(process.env.PARTNER_NOTIFY_COOLDOWN_MIN || '60', 10); // パートナー通知の再送間隔

app.get('/cron/check-heartbeats', async (req, res) => {
  try {
    if (!CRON_SECRET || req.query.secret !== CRON_SECRET) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const dbx = getDb();
    const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - STALE_MINUTES * 60 * 1000);

    // lastHeartbeat が cutoff より古いユーザを抽出
    const q = await dbx
      .collection('users')
      .where('deviceStatus.lastHeartbeat', '<', cutoff)
      .get();

    let checked = 0;
    let fcmTriggered = 0;
    let partnerNotified = 0;

    for (const doc of q.docs) {
      checked++;
      const data = doc.data() || {};
      const deviceStatus = data.deviceStatus || {};
      const pairingStatus = data.pairingStatus || {};
      const uid = data.uid || doc.id;

      const lastHeartbeat = deviceStatus.lastHeartbeat; // Firestore Timestamp
      const fcmToken = deviceStatus.fcmToken;
      const partnerLineUserId = pairingStatus.partnerLineUserId;
      const pairingStatusStr = pairingStatus.status;

      // 1) 端末に「今すぐ心拍」を要求（FCM データメッセージ）
      if (fcmToken) {
        try {
          await admin.messaging().send({
            token: fcmToken,
            data: { action: 'heartbeat_now' },
            android: { priority: 'high' },
          });
          fcmTriggered++;
          // 任意: 送信時刻を保存（デバッグ用）
          await doc.ref.set(
            { deviceStatus: { lastHeartbeatPingSentAt: admin.firestore.FieldValue.serverTimestamp() } },
            { merge: true }
          );
        } catch (e) {
          console.error('FCM send error uid=', uid, e);
        }
      }

      // 2) パートナーへの通知（連投防止: PARTNER_NOTIFY_COOLDOWN_MIN 分）
      const alerts = data.alerts || {};
      const offlineNotifiedAt = alerts.offlineNotifiedAt; // Firestore Timestamp
      const nowTs = admin.firestore.Timestamp.now();

      const shouldNotifyPartner =
        partnerLineUserId &&
        pairingStatusStr === 'paired' &&
        (!offlineNotifiedAt ||
          (nowTs.toMillis() - offlineNotifiedAt.toMillis()) > PARTNER_NOTIFY_COOLDOWN_MIN * 60 * 1000);

      if (shouldNotifyPartner) {
        try {
          const lastStr = lastHeartbeat ? new Date(lastHeartbeat.toMillis()).toLocaleString('ja-JP') : '不明';
          await client.pushMessage(partnerLineUserId, {
            type: 'text',
            text: `【NoMoreBet】\nパートナー端末のハートビートが途絶えています（最終: ${lastStr}）。\nアプリ側に復旧を依頼しました。しばらくしても改善しない場合はご確認ください。`,
          });
          await doc.ref.set(
            { alerts: { offlineNotifiedAt: admin.firestore.FieldValue.serverTimestamp() } },
            { merge: true }
          );
          partnerNotified++;
        } catch (e) {
          console.error('LINE notify error uid=', uid, e);
        }
      }
    }

    return res.json({
      ok: true,
      checked,
      fcmTriggered,
      partnerNotified,
      staleMinutes: STALE_MINUTES,
    });
  } catch (e) {
    console.error('cron/check-heartbeats error', e);
    return res.status(500).json({ error: 'internal_error' });
  }
});



// ==============================
// サーバー起動
// ==============================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on ${PORT}`);
});
