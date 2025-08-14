'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');

// ==============================
// 環境変数
// ==============================
// ※ Render などの環境に必ず設定
// CHANNEL_ACCESS_TOKEN : LINE 長期チャネルアクセストークン
// CHANNEL_SECRET       : LINE チャネルシークレット
// FIREBASE_SERVICE_ACCOUNT_JSON : サービスアカウントJSON（文字列; 未設定ならADCで初期化）
const PORT = process.env.PORT || 3000;

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
      // 環境のADCを使う（Render等では未設定なら失敗するのでログ確認）
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
// LINE 設定
// ==============================
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};
const client = new line.Client(lineConfig);

// ==============================
// Express 準備
// ==============================
const app = express();

// ---- health (監視用)
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

// ==============================
// Webhook（最優先で定義！）
// - @line/bot-sdk の middleware が署名検証と raw ボディ処理を担当
// - 他の body parser（express.json 等）より前に置く
// ==============================
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  // 先に 200 を返す（LINE には成功扱いにする）
  res.sendStatus(200);

  try {
    const events = req.body?.events || [];
    await Promise.all(events.map(handleEvent));
  } catch (e) {
    console.error('webhook error', e);
  }
});

// ==============================
// ここから下は通常の JSON API 用
// webhook より後に body parser を入れる
// ==============================
app.use(express.json());

// ==============================
// Firebase 認証ミドルウェア（アプリの自前API向け）
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
// メインイベントハンドラ
// ==============================
async function handleEvent(event) {
  // 1) テキストメッセージ（ペアコード受信）
  if (event.type === 'message' && event.message?.type === 'text') {
    const text = (event.message.text || '').trim();
    const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
    if (m && event.source?.userId) {
      const code = m[1].toUpperCase();
      const partnerLineUserId = event.source.userId;
      try {
        const dbx = getDb();
        const usersQuery = await dbx.collection('users').where('pairingStatus.code', '==', code).limit(1).get();
        if (usersQuery.empty) return reply(event.replyToken, `コード ${code} は見つかりません。`);

        const userDoc = usersQuery.docs[0];
        const appUserUid = userDoc.id;
        const pairingStatus = userDoc.data().pairingStatus || {};

        if ((pairingStatus.expiresAt || 0) < now()) return reply(event.replyToken, `コード ${code} の有効期限が切れています。`);
        if (pairingStatus.status === 'paired') return reply(event.replyToken, `このコードは既に使用済みです。`);

        const partnerProfile = await client.getProfile(partnerLineUserId);
        const newPairingStatus = {
          ...pairingStatus,
          status: 'paired',
          pairedAt: admin.firestore.FieldValue.serverTimestamp(),
          partnerLineUserId,
          partnerDisplayName: partnerProfile.displayName,
        };

        const userRef = dbx.collection('users').doc(appUserUid);
        await userRef.update({ pairingStatus: newPairingStatus });
        await dbx.collection('codes').doc(code).delete(); // 逆引きコードを削除

        return reply(event.replyToken, `ペアリング完了しました ✅`);
      } catch (error) {
        console.error('pair webhook error', error);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }
  }

  // 2) ポストバック（承認/拒否）
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
      } catch (err) {
        console.error('Approval failed:', err);
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

  // その他イベントは無視
  return;
}

// ==============================
// 自前 API
// ==============================

// 1) ペアコード発行
app.post('/pair/create', firebaseAuthMiddleware, async (req, res) => {
  const appUserUid = req.auth.uid;
  const code = genCode(6).toUpperCase();
  const expiresAt = now() + minutes(30);
  try {
    const dbx = getDb();
    const batch = dbx.batch();

    // 逆引き用 codes コレクション
    const codeRef = dbx.collection('codes').doc(code);
    batch.set(codeRef, { appUserUid, expiresAt });

    // ユーザーの pairingStatus 更新
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

// 2) パートナーへの解除申請（Confirm テンプレ送信）
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
    console.error('Unlock request failed:', e);
    res.status(500).json({ error: 'Failed to process unlock request.' });
  }
});

// ==============================
// サーバー起動
// ==============================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on ${PORT}`);
  initAsync().catch((e) => console.error('initAsync fatal:', e));
});
