'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const crypto = require('crypto');
const admin = require('firebase-admin');

// ★ 認証情報を検証するためのミドルウェアを追加
const firebaseAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.auth = { uid: decodedToken.uid }; // 後続の処理で使えるように、デコードした情報をreqオブジェクトに追加
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(403).json({ error: 'Unauthorized: Invalid token' });
  }
};


const app = express();
app.use(express.json()); // JSONボディをパースするために必要

// ---- health (Renderの監視用)
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

// ---- 起動を最優先
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`listening on ${port}`);
  initAsync().catch(e => console.error('initAsync fatal:', e));
});

// ---- グローバル変数 ----
let db = null;
const getDb = () => {
  if (!db) throw new Error('Firestore not initialized yet');
  return db;
};

// ---- 非同期初期化 ----
async function initAsync() {
  // Firebase Admin SDKの初期化
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

// ---- LINE設定 ----
const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};
const client = new line.Client(config);

// ---- ユーティリティ ----
const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}


// ---- webhook（LINEからの通知を受け取る場所）----
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.get('x-line-signature');
    const bodyString = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : req.body.toString();
    if (!signature || !line.validateSignature(bodyString, config.channelSecret, signature)) {
      return res.sendStatus(401);
    }
    const json = JSON.parse(bodyString);
    await Promise.all((json.events || []).map(handleEvent));
    res.sendStatus(200);
  } catch (e) {
    console.error('webhook error', e);
    res.sendStatus(200); // LINEサーバーには常に成功を返す
  }
});

// ---- メインイベントハンドラ ----
async function handleEvent(event) {
  // ===== 1. パートナーがペアコードを送信した時の処理 =====
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
          partnerLineUserId: partnerLineUserId,
          partnerDisplayName: partnerProfile.displayName,
        };
        
        const userRef = dbx.collection('users').doc(appUserUid);
        await userRef.update({ pairingStatus: newPairingStatus });
        await dbx.collection('codes').doc(code).delete(); // ★ 完了したので逆引きコードを削除

        return reply(event.replyToken, `ペアリング完了しました ✅`);
      } catch (error) {
        console.error('pair webhook error', error);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }
  }

  // ===== 2. パートナーが解除申請を承認/拒否した時の処理 =====
  if (event.type === 'postback') {
    const data = event.postback?.data || '';
    const ap = /^approve:(.+)$/i.exec(data); // approve:{uid}
    const rj = /^reject:(.+)$/i.exec(data);  // reject:{uid}

    if (ap) {
      const appUserUid = ap[1];
      try {
        // ★ FirestoreのblockStatusを直接更新
        const userRef = getDb().collection('users').doc(appUserUid);
        await userRef.update({
          'blockStatus.isActive': false,
          'blockStatus.activatedAt': null
        });
        if (event.source?.userId) {
          await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。' });
        }
      } catch (err) { console.error('Approval failed:', err); }
      return;
    }

    if (rj) {
      // 拒否された場合は何もしないが、パートナーには応答する
      if (event.source?.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
      }
      return;
    }
  }
}

// ---- 返信ユーティリティ ----
function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

// ---- APIエンドポイント ----

// 1. ペアコード発行API
app.post('/pair/create', firebaseAuthMiddleware, async (req, res) => {
  const appUserUid = req.auth.uid;
  const code = genCode(6).toUpperCase();
  const expiresAt = now() + minutes(30);
  try {
    const dbx = getDb();
    const batch = dbx.batch();
    
    // 逆引き用のcodesコレクションに一時的に保存
    const codeRef = dbx.collection('codes').doc(code);
    batch.set(codeRef, { appUserUid, expiresAt });

    // ユーザーのpairingStatusフィールドを更新
    const userRef = dbx.collection('users').doc(appUserUid);
    batch.update(userRef, { 'pairingStatus.code': code, 'pairingStatus.expiresAt': expiresAt, 'pairingStatus.status': 'waiting' });
    
    await batch.commit();
    res.json({ code, expiresAt });
  } catch (e) {
    console.error('Failed to create pair code:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

// 2. パートナーへの解除申請API (新バージョン)
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

    // ★ LINEのボタンに、アプリ利用者のuidを含める
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