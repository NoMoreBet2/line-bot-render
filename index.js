'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();

// ---- health (Renderの監視用)
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

// ---- 起動を最優先（ここでlistenしてからFirebase等を初期化）
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`listening on ${port}`);
  initAsync().catch(e => console.error('initAsync fatal:', e));
});

// ---- 未初期化でもコケないようにガード
let db = null;
const getDb = () => {
  if (!db) throw new Error('Firestore not initialized yet');
  return db;
};

// ---- 非同期初期化（Firebase & LINE 準備・詳細ログ）
async function initAsync() {
  // 例外があっても必ずログに残す
  process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
  process.on('uncaughtException', (e) => console.error('uncaughtException', e));

  // Firebase
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  try {
    if (sa) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
      console.log('Firebase initialized with service account JSON');
    } else {
      admin.initializeApp(); // default (多くのPaaSでは資格情報なしで失敗する)
      console.warn('FIREBASE_SERVICE_ACCOUNT_JSON not set; using default credentials');
    }
    db = admin.firestore();
    console.log('Firestore handle obtained');
  } catch (e) {
    console.error('Firebase init failed:', e);
  }

  // LINE SDK 設定確認
  if (!process.env.CHANNEL_ACCESS_TOKEN || !process.env.CHANNEL_SECRET) {
    console.warn('CHANNEL_ACCESS_TOKEN or CHANNEL_SECRET is missing');
  }
}

// ---- ここから下はあなたの既存ハンドラそのまま ----
const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};
const client = new line.Client(config);

const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function genOneTimeToken() {
  return crypto.randomBytes(24).toString('hex');
}

// webhook
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.get('x-line-signature');
    const bodyString = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : (req.body || '').toString();
    if (!signature || bodyString.length === 0) return res.sendStatus(200);
    if (!line.validateSignature(bodyString, config.channelSecret, signature)) return res.sendStatus(401);

    const json = JSON.parse(bodyString);
    await Promise.all((json.events || []).map(handleEvent));
    return res.sendStatus(200);
  } catch (e) {
    console.error('webhook error', e);
    return res.sendStatus(200);
  }
});

async function handleEvent(event) {
  if (event.type === 'message' && event.message?.type === 'text') {
    const text = (event.message.text || '').trim();
    const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
    if (m && event.source?.userId) {
      const code = m[1].toUpperCase();
      try {
        const docRef = getDb().collection('pairing_status').doc(code);
        const doc = await docRef.get();
        if (!doc.exists) return reply(event.replyToken, `コード ${code} は見つかりません。`);
        if (doc.data().expiresAt < now()) return reply(event.replyToken, `コード ${code} の有効期限が切れています。`);
        await docRef.update({ userId: event.source.userId, status: 'paired' });
        return reply(event.replyToken, `ペアリング完了しました ✅（コード：${code}）`);
      } catch (error) {
        console.error('Firestore update failed:', error);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }
    if (/^help$/i.test(text)) {
      return reply(event.replyToken, '使い方：\n1) アプリでコード発行\n2) ここに「pair CODE」を送信\n3) 解除申請が来たら承認/拒否で応答');
    }
    return reply(event.replyToken, text);
  }

  if (event.type === 'postback') {
    const data = event.postback?.data || '';
    const ap = /^approve:([A-Z0-9]{4,10})$/i.exec(data);
    const rj = /^reject:([A-Z0-9]{4,10})$/i.exec(data);

    if (ap) {
      const code = ap[1].toUpperCase();
      try {
        const token = genOneTimeToken();
        await getDb().collection('unlock_requests').doc(code).set(
          { status: 'approved', token, tokenExpiresAt: now() + minutes(10) },
          { merge: true }
        );
        if (event.source?.userId) {
          await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。解除は10分以内に実行されます。' });
        }
      } catch (err) { console.error('Approval failed:', err); }
      return;
    }

    if (rj) {
      const code = rj[1].toUpperCase();
      try {
        await getDb().collection('unlock_requests').doc(code).set(
          { status: 'rejected', token: null, tokenExpiresAt: null },
          { merge: true }
        );
        if (event.source?.userId) {
          await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
        }
      } catch (err) { console.error('Rejection failed:', err); }
      return;
    }
  }
}

function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

app.get('/pair/create', async (_, res) => {
  const code = genCode(6);
  const expiresAt = now() + minutes(30);
  try {
    await getDb().collection('pairing_status').doc(code).set({ code, expiresAt, userId: null, status: 'waiting' });
    res.json({ code, expiresAt });
  } catch (e) {
    console.error('Failed to create pair code:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

app.post('/pair/create', async (_, res) => {
  // 同上
  const code = genCode(6);
  const expiresAt = now() + minutes(30);
  try {
    await getDb().collection('pairing_status').doc(code).set({ code, expiresAt, userId: null, status: 'waiting' });
    res.json({ code, expiresAt });
  } catch (e) {
    console.error('Failed to create pair code:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

app.post('/unlock/request', express.json(), async (req, res) => {
  const code = (req.body?.code || '').toString().toUpperCase();
  if (!code) return res.status(400).json({ error: 'code is required' });
  try {
    const pairDoc = await getDb().collection('pairing_status').doc(code).get();
    if (!pairDoc.exists) return res.status(404).json({ error: 'pair code not found' });
    const pairData = pairDoc.data();
    if (pairData.expiresAt < now()) return res.status(400).json({ error: 'pair code expired' });
    if (pairData.status !== 'paired' || !pairData.userId) return res.status(400).json({ error: 'not paired yet' });

    await getDb().collection('unlock_requests').doc(code).set({
      status: 'pending', token: null, tokenExpiresAt: null, requestedAt: now()
    });
    await client.pushMessage(pairData.userId, {
      type: 'template',
      altText: '解除申請が届きました',
      template: {
        type: 'confirm',
        text: '解除申請が届きました。承認しますか？（15分限定解除）',
        actions: [
          { type: 'postback', label: '承認', data: `approve:${code}` },
          { type: 'postback', label: '拒否', data: `reject:${code}` },
        ],
      },
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('Unlock request failed:', e);
    res.status(500).json({ error: 'Failed to process unlock request.' });
  }
});

app.get('/unlock/poll', async (req, res) => {
  const code = (req.query.code || '').toString().toUpperCase();
  if (!code) return res.status(400).json({ error: 'code is required' });
  try {
    const doc = await getDb().collection('unlock_requests').doc(code).get();
    if (!doc.exists) return res.json({ status: 'none' });
    const r = doc.data();
    if (r.status === 'rejected') return res.json({ status: 'rejected' });
    if (r.status === 'pending') return res.json({ status: 'pending' });
    if (r.status === 'approved') {
      if (r.tokenExpiresAt < now()) {
        await doc.ref.update({ status: 'expired' });
        return res.json({ status: 'expired' });
      }
      const token = r.token;
      await doc.ref.update({ token: null }); // 1回限り
      return res.json({ status: 'approved', token, tokenExpiresAt: r.tokenExpiresAt });
    }
    return res.json({ status: r.status });
  } catch (e) {
    console.error('Polling failed:', e);
    res.status(500).json({ error: 'Polling failed.' });
  }
});
