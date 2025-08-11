'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const crypto = require('crypto');

const app = express();

/**
 * ==== LINE 設定（Render 環境変数名に合わせ済み）====
 * CHANNEL_ACCESS_TOKEN / CHANNEL_SECRET を Render の Environment に設定しておく
 */
const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};
const client = new line.Client(config);

/**
 * ==== メモリストア（最小構成）====
 * 本番は Firestore 等に置き換え推奨
 */
const pairCodes = new Map();       // code -> { code, expiresAt, userId|null, status:'waiting'|'paired' }
const unlockRequests = new Map();  // code -> { status:'pending'|'approved'|'rejected'|'expired', token|null, tokenExpiresAt|null }

const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 紛らわしい文字除外
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function genOneTimeToken() {
  return crypto.randomBytes(24).toString('hex'); // 48文字
}

/**
 * ==== ルート & ヘルスチェック ====
 */
app.get('/', (_, res) => res.send('LINE Bot is running!'));

/**
 * ==== Webhook（手動署名検証・Verify 対応）====
 * - ここは raw ボディ必須。グローバルの express.json() は絶対に使わない。
 * - LINE Developers の「接続確認（Verify）」は署名・ボディが無い事があるので 200 を返して通す。
 */
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.get('x-line-signature');
    const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    const bodyString = buf.toString('utf8');

    // Verify/空ボディは 200 で返す（設定確認用）
    if (!signature || bodyString.length === 0) {
      console.log('[webhook] verify or empty body -> 200');
      return res.sendStatus(200);
    }

    // 署名検証
    const ok = line.validateSignature(bodyString, config.channelSecret, signature);
    if (!ok) {
      console.warn('[webhook] invalid signature');
      return res.sendStatus(401);
    }

    // JSON パース
    let json;
    try {
      json = JSON.parse(bodyString);
    } catch (e) {
      console.warn('[webhook] JSON parse failed -> 200');
      return res.sendStatus(200);
    }

    const events = Array.isArray(json.events) ? json.events : [];
    await Promise.all(events.map(handleEvent));

    return res.sendStatus(200);
  } catch (e) {
    console.error('webhook error', e);
    // 本番運用では 500 でもOKだが、Verify を通すため 200 にしておく
    return res.sendStatus(200);
  }
});

/**
 * ==== イベント処理 ====
 */
async function handleEvent(event) {
  // テキストメッセージ
  if (event.type === 'message' && event.message?.type === 'text') {
    const text = (event.message.text || '').trim();

    // pair CODE
    const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
    if (m && event.source?.userId) {
      const code = m[1].toUpperCase();
      const rec = pairCodes.get(code);
      if (!rec) return reply(event.replyToken, `コード ${code} は見つかりません。アプリから新しいコードを発行してください。`);
      if (rec.expiresAt < now()) return reply(event.replyToken, `コード ${code} の有効期限が切れています。再発行してください。`);
      rec.userId = event.source.userId;
      rec.status = 'paired';
      pairCodes.set(code, rec);
      return reply(event.replyToken, `ペアリング完了しました ✅（コード：${code}）`);
    }

    if (/^help$/i.test(text)) {
      return reply(
        event.replyToken,
        '使い方：\n1) アプリでコード発行\n2) ここに「pair CODE」を送信\n3) 解除申請が来たら承認/拒否ボタンで応答'
      );
    }

    // 既定はエコー
    return client.replyMessage(event.replyToken, { type: 'text', text });
  }

  // 承認/拒否 postback
  if (event.type === 'postback') {
    const data = event.postback?.data || '';
    const ap = /^approve:([A-Z0-9]{4,10})$/i.exec(data);
    const rj = /^reject:([A-Z0-9]{4,10})$/i.exec(data);

    if (ap) {
      const code = ap[1].toUpperCase();
      const reqRec = unlockRequests.get(code);
      if (!reqRec) return;
      reqRec.status = 'approved';
      if (!reqRec.token) {
        reqRec.token = genOneTimeToken();
        reqRec.tokenExpiresAt = now() + minutes(10); // 5〜10分で調整可
      }
      unlockRequests.set(code, reqRec);
      if (event.source?.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。解除は10分以内に実行されます。' });
      }
      return;
    }

    if (rj) {
      const code = rj[1].toUpperCase();
      const reqRec = unlockRequests.get(code);
      if (!reqRec) return;
      reqRec.status = 'rejected';
      reqRec.token = null;
      reqRec.tokenExpiresAt = null;
      unlockRequests.set(code, reqRec);
      if (event.source?.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
      }
      return;
    }
  }
}

function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

/**
 * ==== 追加API（JSONが必要なものだけ個別にパーサ）====
 */

// A) ペアコード発行（GET/POSTどちらでも）
function issuePair(req, res) {
  const code = genCode(6);
  const expiresAt = now() + minutes(30); // 30分有効
  pairCodes.set(code, { code, expiresAt, userId: null, status: 'waiting' });
  res.json({ code, expiresAt });
}
app.get('/pair/create', issuePair);
app.post('/pair/create', issuePair);

// B) 解除リクエスト → 承認/拒否テンプレをPush
app.post('/unlock/request', express.json(), async (req, res) => {
  const code = (req.body?.code || '').toString().toUpperCase();
  if (!code) return res.status(400).json({ error: 'code is required' });

  const rec = pairCodes.get(code);
  if (!rec) return res.status(404).json({ error: 'pair code not found' });
  if (rec.expiresAt < now()) return res.status(400).json({ error: 'pair code expired' });
  if (!rec.userId) return res.status(400).json({ error: 'not paired yet' });

  unlockRequests.set(code, { status: 'pending', token: null, tokenExpiresAt: null });

  await client.pushMessage(rec.userId, {
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
});

// C) ポーリング：承認済みならワンタイムトークンを1回だけ返す
app.get('/unlock/poll', (req, res) => {
  const code = (req.query.code || '').toString().toUpperCase();
  if (!code) return res.status(400).json({ error: 'code is required' });

  const reqRec = unlockRequests.get(code);
  if (!reqRec) return res.json({ status: 'none' });
  if (reqRec.status === 'rejected') return res.json({ status: 'rejected' });
  if (reqRec.status === 'pending') return res.json({ status: 'pending' });

  // approved
  if (!reqRec.token) {
    reqRec.token = genOneTimeToken();
    reqRec.tokenExpiresAt = now() + minutes(10);
  }
  if (reqRec.tokenExpiresAt < now()) {
    reqRec.status = 'expired';
    unlockRequests.set(code, reqRec);
    return res.json({ status: 'expired' });
  }

  const token = reqRec.token;
  reqRec.token = null; // 1回限り
  unlockRequests.set(code, reqRec);
  res.json({ status: 'approved', token, tokenExpiresAt: reqRec.tokenExpiresAt });
});

/**
 * ==== 起動 ====
 */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`listening on ${port}`);
});
