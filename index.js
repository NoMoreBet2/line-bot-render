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
  process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
  process.on('uncaughtException', (e) => console.error('uncaughtException', e));

  // Firebase
  const sa = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  try {
    if (sa) {
      admin.initializeApp({ credential: admin.credential.cert(JSON.parse(sa)) });
      console.log('Firebase initialized with service account JSON');
    } else {
      admin.initializeApp();
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
function genOneTimeToken() {
  return crypto.randomBytes(24).toString('hex');
}

// ---- webhook（LINE）----
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

// ---- メインイベントハンドラ ----
async function handleEvent(event) {
  if (event.type === 'message' && event.message?.type === 'text') {
    const text = (event.message.text || '').trim();

    // ===== ペアリング（pair CODE） =====
    const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
    if (m && event.source?.userId) {
      const code = m[1].toUpperCase();
      const partnerLineUserId = event.source.userId;

      try {
        const dbx = getDb();

        // 1) 逆引き：/codes/{code} を一発参照
        const codeRef = dbx.collection('codes').doc(code);
        const codeSnap = await codeRef.get();

        let appUserUid = null;
        let codeMeta = null;

        if (codeSnap.exists) {
          codeMeta = codeSnap.data() || {};
          appUserUid = codeMeta.appUserUid || null;
          const exp = codeMeta.expiresAt || 0;
          const st = codeMeta.status || 'waiting';

          if (!appUserUid) {
            // フォールバック：古い発行フローで appUserUid 未保存の場合は検索で補完
            const cg = await dbx.collectionGroup('pairing_status')
              .where('code', '==', code).limit(1).get();
            if (!cg.empty) {
              const path = cg.docs[0].ref.path; // users/{uid}/pairing_status/{code}
              appUserUid = path.split('/')[1];
            }
          }

          if (!appUserUid) return reply(event.replyToken, `コード ${code} は無効です。`);
          if (exp && exp < now()) return reply(event.replyToken, `コード ${code} の有効期限が切れています。`);
          if (st === 'paired') return reply(event.replyToken, `このコードは既に使用済みです。`);
        } else {
          // 逆引きが無い場合のフォールバック：collectionGroup 検索
          const cg = await dbx.collectionGroup('pairing_status')
            .where('code', '==', code).limit(1).get();
          if (cg.empty) return reply(event.replyToken, `コード ${code} は見つかりません。`);
          const path = cg.docs[0].ref.path;
          appUserUid = path.split('/')[1];
          codeMeta = { expiresAt: now() + minutes(5), status: 'waiting' }; // 仮
        }

        // 2) 本体(users/{uid}/pairing_status/{code})を paired に、/codes/{code} も同期
        const userRef = dbx.collection('users').doc(appUserUid)
          .collection('pairing_status').doc(code);

        const batch = dbx.batch();
        batch.set(userRef, {
          code,
          expiresAt: codeMeta.expiresAt || (now() + minutes(30)),
          status: 'paired',
          pairedAt: admin.firestore.FieldValue.serverTimestamp(),
          partnerLineUserId: partnerLineUserId
        }, { merge: true });

        // 逆引きdocが無い/古い場合も作成・更新して同期
        const codePayload = {
          appUserUid: appUserUid,
          status: 'paired',
          pairedAt: admin.firestore.FieldValue.serverTimestamp(),
          lineUserId: partnerLineUserId
        };
        if (codeMeta.expiresAt) codePayload.expiresAt = codeMeta.expiresAt;
        batch.set(codeRef, codePayload, { merge: true });

        await batch.commit();
        return reply(event.replyToken, `ペアリング完了しました ✅（コード：${code}）`);
      } catch (error) {
        console.error('pair webhook error', error);
        return reply(event.replyToken, 'エラーが発生しました。');
      }
    }

    // ヘルプ
    if (/^help$/i.test(text)) {
      return reply(event.replyToken, '使い方：\n1) アプリでコード発行\n2) ここに「pair CODE」を送信\n3) 解除申請が来たら承認/拒否で応答');
    }

    // エコー
    return reply(event.replyToken, text);
  }

  // ===== postback（解除の承認/拒否）=====
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

// ---- 返信ユーティリティ ----
function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

// ---- コード発行API（推奨：POSTでuidを受け取る）----
// クライアント: bodyに { appUserUid } を入れて呼ぶ
app.post('/pair/create', express.json(), async (req, res) => {
  const appUserUid = (req.body?.appUserUid || '').toString().trim();
  if (!appUserUid) return res.status(400).json({ error: 'appUserUid is required' });

  const code = genCode(6).toUpperCase();
  const expiresAt = now() + minutes(30);

  try {
    const dbx = getDb();

    // 逆引き：/codes/{code}
    await dbx.collection('codes').doc(code).set({
      appUserUid,
      expiresAt,
      status: 'waiting',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    // （任意）サーバーでもユーザー配下を作っておきたい場合は以下を有効化
    // await dbx.collection('users').doc(appUserUid)
    //   .collection('pairing_status').doc(code)
    //   .set({ code, expiresAt, status: 'waiting', createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

    res.json({ code, expiresAt });
  } catch (e) {
    console.error('Failed to create pair code:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

// ---- 旧フロー互換: GETでも発行（uidが無いので逆引きは最小）----
app.get('/pair/create', async (_, res) => {
  const code = genCode(6).toUpperCase();
  const expiresAt = now() + minutes(30);
  try {
    const dbx = getDb();
    // appUserUid が無いのでまずは逆引きの器だけ用意（pair時に補完フォールバックあり）
    await dbx.collection('codes').doc(code).set({
      expiresAt,
      status: 'waiting',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    res.json({ code, expiresAt });
  } catch (e) {
    console.error('Failed to create pair code:', e);
    res.status(500).json({ error: 'Failed to issue a pair code.' });
  }
});

// ---- 解除申請 API ----
app.post('/unlock/request', express.json(), async (req, res) => {
  const code = (req.body?.code || '').toString().toUpperCase();
  if (!code) return res.status(400).json({ error: 'code is required' });

  try {
    const dbx = getDb();

    // まず逆引きを参照
    const codeSnap = await dbx.collection('codes').doc(code).get();
    if (!codeSnap.exists) return res.status(404).json({ error: 'pair code not found' });

    const cdata = codeSnap.data() || {};
    if ((cdata.expiresAt || 0) < now()) return res.status(400).json({ error: 'pair code expired' });
    if (cdata.status !== 'paired') return res.status(400).json({ error: 'not paired yet' });

    // パートナーLINE ID（承認依頼の送信先）
    let partnerLineUserId = cdata.lineUserId || null;

    // 無ければユーザー配下から補完
    if (!partnerLineUserId && cdata.appUserUid) {
      const uref = dbx.collection('users').doc(cdata.appUserUid).collection('pairing_status').doc(code);
      const usnap = await uref.get();
      if (usnap.exists) partnerLineUserId = (usnap.data() || {}).partnerLineUserId || null;
    }

    await dbx.collection('unlock_requests').doc(code).set({
      status: 'pending', token: null, tokenExpiresAt: null, requestedAt: now()
    });

    if (partnerLineUserId) {
      await client.pushMessage(partnerLineUserId, {
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
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('Unlock request failed:', e);
    res.status(500).json({ error: 'Failed to process unlock request.' });
  }
});

// ---- 解除ポーリング ----
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
