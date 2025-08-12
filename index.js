'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const crypto = require('crypto');
const admin = require('firebase-admin');

// Firebase Admin SDKを初期化
admin.initializeApp({
  credential: admin.credential.applicationDefault()
});
const db = admin.firestore();

const app = express();

// LINE SDKを初期化
const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};
const client = new line.Client(config);

// ヘルパー関数
const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function genCode(len = 6) {
  return Array.from({ length: len }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join('');
}
function genOneTimeToken() {
  return crypto.randomBytes(24).toString('hex');
}

// ルート
app.get('/', (_, res) => res.send('LINE Bot is running!'));

// Webhook
app.post('/webhook', express.raw({ type: '*/*' }), async (req, res) => {
    try {
        const signature = req.get('x-line-signature');
        const bodyString = req.body.toString('utf8');
        if (!signature || bodyString.length === 0) return res.sendStatus(200);
        if (!line.validateSignature(bodyString, config.channelSecret, signature)) return res.sendStatus(401);
        const json = JSON.parse(bodyString);
        await Promise.all(json.events.map(handleEvent));
        return res.sendStatus(200);
    } catch (e) {
        console.error('webhook error', e);
        return res.sendStatus(200);
    }
});

// イベント処理
async function handleEvent(event) {
    // テキストメッセージ
    if (event.type === 'message' && event.message?.type === 'text') {
        const text = (event.message.text || '').trim();
        const m = /^pair\s+([A-Z0-9]{4,10})$/i.exec(text);
        if (m && event.source?.userId) {
            const code = m[1].toUpperCase();
            try {
                const docRef = db.collection('pairing_status').doc(code);
                const doc = await docRef.get();
                if (!doc.exists) return reply(event.replyToken, `コード ${code} は見つかりません。`);
                if (doc.data().expiresAt < now()) return reply(event.replyToken, `コード ${code} の有効期限が切れています。`);
                await docRef.update({ userId: event.source.userId, status: 'paired' });
                return reply(event.replyToken, `ペアリング完了しました ✅（コード：${code}）`);
            } catch (error) {
                console.error("Firestore update failed:", error);
                return reply(event.replyToken, "エラーが発生しました。");
            }
        }
    }

    // 承認/拒否 postback
    if (event.type === 'postback') {
        const data = event.postback?.data || '';
        const ap = /^approve:([A-Z0-9]{4,10})$/i.exec(data);
        const rj = /^reject:([A-Z0-9]{4,10})$/i.exec(data);

        if (ap) {
            const code = ap[1].toUpperCase();
            try {
                const token = genOneTimeToken();
                await db.collection('unlock_requests').doc(code).update({
                    status: 'approved',
                    token: token,
                    tokenExpiresAt: now() + minutes(10)
                });
                if (event.source?.userId) {
                    await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。解除は10分以内に実行されます。' });
                }
            } catch (error) { console.error("Approval failed:", error); }
            return;
        }

        if (rj) {
            const code = rj[1].toUpperCase();
            try {
                await db.collection('unlock_requests').doc(code).update({
                    status: 'rejected',
                    token: null,
                    tokenExpiresAt: null
                });
                if (event.source?.userId) {
                    await client.pushMessage(event.source.userId, { type: 'text', text: '解除申請を拒否しました。' });
                }
            } catch (error) { console.error("Rejection failed:", error); }
            return;
        }
    }
}

function reply(replyToken, text) {
    return client.replyMessage(replyToken, { type: 'text', text });
}

// ===== 追加API =====

// A) ペアコード発行
async function issuePair(req, res) {
    const code = genCode(6);
    const expiresAt = now() + minutes(30);
    try {
        await db.collection('pairing_status').doc(code).set({
            code: code,
            expiresAt: expiresAt,
            userId: null,
            status: 'waiting'
        });
        res.json({ code, expiresAt });
    } catch (error) {
        console.error("Failed to create pair code:", error);
        res.status(500).json({ error: "Failed to issue a pair code." });
    }
}
app.get('/pair/create', issuePair);
app.post('/pair/create', issuePair);

// B) 解除リクエスト
app.post('/unlock/request', express.json(), async (req, res) => {
    const code = (req.body?.code || '').toString().toUpperCase();
    if (!code) return res.status(400).json({ error: 'code is required' });

    try {
        const pairDoc = await db.collection('pairing_status').doc(code).get();
        if (!pairDoc.exists) return res.status(404).json({ error: 'pair code not found' });
        
        const pairData = pairDoc.data();
        if (pairData.expiresAt < now()) return res.status(400).json({ error: 'pair code expired' });
        if (pairData.status !== 'paired' || !pairData.userId) return res.status(400).json({ error: 'not paired yet' });

        // Firestoreに解除申請ドキュメントを作成
        await db.collection('unlock_requests').doc(code).set({
            status: 'pending',
            token: null,
            tokenExpiresAt: null,
            requestedAt: now()
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
    } catch (error) {
        console.error("Unlock request failed:", error);
        res.status(500).json({ error: "Failed to process unlock request." });
    }
});

// C) ポーリング
app.get('/unlock/poll', async (req, res) => {
    const code = (req.query.code || '').toString().toUpperCase();
    if (!code) return res.status(400).json({ error: 'code is required' });
    
    try {
        const doc = await db.collection('unlock_requests').doc(code).get();
        if (!doc.exists) return res.json({ status: 'none' });

        const reqRec = doc.data();
        if (reqRec.status === 'rejected') return res.json({ status: 'rejected' });
        if (reqRec.status === 'pending') return res.json({ status: 'pending' });
        
        if (reqRec.status === 'approved') {
            if (reqRec.tokenExpiresAt < now()) {
                await doc.ref.update({ status: 'expired' });
                return res.json({ status: 'expired' });
            }
            const token = reqRec.token;
            // トークンを一度返したら無効化する
            await doc.ref.update({ token: null });
            return res.json({ status: 'approved', token, tokenExpiresAt: reqRec.tokenExpiresAt });
        }

        return res.json({ status: reqRec.status });
    } catch (error) {
        console.error("Polling failed:", error);
        res.status(500).json({ error: "Polling failed." });
    }
});

// ==== 起動 ====
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`listening on ${port}`);
});