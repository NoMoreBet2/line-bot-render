'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto'); // cryptoモジュールはここにあるので追加不要

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
// express.json() はWebhookの後で読み込むので、ここでは削除

// ===== LINE =====
const client = new line.Client(lineConfig);

// ===== Firebase Auth MW =====
// ★ 修正点1-A: firebaseAuthMiddleware は /ack-ping で使用されなくなるため、そのまま残しておくか削除するかはお好みで。
//             他のAPIで使う場合は残し、使わないなら削除またはコメントアウトして良い。
//             今回は /ack-ping から削除するだけで、定義自体は残します。
const firebaseAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const idToken = authHeader.substring('Bearer '.length);
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.auth = { uid: decoded.uid, email: decoded.email }; // emailも取得するように変更
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
  // `ts` が admin.firestore.Timestamp か、すでにDateオブジェクトかを判別
  const d = (ts && typeof ts.toDate === 'function') ? ts.toDate() : ts;
  
  // toLocaleStringを使用して、常に日本のタイムゾーンでフォーマットする
  const dateTimeString = d.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false // 24時間表記
  });
  // toLocaleStringは "2025/09/04 16:27" のような形式を返すため、
  // これを "2025-09-04-16-27" の形式に置換する
  return dateTimeString.replace(/\//g, '-').replace(' ', '-');
}

function shortId(uuid) {
  return uuid.replace(/-/g, '').slice(0, 6).toUpperCase();
}

// 修正：makeDocId はタイムスタンプではなく、既に日本時間でフォーマットされた日付文字列を受け取るように変更
function makeDocId(formattedTsStr, uuid) {
  return `${formattedTsStr}-${shortId(uuid)}`;
}

function genCode(len = 5) { // デフォルトの長さを5に変更
  // 10000から99999までのランダムな整数を生成し、文字列として返す
  return String(Math.floor(Math.random() * 90000) + 10000);
}

function reply(replyToken, text) {
  return client.replyMessage(replyToken, { type: 'text', text });
}

// ===== LINE webhook =====
// express.json()より先に定義して、生のbodyをLINEミドルウェアが検証できるようにする
app.post('/webhook', line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  try {
    await Promise.all((req.body.events || []).map(handleEvent));
  } catch (e) {
      console.error('[webhook] error', e);
  }
});

// 修正点：express.json() をここに移動
// これ以降のAPIルートでは、JSONボディが自動的にオブジェクトにパースされる
app.use(express.json());


async function handleEvent(event) {
  if (event.type === 'message' && event.message?.type === 'text' && event.source?.userId) {
        const text = (event.message.text || '').trim();
        const partnerLineUserId = event.source.userId;
        let pairingCode = null;

        if (/^\d{5}$/.test(text)) {
            pairingCode = text;
        } else {
            const match = /^pair\s+([A-Z0-9]{5,10})$/i.exec(text);
            if (match) {
                pairingCode = match[1].toUpperCase();
            }
        }

        if (pairingCode) {
            try {
                const dbx = getDb();
                const usersQuery = await dbx.collection('users')
                    .where('pairingStatus.code', '==', pairingCode)
                    .limit(1)
                    .get();

                if (usersQuery.empty) {
                    return reply(event.replyToken, `コード ${pairingCode} は無効です。`);
                }
                
                const userDoc = usersQuery.docs[0];
                const pairingStatus = userDoc.data().pairingStatus || {};
                
                const expiresAt = pairingStatus.expiresAt;
                let expiresAtMillis = 0;

                if (expiresAt && typeof expiresAt.toMillis === 'function') {
                    // FirestoreのTimestamp型の場合
                    expiresAtMillis = expiresAt.toMillis();
                } else if (typeof expiresAt === 'number') {
                    // ただの数値（エポックミリ秒）の場合
                    expiresAtMillis = expiresAt;
                }
                
                if (!expiresAt || expiresAtMillis < Date.now()) {
                    return reply(event.replyToken, `コード ${pairingCode} は有効期限切れです。`);
                }

                const partnerProfile = await client.getProfile(partnerLineUserId);
                await userDoc.ref.update({
                    'pairingStatus.status': 'paired',
                    'pairingStatus.partnerLineUserId': partnerLineUserId,
                    'pairingStatus.partnerDisplayName': partnerProfile.displayName,
                    'pairingStatus.pairedAt': admin.firestore.FieldValue.serverTimestamp(),
                });

                return reply(event.replyToken, `ペアリングが完了しました ✅`);

            } catch (error) {
                console.error('[webhook/pair] error', error);
                return reply(event.replyToken, 'エラーが発生しました。');
            }
        }
    }

    // --- 2. ポストバックイベントの処理 (変更なし) ---
    if (event.type === 'postback') {
        const data = event.postback?.data || '';
        const ap = /^approve:(.+)$/i.exec(data);
        const rj = /^reject:(.+)$i/.exec(data);
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
    const code = String(Math.floor(Math.random() * 90000) + 10000); 
    const expiresAt = now() + minutes(30);

    try {
        const dbx = getDb();
        const userRef = dbx.collection('users').doc(appUserUid);
        await userRef.update({
            'pairingStatus.code': code,
            'pairingStatus.expiresAt': admin.firestore.Timestamp.fromMillis(expiresAt),
            'pairingStatus.status': 'waiting',
        });
        res.json({ code, expiresAt });
    } catch (e) {
        console.error('[pair/create] failed:', e);
        res.status(500).json({ error: 'Failed to issue a pair code.' });
    }
});

app.post('/request-partner-unlock', firebaseAuthMiddleware, async (req, res) => {
  // ユーザーのemailとuidを認証ミドルウェアから受け取る
  const uid = req.auth.uid;
  const email = req.auth.email;
  const dbx = getDb();

  try {
    // テスト用メールアドレスの場合の特別処理
    if (email === "nomorebettest@gmail.com") {
      const userRef = dbx.collection('users').doc(uid);
      await userRef.update({
        'blockStatus.isActive': false,
        'blockStatus.activatedAt': null,
      });
      console.log(`[test-unlock] テスト用アカウントのブロックを自動解除しました: user=${uid}`);
      return res.json({ ok: true, message: 'Auto-unlocked for test user.' });
    }

    // 通常ユーザーの処理
    const userRef = dbx.collection('users').doc(uid);
    const userSnap = await userRef.get();
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


// 強制解除の通知API
app.post('/force-unlock-notify', firebaseAuthMiddleware, async (req, res) => {
  const uid = req.auth.uid;
  try {
    const dbx = getDb();
    const userSnap = await dbx.collection('users').doc(uid).get();
    if (!userSnap.exists) {
      // ユーザーが見つからない場合は何もしない
      return res.status(4404).json({ error: 'User not found' });
    }

    const pairingStatus = userSnap.data().pairingStatus || {};
    const partnerLineUserId = pairingStatus.partnerLineUserId;

    // パートナーが設定されていれば、LINEで通知を送信
    if (partnerLineUserId && pairingStatus.status === 'paired') {
      await client.pushMessage(partnerLineUserId, {
        type: 'text',
        text: '【nomoreBET お知らせ】\nパートナーが強制解除機能を使用しました。'
      });
      console.log(`[force-unlock] 通知を送信しました: user=${uid}, partner=${partnerLineUserId}`);
    }
    
    res.json({ ok: true });
  } catch (e) {
    console.error(`[force-unlock-notify] failed for user ${uid}:`, e);
    res.status(500).json({ error: 'Failed to send notification.' });
  }
});

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
// ▼▼▼ 修正点2-A: firebaseAuthMiddleware を削除 ▼▼▼
app.post('/ack-ping', async (req, res) => { // ★ ここから firebaseAuthMiddleware を削除 ★
  const uid = req.body?.uid;         // アプリから送られてくる uid を取得
  const fcmTokenFromApp = req.body?.fcmToken; // アプリから送られてくる fcmToken を取得
  const pingId = req.body?.pingId;

  // ▼▼▼ 修正点2-B: 送信された認証情報の基本的な検証 ▼▼▼
  if (!pingId || !uid || !fcmTokenFromApp) {
    console.warn('[ack-ping] 400 Bad Request: Missing pingId, uid, or fcmToken. body:', req.body);
    return res.status(400).json({ error: 'pingId, uid, and fcmToken are required' });
  }

  try {
    const dbx = getDb();
    const userRef = dbx.collection('users').doc(uid);
    const userSnap = await userRef.get();

    // ユーザーが存在しない場合
    if (!userSnap.exists) {
      console.warn(`[ack-ping] User not found for uid=${uid}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const deviceStatus = userSnap.data()?.deviceStatus || {};
    const storedFcmToken = deviceStatus.fcmToken;

    // ▼▼▼ 修正点2-C: Firestoreに保存されているFCMトークンとの比較検証 ▼▼▼
    if (storedFcmToken !== fcmTokenFromApp) {
      console.warn(`[ack-ping] Unauthorized: FCM token mismatch for uid=${uid}. App token=${fcmTokenFromApp}, Stored token=${storedFcmToken}`);
      // セキュリティのため、詳細なエラーはクライアントに返さない方が良い場合もあるが、デバッグのため暫定的に出す
      return res.status(403).json({ error: 'Unauthorized: Invalid device token' });
    }
    // ▲▲▲ 認証情報の検証終わり ▲▲▲


    // 以下、既存のACK処理ロジック (変更なし)
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


// パートナーに約束の通知を送信するAPI
app.post('/api/sendPromiseNotification', firebaseAuthMiddleware, async (req, res) => {
  // firebaseAuthMiddlewareによって、リクエストの認証とuidの取得が自動的に行われます。
  const uid = req.auth.uid;
  const dbx = getDb();

  try {
    const userSnap = await dbx.collection('users').doc(uid).get();
    if (!userSnap.exists) {
      console.warn(`[promise-notify] User not found for uid=${uid}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const pairingStatus = userSnap.data().pairingStatus || {};
    const partnerLineUserId = pairingStatus.partnerLineUserId;
    const promise = pairingStatus.promise; // Firestoreから約束の内容を取得

    // パートナーが設定されておらず、約束も存在しない場合はエラーを返す
    if (!partnerLineUserId || pairingStatus.status !== 'paired' || !promise) {
      console.warn(`[promise-notify] Invalid request for uid=${uid}. Missing partner or promise.`);
      return res.status(400).json({ error: 'Partner is not configured or promise is missing.' });
    }

    // LINEメッセージを作成
    const message = {
      type: 'text',
      text: `【nomoreBET お知らせ】\nパートナーが新しい約束を登録しました：\n\n「${promise}」`,
    };

    // LINEにメッセージをプッシュ送信
    await client.pushMessage(partnerLineUserId, message);
    
    console.log(`[promise-notify] 通知を送信しました: user=${uid}, partner=${partnerLineUserId}`);
    res.json({ ok: true });

  } catch (e) {
    console.error(`[promise-notify] failed for user ${uid}:`, e);
    res.status(500).json({ error: 'Failed to send notification.' });
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
           // lastHeartbeatではなく、Pingの送信時刻 (sentAt) を取得
            const sentAt = ping.data().sentAt;
            let timeString = "一定時間";

            if (sentAt) {
              const date = sentAt.toDate();
              // タイムスタンプを「月日 時:分」の形式に変換
              timeString = new Intl.DateTimeFormat('ja-JP', {
                month: 'numeric',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZone: 'Asia/Tokyo'
              }).format(date);
            }
            
            try {
              await client.pushMessage(partnerLineUserId, {
                type: 'text',
                // 文面を元の状態に戻しました
                text:
                  `【nomoreBET お知らせ】\n` +
                  `パートナーの端末から、ブロック機能が有効であることを示す定期的な信号が途絶えています。\n\n` +
                  `${timeString}ごろ、ブロック機能が一時的に無効になっていた可能性があります。パートナーの方にご確認ください。\n\n` +
                  `※端末の電源OFF、圏外、設定変更などが原因の場合もあります。`
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
      const japanFormattedNow = formatTs(nowTs); 
      const docId = makeDocId(japanFormattedNow, pingUuid);
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
        // ▼▼▼ 修正点3-A: FCMメッセージのデータペイロードに `uid` を追加 ▼▼▼
        await admin.messaging().send({
          token: fcmToken,
          data: { 
            action: 'ping_challenge', 
            pingId: pingUuid,
            uid: uid // ★ ここでユーザーIDを追加 ★
          },
          android: { priority: 'high', ttl: PING_TTL_MS },
        });
        // ▲▲▲ 修正点3-A 終わり ▲▲▲

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