'use strict';

const functions = require('firebase-functions');
const admin = require('firebase-admin');
const line = require('@line/bot-sdk');
const crypto = require('crypto');

// 初期化
admin.initializeApp();
const db = admin.firestore();

// ===== 設定 (環境変数) =====
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN || functions.config().line?.access_token,
  channelSecret: process.env.CHANNEL_SECRET || functions.config().line?.channel_secret,
};

const CRON_SECRET = process.env.CRON_SECRET || functions.config().cron?.secret || '';
// その他の定数
const STALE_MINUTES = 20;
const LONG_OFFLINE_MIN = 1440;
const PING_TTL_MS = 2 * 60 * 1000;
const PING_ACK_WINDOW_MS = PING_TTL_MS;
const FCM_FAIL_THRESHOLD = 3;

// LINE Client
const client = new line.Client(lineConfig);

// ============================================================
//  ヘルパー関数
// ============================================================
const getUid = (context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
  }
  return context.auth.uid;
};

const now = () => Date.now();
const minutes = (n) => n * 60 * 1000;

function formatTs(ts) {
  const d = (ts && typeof ts.toDate === 'function') ? ts.toDate() : ts;
  return d.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).replace(/\//g, '-').replace(' ', '-');
}

function makeDocId(formattedTsStr, uuid) {
  return `${formattedTsStr}-${uuid.replace(/-/g, '').slice(0, 6).toUpperCase()}`;
}

// ============================================================
//  1. ユーザー管理・初期化
// ============================================================
exports.initializeUser = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { email, displayName, photoUrl, role } = data;

  const userRef = db.collection('users').doc(uid);
  const snap = await userRef.get();
  const nowTs = admin.firestore.FieldValue.serverTimestamp();

  if (!snap.exists) {
    // 新規作成
    await userRef.set({
      userInfo: {
        email: email || '',
        displayName: displayName || '',
        photoUrl: photoUrl || '',
        role: role || 'individual',
        registeredAt: nowTs
      },
      blockStatus: {
        isActive: false,
        activatedAt: null,
        deactivatedAt: null,
        unlockMethod: null,
        expiresAt: null,
        unlockDays: null,
        deactivatedReason: null
      },
      heartbeat: { lastHeartbeat: null },
      pairingStatus: {
        status: 'unpaired',
        code: null,
        partnerUid: null,
        authProvider: null,
        expiresAt: null,
        pairedAt: null,
        unpairedAt: null
      },
      consents: {
        accessibilityAgreedAt: null,
        deviceAdminAgreedAt: null,
        accessibilityRevokedAt: null,
        deviceAdminRevokedAt: null
      },
      deviceStatus: { fcmToken: null }
    });
  } else {
    // 既存更新（重要データは触らない）
    await userRef.set({
      userInfo: {
        email: email || '',
        displayName: displayName || '',
        photoUrl: photoUrl || '',
        role: role || 'individual'
      }
    }, { merge: true });
  }
  return { success: true };
});

// ============================================================
//  2. ブロック状態管理
// ============================================================
exports.enableBlocking = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  await db.collection('users').doc(uid).set({
    blockStatus: {
      isActive: true,
      activatedAt: admin.firestore.FieldValue.serverTimestamp()
    },
    heartbeat: {
      lastHeartbeat: admin.firestore.FieldValue.serverTimestamp()
    }
  }, { merge: true });
  return { success: true };
});

exports.requestUnlock = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const reason = data.reason || 'normal';
  
  await db.collection('users').doc(uid).set({
    blockStatus: {
      isActive: false,
      deactivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deactivatedReason: reason
    }
  }, { merge: true });
  return { success: true };
});

exports.setUnlockRule = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { unlockMethod, unlockDays, expiresAtMs } = data;

  let expiresAt = null;
  if (expiresAtMs) {
    expiresAt = admin.firestore.Timestamp.fromMillis(Number(expiresAtMs));
  }

  const updates = { 'blockStatus.unlockMethod': unlockMethod };
  if (unlockDays !== undefined && unlockDays !== null) {
    updates['blockStatus.unlockDays'] = unlockDays;
  }
  if (expiresAt !== null) {
    updates['blockStatus.expiresAt'] = expiresAt;
    updates['pairingStatus.expiresAt'] = expiresAt;
  }

  await db.collection('users').doc(uid).update(updates);
  return { success: true };
});

exports.updateBlockSettings = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  await db.collection('users').doc(uid).set(
    { blockStatus: data },
    { merge: true }
  );
  return { success: true };
});

// ============================================================
//  3. ペアリング管理
// ============================================================
exports.createPairingCode = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const genCode = () => String(Math.floor(Math.random() * 90000) + 10000);
  
  let code = genCode();
  let tries = 0;
  while (tries < 5) {
    const snap = await db.collection('pairingCodes').doc(code).get();
    if (!snap.exists) break;
    code = genCode();
    tries++;
  }
  if (tries >= 5) throw new functions.https.HttpsError('aborted', 'Failed to generate code');

  const expiresAtMs = Date.now() + (30 * 60 * 1000);
  const expiresAt = admin.firestore.Timestamp.fromMillis(expiresAtMs);

  await db.collection('pairingCodes').doc(code).set({
    ownerUid: uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: expiresAt
  });

  await db.collection('users').doc(uid).set({
    pairingStatus: {
      status: 'waiting',
      code: code,
      expiresAt: expiresAt
    }
  }, { merge: true });

  return { code, expiresAt: Math.floor(expiresAtMs / 1000) };
});

exports.acceptPairingCode = functions.https.onCall(async (data, context) => {
  const partnerUid = getUid(context);
  const code = String(data.code || '').trim();

  if (!/^\d{5}$/.test(code)) throw new functions.https.HttpsError('invalid-argument', 'Bad code');

  const codeRef = db.collection('pairingCodes').doc(code);

  try {
    await db.runTransaction(async (tx) => {
      const codeSnap = await tx.get(codeRef);
      if (!codeSnap.exists) throw new Error('invalid');

      const { ownerUid, expiresAt } = codeSnap.data();
      if (!ownerUid) throw new Error('invalid');
      if (ownerUid === partnerUid) throw new Error('self_pair');

      const expMs = expiresAt?.toMillis() || 0;
      if (Date.now() > expMs) throw new Error('expired');

      const actorRef = db.collection('users').doc(ownerUid);
      const partnerRef = db.collection('users').doc(partnerUid);

      const [aSnap, pSnap] = await Promise.all([tx.get(actorRef), tx.get(partnerRef)]);
      const aPair = aSnap.data()?.pairingStatus || {};
      const pPair = pSnap.data()?.pairingStatus || {};

      if (aPair.status === 'paired' && aPair.partnerUid !== partnerUid) throw new Error('actor_already_paired');
      if (pPair.status === 'paired' && pPair.partnerUid !== ownerUid) throw new Error('partner_already_paired');

      const nowTs = admin.firestore.FieldValue.serverTimestamp();

      tx.set(actorRef, {
        pairingStatus: {
          status: 'paired',
          partnerUid: partnerUid,
          partnerProvider: 'app',
          authProvider: 'app',
          pairedAt: nowTs,
          code: null,
          expiresAt: null
        }
      }, { merge: true });

      tx.set(partnerRef, {
        pairingStatus: {
          status: 'paired',
          partnerUid: ownerUid,
          partnerProvider: 'app',
          authProvider: 'app',
          pairedAt: nowTs,
          code: null,
          expiresAt: null
        }
      }, { merge: true });

      tx.delete(codeRef);
    });
    return { success: true };
  } catch (e) {
    console.error('[acceptPairingCode] failed', e);
    let code = 'internal';
    let msg = 'Pairing failed';
    if (e.message === 'invalid') { code = 'not-found'; msg = 'コードが無効です'; }
    if (e.message === 'expired') { code = 'deadline-exceeded'; msg = '期限切れです'; }
    if (e.message === 'self_pair') { code = 'invalid-argument'; msg = '自分自身とはペアリング不可'; }
    if (e.message.includes('already_paired')) { code = 'already-exists'; msg = '既にペアリング済み'; }
    throw new functions.https.HttpsError(code, msg);
  }
});

exports.unpair = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  try {
    await db.runTransaction(async (tx) => {
      const selfRef = db.collection('users').doc(uid);
      const selfSnap = await tx.get(selfRef);
      if (!selfSnap.exists) throw new functions.https.HttpsError('not-found', 'User not found');

      const selfData = selfSnap.data() || {};
      const selfPair = selfData.pairingStatus || {};
      const partnerUid = selfPair.partnerUid;
      const nowTs = admin.firestore.FieldValue.serverTimestamp();

      tx.set(selfRef, {
        pairingStatus: {
          status: 'unpaired',
          partnerUid: null,
          partnerId: null,
          authProvider: null,
          code: null,
          expiresAt: null,
          unpairedAt: nowTs
        },
        blockStatus: {
          unlockMethod: null,
          unlockDays: null,
          expiresAt: null
        }
      }, { merge: true });

      if (partnerUid) {
        const partnerRef = db.collection('users').doc(partnerUid);
        const partnerSnap = await tx.get(partnerRef);
        if (partnerSnap.exists) {
          const pPair = partnerSnap.data()?.pairingStatus || {};
          if (pPair.status === 'paired' && pPair.partnerUid === uid) {
            tx.set(partnerRef, {
              pairingStatus: {
                status: 'unpaired',
                partnerUid: null,
                partnerId: null,
                authProvider: null,
                code: null,
                expiresAt: null,
                unpairedAt: nowTs
              }
            }, { merge: true });
          }
        }
      }
    });
    return { success: true };
  } catch (e) {
    console.error('[unpair] failed', e);
    throw new functions.https.HttpsError('internal', 'Unpair failed');
  }
});

exports.approveUnlockApp = functions.https.onCall(async (data, context) => {
  const partnerUid = getUid(context);
  const partnerSnap = await db.collection('users').doc(partnerUid).get();
  const pPair = partnerSnap.data()?.pairingStatus || {};

  if (pPair.status !== 'paired' || !pPair.partnerUid) {
    throw new functions.https.HttpsError('failed-precondition', 'Not paired');
  }

  const individualUid = pPair.partnerUid;
  const indRef = db.collection('users').doc(individualUid);
  const indSnap = await indRef.get();
  const indPair = indSnap.data()?.pairingStatus || {};

  if (indPair.status !== 'paired' || indPair.partnerUid !== partnerUid) {
    throw new functions.https.HttpsError('permission-denied', 'Pairing mismatch');
  }

  await indRef.set({
    blockStatus: {
      isActive: false,
      activatedAt: null,
      deactivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deactivatedReason: 'partner_approved'
    },
    heartbeat: {
      lastHeartbeat: admin.firestore.FieldValue.serverTimestamp()
    }
  }, { merge: true });

  return { success: true, individualUid };
});

exports.updatePairingSettings = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  await db.collection('users').doc(uid).set(
    { pairingStatus: data },
    { merge: true }
  );
  return { success: true };
});

// ============================================================
//  4. セキュリティ・不正検知
// ============================================================
async function updateRevokedConsents(userRef, isAdminActive, isA11yActive) {
  const snap = await userRef.get();
  const consents = snap.data()?.consents || {};
  const updates = {};

  if (consents.deviceAdminAgreedAt && isAdminActive === false) {
    updates['consents.deviceAdminRevokedAt'] = admin.firestore.FieldValue.serverTimestamp();
  }
  if (consents.accessibilityAgreedAt && isA11yActive === false) {
    updates['consents.accessibilityRevokedAt'] = admin.firestore.FieldValue.serverTimestamp();
  }
  if (Object.keys(updates).length > 0) {
    await userRef.update(updates);
  }
}

exports.reportFraud = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { isDeviceAdminActive, isAccessibilityEnabled } = data;
  const userRef = db.collection('users').doc(uid);
  
  await updateRevokedConsents(userRef, isDeviceAdminActive, isAccessibilityEnabled);

  await userRef.set({
    blockStatus: {
      isActive: false,
      deactivatedAt: admin.firestore.FieldValue.serverTimestamp(),
      deactivatedReason: 'fraud'
    }
  }, { merge: true });
  return { success: true };
});

exports.reportRevokedConsents = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { isDeviceAdminActive, isAccessibilityEnabled } = data;
  const userRef = db.collection('users').doc(uid);
  await updateRevokedConsents(userRef, isDeviceAdminActive, isAccessibilityEnabled);
  return { success: true };
});

exports.saveConsent = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { type } = data; 
  const updates = {};
  if (type === 'accessibility') updates['consents.accessibilityAgreedAt'] = admin.firestore.FieldValue.serverTimestamp();
  else if (type === 'deviceAdmin') updates['consents.deviceAdminAgreedAt'] = admin.firestore.FieldValue.serverTimestamp();

  if (Object.keys(updates).length > 0) {
    await db.collection('users').doc(uid).update(updates);
  }
  return { success: true };
});

// ============================================================
//  5. ハートビート & Ping
// ============================================================
// ============================================================
//  5. ハートビート & Ping
// ============================================================
exports.heartbeat = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { isBlockActive, timingType } = data;
  const nowTs = admin.firestore.FieldValue.serverTimestamp();
  const userRef = db.collection('users').doc(uid);

  // ★ この関数から書かれた印
  const debugMarker = {
    writer: "functions_heartbeat_v1",   // この関数名
    writtenAtMs: Date.now(),            // 関数実行時のクライアント時間(ms)
    timingType: timingType || "unknown" // クライアントから渡された種別
  };

  // users/{uid} ドキュメントの heartbeat フィールドを更新
  await userRef.set({
    heartbeat: {
      lastHeartbeat: nowTs,
      reportedBlockStatus: isBlockActive === true,
      debug: debugMarker              // ★ ここで「この関数から」を刻印
    }
  }, { merge: true });

  // heartbeat_logs 用のID生成
  const d = new Date();
  const docId = d.toLocaleString('ja-JP', { 
    timeZone: 'Asia/Tokyo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit'
  }).replace(/[\/\s:]/g, '-');

  // users/{uid}/heartbeat_logs/{docId} にログを追加
  await userRef.collection('heartbeat_logs').doc(docId).set({
    timestamp: nowTs,
    executedAt: Date.now(),
    timingType: timingType || 'unknown',
    blockStatus: isBlockActive === true,

    // ★ ログ側にも同じ印を残しておく
    writer: "functions_heartbeat_v1"
  });

  return { success: true };
});


exports.ackPing = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { pingId, fcmToken } = data;
  if (!pingId) throw new functions.https.HttpsError('invalid-argument', 'pingId required');

  const userRef = db.collection('users').doc(uid);
  const userSnap = await userRef.get();
  const storedToken = userSnap.data()?.deviceStatus?.fcmToken;
  
  if (fcmToken && storedToken !== fcmToken) {
    console.warn(`[ackPing] Token mismatch for user ${uid}`);
  }

  const q = await userRef.collection('pendingPings').where('id', '==', pingId).limit(1).get();
  if (q.empty) return { success: true, message: 'not found' };

  const doc = q.docs[0];
  const pingData = doc.data();
  if (pingData.status !== 'waiting') return { success: true, message: 'already processed' };

  const sentMs = pingData.sentAt?.toMillis() || 0;
  const deadlineMs = pingData.expiresAt?.toMillis() || (sentMs + PING_ACK_WINDOW_MS);
  const isLate = Date.now() > deadlineMs;
  const newStatus = isLate ? 'replied_late' : 'replied';

  await doc.ref.update({
    status: newStatus,
    repliedAt: admin.firestore.FieldValue.serverTimestamp()
  });
  return { success: true, status: newStatus };
});

// ============================================================
//  ★追加: ブロックリスト操作 (BlockedItemsRepository対応)
// ============================================================
exports.addBlockedItem = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { name, url, appPackageName } = data;

  const newItem = {
    name: name,
    url: url || null,
    appPackageName: appPackageName || null,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };

  const ref = await db.collection('users').doc(uid).collection('blocked_items').add(newItem);
  await ref.update({ id: ref.id });
  return { success: true, id: ref.id };
});

exports.updateBlockedItem = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { itemId, name, url, appPackageName } = data;
  if (!itemId) throw new functions.https.HttpsError('invalid-argument', 'itemId required');

  const updates = {};
  if (name !== undefined) updates.name = name;
  if (url === null) updates.url = admin.firestore.FieldValue.delete();
  else if (url !== undefined) updates.url = url;
  if (appPackageName === null) updates.appPackageName = admin.firestore.FieldValue.delete();
  else if (appPackageName !== undefined) updates.appPackageName = appPackageName;

  await db.collection('users').doc(uid).collection('blocked_items').doc(itemId).update(updates);
  return { success: true };
});

exports.deleteBlockedItem = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { itemId } = data;
  if (!itemId) throw new functions.https.HttpsError('invalid-argument', 'itemId required');

  await db.collection('users').doc(uid).collection('blocked_items').doc(itemId).delete();
  return { success: true };
});

// ============================================================
//  6. LINE Bot & Cron (HTTP Trigger)
// ============================================================
exports.lineWebhook = functions.https.onRequest(async (req, res) => {
  if (req.method !== 'POST') { res.status(405).send('Method Not Allowed'); return; }
  const events = req.body.events || [];
  try {
    await Promise.all(events.map(handleLineEvent));
    res.status(200).send('OK');
  } catch (e) {
    console.error('[lineWebhook] error', e);
    res.status(500).send('Error');
  }
});

async function handleLineEvent(event) {
  if (event.type === 'message' && event.message.type === 'text') {
    const text = event.message.text.trim();
    let pairingCode = null;
    if (/^\d{5}$/.test(text)) pairingCode = text;
    else {
      const m = /^pair\s+([A-Z0-9]{5,10})$/i.exec(text);
      if (m) pairingCode = m[1].toUpperCase();
    }
    if (pairingCode) {
      await finalizePairingByLine(pairingCode, event.source.userId, event.replyToken);
    }
  }
  if (event.type === 'postback') {
    const data = event.postback.data;
    const ap = /^approve:(.+)$/i.exec(data);
    const rj = /^reject:(.+)$/i.exec(data);
    if (ap) {
      const uid = ap[1];
      await db.collection('users').doc(uid).update({
        'blockStatus.isActive': false,
        'blockStatus.activatedAt': null
      });
      if (event.source.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: '承認しました。' });
      }
    } else if (rj && event.source.userId) {
      await client.pushMessage(event.source.userId, { type: 'text', text: '拒否しました。' });
    }
  }
}

async function finalizePairingByLine(code, lineUserId, replyToken) {
  const codeRef = db.collection('pairingCodes').doc(code);
  try {
    await db.runTransaction(async (tx) => {
      const codeSnap = await tx.get(codeRef);
      if (!codeSnap.exists) throw new Error('invalid');
      const { ownerUid, expiresAt } = codeSnap.data();
      if (!ownerUid) throw new Error('invalid');
      if (Date.now() > (expiresAt?.toMillis() || 0)) throw new Error('expired');

      const userRef = db.collection('users').doc(ownerUid);
      const nowTs = admin.firestore.FieldValue.serverTimestamp();

      tx.set(userRef, {
        pairingStatus: {
          status: 'paired',
          partnerUid: lineUserId,
          authProvider: 'line',
          pairedAt: nowTs,
          code: null,
          expiresAt: null
        }
      }, { merge: true });
      tx.delete(codeRef);
    });
    await client.replyMessage(replyToken, { type: 'text', text: 'ペアリングが完了しました。' });
  } catch (e) {
    const msg = e.message === 'expired' ? 'コード期限切れです' : 'コードが無効です';
    await client.replyMessage(replyToken, { type: 'text', text: msg });
  }
}

exports.cronCheckHeartbeats = functions.https.onRequest(async (req, res) => {
  if (req.query.secret !== CRON_SECRET) { res.status(403).send('Forbidden'); return; }
  const nowTs = admin.firestore.Timestamp.now();
  const staleCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(STALE_MINUTES));
  const longOfflineCutoff = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() - minutes(LONG_OFFLINE_MIN));

  try {
    const q = await db.collection('users')
      .where('heartbeat.lastHeartbeat', '<', staleCutoff)
      .where('heartbeat.lastHeartbeat', '>', longOfflineCutoff)
      .get();

    for (const doc of q.docs) {
      const uid = doc.id;
      const data = doc.data();
      const fcmToken = data.deviceStatus?.fcmToken;
      if (!fcmToken) continue;

      const waiting = await doc.ref.collection('pendingPings').where('status', '==', 'waiting').limit(1).get();
      if (!waiting.empty) continue;

      const pingId = crypto.randomUUID();
      const expiresAt = admin.firestore.Timestamp.fromMillis(nowTs.toMillis() + PING_ACK_WINDOW_MS);
      const docId = makeDocId(formatTs(nowTs), pingId);

      await doc.ref.collection('pendingPings').doc(docId).set({
        id: pingId,
        readableId: docId,
        status: 'waiting',
        sentAt: nowTs,
        expiresAt: expiresAt,
        by: 'cron',
        blockStatus: !!(data.blockStatus?.isActive)
      });

      try {
        await admin.messaging().send({
          token: fcmToken,
          data: { action: 'ping_challenge', pingId: pingId, uid: uid },
          android: { priority: 'high', ttl: PING_TTL_MS }
        });
      } catch (err) {
        console.error(`FCM failed for ${uid}:`, err);
      }
    }
    res.json({ ok: true, checked: q.size });
  } catch (e) {
    console.error('cron error', e);
    res.status(500).json({ error: e.message });
  }
});

// 追加 (addPromise)
exports.addPromise = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { text } = data;

  if (!text) throw new functions.https.HttpsError('invalid-argument', 'Text required');

  const nowTs = admin.firestore.FieldValue.serverTimestamp();
  
  await db.collection('users').doc(uid).collection('promises').add({
    text: text,
    createdAt: nowTs,
    updatedAt: nowTs,
    createdBy: 'individual',
    status: 'active'
  });

  return { success: true };
});

// 更新 (updatePromise)
exports.updatePromise = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { promiseId, text } = data;

  if (!promiseId || !text) throw new functions.https.HttpsError('invalid-argument', 'Invalid arguments');

  await db.collection('users').doc(uid).collection('promises').doc(promiseId).update({
    text: text,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  return { success: true };
});

// 削除 (deletePromise)
exports.deletePromise = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { promiseId } = data;

  if (!promiseId) throw new functions.https.HttpsError('invalid-argument', 'promiseId required');

  // ★必要であれば「ブロック中は削除禁止」などのチェックをここに追加可能
  
  await db.collection('users').doc(uid).collection('promises').doc(promiseId).delete();

  return { success: true };
});

// ============================================================
//  FCMトークン保存 (saveFcmToken)
// ============================================================
exports.saveFcmToken = functions.https.onCall(async (data, context) => {
  const uid = getUid(context);
  const { fcmToken } = data;

  if (!fcmToken) return { success: false, message: 'no token' };

  await db.collection('users').doc(uid).set(
    {
      deviceStatus: {
        fcmToken: fcmToken,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }
    },
    { merge: true }
  );

  return { success: true };
});