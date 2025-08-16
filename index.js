'use strict';

const express = require('express');
const line = require('@line/bot-sdk');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ==============================
// Environment Variables
// ==============================
const PORT = process.env.PORT || 3000;
const lineConfig = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

// ==============================
// Firebase Admin Initialization
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
// Express Setup
// ==============================
const app = express();

// Health check for Render
app.get('/', (_, res) => res.send('LINE Bot is running!'));
app.get('/healthz', (_, res) => res.send('healthy'));

// ==============================
// LINE Setup
// ==============================
const client = new line.Client(lineConfig);

// ==============================
// Firebase Auth Middleware
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
  res.sendStatus(200); // Respond immediately
  try {
    await Promise.all((req.body.events || []).map(handleEvent));
  } catch (e) {
    console.error('webhook error', e);
  }
});

// ==============================
// API Body Parser
// ==============================
app.use(express.json());

// ==============================
// Utilities
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
// Main Event Handler (from LINE Webhook)
// ==============================
async function handleEvent(event) {
  // 1) Partner sends pair code
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

        if (!codeSnap.exists || (codeSnap.data().expiresAt || 0) < now()) {
          return reply(event.replyToken, `Code ${code} is invalid or expired.`);
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
        return reply(event.replyToken, `Pairing complete! ✅`);
      } catch (error) {
        console.error('pair webhook error', error);
        return reply(event.replyToken, 'An error occurred.');
      }
    }
  }

  // 2) Partner approves/rejects unlock request
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
          await client.pushMessage(event.source.userId, { type: 'text', text: 'Approved.' });
        }
      } catch (err) { console.error('Approval failed:', err); }
      return;
    }

    if (rj) {
      if (event.source?.userId) {
        await client.pushMessage(event.source.userId, { type: 'text', text: 'Rejected unlock request.' });
      }
      return;
    }
  }
}

// ==============================
// Custom APIs (from Android App)
// ==============================

// 1) Create Pair Code
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

// 2) Request Partner Unlock
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
      type: 'template', altText: 'An unlock request has arrived.',
      template: {
        type: 'confirm', text: 'A request to unlock the block has arrived from your partner. Do you approve?',
        actions: [
          { type: 'postback', label: 'Approve', data: `approve:${uid}` },
          { type: 'postback', label: 'Reject', data: `reject:${uid}` },
        ],
      },
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('Unlock request failed:', e);
    res.status(500).json({ error: 'Failed to process unlock request.' });
  }
});

// 3) Notify Partner of Fraud
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
          text: '[NoMoreBet Warning]\nFraudulent activity (such as reinstalling the app) was detected on your partner\'s app. The block has been deactivated.'
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
// Start Server
// ==============================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`listening on ${PORT}`);
  initAsync(); // Initialize Firebase after starting the server
});