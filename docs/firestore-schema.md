# Firestore Schema (users/{uid})

> スキーマは“設計の約束”です。Firestore はスキーマレスなので、この文書＋Security Rules＋実装の型で実質的に固定します。

```jsonc
{
  "displayName": "hiro",
  "emailVerified": true,
  "lastLoginAt": "<Timestamp>",

  "role": "partner",            // "actor" | "partner"
  "roleSource": "client",       // "client" | "server"

  "pairingStatus": {
    "status": "paired",         // "unpaired" | "waiting" | "paired"
    "partnerUid": "fPZ1...",
    "pairedAt": "<Timestamp>",
    "partnerLineUserId": "Uxxx",// optional
    // ↓ 発行中のみ存在。通常は保存しない/不要になったら削除
    "code": "<string?>",
    "expiresAt": "<Timestamp?>"
  },

  "blockStatus": {
    "isActive": false,
    "updatedAt": "<Timestamp>",
    "lastHeartbeat": "<Timestamp?>" // optional
  },

  "deviceStatus": {
    "deviceName": "iPhone",
    "fcmToken": "eD8cItsV3U...",
    "isScreenTimeAuthorized": false,
    "lastFcmOkAt": "<Timestamp?>",
    "fcmConsecutiveFails": 0,
    "gmsIssueSuspected": false,
    "updatedAt": "<Timestamp?>"
  }
}
