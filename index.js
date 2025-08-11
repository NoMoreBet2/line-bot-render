'use strict';

const express = require('express');
const line = require('@line/bot-sdk');

// 環境変数からアクセストークンとチャネルシークレットを取得
const config = {
  channelAccessToken: process.env.CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.CHANNEL_SECRET,
};

const app = express();

// ルートパスへのアクセス確認用
app.get('/', (req, res) => {
  res.send('LINE Bot is running!');
});

// Webhook用のパス
app.post('/webhook', line.middleware(config), (req, res) => {
  Promise.all(req.body.events.map(handleEvent))
    .then((result) => res.json(result))
    .catch((err) => {
      console.error(err);
      res.status(500).end();
    });
});

const client = new line.Client(config);

// イベント処理
function handleEvent(event) {
  if (event.type !== 'message' || event.message.type !== 'text') {
    return Promise.resolve(null);
  }

  // 受け取ったメッセージをそのまま返す（オウム返し）
  return client.replyMessage(event.replyToken, {
    type: 'text',
    text: event.message.text,
  });
}

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`listening on ${port}`);
});
