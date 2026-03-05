# ssh-key-checker

GitHubユーザーのSSH公開鍵をチェックする Cloudflare Worker。

公開URL: `https://ssh-keycheck.lugiaxetomxv.net`

## なぜ作ったか（背景）

GitHub の公開鍵は `https://github.com/<username>.keys` で誰でも取得できますが、
「その鍵が今の基準で安全か」を手早く判断する方法が意外とありませんでした。

このツールは、次のような場面を想定して作っています。

- 自分やチームの GitHub SSH 鍵を手軽に棚卸ししたい
- 古い RSA / DSA 鍵が残っていないか確認したい
- curl 1発で判定できる軽いセキュリティチェックが欲しい

特に「公開鍵のビット長が短いと、将来的に秘密鍵解析リスクが上がる」という点を
可視化し、Ed25519 への移行判断をしやすくすることを目的にしています。

## 使い方

### 1) 通常チェック（テキスト）

```bash
curl https://ssh-keycheck.lugiaxetomxv.net/TomXV
```

### 2) JSON API

```bash
curl https://ssh-keycheck.lugiaxetomxv.net/TomXV.json
```

### 3) SVGバッジ

```bash
curl https://ssh-keycheck.lugiaxetomxv.net/TomXV/badge
```

### 4) 複数ユーザー同時チェック

```bash
curl https://ssh-keycheck.lugiaxetomxv.net/TomXV,octocat
```

### 5) 直接鍵チェック

```bash
curl "https://ssh-keycheck.lugiaxetomxv.net/?keys=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
```

## 判定ルール

- Ed25519 / Ed448: ✅ 安全
- ECDSA: ⚠️ 条件付きOK（Ed25519移行推奨）
- RSA 1024以下: 🔴 危険
- RSA 2048以上: ⚠️ 移行推奨
- DSA: 🔴 危険（廃止済み）
- PRIVATE KEY文字列検出: 🔴 緊急

## 開発

```bash
npm install
npx wrangler dev --port 8787
```

## デプロイ

```bash
npx wrangler deploy
```
