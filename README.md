# ssh-key-checker

GitHubユーザーのSSH公開鍵をチェックする Cloudflare Worker。

公開URL: `https://ssh-keycheck.lugiaxetomxv.net`

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
