import { Hono } from 'hono'

const app = new Hono()

type KeyType = 'Ed25519' | 'RSA' | 'ECDSA' | 'DSA' | 'Ed448' | 'Unknown'

interface KeyInfo {
  type: KeyType
  bits: number | null
  status: 'ok' | 'warn' | 'danger'
  message: string
}

function parseKeyType(keyLine: string): KeyInfo {
  const parts = keyLine.trim().split(/\s+/)
  const keyType = parts[0]

  // 秘密鍵が誤って登録されてたら緊急警告
  if (keyLine.includes('BEGIN') && keyLine.includes('PRIVATE KEY')) {
    return { type: 'Unknown', bits: null, status: 'danger', message: '🚨 秘密鍵が登録されています！今すぐ削除してください！' }
  }

  if (keyType === 'ssh-ed25519') {
    return { type: 'Ed25519', bits: 256, status: 'ok', message: '安全です' }
  }

  if (keyType === 'ssh-ed448') {
    return { type: 'Ed448', bits: 448, status: 'ok', message: '安全です' }
  }

  if (keyType === 'ssh-rsa') {
    // Base64デコードしてビット数を推定
    const bits = estimateRSABits(parts[1])
    if (bits === null) return { type: 'RSA', bits: null, status: 'warn', message: 'ビット数不明 — Ed25519への移行を推奨' }
    if (bits <= 1024) return { type: 'RSA', bits, status: 'danger', message: '危険！鍵が短すぎます。今すぐ更新してください' }
    if (bits <= 2048) return { type: 'RSA', bits, status: 'warn', message: '非推奨 — Ed25519への移行を推奨します' }
    if (bits <= 3072) return { type: 'RSA', bits, status: 'warn', message: 'Ed25519への移行を推奨します' }
    return { type: 'RSA', bits, status: 'warn', message: 'Ed25519への移行を推奨します' }
  }

  if (keyType === 'ecdsa-sha2-nistp256') return { type: 'ECDSA', bits: 256, status: 'warn', message: '条件付きOK — Ed25519への移行を推奨' }
  if (keyType === 'ecdsa-sha2-nistp384') return { type: 'ECDSA', bits: 384, status: 'warn', message: '条件付きOK — Ed25519への移行を推奨' }
  if (keyType === 'ecdsa-sha2-nistp521') return { type: 'ECDSA', bits: 521, status: 'warn', message: '条件付きOK — Ed25519への移行を推奨' }

  if (keyType === 'ssh-dss') {
    return { type: 'DSA', bits: 1024, status: 'danger', message: '危険！DSAは廃止済みです。今すぐ更新してください' }
  }

  return { type: 'Unknown', bits: null, status: 'warn', message: '不明な鍵タイプ' }
}

function estimateRSABits(b64: string | undefined): number | null {
  if (!b64) return null
  try {
    // RSA公開鍵のサイズからビット数を大まかに推定
    const len = b64.length
    if (len < 300) return 1024
    if (len < 400) return 2048
    if (len < 500) return 3072
    return 4096
  } catch {
    return null
  }
}

function statusIcon(status: string): string {
  if (status === 'ok') return '✅'
  if (status === 'warn') return '⚠️ '
  return '🔴'
}

function renderText(username: string, keys: KeyInfo[], hasDanger: boolean): string {
  const lines: string[] = []
  lines.push(`╔${'═'.repeat(36)}╗`)
  lines.push(`║  SSH Key Checker${' '.repeat(19)}║`)
  lines.push(`║  github.com/${username}${' '.repeat(Math.max(0, 23 - username.length))}║`)
  lines.push(`╚${'═'.repeat(36)}╝`)
  lines.push('')

  if (keys.length === 0) {
    lines.push('  鍵が登録されていません')
  } else {
    for (const key of keys) {
      const icon = statusIcon(key.status)
      const typeStr = key.bits ? `${key.type} ${key.bits}bit` : key.type
      lines.push(`  ${icon} ${typeStr.padEnd(16)} — ${key.message}`)
    }
  }

  lines.push('')

  const hasWarn = keys.some(k => k.status === 'warn')
  if (hasDanger) {
    lines.push('📋 アドバイス')
    lines.push('  危険な鍵が検出されました。今すぐ以下を実行してください:')
    lines.push('')
    lines.push('  # 新しいEd25519鍵を生成')
    lines.push('  ssh-keygen -t ed25519 -C "your@email.com"')
    lines.push('  # GitHubで古い鍵を削除してください')
  } else if (hasWarn) {
    lines.push('📋 アドバイス')
    lines.push('  以下のコマンドでEd25519鍵に移行できます:')
    lines.push('')
    lines.push('  ssh-keygen -t ed25519 -C "your@email.com"')
  } else {
    lines.push('🎉 すべての鍵が安全です！')
  }

  lines.push('')
  return lines.join('\n')
}

app.get('/:username', async (c) => {
  const username = c.req.param('username')
  const userAgent = c.req.header('User-Agent') ?? ''
  const isCurl = userAgent.toLowerCase().includes('curl') ||
                 userAgent.toLowerCase().includes('wget') ||
                 userAgent.toLowerCase().includes('httpie') ||
                 !userAgent.includes('Mozilla')

  // GitHub から公開鍵を取得
  const res = await fetch(`https://github.com/${username}.keys`)
  if (!res.ok) {
    const msg = `ユーザー "${username}" が見つかりません\n`
    return c.text(msg, 404)
  }

  const body = await res.text()
  const lines = body.trim().split('\n').filter(l => l.trim())
  const keys = lines.map(parseKeyType)
  const hasDanger = keys.some(k => k.status === 'danger')

  if (isCurl) {
    return c.text(renderText(username, keys, hasDanger))
  }

  // ブラウザ向けHTML（シンプル）
  const html = `<!DOCTYPE html>
<html lang="ja">
<head><meta charset="UTF-8"><title>SSH Key Checker - ${username}</title>
<style>
  body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; }
  .ok { color: #3fb950; }
  .warn { color: #d29922; }
  .danger { color: #f85149; }
  pre { background: #161b22; padding: 1rem; border-radius: 6px; }
</style>
</head>
<body>
<h1>🔑 SSH Key Checker</h1>
<h2>github.com/${username}</h2>
<pre>${renderText(username, keys, hasDanger)}</pre>
<p>curl でも使えます: <code>curl sshcheck.example.com/${username}</code></p>
</body></html>`

  return c.html(html)
})

app.get('/', (c) => {
  const usage = `SSH Key Checker
═══════════════════════════════════════
GitHubユーザーのSSH公開鍵をチェックします

使い方:
  curl <hostname>/<github-username>

例:
  curl <hostname>/TomXV

`
  return c.text(usage)
})

export default app
