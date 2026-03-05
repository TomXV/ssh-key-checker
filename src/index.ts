import { Hono } from 'hono'

const app = new Hono()

// ANSI colors
const C = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
}

type KeyStatus = 'ok' | 'warn' | 'danger'

interface KeyInfo {
  type: string
  bits: number | null
  status: KeyStatus
  message: string
  raw: string
}

// RSA公開鍵のビット数をDERパースで正確に算出
function parseRSABits(b64: string): number | null {
  try {
    const binary = atob(b64)
    const buf = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i)
    let offset = 0
    const readUint32 = () => {
      const v = (buf[offset] << 24) | (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3]
      offset += 4
      return v >>> 0
    }
    const typeLen = readUint32(); offset += typeLen
    const expLen = readUint32(); offset += expLen
    const modLen = readUint32()
    let actualLen = modLen
    if (buf[offset] === 0x00) actualLen--
    return actualLen * 8
  } catch { return null }
}

function parseKey(keyLine: string): KeyInfo {
  const line = keyLine.trim()
  const parts = line.split(/\s+/)
  const keyType = parts[0]
  if (line.includes('PRIVATE KEY')) {
    return { type: 'PRIVATE KEY', bits: null, status: 'danger', message: '秘密鍵が登録されています！今すぐ削除！', raw: line }
  }
  if (keyType === 'ssh-ed25519') return { type: 'Ed25519', bits: 256, status: 'ok', message: '安全', raw: line }
  if (keyType === 'ssh-ed448') return { type: 'Ed448', bits: 448, status: 'ok', message: '安全', raw: line }
  if (keyType === 'ssh-rsa') {
    const bits = parseRSABits(parts[1])
    if (!bits) return { type: 'RSA', bits: null, status: 'warn', message: 'ビット数不明 — Ed25519移行を推奨', raw: line }
    if (bits <= 1024) return { type: 'RSA', bits, status: 'danger', message: '危険！鍵が短すぎます', raw: line }
    if (bits <= 2048) return { type: 'RSA', bits, status: 'warn', message: '非推奨 — Ed25519移行を推奨', raw: line }
    return { type: 'RSA', bits, status: 'warn', message: 'Ed25519移行を推奨', raw: line }
  }
  if (keyType === 'ecdsa-sha2-nistp256') return { type: 'ECDSA', bits: 256, status: 'warn', message: '条件付きOK — Ed25519移行を推奨', raw: line }
  if (keyType === 'ecdsa-sha2-nistp384') return { type: 'ECDSA', bits: 384, status: 'warn', message: '条件付きOK — Ed25519移行を推奨', raw: line }
  if (keyType === 'ecdsa-sha2-nistp521') return { type: 'ECDSA', bits: 521, status: 'warn', message: '条件付きOK — Ed25519移行を推奨', raw: line }
  if (keyType === 'ssh-dss') return { type: 'DSA', bits: 1024, status: 'danger', message: '危険！DSAは廃止済みです', raw: line }
  return { type: keyType ?? 'Unknown', bits: null, status: 'warn', message: '不明な鍵タイプ', raw: line }
}

function overallStatus(keys: KeyInfo[]): KeyStatus {
  if (keys.some(k => k.status === 'danger')) return 'danger'
  if (keys.some(k => k.status === 'warn')) return 'warn'
  return 'ok'
}

function statusIcon(status: KeyStatus, color = false): string {
  if (!color) {
    if (status === 'ok') return '✅'
    if (status === 'warn') return '⚠️ '
    return '🔴'
  }
  if (status === 'ok') return `${C.green}✅${C.reset}`
  if (status === 'warn') return `${C.yellow}⚠️ ${C.reset}`
  return `${C.red}🔴${C.reset}`
}

function renderText(label: string, keys: KeyInfo[], useColor: boolean): string {
  const lines: string[] = []
  const w = 42
  const h = (s: string) => useColor ? `${C.bold}${C.cyan}${s}${C.reset}` : s
  const d = (s: string) => useColor ? `${C.dim}${s}${C.reset}` : s
  lines.push(h(`╔${'═'.repeat(w)}╗`))
  lines.push(h('║') + `  SSH Key Checker` + ' '.repeat(w - 18) + h('║'))
  lines.push(h('║') + `  ${label}` + ' '.repeat(Math.max(0, w - 2 - label.length)) + h('║'))
  lines.push(h(`╚${'═'.repeat(w)}╝`))
  lines.push('')
  if (keys.length === 0) {
    lines.push('  鍵が登録されていません')
  } else {
    for (const key of keys) {
      const icon = statusIcon(key.status, useColor)
      const typeStr = key.bits ? `${key.type} ${key.bits}bit` : key.type
      const colorMsg = useColor
        ? key.status === 'ok' ? `${C.green}${key.message}${C.reset}`
          : key.status === 'warn' ? `${C.yellow}${key.message}${C.reset}`
          : `${C.red}${key.message}${C.reset}`
        : key.message
      lines.push(`  ${icon} ${typeStr.padEnd(18)} ${d('—')} ${colorMsg}`)
    }
  }
  lines.push('')
  const status = overallStatus(keys)
  if (status === 'danger') {
    lines.push('📋 アドバイス — 危険な鍵が検出されました:')
    lines.push('')
    lines.push('  ssh-keygen -t ed25519 -C "your@email.com"')
    lines.push('  # GitHubで古い鍵を削除: https://github.com/settings/keys')
  } else if (status === 'warn') {
    lines.push('📋 アドバイス — Ed25519鍵への移行を推奨します:')
    lines.push('')
    lines.push('  ssh-keygen -t ed25519 -C "your@email.com"')
  } else {
    lines.push(useColor ? `${C.green}🎉 すべての鍵が安全です！${C.reset}` : '🎉 すべての鍵が安全です！')
  }
  lines.push('')
  return lines.join('\n')
}

function renderHTML(label: string, keys: KeyInfo[]): string {
  const status = overallStatus(keys)
  const statusColor = status === 'ok' ? '#3fb950' : status === 'warn' ? '#d29922' : '#f85149'
  const statusText = status === 'ok' ? '✅ All Good' : status === 'warn' ? '⚠️ Review Recommended' : '🔴 Action Required'
  const rows = keys.map(k => {
    const color = k.status === 'ok' ? '#3fb950' : k.status === 'warn' ? '#d29922' : '#f85149'
    const icon = k.status === 'ok' ? '✅' : k.status === 'warn' ? '⚠️' : '🔴'
    const typeStr = k.bits ? `${k.type} ${k.bits}bit` : k.type
    return `<tr><td>${icon}</td><td style="color:${color}">${typeStr}</td><td>${k.message}</td></tr>`
  }).join('\n')
  return `<!DOCTYPE html>
<html lang="ja"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSH Key Checker — ${label}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,monospace;background:#0d1117;color:#c9d1d9;padding:2rem}
.card{max-width:640px;margin:0 auto}
h1{color:#58a6ff;font-size:1.4rem;margin-bottom:.25rem}
h2{color:#8b949e;font-size:1rem;font-weight:normal;margin-bottom:1.5rem}
.badge{display:inline-block;padding:.3rem .8rem;border-radius:2rem;background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}66;font-weight:bold;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}
th{text-align:left;padding:.6rem 1rem;background:#21262d;color:#8b949e;font-size:.85rem}
td{padding:.6rem 1rem;border-top:1px solid #21262d;font-family:monospace}
.advice{margin-top:1.5rem;background:#161b22;border-radius:8px;padding:1rem 1.25rem}
.advice h3{color:#8b949e;font-size:.9rem;margin-bottom:.5rem}
code{background:#21262d;padding:.2rem .5rem;border-radius:4px;font-size:.9rem}
.hint{margin-top:1.5rem;color:#8b949e;font-size:.85rem}</style>
</head><body><div class="card">
<h1>🔑 SSH Key Checker</h1>
<h2>${label}</h2>
<div class="badge">${statusText}</div>
${keys.length === 0 ? '<p style="color:#8b949e">鍵が登録されていません</p>' : `<table>
<thead><tr><th></th><th>タイプ</th><th>判定</th></tr></thead>
<tbody>${rows}</tbody></table>`}
${status !== 'ok' ? `<div class="advice"><h3>📋 アドバイス</h3>
<code>ssh-keygen -t ed25519 -C "your@email.com"</code></div>` : ''}
<p class="hint">curl でも使えます: <code>curl https://ssh-keycheck.lugiaxetomxv.net/${label.replace('github.com/', '')}</code></p>
</div></body></html>`
}

function makeBadgeSVG(status: KeyStatus): string {
  const color = status === 'ok' ? '#3fb950' : status === 'warn' ? '#e3b341' : '#f85149'
  const label2 = status === 'ok' ? 'secure ✓' : status === 'warn' ? 'review ⚠' : 'danger ✗'
  return `<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">
<rect width="80" height="20" fill="#555"/>
<rect x="80" width="70" height="20" fill="${color}"/>
<text x="40" y="14" fill="#fff" font-family="sans-serif" font-size="11" text-anchor="middle">SSH Keys</text>
<text x="115" y="14" fill="#fff" font-family="sans-serif" font-size="11" text-anchor="middle">${label2}</text>
</svg>`
}

function isCurlLike(ua: string): boolean {
  const lower = ua.toLowerCase()
  return lower.includes('curl') || lower.includes('wget') || lower.includes('httpie') || !ua.includes('Mozilla')
}

async function fetchKeys(username: string): Promise<{ keys: KeyInfo[], status: number }> {
  const res = await fetch(`https://github.com/${username}.keys`)
  if (!res.ok) return { keys: [], status: res.status }
  const body = await res.text()
  const lines = body.trim().split('\n').filter(l => l.trim())
  return { keys: lines.map(parseKey), status: 200 }
}

// GET / — 使い方 (クエリ ?keys= の場合は直接チェック)
app.get('/', async (c) => {
  const keysParam = c.req.query('keys')
  const ua = c.req.header('User-Agent') ?? ''
  if (keysParam) {
    const lines = keysParam.split('\n').filter(l => l.trim())
    const keys = lines.map(parseKey)
    if (isCurlLike(ua)) return c.text(renderText('direct input', keys, true))
    return c.html(renderHTML('direct input', keys))
  }
  if (!isCurlLike(ua)) {
    return c.html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SSH Key Checker</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;max-width:600px;margin:0 auto}
h1{color:#58a6ff}h2{color:#8b949e;margin-top:1.5rem}code{background:#161b22;padding:.2rem .5rem;border-radius:4px}
a{color:#58a6ff}pre{background:#161b22;padding:1rem;border-radius:8px;overflow:auto}</style></head>
<body><h1>🔑 SSH Key Checker</h1>
<p>GitHubユーザーのSSH公開鍵をチェックします。</p>
<h2>使い方</h2>
<pre>curl https://ssh-keycheck.lugiaxetomxv.net/&lt;username&gt;
curl https://ssh-keycheck.lugiaxetomxv.net/&lt;username&gt;.json
curl https://ssh-keycheck.lugiaxetomxv.net/&lt;username&gt;/badge
curl "https://ssh-keycheck.lugiaxetomxv.net/?keys=ssh-ed25519 AAAA..."
curl https://ssh-keycheck.lugiaxetomxv.net/user1,user2,user3</pre>
<p>例: <a href="/TomXV">/TomXV</a></p>
</body></html>`)
  }
  return c.text(`SSH Key Checker
${'═'.repeat(42)}
使い方:
  curl https://ssh-keycheck.lugiaxetomxv.net/<username>
  curl https://ssh-keycheck.lugiaxetomxv.net/<username>.json
  curl https://ssh-keycheck.lugiaxetomxv.net/<username>/badge
  curl "https://ssh-keycheck.lugiaxetomxv.net/?keys=<pubkey>"
  curl https://ssh-keycheck.lugiaxetomxv.net/user1,user2,user3
`)
})

// GET /:username.json
app.get('/:username{[^/,]+\\.json}', async (c) => {
  const param = c.req.param('username')
  const username = param.replace(/\.json$/, '')
  const { keys, status } = await fetchKeys(username)
  if (status !== 200) return c.json({ error: `User "${username}" not found` }, 404)
  return c.json({
    username,
    github_url: `https://github.com/${username}`,
    overall: overallStatus(keys),
    key_count: keys.length,
    keys: keys.map(k => ({ type: k.type, bits: k.bits, status: k.status, message: k.message })),
  })
})

// GET /:username/badge
app.get('/:username/badge', async (c) => {
  const username = c.req.param('username')
  const { keys, status } = await fetchKeys(username)
  if (status !== 200) return c.text('not found', 404)
  const svg = makeBadgeSVG(overallStatus(keys))
  return c.body(svg, 200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'max-age=3600' })
})

// GET /:usernames — 単数または複数 (カンマ区切り)
app.get('/:usernames', async (c) => {
  const param = c.req.param('usernames')
  const ua = c.req.header('User-Agent') ?? ''
  const usernames = param.split(',').map(u => u.trim()).filter(Boolean)

  if (usernames.length === 1) {
    const username = usernames[0]
    const { keys, status } = await fetchKeys(username)
    if (status !== 200) {
      const msg = `ユーザー "${username}" が見つかりません\n`
      return isCurlLike(ua) ? c.text(msg, 404) : c.html(`<h1>404</h1><p>${msg}</p>`, 404)
    }
    if (isCurlLike(ua)) return c.text(renderText(`github.com/${username}`, keys, true))
    return c.html(renderHTML(`github.com/${username}`, keys))
  }

  // 複数ユーザー
  const results = await Promise.all(usernames.map(async u => {
    const { keys, status } = await fetchKeys(u)
    return { username: u, keys, status }
  }))

  if (isCurlLike(ua)) {
    const w = 42
    const header = `${C.bold}${C.cyan}╔${'═'.repeat(w)}╗\n║  SSH Key Checker (複数チェック)${''.padEnd(w-30)}║\n╚${'═'.repeat(w)}╝${C.reset}\n\n`
    const out = results.map(r => {
      if (r.status !== 200) return `  ❓ ${r.username.padEnd(20)} — ユーザーが見つかりません`
      const status = overallStatus(r.keys)
      return `  ${statusIcon(status, true)} ${r.username.padEnd(20)} — ${r.keys.length}鍵`
    }).join('\n')
    return c.text(header + out + '\n\n')
  }

  const rows = results.map(r => {
    if (r.status !== 200) return `<tr><td>❓</td><td><a href="/${r.username}">${r.username}</a></td><td style="color:#8b949e">Not found</td></tr>`
    const status = overallStatus(r.keys)
    const color = status === 'ok' ? '#3fb950' : status === 'warn' ? '#d29922' : '#f85149'
    const icon = status === 'ok' ? '✅' : status === 'warn' ? '⚠️' : '🔴'
    return `<tr><td>${icon}</td><td><a href="/${r.username}" style="color:#58a6ff">${r.username}</a></td><td style="color:${color}">${r.keys.length} keys — ${status}</td></tr>`
  }).join('\n')

  return c.html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SSH Key Checker</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}
table{border-collapse:collapse;width:100%;max-width:640px}
th,td{padding:.6rem 1rem;border-top:1px solid #21262d;text-align:left}
th{background:#21262d;color:#8b949e}a{color:#58a6ff}
h1{color:#58a6ff;margin-bottom:1rem}</style></head>
<body><h1>🔑 SSH Key Checker</h1>
<table><thead><tr><th></th><th>User</th><th>Status</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`)
})

export default app
