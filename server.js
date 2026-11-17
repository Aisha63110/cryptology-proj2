'use strict'
// Chat server: accounts and login, signs certificates (the trusted central party),
// passes encrypted messages along. It never sees any message text.
const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const nc = require('node:crypto')
const core = require('./public/core.js')

const PORT = process.env.PORT || 3000
const DB = path.join(__dirname, 'users.json')
const users = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, 'utf8')) : {}
const saveUsers = () => fs.writeFileSync(DB, JSON.stringify(users))
const sessions = {} // token -> username
const certs = {} // username -> { cert, sig }
const inbox = {} // username -> [entries]
const wire = [] // everything the network carries
let seq = 0
let ca, gov, caJwk, govJwk

const hashPw = (pw, salt) => nc.scryptSync(pw, Buffer.from(salt, 'hex'), 32)
const FILES = { '/': ['index.html', 'text/html'], '/index.html': ['index.html', 'text/html'], '/app.html': ['app.html', 'text/html'], '/style.css': ['style.css', 'text/css'], '/core.js': ['core.js', 'text/javascript'], '/login.js': ['login.js', 'text/javascript'], '/app.js': ['app.js', 'text/javascript'] }

function readBody (req) {
  return new Promise((resolve, reject) => {
    let d = ''
    req.on('data', c => { d += c; if (d.length > 200000) { reject(new Error('Too large')); req.destroy() } })
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}) } catch (e) { reject(new Error('Bad JSON')) } })
  })
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)) }
const fail = (res, code, msg) => send(res, code, { error: msg })

async function api (req, res, url) {
  const me = sessions[req.headers['x-token']]
  const body = req.method === 'POST' ? await readBody(req) : {}
  const route = req.method + ' ' + url

  if (route === 'POST /api/register') {
    const { username, password } = body
    if (!/^[a-z0-9_]{3,20}$/i.test(username || '')) return fail(res, 400, 'Username must be 3 to 20 letters, numbers or underscores')
    if (typeof password !== 'string' || password.length < 6) return fail(res, 400, 'Password must be at least 6 characters')
    const name = username.toLowerCase()
    if (users[name]) return fail(res, 409, 'That username is taken')
    const salt = nc.randomBytes(16).toString('hex')
    users[name] = { salt, hash: hashPw(password, salt).toString('hex'), created: Date.now(), display: '', bio: '' }
    saveUsers()
    return send(res, 200, { ok: true })
  }
  if (route === 'POST /api/login') {
    const name = String(body.username || '').toLowerCase(), u = users[name]
    const ok = u && nc.timingSafeEqual(hashPw(String(body.password || ''), u.salt), Buffer.from(u.hash, 'hex'))
    if (!ok) return fail(res, 401, 'Wrong username or password')
    const token = nc.randomBytes(24).toString('hex')
    sessions[token] = name
    return send(res, 200, { token, username: name })
  }
  if (route === 'GET /api/config') return send(res, 200, { ca: caJwk, gov: govJwk })
  if (route === 'GET /api/wire') {
    return send(res, 200, wire.slice(-30).map(e => ({ id: e.id, from: e.from, to: e.to, ct: e.packet.ct.slice(0, 48), N: e.packet.header.N, PN: e.packet.header.PN })))
  }
  if (route === 'POST /api/gov/read') {
    const e = wire.find(x => x.id === body.id)
    if (!e) return fail(res, 404, 'No such message')
    try { return send(res, 200, await core.govRead(gov.sec, e.packet)) } catch (err) { return fail(res, 400, 'The government could not read this message (it was changed in transit).') }
  }

  if (!me) return fail(res, 401, 'Please log in')
  if (route === 'POST /api/logout') {
    delete sessions[req.headers['x-token']]; delete certs[me]; delete inbox[me]
    return send(res, 200, { ok: true })
  }
  if (route === 'GET /api/profile') {
    const u = users[me]
    return send(res, 200, { username: me, display: u.display || '', bio: u.bio || '', created: u.created || null })
  }
  if (route === 'POST /api/profile') {
    const display = String(body.display || '').trim(), bio = String(body.bio || '').trim()
    if (display.length > 30) return fail(res, 400, 'Display name can be at most 30 characters')
    if (bio.length > 200) return fail(res, 400, 'About me can be at most 200 characters')
    users[me].display = display; users[me].bio = bio; saveUsers()
    return send(res, 200, { ok: true })
  }
  if (route === 'POST /api/password') {
    const u = users[me]
    const okOld = nc.timingSafeEqual(hashPw(String(body.old || ''), u.salt), Buffer.from(u.hash, 'hex'))
    if (!okOld) return fail(res, 401, 'Your current password is wrong')
    if (typeof body.next !== 'string' || body.next.length < 6) return fail(res, 400, 'New password must be at least 6 characters')
    u.salt = nc.randomBytes(16).toString('hex'); u.hash = hashPw(body.next, u.salt).toString('hex'); saveUsers()
    return send(res, 200, { ok: true })
  }
  if (route === 'POST /api/cert') {
    const p = body.pub
    if (!p || typeof p.x !== 'string' || typeof p.y !== 'string') return fail(res, 400, 'Bad key')
    const cert = { username: me, pub: { kty: 'EC', crv: 'P-384', x: p.x, y: p.y } }
    const sig = core.b64(await core.dsaSign(ca.sec, core.certString(cert)))
    certs[me] = { cert, sig }
    inbox[me] = []
    return send(res, 200, certs[me])
  }
  if (req.method === 'GET' && url.startsWith('/api/cert/')) {
    const c = certs[decodeURIComponent(url.slice(10))]
    return c ? send(res, 200, c) : fail(res, 404, 'That user has not logged in yet')
  }
  if (route === 'GET /api/users') return send(res, 200, Object.keys(users).filter(n => n !== me).map(n => ({ name: n, display: users[n].display || '', online: !!certs[n] })))
  if (route === 'POST /api/send') {
    if (!users[body.to] || !certs[body.to] || !body.packet || !body.packet.header) return fail(res, 400, 'Cannot deliver to that user')
    const entry = { id: ++seq, from: me, to: body.to, packet: body.packet }
    ;(inbox[body.to] ||= []).push(entry)
    wire.push(entry); if (wire.length > 200) wire.shift()
    return send(res, 200, { id: entry.id })
  }
  if (route === 'GET /api/inbox') {
    const list = (inbox[me] || []).splice(0)
    return send(res, 200, list.map(e => ({ id: e.id, from: e.from, packet: e.packet })))
  }
  return fail(res, 404, 'Not found')
}

async function main () {
  ca = await core.genDSA(); gov = await core.genEG()
  caJwk = await core.pubJwk(ca.pub); govJwk = await core.pubJwk(gov.pub)
  http.createServer(async (req, res) => {
    const url = req.url.split('?')[0]
    try {
      if (url.startsWith('/api/')) return await api(req, res, url)
      const f = FILES[url]
      if (!f) { res.writeHead(404); return res.end('Not found') }
      res.writeHead(200, { 'Content-Type': f[1] + '; charset=utf-8' })
      res.end(fs.readFileSync(path.join(__dirname, 'public', f[0])))
    } catch (e) { fail(res, 400, e.message) }
  }).listen(PORT, () => console.log('Secure chat running. Open http://localhost:' + PORT + ' in your browser.'))
}
main()