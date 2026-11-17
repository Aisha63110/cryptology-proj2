const { spawn } = require('child_process'); const core = require('./public/core.js'); const assert = require('assert')
const P = 3999, U = 'http://localhost:' + P
const call = async (m, p, body, tok) => { const r = await fetch(U + p, { method: m, headers: { 'content-type': 'application/json', 'x-token': tok || '' }, body: m === 'POST' ? JSON.stringify(body || {}) : undefined }); return { s: r.status, j: await r.json() } }
;(async () => {
  const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT: P }, cwd: __dirname }); await new Promise(r => setTimeout(r, 1200))
  try {
    assert.strictEqual((await call('POST', '/api/register', { username: 'x', password: '123456' })).s, 400)
    for (const n of ['alice', 'bob']) assert.strictEqual((await call('POST', '/api/register', { username: n, password: 'secret1' })).s, 200)
    assert.strictEqual((await call('POST', '/api/register', { username: 'alice', password: 'secret1' })).s, 409)
    assert.strictEqual((await call('POST', '/api/login', { username: 'alice', password: 'wrong!!' })).s, 401)
    const cfg = (await call('GET', '/api/config')).j; const ca = await core.impDSA(cfg.ca), gov = await core.impEG(cfg.gov)
    const mk = async (n) => { const t = (await call('POST', '/api/login', { username: n, password: 'secret1' })).j.token; const c = new core.Client(ca, gov); const cert = await c.makeCert(n); await call('POST', '/api/cert', { pub: cert.pub }, t); return { c, t, n } }
    const a = await mk('alice'), b = await mk('bob')
    const ensure = async (me, peer) => { { const r = (await call('GET', '/api/cert/' + peer, null, me.t)).j; await me.c.takeCert(r.cert, r.sig) } }
    const say = async (from, to, text, tamper) => { await ensure(from, to.n); const pkt = await from.c.send(to.n, text); if (tamper) { const u = core.b64; const raw = Uint8Array.from(atob(pkt.ct), c => c.charCodeAt(0)); raw[0] ^= 1; pkt.ct = u(raw) } await call('POST', '/api/send', { to: to.n, packet: pkt }, from.t) }
    const hear = async (me) => { const out = []; for (const e of (await call('GET', '/api/inbox', null, me.t)).j) { await ensure(me, e.from); try { out.push(await me.c.receive(e.from, e.packet)) } catch (er) { out.push('ERR:' + er.message) } } return out }
    await say(a, b, 'hello bob'); assert.deepStrictEqual(await hear(b), ['hello bob'])
    await say(b, a, 'hi alice'); assert.deepStrictEqual(await hear(a), ['hi alice'])
    await say(a, b, 'tampered', true); assert.ok((await hear(b))[0].startsWith('ERR:Tampering'))
    await say(a, b, 'still works'); const r = await hear(b); assert.deepStrictEqual(r, ['still works']); await say(b, a, 'x1'); await say(b, a, 'x2'); assert.deepStrictEqual(await hear(a), ['x1', 'x2'])
    const w = (await call('GET', '/api/wire')).j; console.log('wire entries', w.length)
    const g = await call('POST', '/api/gov/read', { id: w[0].id }); console.log('gov read:', g.j.text)
    assert.ok(!JSON.stringify(w).includes('hello'))
    const b2 = await mk('bob') // bob logs in again with brand new keys
    await say(a, b2, 'after relogin'); assert.deepStrictEqual(await hear(b2), ['after relogin'])
    await say(b2, a, 'hi again'); assert.deepStrictEqual(await hear(a), ['hi again'])
    console.log('RELOGIN OK')
    assert.strictEqual((await call('POST', '/api/profile', { display: 'Alice A', bio: 'hello' }, a.t)).s, 200)
    assert.strictEqual((await call('GET', '/api/profile', null, a.t)).j.display, 'Alice A')
    assert.strictEqual((await call('POST', '/api/profile', { display: 'x'.repeat(31) }, a.t)).s, 400)
    assert.strictEqual((await call('POST', '/api/password', { old: 'nope', next: 'newpass1' }, a.t)).s, 401)
    assert.strictEqual((await call('POST', '/api/password', { old: 'secret1', next: 'newpass1' }, a.t)).s, 200)
    assert.strictEqual((await call('POST', '/api/login', { username: 'alice', password: 'secret1' })).s, 401)
    const t2 = (await call('POST', '/api/login', { username: 'alice', password: 'newpass1' })).j.token
    assert.ok(t2)
    await call('POST', '/api/logout', {}, t2)
    assert.strictEqual((await call('GET', '/api/profile', null, t2)).s, 401)
    console.log('PROFILE/PASSWORD/LOGOUT OK')
    console.log('SERVER FLOW OK')
  } finally { srv.kill() }
})().catch(e => { console.error(e); process.exit(1) })