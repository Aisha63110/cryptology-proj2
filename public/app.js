const $ = (id) => document.getElementById(id)
let token = sessionStorage.getItem('token') || '', me = sessionStorage.getItem('me') || '', display = '', client = null, peer = '', convos = {}, unread = {}, seen = new Set(), timer = null, userList = []
const stats = { sent: 0, recv: 0, rej: 0 }, activity = []

// ---------- helpers ----------
async function api (method, path, body) {
  const r = await fetch(path, { method, headers: { 'content-type': 'application/json', 'x-token': token }, body: method === 'POST' ? JSON.stringify(body || {}) : undefined })
  const j = await r.json().catch(() => ({}))
  if (r.status === 401 && token) { sessionStorage.clear(); location.replace('/') }
  if (!r.ok) throw new Error(j.error || 'Request failed')
  return j
}
function flash (id, text, bad) { const e = $(id); e.textContent = text; e.className = bad ? 'err' : '' }
function act (text) { activity.unshift(new Date().toLocaleTimeString() + '  ' + text); if (activity.length > 8) activity.pop(); drawDash() }
function drawDash () {
  $('welcome').textContent = 'Welcome, ' + (display || me)
  $('s-sent').textContent = stats.sent; $('s-recv').textContent = stats.recv; $('s-rej').textContent = stats.rej
  $('s-online').textContent = userList.filter(u => u.online).length
  const ul = $('activity'); ul.textContent = ''
  if (!activity.length) { const li = document.createElement('li'); li.textContent = 'Nothing yet. Open Chat and send a message.'; ul.append(li) }
  for (const t of activity) { const li = document.createElement('li'); li.textContent = t; ul.append(li) }
}

// ---------- pages ----------
function showView (name) {
  for (const v of document.querySelectorAll('.view')) v.hidden = v.id !== 'v-' + name
  for (const b of document.querySelectorAll('.side nav a')) b.classList.toggle('active', b.dataset.view === name)
  if (name === 'profile') loadProfile()
  if (name === 'chat' && peer) $('msg').focus()
}
function route () { const n = location.hash.slice(1); showView(['dashboard', 'chat', 'profile', 'settings'].includes(n) ? n : 'dashboard') }
window.addEventListener('hashchange', route)

async function loadProfile () {
  try {
    const p = await api('GET', '/api/profile')
    $('p-user').textContent = p.username; $('p-since').textContent = p.created ? new Date(p.created).toLocaleDateString() : 'unknown'
    $('p-display').value = p.display; $('p-bio').value = p.bio; display = p.display; drawDash()
  } catch (e) { flash('p-msg', e.message, true) }
}
$('p-save').onclick = async () => {
  try { await api('POST', '/api/profile', { display: $('p-display').value, bio: $('p-bio').value }); display = $('p-display').value.trim(); flash('p-msg', 'Profile saved.'); drawDash() } catch (e) { flash('p-msg', e.message, true) }
}
$('s-pass').onclick = async () => {
  try { await api('POST', '/api/password', { old: $('s-old').value, next: $('s-new').value }); $('s-old').value = ''; $('s-new').value = ''; flash('s-msg', 'Password changed.') } catch (e) { flash('s-msg', e.message, true) }
}
function applyTheme (t) { if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.dataset.theme = t }
function applyWire (on) { $('wirepanel').hidden = !on }
$('s-theme').onchange = () => { localStorage.setItem('theme', $('s-theme').value); applyTheme($('s-theme').value) }
$('s-wire').onchange = () => { localStorage.setItem('wire', $('s-wire').checked ? '1' : '0'); applyWire($('s-wire').checked) }
try {
  const t = localStorage.getItem('theme') || 'system', w = localStorage.getItem('wire') !== '0'
  $('s-theme').value = t; applyTheme(t); $('s-wire').checked = w; applyWire(w)
} catch (e) {}

// ---------- chat ----------
function saveConvos () { try { sessionStorage.setItem('convos:' + me, JSON.stringify(convos)) } catch (e) {} }
function say (user, kind, text) {
  (convos[user] ||= []).push({ kind, text }); saveConvos()
  if (user === peer) drawLog(); else if (kind !== 'mine') { unread[user] = (unread[user] || 0) + 1; drawUsers() }
}
function drawLog () {
  const log = $('log'); log.textContent = ''
  for (const m of convos[peer] || []) { const d = document.createElement('div'); d.className = 'msg ' + (m.kind === 'mine' ? 'mine' : m.kind === 'theirs' ? 'theirs' : 'bad'); d.textContent = m.text; log.append(d) }
  log.scrollTop = 1e9
}
function drawUsers () {
  const ul = $('users'); ul.textContent = ''
  if (!userList.length) { const li = document.createElement('li'); li.className = 'sub'; li.textContent = 'No one else yet. Create a second account in another tab.'; ul.append(li) }
  for (const u of userList) {
    const li = document.createElement('li'), b = document.createElement('button'); if (u.name === peer) b.className = 'sel'
    const av = document.createElement('span'); av.className = 'av'; av.textContent = u.name[0].toUpperCase()
    const n = document.createElement('span'); n.className = 'nm'; n.textContent = u.display ? u.display + ' (' + u.name + ')' : u.name
    const s = document.createElement('span'); s.className = 'dot' + (u.online ? ' on' : ''); s.textContent = u.online ? 'online' : 'not logged in'
    if (unread[u.name]) { s.className = 'unread'; s.textContent = unread[u.name] + ' new' }
    b.append(av, n, s); b.onclick = () => pick(u.name); li.append(b); ul.append(li)
  }
}
function pick (name) { peer = name; unread[name] = 0; $('with').textContent = 'Chat with ' + name; $('msg').disabled = false; $('send').disabled = false; drawUsers(); drawLog(); $('msg').focus() }
async function ensureCert (user) {
  const r = await api('GET', '/api/cert/' + encodeURIComponent(user))
  await client.takeCert(r.cert, r.sig)
}
async function sendMsg () {
  const text = $('msg').value.trim(); if (!text || !peer) return
  $('msg').value = ''
  try {
    await ensureCert(peer)
    const pkt = await client.send(peer, text)
    if ($('tamper').checked) { const raw = unb64(pkt.ct); raw[0] ^= 1; pkt.ct = b64(raw); $('tamper').checked = false; act('Changed a message to ' + peer + ' in transit (attack demo)') }
    await api('POST', '/api/send', { to: peer, packet: pkt })
    say(peer, 'mine', text); stats.sent++; act('Sent a message to ' + peer)
  } catch (e) { say(peer, 'bad', 'Could not send: ' + e.message) }
}
async function poll () {
  try {
    userList = await api('GET', '/api/users'); drawUsers()
    for (const e of await api('GET', '/api/inbox')) {
      try { await ensureCert(e.from); say(e.from, 'theirs', await client.receive(e.from, e.packet)); stats.recv++; act('Received a message from ' + e.from) } catch (err) { say(e.from, 'bad', 'Rejected a message: ' + err.message); stats.rej++; act('Rejected a message from ' + e.from + ': ' + err.message) }
    }
    drawWire(await api('GET', '/api/wire')); drawDash()
  } catch (e) { $('status').textContent = e.message }
}
function drawWire (list) {
  const box = $('wire')
  for (const m of list) {
    if (seen.has(m.id)) continue; seen.add(m.id)
    const r = document.createElement('div'); r.className = 'row'
    const who = document.createElement('div'); who.className = 'who'; who.textContent = m.from + ' to ' + m.to
    const ct = document.createElement('code'); ct.className = 'ct'; ct.textContent = m.ct + '…'
    const meta = document.createElement('div'); meta.className = 'meta'; meta.textContent = 'message number ' + m.N + ' in this chain, previous chain had ' + m.PN
    const btn = document.createElement('button'); btn.className = 'ghost'; btn.textContent = 'Read as government'
    const g = document.createElement('div'); g.className = 'gov'; g.hidden = true
    btn.onclick = async () => { g.hidden = false; try { const x = await api('POST', '/api/gov/read', { id: m.id }); g.textContent = 'Government unlocked the message key and read: "' + x.text + '"' } catch (e) { g.textContent = e.message } }
    r.append(who, ct, meta, btn, g); box.prepend(r)
  }
}

// ---------- login / logout ----------
async function fingerprint (jwk) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(jwk.x + jwk.y))
  return [...new Uint8Array(d)].slice(0, 12).map(x => x.toString(16).padStart(2, '0')).join('').match(/.{4}/g).join(' ')
}
async function init () {
  if (!token) return location.replace('/')
  try {
    convos = JSON.parse(sessionStorage.getItem('convos:' + me) || '{}')
    $('me').textContent = me; $('av').textContent = me[0].toUpperCase()
    const cfg = await api('GET', '/api/config')
    client = new Client(await impDSA(cfg.ca), await impEG(cfg.gov))
    const cert = await client.makeCert(me); await api('POST', '/api/cert', { pub: cert.pub })
    const fp = await fingerprint(cert.pub); $('p-fp').textContent = fp; $('fp-hero').textContent = fp
    display = (await api('GET', '/api/profile')).display
    act('Created fresh keys for this tab')
    route(); poll(); timer = setInterval(poll, 1500)
  } catch (e) { $('status').textContent = e.message }
}
async function logout () {
  clearInterval(timer)
  try { await api('POST', '/api/logout') } catch (e) {}
  sessionStorage.clear(); location.replace('/')
}
$('send').onclick = sendMsg; $('msg').addEventListener('keydown', e => { if (e.key === 'Enter') sendMsg() })
$('logout').onclick = logout
init()