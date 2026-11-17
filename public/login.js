const $ = (id) => document.getElementById(id)
let mode = 'login'
try { const t = localStorage.getItem('theme'); if (t && t !== 'system') document.documentElement.dataset.theme = t } catch (e) {}
if (sessionStorage.getItem('token')) location.replace('/app.html')

function setMode (m) {
  mode = m
  $('t-login').className = m === 'login' ? 'on' : ''; $('t-reg').className = m === 'reg' ? 'on' : ''
  $('ttl').textContent = m === 'login' ? 'Welcome back' : 'Create your account'
  $('go').textContent = m === 'login' ? 'Log in' : 'Create account and log in'
  $('p').autocomplete = m === 'login' ? 'current-password' : 'new-password'; $('authmsg').textContent = ''
}
async function call (path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(j.error || 'Request failed')
  return j
}
async function submit () {
  const username = $('u').value.trim(), password = $('p').value
  $('authmsg').textContent = ''; $('go').disabled = true
  try {
    if (mode === 'reg') await call('/api/register', { username, password })
    const s = await call('/api/login', { username, password })
    sessionStorage.setItem('token', s.token); sessionStorage.setItem('me', s.username)
    location.href = '/app.html'
  } catch (e) { $('authmsg').textContent = e.message; $('go').disabled = false }
}
$('t-login').onclick = () => setMode('login'); $('t-reg').onclick = () => setMode('reg')
$('go').onclick = submit
$('p').addEventListener('keydown', e => { if (e.key === 'Enter') submit() })
$('u').focus()