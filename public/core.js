// Cryptography for the secure chat app (runs in the browser and in Node).
// Same steps as messenger.js: certificates, Diffie-Hellman, ratchet, AES-GCM, government copy.
const cry = globalThis.crypto || require('node:crypto').webcrypto
const S = cry.subtle, enc = new TextEncoder(), dec = new TextDecoder()
const GOV_STR = 'AES-GENERATION'
const b64 = (buf) => { let s = ''; for (const x of new Uint8Array(buf)) s += String.fromCharCode(x); return btoa(s) }
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const salt = (n = 16) => cry.getRandomValues(new Uint8Array(n))
const gen = async (name, usages) => { const k = await S.generateKey({ name, namedCurve: 'P-384' }, true, usages); return { pub: k.publicKey, sec: k.privateKey } }
const genEG = () => gen('ECDH', ['deriveKey'])
const genDSA = () => gen('ECDSA', ['sign', 'verify'])
const dsaSign = (k, m) => S.sign({ name: 'ECDSA', hash: 'SHA-384' }, k, enc.encode(m))
const dsaVerify = (k, m, sig) => S.verify({ name: 'ECDSA', hash: 'SHA-384' }, k, sig, enc.encode(m))
const pubJwk = async (k) => { const j = await S.exportKey('jwk', k); return { kty: j.kty, crv: j.crv, x: j.x, y: j.y } }
const impEG = (j) => S.importKey('jwk', { ...j, ext: true }, { name: 'ECDH', namedCurve: 'P-384' }, true, [])
const impDSA = (j) => S.importKey('jwk', { ...j, ext: true }, { name: 'ECDSA', namedCurve: 'P-384' }, true, ['verify'])
const certString = (c) => JSON.stringify([c.username, c.pub.x, c.pub.y])
const keyId = (j) => j.x + '|' + j.y
const headerAD = (h) => JSON.stringify([h.dh.x, h.dh.y, h.N, h.PN, h.vGov.x, h.vGov.y, h.cGov, h.ivGov, h.receiverIV])
const dh = (sec, pub) => S.deriveKey({ name: 'ECDH', public: pub }, sec, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign', 'verify'])
const hmacKey = (raw) => S.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'])
async function toAES (key, data, raw = false) {
  const out = await S.importKey('raw', await S.sign('HMAC', key, enc.encode(data)), 'AES-GCM', true, ['encrypt', 'decrypt'])
  return raw ? S.exportKey('raw', out) : out
}
const toHMAC = async (key, data) => hmacKey(await S.sign('HMAC', key, enc.encode(data)))
async function hkdf (inKey, saltKey, info) {
  const ik = await S.importKey('raw', await S.sign('HMAC', inKey, enc.encode('0')), 'HKDF', false, ['deriveKey'])
  const out = async (s) => S.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: await S.sign('HMAC', saltKey, enc.encode(s)), info: enc.encode(info) }, ik, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'])
  return [await out('salt1'), await out('salt2')]
}
const gcmEnc = (k, pt, iv, ad) => S.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(ad) }, k, typeof pt === 'string' ? enc.encode(pt) : pt)
const gcmDec = (k, ct, iv, ad) => S.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(ad) }, k, ct)

class Client {
  constructor (caPub, govPub) { this.ca = caPub; this.gov = govPub; this.conns = {}; this.certs = {}; this.eg = null }
  async makeCert (username) { this.eg = await genEG(); return { username, pub: await pubJwk(this.eg.pub) } }
  async takeCert (cert, sig) {
    if (!(await dsaVerify(this.ca, certString(cert), unb64(sig)))) throw new Error('Certificate signature is invalid')
    const id = keyId(cert.pub)
    if (this.certs[cert.username] && this.certs[cert.username].id === id) return
    delete this.conns[cert.username] // the peer has new keys: start a fresh session
    this.certs[cert.username] = { pub: await impEG(cert.pub), id }
  }
  has (name) { return !!this.certs[name] }
  async open (name) {
    const c = this.certs[name]; if (!c) throw new Error('No certificate for ' + name)
    return { RK: await dh(this.eg.sec, c.pub), DHs: this.eg, DHr: c.pub, DHrId: c.id, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, sendRatchet: true, skipped: {} }
  }
  async step (CK) { return [await toHMAC(CK, 'chain-key-step'), await toAES(CK, 'message-key-step'), await toAES(CK, 'message-key-step', true)] }
  async send (name, text) {
    const c = (this.conns[name] ||= await this.open(name))
    if (c.sendRatchet) {
      const n = await genEG()
      ;[c.RK, c.CKs] = await hkdf(await dh(n.sec, c.DHr), c.RK, 'ratchet-str')
      c.DHs = n; c.PN = c.Ns; c.Ns = 0; c.sendRatchet = false
    }
    const [next, mk, mkRaw] = await this.step(c.CKs); c.CKs = next
    const g = await genEG()
    const gk = await toAES(await dh(g.sec, this.gov), GOV_STR)
    const ivGov = salt(), rIV = salt()
    const h = { dh: await pubJwk(c.DHs.pub), N: c.Ns, PN: c.PN, vGov: await pubJwk(g.pub), cGov: b64(await gcmEnc(gk, mkRaw, ivGov, '')), ivGov: b64(ivGov), receiverIV: b64(rIV) }
    c.Ns++
    return { header: h, ct: b64(await gcmEnc(mk, text, rIV, headerAD(h))) }
  }
  async receive (name, pkt) {
    const c = (this.conns[name] ||= await this.open(name))
    const h = pkt && pkt.header; if (!h || !h.dh) throw new Error('Malformed message')
    const ad = headerAD(h), id = keyId(h.dh), ct = unb64(pkt.ct), iv = unb64(h.receiverIV)
    // A late message whose key was saved earlier
    const saved = c.skipped[id + ':' + h.N]
    if (saved) {
      let pt
      try { pt = await gcmDec(saved, ct, iv, ad) } catch (e) { throw new Error('Tampering detected: message failed authentication') }
      delete c.skipped[id + ':' + h.N]
      return dec.decode(pt)
    }
    let { RK, CKr, Nr, DHr, DHrId } = c, ratcheted = false
    const skipped = { ...c.skipped }
    const skipUntil = async (n) => {
      if (n - Nr + Object.keys(skipped).length > 5000) throw new Error('Too many skipped messages')
      while (Nr < n) { const [nx, k] = await this.step(CKr); CKr = nx; skipped[DHrId + ':' + Nr] = k; Nr++ }
    }
    try {
      if (id !== DHrId) {
        if (CKr) await skipUntil(h.PN)
        const pub = await impEG(h.dh)
        ;[RK, CKr] = await hkdf(await dh(c.DHs.sec, pub), RK, 'ratchet-str')
        Nr = 0; DHr = pub; DHrId = id; ratcheted = true
      }
    } catch (e) { throw new Error('Malformed message header') }
    if (!CKr) throw new Error('No receiving chain')
    if (h.N < Nr) throw new Error('Replayed message')
    await skipUntil(h.N)
    const [next, mk] = await this.step(CKr)
    let pt
    try { pt = await gcmDec(mk, ct, iv, ad) } catch (e) { throw new Error('Tampering detected: message failed authentication') }
    Object.assign(c, { RK, CKr: next, Nr: Nr + 1, DHr, DHrId, skipped })
    if (ratcheted) c.sendRatchet = true
    return dec.decode(pt)
  }
}
// What the government does with its secret key
async function govRead (govSec, pkt) {
  const h = pkt.header
  const gk = await toAES(await dh(govSec, await impEG(h.vGov)), GOV_STR)
  const raw = await gcmDec(gk, unb64(h.cGov), unb64(h.ivGov), '')
  const mk = await S.importKey('raw', raw, 'AES-GCM', false, ['decrypt'])
  return { key: b64(raw), text: dec.decode(await gcmDec(mk, unb64(pkt.ct), unb64(h.receiverIV), headerAD(h))) }
}
if (typeof module !== 'undefined') module.exports = { genEG, genDSA, dsaSign, pubJwk, impEG, impDSA, certString, govRead, b64, Client }