'use strict';
// CFR fork'un ParamSpecializer'ı her sınıfa şifre çözücünün bir kopyasını ("d$spec0(String, int, int)") koyuyor ve çağrılar
// Cls.d$spec0("base64", k1, k2) biçiminde kalıyor. Çözücünün sabitlerini kopyanın gövdesinden okuyup çağrıları gerçek metne çevirir.

function javaStr(s) {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '\\') o += '\\\\';
    else if (ch === '"') o += '\\"';
    else if (ch === '\n') o += '\\n';
    else if (ch === '\r') o += '\\r';
    else if (ch === '\t') o += '\\t';
    else if (c >= 32 && c < 127) o += ch;
    else if (c > 0xFFFF) { const h = Math.floor((c - 0x10000) / 0x400) + 0xD800, l = ((c - 0x10000) % 0x400) + 0xDC00; o += '\\u' + h.toString(16) + '\\u' + l.toString(16); }
    else o += '\\u' + c.toString(16).padStart(4, '0');
  }
  return o + '"';
}

function methodBody(text, from) {
  const open = text.indexOf('{', from);
  let d = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') d++;
    else if (text[i] === '}' && --d === 0) return [open, i];
  }
  return null;
}

const intLit = s => { const t = s.trim(); return (/^-?0x/i.test(t) ? (t.startsWith('-') ? -parseInt(t.slice(3), 16) : parseInt(t, 16)) : parseInt(t, 10)) | 0; };

function decrypt(b64, k1, k2, P) {
  const buf = Buffer.from(b64, 'base64');
  const n = buf.length;
  if (!n) return '';
  const n7 = (Math.imul(k1, 31) + k2) | 0;
  let n8 = n7 ^ P.xor;
  for (let i = n - 1; i >= 0; i--) {
    n8 = (Math.imul(n8, P.mul) + P.add1) | 0;
    buf[i] = (buf[i] - (n8 >>> 19)) & 0xFF;
  }
  let idx = n - 2 - (n & 1);
  while (idx >= 0) {
    const sw = (((idx + 1) ^ (n7 >>> 8)) >>> 0) % n;
    const t = buf[idx]; buf[idx] = buf[sw]; buf[sw] = t;
    idx -= 2;
  }
  let st = n7;
  for (let i = 0; i < n; i++) {
    st = (Math.imul(st, P.mul) + P.add3) | 0;
    let h = st ^ (st >>> 16);
    h = Math.imul(h, P.mix1);
    h ^= h >>> 15;
    h = Math.imul(h, P.mix2);
    h ^= h >>> 16;
    buf[i] ^= (h ^ (n7 >>> ((i & 3) << 3))) & 0xFF;
  }
  return buf.toString('utf8');
}

function parseProfile(body) {
  const xor = /\bn\d+\s*=\s*n\d+\s*\^\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*;/.exec(body);
  const loop1 = /(\w+)\s*=\s*\1\s*\*\s*(-?\d+)\s*\+\s*(-?\d+)\s*;/.exec(body);
  const loop3 = /(\w+)\s*=\s*\1\s*\*\s*(-?\d+)\s*\+\s*(\d+)\s*;/g;
  let l3 = null, m;
  while ((m = loop3.exec(body))) if (loop1 && m.index > loop1.index && m[3] !== loop1[3]) { l3 = m; break; }
  const mixes = [...body.matchAll(/\b\w+\s*\*=\s*(-?\d+)\s*;/g)].map(x => intLit(x[1]));
  const ov = /\bn2\s*=\s*(-?\d+)\s*;/.exec(body.slice(0, 200));        // özelleştirilmiş sabit parametre
  if (!xor || !loop1 || !l3 || mixes.length < 2) return null;
  return { xor: intLit(xor[1]), mul: intLit(loop1[2]), add1: intLit(loop1[3]), add3: intLit(l3[3]), mix1: mixes[0], mix2: mixes[1], k2: ov ? intLit(ov[1]) : null };
}

function decryptSpecWrappers(text, stats) {
  const hdr = /(?:public |private |protected )?static String (d\$spec\d+)\(String (\w+), int (\w+), int (\w+)\)\s*\{/g;
  const profs = new Map();
  let m;
  while ((m = hdr.exec(text))) {
    const span = methodBody(text, m.index);
    if (!span || !/Base64\.getDecoder\(\)\.decode/.test(text.slice(span[0], span[1]))) continue;
    const P = parseProfile(text.slice(span[0], span[1] + 1));
    if (P) profs.set(m[1], P);
  }
  if (!profs.size) return text;
  let n = 0;
  const callRe = /(?:\b\w+\.)?(d\$spec\d+)\(\s*("(?:\\.|[^"\\])*")\s*,\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*,\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*\)/g;
  let out = text.replace(callRe, (all, name, lit, a, b) => {
    const P = profs.get(name); if (!P) return all;
    try {
      const raw = lit.slice(1, -1).replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\(["\\])/g, '$1');
      const plain = decrypt(raw, intLit(a), P.k2 !== null ? P.k2 : intLit(b), P);
      n++;
      return javaStr(plain);
    } catch { return all; }
  });
  if (stats && n) stats.furryStrings = (stats.furryStrings || 0) + n;
  // kullanılmayan çözücü kopyalarını sil
  for (const name of profs.keys()) {
    const used = new RegExp(`\\b${name.replace('$', '\\$')}\\(`, 'g');
    const defRe = () => new RegExp(`[ \\t]*(?:public |private |protected )?static String ${name.replace('$', '\\$')}\\(String \\w+, int \\w+, int \\w+\\)\\s*\\{`, 'g');
    const total = (out.match(used) || []).length, defs = (out.match(defRe()) || []).length;
    if (total - defs <= 0) {                               // çağrı kalmadı: tüm kopyaları (iç sınıflardakiler dahil) sil
      for (let guard = 0; guard < 20; guard++) {
        const h = defRe().exec(out);
        if (!h) break;
        const sp = methodBody(out, h.index);
        if (!sp) break;
        let e = sp[1] + 1; while (out[e] === '\n') e++;
        out = out.slice(0, h.index) + out.slice(e);
      }
    }
  }
  return out;
}

/** 40 hex karakterlik sentetik filigran alanları (kullanılmıyorsa sil) */
function dropWatermarks(text) {
  return text.replace(/^[ \t]*(?:(?:final|static|private|public|protected)\s+)+String\s+(\w+)\s*=\s*"[0-9a-f]{40}"\s*;[ \t]*\n/gm, (all, name) => {
    const rest = text.replace(all, '');
    return new RegExp(`\\b${name}\\b`).test(rest) ? all : '';
  });
}

module.exports = { decryptSpecWrappers, dropWatermarks };
