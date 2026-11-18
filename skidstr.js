'use strict';
/*
 * Skidfuscator "basic" string encryption (CFR çıktısı üzerinde):
 *   static String dec(byte[] b, int key) {   // b[i] ^= Integer.toString(key).getBytes()[i % len]; b[i] ^= KEYS[i % KEYS.length]; new String(b, UTF_16)
 *   ...  Cls.dec(Cls.provider(), 2028787983)  ->  "gerçek string"
 * Şifreli baytlar provider() metodunun içindeki "new byte[]{...}" dizisinde, KEYS static alanı da bir provider'dan gelir.
 */

const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

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

function methodSpan(text, headerIdx) {
  const open = text.indexOf('{', headerIdx);
  let d = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') d++;
    else if (text[i] === '}' && --d === 0) return [open, i];
  }
  return null;
}

function parseBytes(src) {
  const nums = src.split(',').map(s => s.trim()).filter(Boolean).map(s => parseInt(s, 10));
  if (nums.some(Number.isNaN)) return null;
  return Uint8Array.from(nums.map(n => n & 255));
}

function decodeJava(bytes, cs) {
  if (/UTF_8/.test(cs)) return Buffer.from(bytes).toString('utf8');
  if (/UTF_16LE/.test(cs)) return Buffer.from(bytes).toString('utf16le');
  let b = Buffer.from(bytes), le = false;
  if (/UTF_16BE/.test(cs)) { /* BOM yok sayılır */ }
  else if (b.length >= 2 && b[0] === 0xFE && b[1] === 0xFF) b = b.subarray(2);
  else if (b.length >= 2 && b[0] === 0xFF && b[1] === 0xFE) { b = b.subarray(2); le = true; }
  if (le) return b.toString('utf16le');
  const sw = Buffer.alloc(b.length - (b.length & 1));
  for (let i = 0; i + 1 < b.length; i += 2) { sw[i] = b[i + 1]; sw[i + 1] = b[i]; }
  return sw.toString('utf16le');
}

function decryptSkidStrings(text, stats) {
  // 1) çözücü metot
  const dm = /(?:public |private |protected )?static String (\w+)\(byte\[\] (\w+), int (\w+)\) \{/.exec(text);
  if (!dm) return text;
  const span = methodSpan(text, dm.index);
  if (!span) return text;
  const body = text.slice(span[0], span[1] + 1);
  if (!/Integer\.toString\(/.test(body) || !/new String\(/.test(body)) return text;
  const cs = (/StandardCharsets\.(UTF_\w+)/.exec(body) || [null, 'UTF_16'])[1];
  const decName = dm[1];

  // 2) anahtar dizisi alanı ("byte[] x = FIELD;" iki kez geçer)
  let keyField = null;
  for (const fm of body.matchAll(/byte\[\] \w+ = (\w+);/g))
    if (new RegExp(`static (?:final )?byte\\[\\] ${esc(fm[1])}\\b`).test(text)) { keyField = fm[1]; break; }
  if (!keyField) return text;
  const asg = new RegExp(`\\b${esc(keyField)} = (?:\\w+\\.)?(\\w+)\\(\\);`).exec(text);
  if (!asg) return text;
  const provRe = name => new RegExp(`(?:private |public |protected )?static byte\\[\\] ${esc(name)}\\(\\) \\{\\s*return new byte\\[\\]\\{([^}]*)\\};\\s*\\}`);
  const km = provRe(asg[1]).exec(text);
  if (!km) return text;
  const keys = parseBytes(km[1]);
  if (!keys || !keys.length) return text;

  // 3) çağrıları çöz
  const provCache = new Map();
  const provBytes = name => {
    if (provCache.has(name)) return provCache.get(name);
    const m = provRe(name).exec(text);
    const v = m ? parseBytes(m[1]) : null;
    provCache.set(name, v);
    return v;
  };
  const callRe = new RegExp(`(?:\\w+\\.)?${esc(decName)}\\(\\s*(?:\\w+\\.)?(\\w+)\\(\\)\\s*,\\s*(-?\\d+)\\s*\\)`, 'g');
  let n = 0;
  const used = new Set();
  let out = text.replace(callRe, (all, prov, key) => {
    const b = provBytes(prov);
    if (!b) return all;
    const kb = Buffer.from(String(parseInt(key, 10) | 0));
    const r = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) r[i] = b[i] ^ kb[i % kb.length] ^ keys[i % keys.length];
    n++; used.add(prov);
    return javaStr(decodeJava(r, cs));
  });
  if (!n) return text;
  if (stats) stats.skidStrings = (stats.skidStrings || 0) + n;

  // 4) artık kullanılmayan provider'ları, çözücüyü, anahtar alanını sil
  const dropMethod = (src, header) => {
    const m = header.exec(src);
    if (!m) return src;
    const sp = methodSpan(src, m.index);
    if (!sp) return src;
    let s = m.index; while (s > 0 && (src[s - 1] === ' ' || src[s - 1] === '\t')) s--;
    let e = sp[1] + 1; while (src[e] === '\n') e++;
    return src.slice(0, s) + src.slice(e);
  };
  for (const prov of used) {
    const still = new RegExp(`\\b${esc(prov)}\\(`, 'g');
    const cnt = (out.match(still) || []).length;
    if (cnt <= 1) out = dropMethod(out, new RegExp(`(?:private |public |protected )?static byte\\[\\] ${esc(prov)}\\(\\) \\{`));
  }
  if (!new RegExp(`\\b${esc(decName)}\\(`, 'g').test(out.replace(new RegExp(`static String ${esc(decName)}\\(`), ''))) {
    out = dropMethod(out, new RegExp(`(?:public |private |protected )?static String ${esc(decName)}\\(byte\\[\\] \\w+, int \\w+\\) \\{`));
    out = out.replace(new RegExp(`^[ \\t]*(?:\\w+\\.)?${esc(keyField)} = (?:\\w+\\.)?${esc(asg[1])}\\(\\);[ \\t]*\\n`, 'm'), '');
    out = dropMethod(out, new RegExp(`(?:private |public |protected )?static byte\\[\\] ${esc(asg[1])}\\(\\) \\{`));
    out = out.replace(new RegExp(`^[ \\t]*(?:private |public |protected )?static byte\\[\\] ${esc(keyField)};[ \\t]*\\n`, 'm'), '');
  }
  return out;
}

module.exports = { decryptSkidStrings };
