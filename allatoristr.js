'use strict';
// Allatori ve Genel Java String Çözücü
// CFR ile decompile edilmiş statik string çözücü metotlarını (XOR döngüleri, char[] dizileri) tespit eder,
// metot gövdesini güvenli biçimde simüle eder ve çağrıları düz metin string literalleriyle değiştirir.

function javaString(v) {
  let out = '"';
  for (let i = 0; i < v.length; i++) {
    const ch = v[i], c = v.charCodeAt(i);
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c >= 32 && c < 127) out += ch;
    else if (c > 0xFFFF) {
      const h = Math.floor((c - 0x10000) / 0x400) + 0xD800, l = ((c - 0x10000) % 0x400) + 0xDC00;
      out += `\\u${h.toString(16)}\\u${l.toString(16)}`;
    } else {
      out += '\\u' + c.toString(16).padStart(4, '0');
    }
  }
  return out + '"';
}

function unescapeJava(s) {
  return s.replace(/\\([\\"ntrbfae0-7]|u[0-9a-fA-F]{4})/g, (m, c) => {
    if (c === '"' || c === '\\') return c;
    if (c === 'n') return '\n';
    if (c === 't') return '\t';
    if (c === 'r') return '\r';
    if (c === 'b') return '\b';
    if (c === 'f') return '\f';
    if (c.startsWith('u')) return String.fromCharCode(parseInt(c.slice(1), 16));
    return m;
  });
}

function matchBrace(s, start) {
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    if (s[i] === '{') depth++;
    else if (s[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function translateJavaDecryptor(body) {
  let js = body;
  js = js.replace(/\b(?:int|char|byte|short|long|boolean)\s+/g, 'let ');
  js = js.replace(/char\[\]\s+(\w+)\s*=\s*new char\[[^\]]+\];/g, 'let $1 = [];');
  js = js.replace(/char\[\]\s+(\w+)\s*=\s*(\w+)\.toCharArray\(\);/g, 'let $1 = Array.from($2).map(c => c.charCodeAt(0));');
  js = js.replace(/\.charAt\(([^)]+)\)/g, '.charCodeAt($1)');
  js = js.replace(/\.length(?:\(\))?/g, '.length');
  js = js.replace(/\((?:char|int|byte|short|long)\)/g, '');
  js = js.replace(/return new String\((\w+)\);/g, 'return Array.from($1).map(c => String.fromCharCode(c & 0xFFFF)).join("");');
  return js;
}

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function decryptAllatori(code, stats) {
  let modified = false;
  let totalDecrypted = 0;

  // 1. Aday metotları tespit et
  // static String <name>(String s) veya static String <name>(String s, int key)
  const methodHeadRe = /(?:public|private|protected)?\s*static\s+String\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
  let m;
  const candidates = [];

  while ((m = methodHeadRe.exec(code))) {
    const name = m[1];
    const params = m[2].trim();
    const openBrace = m.index + m[0].length - 1;
    const closeBrace = matchBrace(code, openBrace);
    if (closeBrace < 0) continue;

    const body = code.slice(openBrace + 1, closeBrace);

    // Güvenlik ve heuristik filtreler: sadece saf string-char XOR döngüleri
    if (!body.includes('char') || !body.includes('^') || !body.includes('new String(')) continue;
    if (/(?:System\.|Runtime\.|ProcessBuilder|ClassLoader|Thread\.|File|Socket|exec|native|sun\.)/.test(body)) continue;

    const pTypes = params.split(',').map(p => p.trim().split(/\s+/)[0]).filter(Boolean);
    if (pTypes.length === 1 && pTypes[0] === 'String') {
      const pName = params.trim().split(/\s+/)[1];
      candidates.push({ name, pCount: 1, pName, start: m.index, end: closeBrace + 1, body });
    } else if (pTypes.length === 2 && pTypes[0] === 'String' && (pTypes[1] === 'int' || pTypes[1] === 'long')) {
      const parts = params.split(',').map(x => x.trim().split(/\s+/));
      candidates.push({ name, pCount: 2, pName: parts[0][1], keyName: parts[1][1], start: m.index, end: closeBrace + 1, body });
    }
  }

  for (const cand of candidates) {
    try {
      const jsBody = translateJavaDecryptor(cand.body);
      const args = cand.pCount === 1 ? [cand.pName] : [cand.pName, cand.keyName];
      const fn = new Function(...args, jsBody);

      // Basit doğrulama: test stringi çalıştır
      const testRes = cand.pCount === 1 ? fn('test') : fn('test', 123);
      if (typeof testRes !== 'string' || testRes.length !== 4) continue;

      let callRe;
      if (cand.pCount === 1) {
        callRe = new RegExp(String.raw`(?:\b\w+\.)?\b${esc(cand.name)}\(\s*"((?:\\.|[^"\\])*)"\s*\)`, 'g');
      } else {
        callRe = new RegExp(String.raw`(?:\b\w+\.)?\b${esc(cand.name)}\(\s*"((?:\\.|[^"\\])*)"\s*,\s*(-?\d+)\s*\)`, 'g');
      }

      let count = 0;
      code = code.replace(callRe, (all, encStr, keyStr) => {
        try {
          const raw = unescapeJava(encStr);
          const dec = cand.pCount === 1 ? fn(raw) : fn(raw, parseInt(keyStr, 10));
          if (typeof dec === 'string') {
            count++;
            return javaString(dec);
          }
        } catch {}
        return all;
      });

      if (count > 0) {
        totalDecrypted += count;
        modified = true;
        // Metot çağrısı kalmadıysa metodu temizle
        const checkRe = new RegExp(String.raw`\b${esc(cand.name)}\(`);
        const withoutMethod = code.slice(0, cand.start) + code.slice(cand.end);
        if (!checkRe.test(withoutMethod)) {
          code = withoutMethod;
        }
      }
    } catch {}
  }

  if (stats && totalDecrypted) {
    stats.strings = (stats.strings || 0) + totalDecrypted;
    stats.allatori = (stats.allatori || 0) + totalDecrypted;
  }

  return { code, count: totalDecrypted };
}

module.exports = { decryptAllatori };
