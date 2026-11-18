'use strict';
// ZKM ve Statik String[] Dizi Deobfuscator
// <clinit> / static { } içinde veya alan tanımında başlatılan static String[] dizilerini çözer,
// array[index] erişimlerini doğrudan düz metin string literalleriyle değiştirir ve gereksiz alanları siler.

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

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function foldStaticStringArrays(code, stats) {
  const arrayMap = new Map();

  // 1. Alan tanımlarını tara: private static [final] String[] fieldName [ = new String[] { ... } ];
  const fieldDeclRe = /(?:private|protected|public)?\s*static\s+(?:final\s+)?String\[\]\s+(\w+)\s*(?:=\s*new\s+String\[\]\s*\{([^}]+)\})?\s*;/g;
  let fm;
  while ((fm = fieldDeclRe.exec(code))) {
    const name = fm[1];
    if (fm[2]) {
      const parts = fm[2].match(/"(?:\\.|[^"\\])*"/g) || [];
      arrayMap.set(name, parts.map(s => unescapeJava(s.slice(1, -1))));
    } else {
      arrayMap.set(name, []);
    }
  }

  // 2. static { } bloklarını tara: indexed string assignment'lar
  const staticBlockRe = /static\s*\{([\s\S]*?)\}/g;
  let sm;
  while ((sm = staticBlockRe.exec(code))) {
    const sbody = sm[1];
    for (const [fname, list] of arrayMap) {
      if (list.length > 0) continue;
      // alias tespiti: arr = new String[N]; ... fieldName = arr;
      const aliasM = new RegExp(String.raw`(\w+)\s*=\s*new\s+String\[\d+\];[\s\S]*?${fname}\s*=\s*\1;`).exec(sbody);
      const targetVar = aliasM ? aliasM[1] : fname;
      const assignRe = new RegExp(String.raw`\b${targetVar}\[\s*(\d+)\s*\]\s*=\s*"((?:\\.|[^"\\])*)";`, 'g');
      let am;
      const map = [];
      while ((am = assignRe.exec(sbody))) {
        map[parseInt(am[1], 10)] = unescapeJava(am[2]);
      }
      if (map.length > 0) arrayMap.set(fname, map);
    }
  }

  let totalInlined = 0;
  for (const [fname, elems] of arrayMap) {
    if (!elems.length) continue;
    const accessRe = new RegExp(String.raw`(?:\b\w+\.)?\b${esc(fname)}\[\s*(\d+)\s*\]`, 'g');
    let replacedForField = 0;
    code = code.replace(accessRe, (all, idxStr) => {
      const idx = parseInt(idxStr, 10);
      if (idx >= 0 && idx < elems.length && elems[idx] !== undefined) {
        replacedForField++;
        return javaString(elems[idx]);
      }
      return all;
    });

    if (replacedForField > 0) {
      totalInlined += replacedForField;
      // Diziye başka erişim kalmadıysa alan ve statik atamaları temizle
      if (!new RegExp(String.raw`\b${esc(fname)}\[`).test(code)) {
        code = code.replace(new RegExp(String.raw`^[ \t]*(?:private|protected|public)?\s*static\s+(?:final\s+)?String\[\]\s+${esc(fname)}[^;\n]*;[ \t]*\n?`, 'gm'), '');
        code = code.replace(new RegExp(String.raw`^[ \t]*${esc(fname)}\s*=\s*[^;\n]+;[ \t]*\n?`, 'gm'), '');
      }
    }
  }

  // Boş veya sadece yerel string dizisi oluşturup atanan static { } bloklarını temizle
  code = code.replace(/static\s*\{\s*String\[\]\s+\w+\s*=\s*new\s+String\[\d+\];(?:\s*\w+\[\d+\]\s*=\s*"[^"]*";)*\s*\}/g, '');
  code = code.replace(/static\s*\{\s*\}/g, '');

  if (stats && totalInlined) {
    stats.strings = (stats.strings || 0) + totalInlined;
    stats.zkm = (stats.zkm || 0) + totalInlined;
  }

  return { code, count: totalInlined };
}

module.exports = { foldStaticStringArrays };
