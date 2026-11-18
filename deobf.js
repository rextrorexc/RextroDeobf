'use strict';
const { decryptSkidStrings } = require('./skidstr');
const { decryptAllatori } = require('./allatoristr');
const { foldStaticStringArrays } = require('./zkmstr');

/* "try { throw new IOException(); } catch (IOException e) { }" gibi sahte istisna blokları */
function removeJunkTry(text) {
  // boş try-catch
  text = text.replace(/^[ \t]*try \{\s*\}\s*catch \([\w.]+(?:\s*\|\s*[\w.]+)* \w+\) \{\s*\}[ \t]*\n/gm, '');
  const empty = /^[ \t]*try \{\s*\n\s*throw new ([\w.]+)\((?:"[^"]*")?\);\s*\n\s*\}\s*\n?\s*catch \(\1 \w+\) \{\s*\n?\s*\}[ \t]*\n/gm;
  // gövdeli: try { throw new X(); } catch (X e) { KOD }  ->  KOD   (fırlatılan hata hep yakalanır)
  const body = /^([ \t]*)try \{\s*\n\s*throw new ([\w.]+)\((?:"[^"]*")?\);\s*\n\s*\}\s*\n?\s*catch \(\2 \w+\) \{[ \t]*\n([^{}]*?)\n[ \t]*\}[ \t]*\n/gm;
  return text.replace(empty, '').replace(body, (all, ind, cls, inner) => inner + '\n');
}
/*
 * RextroDeobf - CFR çıktısı üzerinde akış (flow) deobfuscation.
 *
 * Hedef: "anahtar değişkeni + yardımcı sınıf" tarzı obfuscator'lar
 *   n2 = 0x2C296831 ^ (0x19C54466 ^ n);
 *   if (Helper.f(n2) != 793861722) break block6;     <- hep doğru yoldan geçilir
 *   while (Helper.f(n2) != ... ) { }  throw new IOException("double");   <- ölü kod
 *   switch (Helper.f(n2)) { ... }
 *
 * Adımlar:
 *  1. Saf çöp satırları ve CFR yorum gürültüsünü sil
 *  2. Yardımcı (helper) çağrılarını tespit et
 *  3. Anahtar zincirini sırayla hesapla; (byte)(C ^ n2) gibi sabitleri gerçek değerlerine çevir
 *  4. Guard'ları, ölü döngüleri, switch'leri ve if(==) sarmallarını aç
 *  5. Artık kullanılmayan anahtar atamalarını, etiketleri ve boş blokları temizle
 *  6. Yeniden girintile
 */

const INT = '-?(?:0[xX][0-9A-Fa-f]+|\\d+)';
const NOT_METHOD = new Set(['if', 'while', 'for', 'switch', 'catch', 'synchronized', 'return', 'new', 'else', 'try']);

/* ------------------------------------------------------------ yardımcılar */

const maskStr = l => l.replace(/"(?:\.|[^"\\n])*"|'(?:\.|[^'\\n])*'/g, '""');
function subOutside(line, re, rep) {
  return line.split(/("(?:\.|[^"\\n])*"|'(?:\.|[^'\\n])*')/).map((part, i) => (i % 2 ? part : part.replace(re, rep))).join('');
}
function replaceOutside(line, re, rep) {
  if (!line.includes('"') && !line.includes("'")) return line.replace(re, rep);
  return subOutside(line, re, rep);
}

function javaString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c >= 32 && c < 127) out += ch;
    else if (c > 0xFFFF) { const h = Math.floor((c - 0x10000) / 0x400) + 0xD800, l = ((c - 0x10000) % 0x400) + 0xDC00; out += `\\u${h.toString(16)}\\u${l.toString(16)}`; }
    else out += '\\u' + c.toString(16).padStart(4, '0');
  }
  return out + '"';
}

function sanitize(line) {
  return line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""').replace(/\/\/.*$/, '');
}

function matchClose(lines, i, skipLeadingClose) {
  let depth = 0;
  for (let j = i; j < lines.length; j++) {
    let s = sanitize(lines[j]);
    if (j === i && skipLeadingClose) s = s.replace(/^\s*\}/, '');
    for (const ch of s) {
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) return j; }
    }
  }
  return -1;
}

function parseIntLit(s) {
  return s.toLowerCase().startsWith('-0x') ? -parseInt(s.slice(3), 16)
    : s.toLowerCase().startsWith('0x') ? parseInt(s.slice(2), 16) : parseInt(s, 10);
}

/* Gelişmiş ifade çözücü: tam operatör önceliği, aritmetik, mantıksal, bitwise, fonksiyonlar */
function evalExpr(src, env) {
  const re = /\s*(\(byte\)|\(short\)|\(int\)|\(char\)|0[xX][0-9a-fA-F]+L?|\d+L?|Integer\.(?:parseInt|valueOf)|Math\.(?:abs|min|max)|[A-Za-z_$][\w$]*|"[^"]*"|>>>|<<|>>|==|!=|<=|>=|&&|\|\||[()^\-+*\/%&|~!?:,])/y;
  const toks = [];
  let pos = 0;
  src = src.trim();
  while (pos < src.length) {
    re.lastIndex = pos;
    const m = re.exec(src);
    if (!m) throw new Error('tok');
    toks.push(m[1]);
    pos = re.lastIndex;
    while (pos < src.length && /\s/.test(src[pos])) pos++;
  }
  let k = 0;
  const peek = () => toks[k];

  function primary() {
    const t = toks[k++];
    if (t === undefined) throw new Error('eof');
    if (t === '(') {
      const v = ternary();
      if (toks[k++] !== ')') throw new Error(')');
      return v;
    }
    if (t === '+') return primary() | 0;
    if (t === '-') return (-primary()) | 0;
    if (t === '~') return (~primary()) | 0;
    if (t === '!') return primary() ? 0 : 1;
    if (t === '(byte)') return (primary() << 24) >> 24;
    if (t === '(short)') return (primary() << 16) >> 16;
    if (t === '(char)') return primary() & 0xFFFF;
    if (t === '(int)') return primary() | 0;
    if (t === 'Integer.parseInt' || t === 'Integer.valueOf') {
      if (toks[k++] !== '(') throw new Error('(');
      const s = toks[k++];
      if (!s || s[0] !== '"') throw new Error('str');
      if (toks[k++] !== ')') throw new Error(')');
      const n = parseInt(s.slice(1, -1), 10);
      if (Number.isNaN(n)) throw new Error('nan');
      return n | 0;
    }
    if (t === 'Math.abs') {
      if (toks[k++] !== '(') throw new Error('(');
      const arg = ternary();
      if (toks[k++] !== ')') throw new Error(')');
      return Math.abs(arg) | 0;
    }
    if (t === 'Math.max') {
      if (toks[k++] !== '(') throw new Error('(');
      const a1 = ternary();
      if (toks[k++] !== ',') throw new Error(',');
      const a2 = ternary();
      if (toks[k++] !== ')') throw new Error(')');
      return Math.max(a1, a2) | 0;
    }
    if (t === 'Math.min') {
      if (toks[k++] !== '(') throw new Error('(');
      const a1 = ternary();
      if (toks[k++] !== ',') throw new Error(',');
      const a2 = ternary();
      if (toks[k++] !== ')') throw new Error(')');
      return Math.min(a1, a2) | 0;
    }
    if (/^(0[xX]|\d)/.test(t)) {
      if (/L$/i.test(t)) throw new Error('long');
      return parseIntLit(t) | 0;
    }
    if (t === 'true') return 1;
    if (t === 'false') return 0;
    if (/^[A-Za-z_$]/.test(t)) {
      if (env && Object.prototype.hasOwnProperty.call(env, t)) return env[t] | 0;
      throw new Error('var ' + t);
    }
    throw new Error('bad ' + t);
  }

  function mul() {
    let v = primary();
    while (peek() === '*' || peek() === '/' || peek() === '%') {
      const op = toks[k++];
      const r = primary();
      if (op === '*') v = Math.imul(v, r);
      else if (op === '/') { if (r === 0) throw new Error('div0'); v = (v / r) | 0; }
      else { if (r === 0) throw new Error('mod0'); v = (v % r) | 0; }
    }
    return v;
  }

  function add() {
    let v = mul();
    while (peek() === '+' || peek() === '-') {
      const op = toks[k++];
      const r = mul();
      v = (op === '+' ? v + r : v - r) | 0;
    }
    return v;
  }

  function shift() {
    let v = add();
    while (peek() === '<<' || peek() === '>>' || peek() === '>>>') {
      const op = toks[k++];
      const r = add() & 31;
      v = op === '<<' ? v << r : op === '>>' ? v >> r : v >>> r;
    }
    return v;
  }

  function rel() {
    let v = shift();
    while (peek() === '<' || peek() === '>' || peek() === '<=' || peek() === '>=') {
      const op = toks[k++];
      const r = shift();
      v = (op === '<' ? v < r : op === '>' ? v > r : op === '<=' ? v <= r : v >= r) ? 1 : 0;
    }
    return v;
  }

  function eq() {
    let v = rel();
    while (peek() === '==' || peek() === '!=') {
      const op = toks[k++];
      const r = rel();
      v = (op === '==' ? v === r : v !== r) ? 1 : 0;
    }
    return v;
  }

  function bitAnd() {
    let v = eq();
    while (peek() === '&') {
      k++;
      v = (v & eq()) | 0;
    }
    return v;
  }

  function bitXor() {
    let v = bitAnd();
    while (peek() === '^') {
      k++;
      v = (v ^ bitAnd()) | 0;
    }
    return v;
  }

  function bitOr() {
    let v = bitXor();
    while (peek() === '|') {
      k++;
      v = (v | bitXor()) | 0;
    }
    return v;
  }

  function logAnd() {
    let v = bitOr();
    while (peek() === '&&') {
      k++;
      const r = bitOr();
      v = (v && r) ? 1 : 0;
    }
    return v;
  }

  function logOr() {
    let v = logAnd();
    while (peek() === '||') {
      k++;
      const r = logAnd();
      v = (v || r) ? 1 : 0;
    }
    return v;
  }

  function ternary() {
    const c = logOr();
    if (peek() === '?') {
      k++;
      const t = ternary();
      if (toks[k++] !== ':') throw new Error(':');
      const f = ternary();
      return c ? t : f;
    }
    return c;
  }

  const v = ternary();
  if (k !== toks.length) throw new Error('trailing');
  return v;
}

/* Sabit katlama: aritmetik, bit kaydırma, bitwise, tipler, Math metodları ve cebirsel özdeşlikler */
function foldConsts(line) {
  let prev;
  do {
    prev = line;

    // Casts
    line = replaceOutside(line, /\(byte\)\s*\(\s*(-?\d+)\s*\)/g, (_, a) => String((parseInt(a, 10) << 24) >> 24));
    line = replaceOutside(line, /\(byte\)\s*(-?\d+)\b/g, (_, a) => String((parseInt(a, 10) << 24) >> 24));
    line = replaceOutside(line, /\(short\)\s*\(\s*(-?\d+)\s*\)/g, (_, a) => String((parseInt(a, 10) << 16) >> 16));
    line = replaceOutside(line, /\(short\)\s*(-?\d+)\b/g, (_, a) => String((parseInt(a, 10) << 16) >> 16));
    line = replaceOutside(line, /\(char\)\s*\(\s*(-?\d+)\s*\)/g, (_, a) => String(parseInt(a, 10) & 0xFFFF));
    line = replaceOutside(line, /\(int\)\s*\(\s*(-?\d+)\s*\)/g, '$1');
    line = replaceOutside(line, /\(int\)\s*(-?\d+)\b/g, '$1');

    // Bitwise NOT
    line = replaceOutside(line, /~\s*\(\s*(-?\d+)\s*\)/g, (_, a) => String(~parseIntLit(a)));

    // Multiplication, Division, Modulo
    line = replaceOutside(line, new RegExp(`(${INT})\\s*\\*\\s*(${INT})`, 'g'), (_, a, b) => String(Math.imul(parseIntLit(a), parseIntLit(b))));
    line = replaceOutside(line, new RegExp(`(${INT})\\s*\\/\\s*(${INT})`, 'g'), (_, a, b) => {
      const den = parseIntLit(b);
      return den !== 0 ? String((parseIntLit(a) / den) | 0) : _;
    });
    line = replaceOutside(line, new RegExp(`(${INT})\\s*%\\s*(${INT})`, 'g'), (_, a, b) => {
      const den = parseIntLit(b);
      return den !== 0 ? String((parseIntLit(a) % den) | 0) : _;
    });

    // Shifts
    line = replaceOutside(line, new RegExp(`(${INT})\\s*<<\\s*(${INT})`, 'g'), (_, a, b) => String((parseIntLit(a) << (parseIntLit(b) & 31)) | 0));
    line = replaceOutside(line, new RegExp(`(${INT})\\s*>>\\s*(${INT})`, 'g'), (_, a, b) => String(parseIntLit(a) >> (parseIntLit(b) & 31)));
    line = replaceOutside(line, new RegExp(`(${INT})\\s*>>>\\s*(${INT})`, 'g'), (_, a, b) => String(parseIntLit(a) >>> (parseIntLit(b) & 31)));

    // Addition & Subtraction
    line = replaceOutside(line, new RegExp(`(${INT})\\s*\\+\\s*(${INT})`, 'g'), (_, a, b) => String((parseIntLit(a) + parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`(?<=[\\w)\\]])\\s*-\\s*(${INT})`, 'g'), (all, b, off, str) => {
      const lm = new RegExp(`(${INT})\\s*$`).exec(str.slice(0, off));
      if (!lm) return all;
      return String((parseIntLit(lm[1]) - parseIntLit(b)) | 0);
    });

    // Bitwise AND, XOR, OR
    line = replaceOutside(line, new RegExp(`(${INT})\\s*&\\s*(${INT})`, 'g'), (_, a, b) => String((parseIntLit(a) & parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`(${INT})\\s*\\^\\s*(${INT})`, 'g'), (_, a, b) => String((parseIntLit(a) ^ parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`(${INT})\\s*\\|\\s*(${INT})`, 'g'), (_, a, b) => String((parseIntLit(a) | parseIntLit(b)) | 0));

    // Math functions
    line = replaceOutside(line, new RegExp(`Math\\.abs\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => String(Math.abs(parseIntLit(a)) | 0));
    line = replaceOutside(line, new RegExp(`Math\\.max\\(\\s*(${INT})\\s*,\\s*(${INT})\\s*\\)`, 'g'), (_, a, b) => String(Math.max(parseIntLit(a), parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`Math\\.min\\(\\s*(${INT})\\s*,\\s*(${INT})\\s*\\)`, 'g'), (_, a, b) => String(Math.min(parseIntLit(a), parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`Math\\.sqrt\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => String(Math.sqrt(Math.max(0, parseIntLit(a))) | 0));
    line = replaceOutside(line, new RegExp(`Math\\.pow\\(\\s*(${INT})\\s*,\\s*(${INT})\\s*\\)`, 'g'), (_, a, b) => String(Math.pow(parseIntLit(a), parseIntLit(b)) | 0));
    line = replaceOutside(line, new RegExp(`Math\\.floor\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => String(parseIntLit(a)));
    line = replaceOutside(line, new RegExp(`Math\\.ceil\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => String(parseIntLit(a)));
    line = replaceOutside(line, new RegExp(`Math\\.round\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => String(parseIntLit(a)));

    // Integer helper methods
    line = replaceOutside(line, new RegExp(`Integer\\.bitCount\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      let v = parseIntLit(a) | 0;
      v = v - ((v >>> 1) & 0x55555555);
      v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
      return String((((v + (v >>> 4)) & 0x0F0F0F0F) * 0x01010101) >>> 24);
    });
    line = replaceOutside(line, new RegExp(`Integer\\.numberOfLeadingZeros\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      const v = parseIntLit(a) | 0;
      return String(v === 0 ? 32 : Math.clz32(v));
    });
    line = replaceOutside(line, new RegExp(`Integer\\.numberOfTrailingZeros\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      const v = parseIntLit(a) | 0;
      return String(v === 0 ? 32 : 31 - Math.clz32(v & -v));
    });
    line = replaceOutside(line, new RegExp(`Integer\\.highestOneBit\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      const v = parseIntLit(a) | 0;
      return String(v === 0 ? 0 : 1 << (31 - Math.clz32(v)));
    });
    line = replaceOutside(line, new RegExp(`Integer\\.lowestOneBit\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      const v = parseIntLit(a) | 0;
      return String(v & -v);
    });
    line = replaceOutside(line, new RegExp(`Integer\\.reverseBytes\\(\\s*(${INT})\\s*\\)`, 'g'), (_, a) => {
      const v = parseIntLit(a) | 0;
      return String((((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >>> 8) & 0xFF00) | ((v >>> 24) & 0xFF)) | 0);
    });

    // Character methods
    line = replaceOutside(line, /Character\.toUpperCase\(\s*'([^'\\]|\\.)'\s*\)/g, (_, c) => `'${c.toUpperCase()}'`);
    line = replaceOutside(line, /Character\.toLowerCase\(\s*'([^'\\]|\\.)'\s*\)/g, (_, c) => `'${c.toLowerCase()}'`);
    line = replaceOutside(line, /Character\.isDigit\(\s*'([^'\\]|\\.)'\s*\)/g, (_, c) => (/^\d$/.test(c) ? 'true' : 'false'));
    line = replaceOutside(line, /Character\.isLetter\(\s*'([^'\\]|\\.)'\s*\)/g, (_, c) => (/^[a-zA-Z]$/.test(c) ? 'true' : 'false'));

    // Değişken karşılaştırma özdeşlikleri
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*==\s*\1\b/g, 'true');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*!=\s*\1\b/g, 'false');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*<=\s*\1\b/g, 'true');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*>=\s*\1\b/g, 'true');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*<\s*\1\b/g, 'false');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*>\s*\1\b/g, 'false');

    // Cebirsel özdeşlikler
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\^\s*\1\b/g, '0');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*-\s*\1\b/g, '0');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\^\s*0\b/g, '$1');
    line = replaceOutside(line, /\b0\s*\^\s*([A-Za-z_]\w*)\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\|\s*0\b/g, '$1');
    line = replaceOutside(line, /\b0\s*\|\s*([A-Za-z_]\w*)\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\+\s*0\b/g, '$1');
    line = replaceOutside(line, /\b0\s*\+\s*([A-Za-z_]\w*)\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*-\s*0\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\*\s*1\b/g, '$1');
    line = replaceOutside(line, /\b1\s*\*\s*([A-Za-z_]\w*)\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*\/\s*1\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*&\s*-1\b/g, '$1');
    line = replaceOutside(line, /\b-1\s*&\s*([A-Za-z_]\w*)\b/g, '$1');
    line = replaceOutside(line, /\b([A-Za-z_]\w*)\s*&\s*0\b/g, '0');
    line = replaceOutside(line, /\b0\s*&\s*([A-Za-z_]\w*)\b/g, '0');
    line = replaceOutside(line, /Math\.max\(([A-Za-z_]\w*),\s*\1\)/g, '$1');
    line = replaceOutside(line, /Math\.min\(([A-Za-z_]\w*),\s*\1\)/g, '$1');

    // Tek sabit veya tanımlayıcı parantezi
    line = replaceOutside(line, new RegExp(`(?<![\\w)\\]])\\(\\s*(${INT})\\s*\\)`, 'g'), '$1');
    line = replaceOutside(line, /(?<![\w)\]])\(\s*([A-Za-z_]\w*)\s*\)/g, '$1');
  } while (line !== prev);
  return line;
}

function cleanRedundantCasts(text) {
  let prev;
  do {
    prev = text;
    text = text.replace(/\(String\)\s*\(\(Object\)\s*("(?:\\.|[^"\\])*")\)/g, '$1');
    text = text.replace(/\(String\)\s*("(?:\\.|[^"\\])*")/g, '$1');
    text = text.replace(/\(Object\)\s*("(?:\\.|[^"\\])*")/g, '$1');
    text = text.replace(/\(int\)\s*(-?\d+)\b/g, '$1');
    text = text.replace(/\(long\)\s*(-?\d+L?)\b/g, '$1');
    text = text.replace(/\(boolean\)\s*(true|false)\b/g, '$1');
    text = text.replace(/\(Boolean\)\s*(true|false)\b/g, '$1');
    text = text.replace(/\bInteger\.valueOf\(\s*(-?\d+)\s*\)\.intValue\(\)/g, '$1');
    text = text.replace(/\bBoolean\.valueOf\(\s*(true|false)\s*\)\.booleanValue\(\)/g, '$1');
    text = text.replace(/\bLong\.valueOf\(\s*(-?\d+L?)\s*\)\.longValue\(\)/g, '$1');
    text = text.replace(/;;+/g, ';');
  } while (text !== prev);
  return text;
}

function foldBooleansAndBranches(text, stats) {
  let prev;
  let round = 0;
  do {
    prev = text;
    // 1) Mantıksal sabit ifadeler
    text = text.replace(/!true\b/g, 'false');
    text = text.replace(/!false\b/g, 'true');
    text = text.replace(/!\s*\(!\s*([A-Za-z_]\w*)\s*\)/g, '$1');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*==\s*([A-Za-z_]\w*)\s*\)/g, '$1 != $2');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*!=\s*([A-Za-z_]\w*)\s*\)/g, '$1 == $2');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*<\s*([A-Za-z_]\w*)\s*\)/g, '$1 >= $2');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*<=\s*([A-Za-z_]\w*)\s*\)/g, '$1 > $2');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*>\s*([A-Za-z_]\w*)\s*\)/g, '$1 <= $2');
    text = text.replace(/!\s*\(\s*([A-Za-z_]\w*)\s*>=\s*([A-Za-z_]\w*)\s*\)/g, '$1 < $2');
    text = text.replace(/true\s*&&\s*([A-Za-z_]\w*)/g, '$1');
    text = text.replace(/([A-Za-z_]\w*)\s*&&\s*true\b/g, '$1');
    text = text.replace(/false\s*\|\|\s*([A-Za-z_]\w*)/g, '$1');
    text = text.replace(/([A-Za-z_]\w*)\s*\|\|\s*false\b/g, '$1');
    text = text.replace(/true\s*==\s*true\b/g, 'true');
    text = text.replace(/false\s*==\s*false\b/g, 'true');
    text = text.replace(/true\s*!=\s*false\b/g, 'true');
    text = text.replace(/false\s*!=\s*true\b/g, 'true');
    text = text.replace(/true\s*==\s*false\b/g, 'false');
    text = text.replace(/false\s*==\s*true\b/g, 'false');
    text = text.replace(/\b1\s*==\s*1\b/g, 'true');
    text = text.replace(/\b0\s*==\s*0\b/g, 'true');
    text = text.replace(/\b1\s*!=\s*0\b/g, 'true');
    text = text.replace(/\b0\s*!=\s*1\b/g, 'true');
    text = text.replace(/\b1\s*==\s*0\b/g, 'false');
    text = text.replace(/\b0\s*==\s*1\b/g, 'false');
    text = text.replace(/\b1\s*!=\s*1\b/g, 'false');
    text = text.replace(/\b0\s*!=\s*0\b/g, 'false');

    // 2) Ternary operatörleri
    text = text.replace(/\btrue\s*\?\s*([^:;\n)]+?)\s*:\s*([^;,\n)]+)/g, '$1');
    text = text.replace(/\bfalse\s*\?\s*([^:;\n)]+?)\s*:\s*([^;,\n)]+)/g, '$2');
    text = text.replace(/([A-Za-z_]\w*)\s*\?\s*true\s*:\s*false\b/g, '$1');
    text = text.replace(/([A-Za-z_]\w*)\s*\?\s*false\s*:\s*true\b/g, '!$1');

    // 3) if/while blokları
    const lines = text.split('\n');
    let changed = false;
    for (let i = 0; i < lines.length && !changed; i++) {
      const t = lines[i].trim();
      if (/^if\s*\(\s*true\s*\)\s*\{$/.test(t)) {
        const j = matchClose(lines, i);
        if (j > i) {
          if (lines[j].trim() === '}') {
            let k = j + 1;
            while (k < lines.length && lines[k].trim() === '') k++;
            if (k < lines.length && /^(?:\}\s*)?else\s*\{$/.test(lines[k].trim())) {
              const elEnd = matchClose(lines, k);
              if (elEnd > k) lines.splice(k, elEnd - k + 1);
            }
            lines.splice(j, 1);
            lines.splice(i, 1);
            changed = true; break;
          } else if (/^\}\s*else\s*\{$/.test(lines[j].trim())) {
            const elEnd = matchClose(lines, j, true);
            if (elEnd > j) {
              lines.splice(j, elEnd - j + 1);
              lines.splice(i, 1);
              changed = true; break;
            }
          }
        }
      } else if (/^if\s*\(\s*false\s*\)\s*\{$/.test(t)) {
        const j = matchClose(lines, i);
        if (j > i) {
          if (lines[j].trim() === '}') {
            let k = j + 1;
            while (k < lines.length && lines[k].trim() === '') k++;
            if (k < lines.length && /^(?:\}\s*)?else\s*\{$/.test(lines[k].trim())) {
              const elEnd = matchClose(lines, k);
              if (elEnd > k) {
                lines.splice(elEnd, 1);
                lines.splice(i, k - i + 1);
                changed = true; break;
              }
            } else {
              lines.splice(i, j - i + 1);
              changed = true; break;
            }
          } else if (/^\}\s*else\s*\{$/.test(lines[j].trim())) {
            const elEnd = matchClose(lines, j, true);
            if (elEnd > j) {
              lines.splice(elEnd, 1);
              lines.splice(i, j - i + 1);
              changed = true; break;
            }
          }
        }
      } else if (/^while\s*\(\s*(?:false|0\s*!=\s*0|1\s*==\s*0)\s*\)\s*\{$/.test(t)) {
        const j = matchClose(lines, i);
        if (j > i) {
          lines.splice(i, j - i + 1);
          changed = true; break;
        }
      } else if (/^do\s*\{$/.test(t)) {
        const j = matchClose(lines, i);
        if (j > i && /^\}\s*while\s*\(\s*false\s*\);$/.test(lines[j].trim())) {
          lines.splice(j, 1);
          lines.splice(i, 1);
          changed = true; break;
        }
      }
    }
    if (changed) text = lines.join('\n');
  } while (text !== prev && round++ < 20);
  return text;
}

function foldStrings(text, stats) {
  let prev;
  let count = 0;
  do {
    prev = text;

    // 1) Base64 String Açma
    text = text.replace(/new String\(\s*Base64\.(?:getDecoder|getUrlDecoder)\(\)\.decode\(\s*"([A-Za-z0-9+/=_\-]+)"\s*\)(?:\s*,\s*(?:StandardCharsets\.)?(?:UTF_8|"UTF-8"))?\s*\)/g, (all, b64) => {
      try {
        const cleanB64 = b64.replace(/-/g, '+').replace(/_/g, '/');
        const buf = Buffer.from(cleanB64, 'base64');
        const decoded = buf.toString('utf8');
        if (!decoded.includes('\uFFFD') && decoded.length > 0) {
          count++;
          return javaString(decoded);
        }
      } catch {}
      return all;
    });

    // 2) StringBuilder / StringBuffer zincir katlama
    text = text.replace(/new (?:StringBuilder|StringBuffer)\(\s*(?:"((?:\\.|[^"\\])*)")?\s*\)((?:\.append\((?:"(?:\\.|[^"\\])*"|-?\d+|true|false)\))+)\.toString\(\)/g, (all, init, chain) => {
      let res = init || '';
      const appRe = /\.append\(\s*(?:"((?:\\.|[^"\\])*)"|(-?\d+|true|false))\s*\)/g;
      let am;
      while ((am = appRe.exec(chain))) {
        res += am[1] !== undefined ? am[1] : am[2];
      }
      count++;
      return javaString(res);
    });
    text = text.replace(/new StringBuilder\(\s*"((?:\\.|[^"\\])*)"\s*\)\.append\(\s*"((?:\\.|[^"\\])*)"\s*\)/g, 'new StringBuilder("$1$2")');
    text = text.replace(/new StringBuilder\(\s*\)\.append\(\s*"((?:\\.|[^"\\])*)"\s*\)/g, 'new StringBuilder("$1")');
    text = text.replace(/new StringBuilder\(\s*"((?:\\.|[^"\\])*)"\s*\)\.append\(\s*(-?\d+)\s*\)/g, 'new StringBuilder("$1$2")');
    text = text.replace(/new StringBuilder\(\s*"((?:\\.|[^"\\])*)"\s*\)\.append\(\s*(true|false)\s*\)/g, 'new StringBuilder("$1$2")');
    text = text.replace(/new StringBuilder\(\s*"((?:\\.|[^"\\])*)"\s*\)\.toString\(\)/g, '"$1"');
    text = text.replace(/new StringBuffer\(\s*"((?:\\.|[^"\\])*)"\s*\)\.toString\(\)/g, '"$1"');

    // 3) String birleştirme
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\s*\+\s*"((?:\\.|[^"\\\n])*)"/g, '"$1$2"');

    // 4) String literal metotları
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.length\(\)/g, (_, s) => String(s.length));
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.substring\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (all, s, a, b) => {
      const start = parseInt(a, 10), end = parseInt(b, 10);
      if (start >= 0 && end >= start && end <= s.length) {
        return javaString(s.slice(start, end));
      }
      return all;
    });
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.substring\(\s*(\d+)\s*\)/g, (all, s, a) => {
      const start = parseInt(a, 10);
      if (start >= 0 && start <= s.length) {
        return javaString(s.slice(start));
      }
      return all;
    });
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.toLowerCase\(\)/g, (_, s) => javaString(s.toLowerCase()));
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.toUpperCase\(\)/g, (_, s) => javaString(s.toUpperCase()));
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.trim\(\)/g, (_, s) => javaString(s.trim()));
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.concat\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => javaString(a + b));
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.equals\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => a === b ? 'true' : 'false');
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.equalsIgnoreCase\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => a.toLowerCase() === b.toLowerCase() ? 'true' : 'false');
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.contains\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => a.includes(b) ? 'true' : 'false');
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.startsWith\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => a.startsWith(b) ? 'true' : 'false');
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.endsWith\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, (_, a, b) => a.endsWith(b) ? 'true' : 'false');
    text = text.replace(/"((?:\\.|[^"\\\n])*)"\.isEmpty\(\)/g, (_, s) => s.length === 0 ? 'true' : 'false');
    text = text.replace(/String\.valueOf\(\s*"((?:\\.|[^"\\\n])*)"\s*\)/g, '"$1"');
    text = text.replace(/String\.valueOf\(\s*(-?\d+)\s*\)/g, '"$1"');
    text = text.replace(/String\.valueOf\(\s*(true|false)\s*\)/g, '"$1"');

    // 5) Char[] ve Byte[] dizi dizgeleri
    text = text.replace(/new String\(\s*new char\[\]\s*\{([^}]+)\}\s*\)/g, (all, inner) => {
      try {
        const parts = inner.split(',').map(x => x.trim()).filter(Boolean);
        let s = '';
        for (const p of parts) {
          if (p.startsWith("'") && p.endsWith("'") && p.length >= 3) {
            const ch = p.slice(1, -1);
            s += ch === "\\'" ? "'" : ch === '\\\\' ? '\\' : ch === '\\n' ? '\n' : ch === '\\t' ? '\t' : ch;
          } else if (/^\d+$/.test(p)) {
            s += String.fromCharCode(parseInt(p, 10));
          } else {
            return all;
          }
        }
        count++;
        return javaString(s);
      } catch { return all; }
    });
    text = text.replace(/new String\(\s*new byte\[\]\s*\{([^}]+)\}(?:\s*,\s*(?:StandardCharsets\.)?UTF_8)?\s*\)/g, (all, inner) => {
      try {
        const bytes = inner.split(',').map(x => parseInt(x.trim(), 10) & 255);
        if (bytes.some(Number.isNaN)) return all;
        const s = Buffer.from(bytes).toString('utf8');
        if (!s.includes('\uFFFD') && s.length > 0) {
          count++;
          return javaString(s);
        }
      } catch {}
      return all;
    });

  } while (text !== prev);

  // 6) String içi yazdırılabilir unicode temizliği (\u0048 -> H)
  text = text.replace(/"((?:\\.|[^"\\\n])*)"/g, (all, inner) => {
    if (!inner.includes('\\u00')) return all;
    const unesc = inner.replace(/\\u00([2-7][0-9a-fA-F])/g, (m, hex) => {
      const code = parseInt(hex, 16);
      if (code >= 0x20 && code <= 0x7e && code !== 0x22 && code !== 0x5c) {
        return String.fromCharCode(code);
      }
      return m;
    });
    return `"${unesc}"`;
  });

  if (stats && count) stats.strings = (stats.strings || 0) + count;
  return text;
}

const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/* ------------------------------------------------------------ ana işlev */

/* CFR'nin bıraktığı gürültü: etiketler, GOTO işaretleri, yığın izi yorumları */
function cleanCfrNoise(text) {
  return text
    .replace(/\/\*\s*\n\s*\* Could not load the following classes:[\s\S]*?\*\/[ \t]*\n/, '')
    .replace(/\/\*\s*\n(?:\s*\* (?:Unable to fully structure code|Enabled [a-z ]+|Lifted jumps to return sinks|Duplicating code[a-z ]*|Loose catch block)[ \t]*\n)+\s*\*\/[ \t]*\n/g, '')
    .replace(/\/\*\s*\n\s*\* This method has failed to decompile\.[^\n]*\n\s*\*[ \t]*\n\s*\* ([^\n]*)\n(?:\s*\*[^\n]*\n)*?\s*\*\//g,
      (m, why) => `// CFR bu metodu decompile edemedi: ${why.replace(/^[\w.]*Exception:\s*/, '')}`)
    .replace(/\}[ \t]*else[ \t]+lbl-?\d+:/g, '}')              // "} else lbl-1000:"
    .replace(/^[ \t]*lbl-?\d+:[ \t]*\n/gm, '')                   // "lbl178:"
    .replace(/^[ \t]*\/\/\s*\d+ sources?[ \t]*\n/gm, '')         // "// 3 sources"
    .replace(/^[ \t]*\*\* GOTO \S+[ \t]*\n/gm, '');              // çıplak "** GOTO lbl-1000"
}

/* "try { KOD } catch (Throwable t) { throw Cls.a(t); }"  ->  KOD
 * (exception-sarmalayıcı çöp; yalnızca tek catch'i bu olan ve finally'siz try'lar açılır) */
function unwrapRethrowTry(text) {
  const lines = text.split('\n');
  const tryRe = /^\s*try \{\s*$/;
  const catchRe = /^\s*(?:\}\s*)?catch \((?:[\w.]+(?:\s*\|\s*[\w.]+)*) (\w+)\) \{\s*$/;
  const throwRe = (v) => new RegExp(String.raw`^\s*throw [A-Za-z_][\w.]*\.[A-Za-z_]\w*\(\s*${v}\s*\);\s*$`);
  for (let guard = 0; guard < 20000; guard++) {
    let hit = false;
    for (let i = lines.length - 1; i >= 0 && !hit; i--) {      // iç içe try'lar: içten dışa
      if (!tryRe.test(lines[i])) continue;
      const j = matchClose(lines, i, false);
      if (j < 0 || j + 3 >= lines.length) continue;
      if (lines[j].trim() !== '}') continue;
      let k = j + 1; while (k < lines.length && lines[k].trim() === '') k++;
      const c = catchRe.exec(lines[k] || '');
      if (!c || !throwRe(c[1]).test(lines[k + 1] || '') || (lines[k + 2] || '').trim() !== '}') continue;
      const nx = (lines[k + 3] || '').trim();
      if (/^(?:catch|finally)\b/.test(nx) || /^\}\s*(?:catch|finally)\b/.test(nx)) continue;
      lines.splice(k, 3);       // catch bloğu
      lines.splice(j, 1);       // try'ın kapanışı
      lines.splice(i, 1);       // "try {"
      hit = true;
    }
    if (!hit) break;
  }
  return lines.join('\n');
}

function deobfuscate(original) {
  try { return deobfuscateCore(original); }
  catch (e) {   // sağlamlık: bir geçiş çökerse dosyayı yalnızca CFR gürültüsü temizlenmiş haliyle ver
    let t = original;
    try { t = cleanCfrNoise(original.replace(/\r\n/g, '\n')); } catch {}
    return { text: t, stats: { helpers: 0, constants: 0, inlined: 0, removedLines: 0, error: String(e && e.message || e) } };
  }
}

function deobfuscateCore(original) {
  const before = original.split('\n').length;
  const pre = {};
  let input = cleanCfrNoise(original.replace(/\r\n/g, '\n'));
  input = decryptSkidStrings(input, pre);       // Skidfuscator string şifreleme (ByteArray + Integer.toString(key) XOR)
  input = decryptAllatori(input, pre).code;     // Allatori ve genel XOR string çözücü
  input = foldStaticStringArrays(input, pre).code; // ZKM ve statik String[] dizi çözücü
  input = removeJunkTry(input);                 // sahte "try { throw new X(); } catch (X e) { }" blokları
  input = unwrapRethrowTry(input);              // "catch (Throwable t) { throw X.a(t); }" sarmalayıcıları
  input = cleanRedundantCasts(input);           // gereksiz cast'ler
  input = foldStrings(input, pre);              // base64, stringbuilder, concat, literal metotları
  input = foldBooleansAndBranches(input, pre);  // boolean ve dal temizliği
  input = input.split('\n').map(l => (/[+\-*\/%^&|~<>]|0x|Math\.|Integer\.|Character\./.test(l) ? foldConsts(l) : l)).join('\n');

  const hasFlow = input.includes('^') && /[!=]=\s*\(?-?\d{6,}/.test(input);
  const hasStr = /UTF_16BE/.test(input) && /asCharBuffer\(\)/.test(input);
  const keyCalls = (input.match(/,\s*-?\d{8,}\)/g) || []).length >= 3;      // "metot(args, 2107110457)" anahtar parametreleri
  const hasConstMath = /\b(?:0x[0-9a-fA-F]+|\d+)\s*[\+\-\*\/%^&|]\s*(?:0x[0-9a-fA-F]+|\d+)\b/.test(input);
  const hasBase64 = /Base64\.(?:getDecoder|getUrlDecoder)/.test(input);
  const obf = hasFlow || hasStr || keyCalls || hasConstMath || hasBase64 || !!pre.skidStrings || !!pre.strings || !!pre.allatori || !!pre.zkm;
  if (!obf)
    return { text: input, stats: { helpers: 0, constants: pre.strings || 0, inlined: 0, removedLines: 0 } };
  let text = input;

  /* 1. CFR gürültüsü */
  text = text
    .replace(/\/\*\s*\n\s*\*\s*Unable to fully structure code\s*\n\s*\*\/\s*\n/g, '')
    .replace(/\/\*\s*\n(?:\s*\*[^\n]*\n)*?\s*\*\s*(?:Exception decompiling|Could not resolve)[^\n]*\n(?:\s*\*[^\n]*\n)*?\s*\*\/\s*\n/g, '')
    .replace(/^[ \t]*\/\/\s*\/\*.*\*\/[ \t]*\n/gm, '')          // // /* GOTO lbl */
    .replace(/[ \t]*\/\/\s*\/\*.*\*\/[ \t]*$/gm, '')            // sondaki // /* lbl-1000: */
    .replace(/\belse\s*\n\s*\{/g, 'else {');

  let lines = text.split('\n');

  /* saf çöp: "123 ^ var;" ve cfr_ignored */
  lines = lines.filter(l => {
    const t = l.trim();
    return !(/^-?\d+ \^ \w+;$/.test(t) || /^(?:final\s+)?(?:int|long|boolean|Object|double|float|short|byte|char|var|[\w.<>\[\]]+)\s+cfr_ignored_\d+\s*(?:=\s*[^;\n]+)?;$/.test(t));
  });
  text = lines.join('\n');

  /* 2. Yardımcı çağrıları */
  const helperCount = new Map();
  const stateVars = new Set();
  const det = new RegExp(`\\b([A-Za-z_]\\w*\\.[A-Za-z_]\\w*)\\(\\s*([A-Za-z_]\\w*)\\s*\\)\\s*[!=]=\\s*\\(?\\s*(${INT})`, 'g');
  let m;
  const cand = [];
  while ((m = det.exec(text))) {
    if (Math.abs(parseIntLit(m[3])) < 100000) continue;
    helperCount.set(m[1], (helperCount.get(m[1]) || 0) + 1);
    cand.push([m[1], m[2]]);
  }
  const helpers = [...helperCount].filter(([, c]) => c >= 3).map(([n]) => n);
  const helperClasses = new Set(helpers.map(h => h.split('.')[0]));
  const guardSrc = helperClasses.size ? String.raw`(?:${[...helperClasses].map(esc).join('|')})\.\w+\(\s*\w+\s*\)` : null;
  const guardRe = guardSrc ? new RegExp(guardSrc) : null;
  if (guardSrc) {
    const any = new RegExp(String.raw`(?:${[...helperClasses].map(esc).join('|')})\.\w+\(\s*([A-Za-z_]\w*)\s*\)`, 'g');
    let q; while ((q = any.exec(text))) stateVars.add(q[1]);
  }

  const stats = { helpers: helpers.length, constants: pre.strings || 0, inlined: 0 };

  // aynı satıra sıkışmış guard'lar:  if (H(x) != C) break label;
  if (guardSrc) {
    const g = `if \\(${guardSrc}\\s*!=\\s*\\(?-?\\d+\\)?\\)\\s*(?:break|continue)(?: \\w+)?;`;
    text = text.replace(new RegExp(`^[ \\t]*${g}[ \\t]*\\n`, 'gm'), '')          // satırın tamamı guard
               .replace(new RegExp(`${g}[ \\t]*`, 'g'), '');                    // satır içindeki guard'lar
  }

  /* 3. Anahtar zincirini hesapla */
  if (guardRe) text = simulateKeys(text, stateVars, guardRe, stats);

  /* 4-5. Yapısal temizlik (kararlı olana kadar) */
  lines = text.split('\n');
  for (let round = 0; round < 25; round++) {
    const n0 = lines.length;
    if (guardRe) lines = structuralPass(lines, guardRe);
    lines = deadAfterReturn(lines);
    lines = unwrapBlocks(lines);
    if (lines.length === n0) break;
  }
  if (stateVars.size) lines = removeDeadKeys(lines, stateVars);
  for (let round = 0; round < 10; round++) {
    const n0 = lines.length;
    lines = deadAfterReturn(lines);
    lines = unwrapBlocks(lines);
    if (lines.length === n0) break;
  }
  text = lines.join('\n');
  text = foldBooleansAndBranches(text, stats);
  text = decryptStrings(text, stats);          // şifreli string'leri gerçek değerlerine çevir, çözücüyü sil
  text = decryptAllatori(text, stats).code;
  text = foldStaticStringArrays(text, stats).code;
  text = foldStrings(text, stats);
  text = removeJunkArrays(text, stats);        // "nothing_to_see_here" dizileri, Random çöpleri
  lines = text.split('\n');
  if (obf) lines = cleanLocals(lines, stats);
  lines = lines.map(l => (/[+\-*\/%^&|~<>]|0x|Math\./.test(l) ? foldConsts(l) : l));
  text = lines.join('\n');
  text = foldBooleansAndBranches(text, stats);
  text = cleanRedundantCasts(text);
  if (obf) { text = removeKeyParams(text, stats); text = removeJunkFields(text, stats); }

  /* kullanılmayan helper import'ları */
  for (const cls of helperClasses) {
    const body = text.replace(/^import .*;$/gm, '');
    if (!new RegExp(`\\b${esc(cls)}\\b`).test(body)) text = text.replace(new RegExp(`^import [\\w.]*\\b${esc(cls)};\\n`, 'm'), '');
  }

  if (obf) {   // kullanılmayan import'lar
    const body = text.replace(/^import .*;$/gm, '');
    text = text.replace(/^import (?:static )?[\w.]*\.(\w+);\n/gm, (all, simple) => (new RegExp(`\\b${simple}\\b`).test(body) ? all : ''));
  }

  text = reindent(text).replace(/\n{3,}/g, '\n\n').replace(/\{\n\n/g, '{\n').replace(/\n\n(\s*\})/g, '\n$1');
  stats.removedLines = Math.max(0, before - text.split('\n').length);
  return { text, stats };
}

/* ------------------------------------------------------------ anahtar simülasyonu */

function findMethods(lines) {
  const out = [];
  // geri izlemesiz (backtracking) metot başlığı: [değiştiriciler] [tip] ad(parametreler) [throws ..] {
  const defRe = /^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*(?:[\w.]+(?:<[^()]*?>)?(?:\[\])*\s+)?(\w+)\(([^)]*)\)\s*(?:throws [\w., ]+)?\{\s*$/;
  const FIRST_KW = /^\s*(?:if|for|while|switch|catch|try|do|else|return|throw|new|\}|case|default|synchronized\s*\()\b/;
  for (let i = 0; i < lines.length; i++) {
    const L = lines[i];
    if (L.charCodeAt(L.length - 1) !== 123 /* { */ || L.indexOf('(') < 0 || L.length > 400 || FIRST_KW.test(L)) continue;
    const d = defRe.exec(L);
    if (!d || NOT_METHOD.has(d[1])) continue;
    if (/^\s*(?:else|\}|\w+\s*=)/.test(lines[i])) continue;
    const close = matchClose(lines, i);
    if (close < 0) continue;
    const pm = /\bint\s+(\w+)\s*$/.exec(d[2].trim());
    out.push({ name: d[1], start: i, end: close, lastIntParam: pm ? pm[1] : null });
  }
  return out;
}

function simulateKeys(text, stateVars, guardRe, stats) {
  const lines = text.split('\n');
  // çağrı noktalarından sabit parametreler (super.* hariç)
  const callMap = new Map();
  const callRe = /(?<![\w.])((?:\w+\.)?)(\w+)\s*\(([^()]*?)(-?\d{6,})\)/g;
  for (const l of lines) {
    let c;
    callRe.lastIndex = 0;
    while ((c = callRe.exec(l))) {
      if (c[1] === 'super.') continue;
      const s = callMap.get(c[2]) || new Set(); s.add(c[4]); callMap.set(c[2], s);
    }
  }
  // "x.name(" biçimindeki çağrılar için de dene
  const callRe2 = /\b\w+\.(\w+)\s*\(([^()]*?)(-?\d{6,})\)/g;
  for (const l of lines) {
    let c; callRe2.lastIndex = 0;
    while ((c = callRe2.exec(l))) {
      if (/super\.\w+\s*\(/.test(c[0])) continue;
      const s = callMap.get(c[1]) || new Set(); s.add(c[3]); callMap.set(c[1], s);
    }
  }

  for (const meth of findMethods(lines)) {
    // çağrı noktasından gelen sabit parametre (varsa); yoksa yalnızca parametresiz zincirler çözülür
    const lits = callMap.get(meth.name);
    const param = meth.lastIntParam;
    const literal = param && lits && lits.size === 1 ? parseInt([...lits][0], 10) | 0 : null;

    const ids = new Set(lines.slice(meth.start, meth.end + 1).join('\n').match(/[A-Za-z_]\w*/g) || []);
    const vars = new Set([...stateVars].filter(v => ids.has(v)));

    for (const v of vars) {
      const env = literal === null ? {} : { [param]: literal };
      const edits = new Map();           // satır -> yeni metin | null (sil)
      let ok = true;
      const vre = new RegExp(`\\b${esc(v)}\\b`);
      const asg = new RegExp(`^(\\s*)(?:int |long )?${esc(v)} = (.*);\\s*$`);
      for (let i = meth.start + 1; i < meth.end && ok; i++) {
        const l = lines[i];
        if (!vre.test(l)) continue;
        if (new RegExp(String.raw`^\s*(?:int|long) ${esc(v)};\s*$`).test(l)) { edits.set(i, null); continue; }
        const a = asg.exec(l);
        if (a) {
          try { env[v] = evalExpr(a[2], env); edits.set(i, null); }
          catch { ok = false; }
          continue;
        }
        if (guardRe.test(l)) continue;              // guard'lar zaten silinecek
        if (!Object.prototype.hasOwnProperty.call(env, v)) { ok = false; break; }
        edits.set(i, foldConsts(l.replace(new RegExp(`\\b${esc(v)}\\b`, 'g'), String(env[v]))));
      }
      if (!ok) continue;
      let n = 0;
      for (const [i, val] of edits) { if (val !== null) n++; lines[i] = val === null ? '\u0000DEL' : val; }
      stats.constants += n;
    }
  }
  return lines.filter(l => l !== '\u0000DEL').join('\n');
}

/* ------------------------------------------------------------ yapısal temizlik */

const JUNK_THROW = /^throw new \w+(?:\((?:"[^"]*")?\))?;$/;

function structuralPass(lines, guardRe) {
  const del = new Set();
  const mark = (a, b) => { for (let x = a; x <= b; x++) del.add(x); };

  for (let i = 0; i < lines.length; i++) {
    if (del.has(i)) continue;
    const t = lines[i].trim();
    const t2 = t.replace(/^\w+:\s+(?=(?:while|do)\b)/, '');       // "block20: while (true) {" -> "while (true) {"

    // ölü döngüler (while / do-while) ve içinde sadece "break;" olan döngü
    if ((/^while \(/.test(t2) || /^do \{$/.test(t2)) && t2.endsWith('{')) {
      const j = matchClose(lines, i);
      if (j >= i && guardRe.test(lines.slice(i, j + 1).join('\n'))) {
        mark(i, j);
        for (let k = j + 1; k < lines.length; k++) {
          const u = lines[k].trim();
          if (u === '' || JUNK_THROW.test(u) || /^-?\d+ \^ \w+;$/.test(u) || /^int cfr_ignored_\d+/.test(u)) del.add(k); else break;
        }
        continue;
      }
    }
    if (/^while \(true\) \{$/.test(t2)) {
      const j = matchClose(lines, i);
      const body = j > i ? lines.slice(i + 1, j) : [];
      if (j > i && body.some(x => x.trim() === 'break;') && body.every(x => /^\s*(?:break;)?\s*$/.test(x))) { mark(i, j); continue; }
    }
    // switch (Helper.f(x))
    if (/^switch \(/.test(t) && guardRe.test(t) && t.endsWith('{')) {
      const j = matchClose(lines, i); if (j >= i) { mark(i, j); continue; }
    }
    if (/^if \(/.test(t) && guardRe.test(t)) {
      // if (H(x) != C) break/continue;  -> asla çalışmaz
      if (/!=/.test(t) && /\)\s*(?:(?:break|continue)(?: \w+)?;|\*\* GOTO \S+)$/.test(t) && !/&&/.test(t)) { del.add(i); continue; }
      // if (H(x) == C) { ... } else { ... } -> gövdeyi aç, else'i at
      if (/^if \(\w+\.\w+\(\w+\) == -?\d+\) \{$/.test(t)) {
        const j = matchClose(lines, i);
        if (j < 0) continue;
        const e = lines[j].trim();
        if (e === '}') { del.add(i); del.add(j); }
        else if (/^\}\s*else\s*\{$/.test(e)) {
          const k = matchClose(lines, j, true);
          if (k < 0) continue;
          del.add(i); mark(j, k);
        }
      }
    }
  }
  return lines.filter((_, i) => !del.has(i));
}

/* return/throw/break sonrasındaki ulaşılamaz "break label;" ifadeleri */
function deadAfterReturn(lines) {
  const out = [];
  let dead = false;
  for (const l of lines) {
    const t = l.trim();
    if (dead) {
      if (/^(?:break|continue)(?: \w+)?;$/.test(t)) continue;
      if (t !== '') dead = false;
    }
    out.push(l);
    if (/^(?:return\b.*|throw\b.*);$/.test(t)) dead = true;
  }
  return out;
}

/* kullanılmayan etiketler, çıplak { } blokları, boş else */
function unwrapBlocks(lines) {
  const refs = new Set();
  const refRe = /\b(?:break|continue) (\w+);/g;
  const allText = lines.join('\n');
  let rm; while ((rm = refRe.exec(allText))) refs.add(rm[1]);
  const del = new Set();

  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    const lab = /^(\w+): \{$/.exec(t);
    if (lab && !refs.has(lab[1])) {
      const j = matchClose(lines, i); if (j > i) { del.add(i); del.add(j); }
    } else if (t === '{') {
      const j = matchClose(lines, i); if (j > i) { del.add(i); del.add(j); }
    }
  }
  lines = lines.filter((_, i) => !del.has(i));

  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    // "} else {" + "}" -> "}"
    if (/^\}\s*else\s*\{$/.test(t)) {
      let k = i + 1; while (k < lines.length && lines[k].trim() === '') k++;
      if (k < lines.length && lines[k].trim() === '}') { out.push(lines[i].replace(/\}\s*else\s*\{/, '}')); i = k; continue; }
    }
    out.push(lines[i]);
  }
  return out;
}

/* kullanılmayan anahtar atamaları */
function removeDeadKeys(lines, stateVars) {
  const del = new Set();
  for (const meth of findMethods(lines)) {
    const ids = new Set(lines.slice(meth.start, meth.end + 1).join('\n').match(/[A-Za-z_]\w*/g) || []);
    for (const v of stateVars) {
      if (!ids.has(v)) continue;
      const vre = new RegExp(`\\b${esc(v)}\\b`);
      const asg = new RegExp(`^\\s*(?:(?:int|long) ${esc(v)};|(?:int |long )?${esc(v)} = .*;)\\s*$`);
      let refs = 0; const asgLines = [];
      for (let i = meth.start; i <= meth.end; i++) {
        if (!vre.test(lines[i])) continue;
        if (asg.test(lines[i])) asgLines.push(i); else refs++;
      }
      if (refs === 0) asgLines.forEach(i => del.add(i));
    }
  }
  return lines.filter((_, i) => !del.has(i));
}

/* ------------------------------------------------------------ string şifre çözme */

/*
 * Bilinen düzen:
 *   static String T = ByteBuffer.wrap(tableBytes()).asCharBuffer().toString();
 *   static String dec(byte[] spec, int key) { ...substring(offset, offset+len)... UTF_16BE ... ^ key(Integer.toString)... }
 *   dec(specBytes(), 1234567)  ->  "gerçek string"
 */
function decryptStrings(text, stats) {
  const decM = /static String (\w+)\(byte\[\] \w+, int \w+\) \{/.exec(text);
  const tbl = /(\w+) = ByteBuffer\.wrap\((?:\w+\.)?(\w+)\(\)\)\.asCharBuffer\(\)\.toString\(\);/.exec(text);
  if (!decM || !tbl) return text;
  const decName = decM[1], tableField = tbl[1], tableMethod = tbl[2];

  let lines = text.split('\n');
  const decMeth = findMethods(lines).find(m => m.name === decName);
  if (!decMeth) return text;
  const body = lines.slice(decMeth.start, decMeth.end + 1).join('\n');
  if (!/\.substring\(/.test(body) || !/UTF_16BE/.test(body) || !/\^/.test(body) || !/Integer\.toString\(/.test(body)) return text;

  // sabit byte[] döndüren metotlar
  const arrays = new Map();
  const arrRe = /static byte\[\] (\w+)\(\) \{\s*return new byte\[\]\s*\{([^}]*)\};\s*\}/g;
  let a;
  while ((a = arrRe.exec(text))) arrays.set(a[1], a[2].split(',').map(x => parseInt(x.trim(), 10) & 255));
  const table = arrays.get(tableMethod);
  if (!table) return text;
  const chars = [];
  for (let i = 0; i + 1 < table.length; i += 2) chars.push((table[i] << 8) | table[i + 1]);

  const callRe = new RegExp(String.raw`(?:\w+\.)?${esc(decName)}\(\s*(?:\w+\.)?(\w+)\(\)\s*,\s*(-?\d+)\s*\)`, 'g');
  let replaced = 0;
  text = text.replace(callRe, (all, specName, keyStr) => {
    const spec = arrays.get(specName);
    if (!spec || spec.length !== 8) return all;
    const len = ((spec[0] << 24) | (spec[1] << 16) | (spec[2] << 8) | spec[3]) | 0;
    const off = ((spec[4] << 24) | (spec[5] << 16) | (spec[6] << 8) | spec[7]) | 0;
    if (len < 0 || off < 0 || off + len > chars.length) return all;
    const key = Buffer.from(String(parseInt(keyStr, 10) | 0), 'latin1');
    const bytes = [];
    for (const c of chars.slice(off, off + len)) bytes.push(c >> 8, c & 255);
    for (let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
    let s = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    replaced++;
    return javaString(s);
  });
  if (!replaced) return text;
  stats.strings = (stats.strings || 0) + replaced;

  // artık kullanılmayan çözücü, byte[] metotları ve tablo alanı
  lines = text.split('\n');
  const stillCalled = new RegExp(String.raw`\b${esc(decName)}\(`);
  const names = new Set();
  const dm = findMethods(lines).find(m => m.name === decName);
  if (dm && !lines.some((l, i) => (i < dm.start || i > dm.end) && stillCalled.test(l))) names.add(decName);
  lines = removeDeadMethods(lines, names);

  const tre = new RegExp(String.raw`(?<![\w.])${esc(tableField)}\b`);
  const refs = lines.map((l, i) => (tre.test(l) ? i : -1)).filter(i => i >= 0);
  if (refs.length === 2 && refs.every(i => /ByteBuffer\.wrap|^\s*(?:(?:private|public|protected|static|final)\s+)*String\s+\w+;\s*$/.test(lines[i]))) {
    lines = lines.filter((_, i) => !refs.includes(i));
    lines = removeDeadMethods(lines, new Set());        // tablo byte[] metodu artık kullanılmıyor
  }
  return lines.join('\n');
}

/* hiçbir yerden çağrılmayan private static metotları (ve verilen adları) sil */
function removeDeadMethods(lines, alwaysNames) {
  for (let round = 0; round < 12; round++) {
    const text = lines.join('\n');
    const counts = new Map();
    for (const id of text.match(/[A-Za-z_]\w*/g) || []) counts.set(id, (counts.get(id) || 0) + 1);
    let removed = false;
    for (const m of findMethods(lines).sort((x, y) => y.start - x.start)) {
      const isPrivStatic = /\bprivate\b.*\bstatic\b|\bstatic\b.*\bprivate\b/.test(lines[m.start]);
      if (!(isPrivStatic || alwaysNames.has(m.name)) || counts.get(m.name) !== 1) continue;
      let s = m.start;
      while (s > 0 && /^\s*@\w+/.test(lines[s - 1])) s--;           // üstündeki @Annotation'lar
      lines.splice(s, m.end - s + 1);
      removed = true; break;
    }
    if (!removed) break;
  }
  return lines;
}

/* yazılıp hiç okunmayan String[] dizileri ve static bloklardaki Random çöpleri */
function removeJunkArrays(text, stats) {
  let lines = text.split('\n');
  const mods = String.raw`(?:(?:private|public|protected|static|final)\s+)*`;
  const names = new Set();
  for (const l of lines) { const d = new RegExp(String.raw`^\s*${mods}String\[\] (\w+)(?: = new String\[\d+\])?;\s*$`).exec(l); if (d) names.add(d[1]); }
  const del = new Set();
  for (const name of names) {
    const wre = new RegExp(String.raw`(?<![\w])${esc(name)}\b`);
    const allowed = [
      new RegExp(String.raw`^\s*${mods}String\[\] ${esc(name)}(?: = new String\[\d+\])?;\s*$`),
      new RegExp(String.raw`^\s*(?:\w+\.)?${esc(name)} = new String\[\d+\];\s*$`),
      new RegExp(String.raw`^\s*(?:\w+\.)?${esc(name)}\[\d+\] = "(?:\\.|[^"\\])*";\s*$`),
    ];
    const hits = []; let ok = true;
    for (let i = 0; i < lines.length; i++) {
      if (!wre.test(lines[i])) continue;
      if (allowed.some(r => r.test(lines[i]))) hits.push(i); else { ok = false; break; }
    }
    if (ok) hits.forEach(i => del.add(i));
  }
  // static { ... } içindeki "int n = new Random(123L).nextInt();"
  const randRe = /^\s*(?:int|long) \w+ = new Random\(-?\d+L?\)\.nextInt\(\);\s*$/;
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*static \{\s*$/.test(lines[i])) continue;
    const j = matchClose(lines, i);
    if (j < 0) continue;
    for (let k = i + 1; k < j; k++) if (randRe.test(lines[k])) del.add(k);
  }
  if (del.size) stats.junkFields = (stats.junkFields || 0) + del.size;
  lines = lines.filter((_, i) => !del.has(i));
  // boşalan static blokları sil
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*static \{\s*$/.test(lines[i])) continue;
    const j = matchClose(lines, i);
    if (j > i && lines.slice(i + 1, j).every(x => x.trim() === '')) { lines.splice(i, j - i + 1); i--; }
  }
  return lines.join('\n');
}

/* void metodun en dıştaki etiketli bloğundan çıkan "break X;" aslında metodun sonu = return */
function breakToReturn(lines) {
  if (!/\bvoid\s+\w+\(/.test(lines[0])) return lines;
  for (let i = 1; i < lines.length - 1; i++) {
    const lab = /^\s*(\w+): \{$/.exec(lines[i]);
    if (!lab) continue;
    const j = matchClose(lines, i);
    if (j < 0 || !lines.slice(j + 1, lines.length - 1).every(x => x.trim() === '')) continue;
    const re = new RegExp(String.raw`\bbreak ${lab[1]};`);
    for (let k = i + 1; k < j; k++) lines[k] = lines[k].replace(re, 'return;');
  }
  return lines;
}

const foldStr = line => {
  const re = /"((?:\\.|[^"\\\n])*)"\s*\+\s*"((?:\\.|[^"\\\n])*)"/g;
  let prev;
  do { prev = line; line = line.replace(re, (_, a, b) => `"${a}${b}"`); } while (line !== prev);
  return line;
};

/* ------------------------------------------------------------ geçici değişken / anahtar parametre sadeleştirme */

function splitArgs(s) {
  const out = []; let depth = 0, cur = '', inStr = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inStr) { cur += ch; if (ch === '\\') cur += s[++i] || ''; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { inStr = true; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim() !== '' || out.length) out.push(cur);
  return out;
}

function closingParen(s, open) {
  let depth = 0, inStr = false;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (inStr) { if (ch === '\\') i++; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/* private metotların kullanılmayan son "int key" parametresini ve çağrılardaki sabitini sil */
function removeKeyParams(text, stats) {
  const lines = text.split('\n');
  for (const meth of findMethods(lines)) {
    if (!meth.lastIntParam || !/\bprivate\b/.test(lines[meth.start])) continue;
    const bodyText = lines.slice(meth.start + 1, meth.end).join('\n');
    if (/Decompilation failed/.test(bodyText)) continue;
    if (new RegExp(String.raw`(?<![\w.])${esc(meth.lastIntParam)}\b`).test(bodyText)) continue;        // parametre kullanılıyor
    const hm = new RegExp(String.raw`\b${esc(meth.name)}\(([^)]*)\)`).exec(lines[meth.start]);
    if (!hm) continue;
    const params = splitArgs(hm[1]);
    if (!params.length || !new RegExp(String.raw`\bint\s+${esc(meth.lastIntParam)}\s*$`).test(params[params.length - 1])) continue;

    // tüm çağrılar son argüman olarak büyük sabit vermeli
    const edits = []; let ok = true;
    const callRe = new RegExp(String.raw`(?<![\w])${esc(meth.name)}\(`, 'g');
    for (let i = 0; i < lines.length && ok; i++) {
      if (i === meth.start) continue;
      let c; callRe.lastIndex = 0;
      while ((c = callRe.exec(lines[i]))) {
        const open = c.index + meth.name.length;
        const close = closingParen(lines[i], open);
        if (close < 0) { ok = false; break; }
        const args = splitArgs(lines[i].slice(open + 1, close));
        if (args.length !== params.length || !/^-?\d{6,}$/.test(args[args.length - 1].trim())) { ok = false; break; }
        edits.push({ i, nameStart: c.index, close, args });
      }
    }
    if (!ok || !edits.length) continue;
    edits.sort((x, y) => (y.i - x.i) || (y.nameStart - x.nameStart));
    for (const e of edits) {
      const L = lines[e.i];
      lines[e.i] = L.slice(0, e.nameStart) + meth.name + '(' + e.args.slice(0, -1).map(x => x.trim()).join(', ') + ')' + L.slice(e.close + 1);
    }
    lines[meth.start] = lines[meth.start].replace(hm[0], `${meth.name}(${params.slice(0, -1).map(x => x.trim()).join(', ')})`);
    stats.keyParams = (stats.keyParams || 0) + 1;
  }
  return lines.join('\n');
}

/* "T x = EXPR;" sonraki satırda tek kez kullanılıyorsa (saf ifade) oraya taşı; "T x = ...; return x;" -> "return ...;" */
function forwardTemp(lines, i, a, b) {
  const m = /^(\s*)(?:((?:final )?[A-Za-z_][\w<>\[\],.? ]*?) )?([A-Za-z_]\w*) = (.+);\s*$/.exec(lines[i]);
  if (!m) return false;
  const type = (m[2] || '').trim(), name = m[3], expr = m[4].trim();
  if (/^(?:return|throw|else|case|new|if|while|for|do)$/.test(type) || /^(?:byte|short|char|float)$/.test(type)) return false;
  if (/(?<![=!<>])=(?!=)/.test(expr)) return false;                              // zincir atama
  if (assignCount(lines, a, b, name) !== 1 || refCount(lines, a, b, name, i) !== 1) return false;
  let k = i + 1;
  while (k <= b && lines[k].trim() === '') k++;
  if (k > b) return false;
  const useRe = new RegExp(String.raw`(?<![\w.])${esc(name)}\b`, 'g');
  if ((maskStr(lines[k]).match(useRe) || []).length !== 1) return false;

  if (lines[k].trim() === `return ${name};`) {
    lines[k] = subOutside(lines[k], useRe, () => expr);
    lines.splice(i, 1);
    return true;
  }
  // saf (yan etkisiz) aritmetik ifade mi?
  const e0 = expr.replace(/Math\.(?:max|min|abs)\(/g, '(');
  if (!/^[\w\s+\-*\/%(),.]+$/.test(e0.replace(/\./g, '')) || /\w\s*\(/.test(e0) || /\+\+|--/.test(e0) || /\.[A-Za-z_]/.test(e0)) return false;
  if (/^(?:long|double)$/.test(type) && !/\d[Ll]\b|\d\.\d/.test(expr)) return false;
  const ids = new Set(e0.match(/[A-Za-z_]\w*/g) || []);
  const lhs = /^\s*(?:[A-Za-z_][\w<>\[\],.? ]*? )?([A-Za-z_]\w*) = /.exec(lines[k]);
  if (lhs && ids.has(lhs[1])) return false;
  const atomic = /^-?[\w.]+$/.test(expr) || (/^Math\.\w+\(/.test(expr) && closingParen(expr, expr.indexOf('(')) === expr.length - 1);
  const ctx = new RegExp(String.raw`(?:^|[(,=]\s*)${esc(name)}(?=\s*[,);])`);
  const rep = atomic || ctx.test(maskStr(lines[k])) ? expr : `(${expr})`;
  lines[k] = subOutside(lines[k], useRe, () => rep);
  lines.splice(i, 1);
  return true;
}

/* CFR'nin tipini bulamadığı "var5_6 = ..." / "n5 = ..." ilk atamalarını "var" ile bildir */
function declareUndeclared(lines) {
  const seen = new Set(lines[0].match(/[A-Za-z_]\w*/g) || []);
  for (let i = 1; i < lines.length; i++) {
    const m = /^(\s*)([A-Za-z_]\w*\d) = (?!null;)(.+)$/.exec(lines[i]);
    if (m && !seen.has(m[2])) lines[i] = `${m[1]}var ${m[2]} = ${m[3]}`;
    for (const id of lines[i].match(/[A-Za-z_]\w*/g) || []) seen.add(id);
  }
  return lines;
}

/* ------------------------------------------------------------ çöp alanlar */

/* private alan hiç okunmuyorsa (tanım + en fazla bir "x = ... ^ ...;" ataması) sil */
function removeJunkFields(text, stats) {
  const declRe = /^[ \t]*private (?:(?:static|final|transient|volatile) )*[\w.<>\[\], ?]+? (\w+)(?: = [^;\n]+)?;[ \t]*$/;
  for (let round = 0; round < 6; round++) {
    const lines = text.split('\n');
    const counts = new Map();
    for (const l of lines) { const ids = l.match(/[A-Za-z_]\w*/g); if (ids) for (const id of ids) counts.set(id, (counts.get(id) || 0) + 1); }
    const del = new Set();
    for (let i = 0; i < lines.length; i++) {
      const d = declRe.exec(lines[i]); if (!d) continue;
      const name = d[1], c = counts.get(name) || 0;
      if (c === 1) { del.add(i); continue; }
      if (c === 2) {
        const asg = new RegExp(String.raw`^\s*(?:this\.)?${esc(name)} = [^;]*\^[^;]*;\s*$`);
        const j = lines.findIndex((l, k) => k !== i && asg.test(l));
        if (j >= 0) { del.add(i); del.add(j); }
      }
    }
    if (!del.size) break;
    stats.junkFields = (stats.junkFields || 0) + del.size;
    text = lines.filter((_, i) => !del.has(i)).join('\n');
  }
  return text;
}

/* ------------------------------------------------------------ yerel değişken temizliği */

function assignCount(lines, a, b, name) {
  const n = esc(name);
  const re = new RegExp(String.raw`(?<![\w.])${n}\s*(?:=(?!=)|\+=|-=|\*=|/=|\^=|\|=|&=|<<=|>>=|\+\+|--)|(?:\+\+|--)${n}\b`, 'g');
  let c = 0;
  for (let i = a; i <= b; i++) { const m = maskStr(lines[i]).match(re); if (m) c += m.length; }
  return c;
}
function refCount(lines, a, b, name, skip) {
  const re = new RegExp(String.raw`(?<![\w.])${esc(name)}\b`);
const decl = new RegExp(String.raw`^\s*(?!(?:return|throw|else|case)\b)[A-Za-z_][\w<>\[\],.? ]*? ${esc(name)};\s*$`);
  let c = 0;
  for (let i = a; i <= b; i++) if (i !== skip && re.test(maskStr(lines[i])) && !decl.test(lines[i])) c++;
  return c;
}

/* tek atamalı takma adları ve sabitleri yerine koy, kullanılmayan geçici değişkenleri sil */
/* her metodu kendi diliminde işle (sınıf boyutundan bağımsız, hızlı) */
function cleanLocals(lines, stats) {
  const all = findMethods(lines).sort((x, y) => x.start - y.start);
  const kept = [];
  for (const m of all) if (!kept.length || m.start > kept[kept.length - 1].end) kept.push(m);   // iç içe olanları atla
  for (const m of kept.reverse()) {
    const sub = cleanMethodBody(lines.slice(m.start, m.end + 1), stats);
    lines.splice(m.start, m.end - m.start + 1, ...sub);
  }
  return lines;
}

function cleanMethodBody(lines, stats) {
  lines = unwrapBlocks(breakToReturn(lines));
  const TYPE = String.raw`(?:[A-Za-z_][\w<>\[\],.? ]*? )?`;
  const aliasRe = new RegExp(String.raw`^\s*(${TYPE})(\w+) = (this|[A-Za-z_]\w*|-?\d[\d.]*[LlFfDd]?|"(?:\\.|[^"\\\n])*");\s*$`);
  const chainRe = /^(\s*)(?:[A-Za-z_][\w<>\[\],.? ]*? )?(\w+) = (\w+) = (.+);\s*$/;
  const fieldChainRe = /^(\s*)(.*?[\w\]]) = (\w+) = (.+);\s*$/;
  const declRe = new RegExp(String.raw`^\s*${TYPE}(\w+);\s*$`);

  for (let round = 0; round < 600; round++) {
    let changed = false;
    for (const meth of findMethods(lines)) {
      const a = meth.start + 1, b = meth.end - 1;
      for (let i = a; i <= b && !changed; i++) {
        const l = lines[i];

        // A = B = expr;  (B başka yerde kullanılmıyorsa)
        let c = chainRe.exec(l);
        if (c && !/^\s*(?:if|for|while|return)\b/.test(l)) {
          if (refCount(lines, a, b, c[3], i) === 0) { lines[i] = `${c[1]}${c[2]} = ${c[4]};`; changed = true; stats.inlined++; break; }
        }
        c = fieldChainRe.exec(l);
        if (c && !/^\s*(?:if|for|while|return)\b/.test(l) && /[.\]]/.test(c[2]) && refCount(lines, a, b, c[3], i) === 0) {
          lines[i] = `${c[1]}${c[2]} = ${c[4]};`; changed = true; stats.inlined++; break;
        }

        // tek kullanımlık geçici değişkeni sonraki satıra taşı
        if (forwardTemp(lines, i, a, b)) { changed = true; stats.inlined++; break; }

        // x = y;  /  x = 123;  (tek atama) -> kullanımları değiştir
        const m = aliasRe.exec(l);
        if (!m) continue;
        const type = (m[1] || '').trim(), name = m[2], rhs = m[3];
        if (/^(?:return|throw|else|case|new)$/.test(type)) continue;
        const isLit = /^(?:-?\d|")/.test(rhs);
        if (isLit && /^(?:char|float)$/.test(type)) continue;
        if (assignCount(lines, a, b, name) !== 1) continue;
        if (!isLit && rhs !== 'this' && assignCount(lines, a, b, rhs) > 1) continue;
        const useRe = new RegExp(String.raw`(?<![\w.])${esc(name)}\b`, 'g');
        for (let k = a; k <= b; k++) if (k !== i) lines[k] = foldStr(subOutside(lines[k], useRe, () => rhs));
        lines.splice(i, 1);
        changed = true; stats.inlined++; break;
      }
      if (changed) break;
      // kullanılmayan "Type name;" bildirimleri
      for (let i = a; i <= b; i++) {
        const d = declRe.exec(lines[i]);
        if (d && !/^\s*(?:return|throw|break|continue)\b/.test(lines[i]) && refCount(lines, a, b, d[1], i) === 0) {
          lines.splice(i, 1); changed = true; break;
        }
      }
      if (changed) break;
    }
    if (!changed) break;
  }
  // void metodun sonundaki gereksiz "return;"
  for (const meth of findMethods(lines).reverse()) {
    if (!/\bvoid\s+\w+\(/.test(lines[meth.start])) continue;
    let k = meth.end - 1;
    while (k > meth.start && lines[k].trim() === '') k--;
    if (lines[k].trim() !== 'return;') continue;
    lines.splice(k, 1);
    // "if (x) return;" hemen ardından gelen "return;" ile aynı yere gittiği için gereksiz (koşul çağrı içermiyorsa)
    k--;
    while (k > meth.start && lines[k].trim() === '') k--;
    if (/^if \([^()]*\) return;$/.test(lines[k].trim())) lines.splice(k, 1);
  }
  return declareUndeclared(lines);
}

/* ------------------------------------------------------------ girinti */

function reindent(text) {
  let depth = 0, inBlock = false;
  const out = [];
  for (const raw of text.split('\n')) {
    const t = raw.trim();
    if (t === '') { out.push(''); continue; }
    if (inBlock || t.startsWith('/*')) {
      out.push(' '.repeat(depth * 4) + (t.startsWith('/*') ? '' : ' ') + t);
      inBlock = !t.includes('*/');
      continue;
    }
    const s = sanitize(t);
    const lead = (/^\}+/.exec(s) || [''])[0].length;
    const indent = Math.max(0, depth - lead);
    out.push(' '.repeat(indent * 4) + (/^(?:case .*|default):$/.test(t) ? '' : '') + t);
    for (const ch of s) { if (ch === '{') depth++; else if (ch === '}') depth = Math.max(0, depth - 1); }
  }
  return out.join('\n');
}

module.exports = { deobfuscate, evalExpr, foldConsts, unwrapRethrowTry };
