'use strict';
// "_xxxx" tohum alanlarına dayalı opaque predicate'ler:
//   if (a - a != 0) { throw null; }          -> silinir (hep yanlış)
//   if (n <= (n | 1)) return false; throw null;  -> return false;  (hep doğru)
// Koşul yalnızca tam sayı aritmetiğinden ve tohum/alias değişkenlerinden oluşuyorsa, birkaç test değeriyle hesaplanıp sabitse katlanır.

const SEED = /(?:\b\w+\.)?\b_[0-9a-f]{3,4}\b/;
const TESTS = [0, 1, -1, 2, -2, 7, -8, 123456789, -987654321, 0x7fffffff, -0x80000000, 0x5a5a5a5a];

function tokenize(s) {
  const toks = [];
  const re = /\s*(?:(0[xX][0-9a-fA-F]+|\d+)[Ll]?|((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)|(>>>|<<|>>|<=|>=|==|!=|[-+*&|^~()<>!]))/y;
  let i = 0;
  while (i < s.length) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) return null;
    if (m[1] !== undefined) toks.push({ t: 'n', v: Number(m[1]) | 0 });
    else if (m[2] !== undefined) toks.push({ t: 'v', v: m[2] });
    else toks.push({ t: 'o', v: m[3] });
    i = re.lastIndex;
    while (i < s.length && /\s/.test(s[i])) i++;
  }
  return toks;
}

function evalCond(toks, env) {
  let k = 0;
  const peek = () => toks[k], isOp = v => toks[k] && toks[k].t === 'o' && toks[k].v === v;
  const prim = () => {
    const t = toks[k++];
    if (!t) throw 0;
    if (t.t === 'n') return t.v;
    if (t.t === 'v') { if (!(t.v in env)) throw 0; return env[t.v]; }
    if (t.v === '(') { const v = or(); if (!isOp(')')) throw 0; k++; return v; }
    if (t.v === '-') return (-prim()) | 0;
    if (t.v === '~') return ~prim();
    if (t.v === '!') return prim() ? 0 : 1;
    throw 0;
  };
  const mul = () => { let v = prim(); while (isOp('*')) { k++; v = Math.imul(v, prim()); } return v; };
  const add = () => { let v = mul(); while (isOp('+') || isOp('-')) { const o = toks[k++].v; const r = mul(); v = (o === '+' ? v + r : v - r) | 0; } return v; };
  const shift = () => { let v = add(); while (isOp('<<') || isOp('>>')) { const o = toks[k++].v; const r = add() & 31; v = o === '<<' ? v << r : v >> r; } return v; };
  const rel = () => { let v = shift(); while (isOp('<') || isOp('>') || isOp('<=') || isOp('>=')) { const o = toks[k++].v; const r = shift(); v = (o === '<' ? v < r : o === '>' ? v > r : o === '<=' ? v <= r : v >= r) ? 1 : 0; } return v; };
  const eq = () => { let v = rel(); while (isOp('==') || isOp('!=')) { const o = toks[k++].v; const r = rel(); v = (o === '==' ? v === r : v !== r) ? 1 : 0; } return v; };
  const band = () => { let v = eq(); while (isOp('&')) { k++; v &= eq(); } return v; };
  const bxor = () => { let v = band(); while (isOp('^')) { k++; v ^= band(); } return v; };
  const or = () => { let v = bxor(); while (isOp('|')) { k++; v |= bxor(); } return v; };
  const r = or();
  if (k !== toks.length) throw 0;
  return r;
}

/** koşul değişkenler içeriyor ve her test değerinde aynı mantıksal sonucu veriyorsa true/false, değilse null */
function constantTruth(cond, aliases) {
  const toks = tokenize(cond);
  if (!toks || !toks.length) return null;
  const vars = [...new Set(toks.filter(t => t.t === 'v').map(t => t.v))];
  if (vars.length > 3) return null;
  // Sabit veya matematiksel özdeşlik: değişkenler varsa test değerleri üzerinden doğrula
  let res = null;
  const combos = vars.length === 0 ? [[]]
    : vars.length === 1 ? TESTS.map(x => [x])
    : vars.length === 2 ? TESTS.flatMap(a => TESTS.slice(0, 7).map(b => [a, b]))
    : TESTS.flatMap(a => TESTS.slice(0, 5).flatMap(b => TESTS.slice(0, 4).map(c => [a, b, c])));
  try {
    for (const c of combos) {
      const env = {}; vars.forEach((v, i) => { env[v] = c[i]; });
      const r = evalCond(toks, env) ? true : false;
      if (res === null) res = r; else if (res !== r) return null;
    }
  } catch { return null; }
  return res;
}

function matchParen(s, open) {
  let d = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === '(') d++;
    else if (s[i] === ')' && --d === 0) return i;
  }
  return -1;
}

function foldOpaque(text) {
  const aliases = new Set();
  for (const m of text.matchAll(/\b(?:int|long|var)\s+(\w+)\s*=\s*(?:\w+\.)?(?:_[0-9a-f]{3,4}|-?\d+)\s*;/g)) aliases.add(m[1]);
  let n = 0;
  const re = /^([ \t]*)(?:else )?if \(/gm;
  let out = '', pos = 0, m;
  while ((m = re.exec(text))) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(text, open);
    if (close < 0) continue;
    const cond = text.slice(open + 1, close);
    const truth = constantTruth(cond, aliases);
    if (truth === null) continue;
    const rest = text.slice(close + 1);

    // A) truth === false: if (false) { ... } veya if (false) { ... } else { ... }
    let t;
    if (truth === false) {
      if ((t = /^\s*\{\s*(?:throw\s+null;|throw new \w+\([^)]*\);)\s*\}[ \t]*\n?/.exec(rest))) {
        out += text.slice(pos, m.index); pos = close + 1 + t[0].length; re.lastIndex = pos; n++; continue;
      }
      if ((t = /^\s*(?:continue|break)(?: \w+)?;[ \t]*\n?/.exec(rest))) {
        out += text.slice(pos, m.index); pos = close + 1 + t[0].length; re.lastIndex = pos; n++; continue;
      }
    }

    // B) truth === true: if (true) return X; throw null;
    if (truth === true && (t = /^\s*(return[^;]*;)[ \t]*\n(?:[ \t]*throw null;[ \t]*\n?)?/.exec(rest))) {
      out += text.slice(pos, m.index) + m[1] + t[1] + '\n'; pos = close + 1 + t[0].length; re.lastIndex = pos; n++; continue;
    }

    // C) truth === true && if (true) continue/break;
    if (truth === true && (t = /^\s*(continue|break)(?: \w+)?;[ \t]*\n?/.exec(rest))) {
      out += text.slice(pos, m.index) + m[1] + t[0].trim() + '\n'; pos = close + 1 + t[0].length; re.lastIndex = pos; n++; continue;
    }

    // D) Genel durum: if (cond) -> if (true) veya if (false) (foldBooleansAndBranches açar)
    out += text.slice(pos, open + 1) + (truth ? 'true' : 'false');
    pos = close;
    re.lastIndex = pos;
    n++;
  }
  out += text.slice(pos);
  // return veya throw'dan sonra kalan ölü kodlar
  out = out.replace(/(\b(?:return|throw)\b[^;{}]*;)([ \t]*\n)(?:[ \t]*(?:throw\s+null;|throw\s+new\s+\w+\([^)]*\);|cfr_ignored_\d+\s*=\s*[^;\n]+;)[ \t]*\n)+/g, '$1$2');
  return { text: out, n };
}

module.exports = { foldOpaque };
