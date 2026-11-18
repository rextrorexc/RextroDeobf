// CFR kalıntıları: tür adıyla adlandırılmış yerel değişkenler (class_12972) ve kullanılmayan kopya değişkenler.
const PRIM = { int: 'i', long: 'l', short: 's', byte: 'b', float: 'f', double: 'd', boolean: 'flag', char: 'c' };
const KW = /^(?:abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|goto|if|implements|import|instanceof|int|interface|long|native|new|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|try|void|volatile|while)$/;

function varNameFor(type) {
  let t = type.replace(/<.*>/, '').replace(/\s+/g, '');
  const arr = /\[\]/.test(t); t = t.replace(/\[\]/g, '');
  t = t.slice(t.lastIndexOf('.') + 1);
  let base = PRIM[t] || (t ? t[0].toLowerCase() + t.slice(1) : 'value');
  if (KW.test(base)) base += 'Value';
  return arr ? base + 's' : base;
}

// "Entity class_12972 = target;"  ->  "Entity entity = target;"  (dosyadaki tüm kullanımlarıyla)
function renameClassNamedLocals(text, resolve = x => x) {
  const DECL = /(?<![\w.])((?:class_\d+|[A-Z][\w.]*(?:<[^;=(){}]*?>)?|int|long|short|byte|float|double|boolean|char)(?:\[\])*)\s+(class_\d+)\s*(?=[=;,):])/g;
  const vars = new Map();
  let m;
  while ((m = DECL.exec(text))) if (!vars.has(m[2])) vars.set(m[2], m[1]);
  vars.delete(undefined);
  if (!vars.size) return { text, n: 0 };
  const used = new Set(text.match(/\b[A-Za-z_]\w*\b/g));
  const ren = new Map();
  for (const [id, type] of vars) {
    const base = varNameFor(type.replace(/\bclass_\d+\b/g, resolve));
    let k = base, i = 2;
    while (used.has(k)) k = base + i++;
    used.add(k); ren.set(id, k);
  }
  const out = text.replace(/("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|\b(class_\d+)\b/g, (all, str, id) => (str ? all : ren.get(id) || all));
  return { text: out, n: ren.size };
}

function blockEnd(text, from) {
  let d = 0;
  for (let i = from; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{') d++;
    else if (ch === '}' && --d < 0) return i;
  }
  return text.length;
}

// Kullanılmayan "boolean bl = x;", "float f3 = f2 = ...;", "float f2;" satırlarını sil
function cleanDeadLocals(text) {
  let n = 0, changed = true, guard = 0;
  // Kendi kendine atamalar: "x = x;", "this.x = this.x;"
  text = text.replace(/^[ \t]*(?:this\.)?(\w+)\s*=\s*(?:this\.)?\1;[ \t]*\n/gm, '');
  // cfr_ignored bildirimleri
  text = text.replace(/^[ \t]*(?:final\s+)?(?:int|long|boolean|Object|double|float|short|byte|char|var|[\w.<>\[\]]+)\s+cfr_ignored_\d+\s*(?:=\s*[^;\n]+)?;[ \t]*\n/gm, () => { n++; return ''; });

  const LINE = /^([ \t]*)(?:final )?([A-Za-z][\w.<>\[\]?, ]*?) (\w+)(?: = ([^;\n]*))?;[ \t]*\n/gm;
  while (changed && guard++ < 6) {
    changed = false;
    text = text.replace(LINE, (all, ind, type, name, rhs, off) => {
      if (/^(?:return|throw|else|case|new|import|package|break|continue)\b/.test(type)) return all;
      if (!/^(?:bl\d*|[a-z]\d*|cfr_ignored_\d+|var\d+|n\d+|c\d+|l\d+|s\d+|flag\d*)$/.test(name)) return all;
      const rest = text.slice(off + all.length, blockEnd(text, off + all.length));
      if (new RegExp('\\b' + name + '\\b').test(rest)) return all;
      if (rhs === undefined || /^[\w.]+$/.test(rhs)) { n++; changed = true; return ''; }   // kullanılmayan / saf kopya
      const ch = rhs.match(/^(\w+) = ([\s\S]+)$/);                                         // x = y = expr
      if (ch) { n++; changed = true; return ind + ch[1] + ' = ' + ch[2] + ';\n'; }
      return all;
    });
  }
  return { text, n };
}

module.exports = { renameClassNamedLocals, cleanDeadLocals };
