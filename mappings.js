// Minecraft intermediary adlarını (class_1234, field_5678, method_9012) yarn adlarına çevirir.
// Tablo: lib/yarn.json (tools/build-yarn.js ile üretilir). String literal içine dokunmaz.
const fs = require('fs'), path = require('path');
const { renameClassNamedLocals, cleanDeadLocals } = require('./localfix');
let Y = null;
function load() {
  if (Y) return Y;
  try { Y = JSON.parse(fs.readFileSync(path.join(__dirname, 'lib', 'yarn.json'), 'utf8')); }
  catch { Y = { c: {}, f: {}, m: {} }; }
  return Y;
}
const simple = full => full.slice(full.lastIndexOf('/') + 1).replace(/^.*\$/, '');
const dotted = full => full.replace(/[\/$]/g, '.');
const RE = /("(?:\.|[^"\\n])*"|'(?:\.|[^'\\n])*')|\b(?:net\.minecraft\.)?class_(\d+)(?:\.class_(\d+))*\b|\b(field|method)_(\d+)\b/g;

function mapNames(text) {
  if (!/\b(?:class|field|method)_\d+\b/.test(text)) return cleanDeadLocals(text);
  const { c, f, m } = load(); let n = 0;
  const lv = renameClassNamedLocals(text, t => { const full = c[t.slice(6)]; return full ? simple(full) : t; }); text = lv.text; n += lv.n;
  const out = text.replace(RE, (all, str, cid, _x, kind, fid) => {
    if (str) return all;
    if (kind) { const nm = (kind === 'field' ? f : m)[fid]; if (!nm) return all; n++; return nm; }
    const ids = all.match(/class_(\d+)/g).map(s => s.slice(6));
    const last = c[ids[ids.length - 1]];
    if (all.startsWith('net.minecraft.')) {            // import / tam nitelikli ad
      const full = last || c[ids[0]]; if (!full) return all;
      n++; return dotted(full);
    }
    if (ids.length > 1) {                              // Dış.İç  ->  yarn basit adlar
      const parts = ids.map(i => c[i] ? simple(c[i]) : 'class_' + i); n++; return parts.join('.');
    }
    if (!last) return all;
    n++; return simple(last);
  });
  const dl = cleanDeadLocals(out);
  return { text: dl.text, n: n + dl.n };
}
module.exports = { mapNames };
