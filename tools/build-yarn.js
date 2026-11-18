// Gradle/Loom önbelleğindeki yarn eşlemelerinden lib/yarn.json üretir (intermediary -> yarn). Yeni sürümler önce gelir.
const fs = require('fs'), path = require('path');
const root = path.join(process.env.USERPROFILE || process.env.HOME, '.gradle', 'caches', 'fabric-loom');
const ver = v => v.split('.').map(Number);
const cmp = (a, b) => { const x = ver(a), y = ver(b); for (let i = 0; i < 4; i++) { const d = (y[i] || 0) - (x[i] || 0); if (d) return d; } return 0; };
const maps = [];
for (const v of fs.readdirSync(root).filter(d => /^\d+\.\d+(\.\d+)?$/.test(d)).sort(cmp)) {
  for (const d of fs.readdirSync(path.join(root, v)).filter(d => d.startsWith('net.fabricmc.yarn')).sort().reverse()) {
    const f = path.join(root, v, d, 'mappings.tiny'); if (fs.existsSync(f)) maps.push(f);
  }
}
const C = {}, F = {}, M = {};
for (const f of maps) {
  for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
    const p = line.split('\t');
    if (p[0] === 'c') { const id = p[2].match(/class_(\d+)$/); if (id && !(id[1] in C)) C[id[1]] = p[3]; }
    else if (p[0] === '' && (p[1] === 'f' || p[1] === 'm')) {
      const id = (p[4] || '').match(/^(field|method)_(\d+)$/);
      if (id && p[5] && p[5] !== p[4]) { const T = p[1] === 'f' ? F : M; if (!(id[2] in T)) T[id[2]] = p[5]; }
    }
  }
  console.log('okundu', f);
}
fs.writeFileSync(path.join(__dirname, '..', 'lib', 'yarn.json'), JSON.stringify({ c: C, f: F, m: M }));
console.log(Object.keys(C).length, Object.keys(F).length, Object.keys(M).length);
