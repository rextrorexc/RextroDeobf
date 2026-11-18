// deobf işçisi: verilen .java dosyalarını okur, deobf eder, geri yazar
const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const { deobfuscate } = require('./deobf');
const { mapNames } = require('./mappings');
const { fixProguard } = require('./proguardfix');
const { foldOpaque } = require('./opaque');
const { decryptSpecWrappers, dropWatermarks } = require('./furrystr');

const agg = { cleaned: 0, deobfClasses: 0, constants: 0, removedLines: 0, junkFields: 0, renamed: 0, errors: 0 };
for (const f of workerData.files) {
  try {
    const full = path.join(workerData.dir, f);
    const o = fs.readFileSync(full, 'utf8');
    let s = o.replace(/\r\n/g, '\n');
    s = s.replace(/^\/\*\s*\n(?=\s*(?:package|import)\s)/, '');   // furryhook betiği başlık yorumunun kapanışını silebiliyor
    s = dropWatermarks(decryptSpecWrappers(s, agg));
    // CFR --renameillegalidents ürünü (rakamla başlayan alan/metot adları): okunur ad ver
    s = s.replace(/\bcfr_renamed_(\d+)(?=\s*\()|::cfr_renamed_(\d+)\b/g, (m, a1, a2) => a2 ? '::method' + a2 : 'method' + a1)
         .replace(/\bcfr_renamed_(\d+)\b/g, 'field$1');
    const r = deobfuscate(s);
    if (r.stats.helpers || r.stats.constants) agg.deobfClasses++;
    agg.constants += r.stats.constants; agg.removedLines += r.stats.removedLines; agg.junkFields += r.stats.junkFields || 0;
    s = r.text.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n').replace(/\/\*\s*\*\/\s*/g, '');
    const mp = mapNames(s); s = mp.text; agg.renamed += mp.n;
    s = fixProguard(s).text;
    const fo = foldOpaque(s);
    if (fo.n > 0) {
      s = fo.text;
      const r2 = deobfuscate(s);
      s = r2.text.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n');
    }
    if (s !== o) {
      // yalnızca değişen dosyaların ham halini sakla (geri kalanı için raw = out)
      const rawPath = path.join(workerData.rawDir, f);
      fs.mkdirSync(path.dirname(rawPath), { recursive: true });
      fs.writeFileSync(rawPath, o);
      fs.writeFileSync(full, s); agg.cleaned++;
    }
  } catch { agg.errors++; }
}
parentPort.postMessage(agg);
