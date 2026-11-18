// RextroDeobf - JAR decompile + deobf sunucusu (bağımlılık yok)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { deobfuscate } = require('./deobf');
const { mapNames } = require('./mappings');
const { renameClasses } = require('./classrename');
const { fixProguard } = require('./proguardfix');
const { foldOpaque } = require('./opaque');
const { Worker } = require('worker_threads');
const { spawn, spawnSync } = require('child_process');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const WORK = path.join(ROOT, 'work');
const CFR = path.join(ROOT, 'lib', 'cfr.jar');
const MAX_UPLOAD = 200 * 1024 * 1024; // 200 MB
const TTL_MS = 60 * 60 * 1000;        // işler 1 saat sonra silinir

fs.mkdirSync(WORK, { recursive: true });

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon',
};

// CFR'nin deobf ile ilgili seçenekleri
const CFR_OPTS = [
  '--renameillegalidents', 'true',   // geçersiz/Unicode çöp isimleri düzelt
  '--renamedupmembers', 'true',      // aynı isimli üyeleri yeniden adlandır
  '--renameenumidents', 'true',
  '--decodestringswitch', 'true',
  '--decodelambdas', 'true',
  '--decodeenumswitch', 'true',
  '--sugarenums', 'true',
  '--sugarasserts', 'true',
  '--sugarboxing', 'true',
  '--removeboilerplate', 'true',
  '--removeinnerclasssynthetics', 'true',
  '--tidymonitors', 'true',
  '--hideutf', 'false',
  '--comments', 'false',
  '--showversion', 'false',
  '--silent', 'true',
];

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function isId(s) { return /^[a-f0-9]{24}$/.test(s || ''); }

function walk(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, base, out);
    else out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('Dosya çok büyük (en fazla 200 MB).')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Python yardımcısı (Method motoru: engine/pipeline.py)
const PYTHON = process.env.PYTHON || (() => {
  for (const c of ['python3', 'python']) { try { if (spawnSync(c, ['-V']).status === 0) return c; } catch {} }
  return 'python3';
})();
const PIPELINE = path.join(ROOT, 'engine', 'pipeline.py');

function runPython(args, timeoutMs) {
  return new Promise((resolve) => {
    const p = spawn(PYTHON, ['-I', PIPELINE, ...args], { windowsHide: true, cwd: path.join(ROOT, 'engine') });
    let out = '', err = '';
    p.stdout.on('data', d => { if (out.length < 200000) out += d; });
    p.stderr.on('data', d => { if (err.length < 20000) err += d; });
    const timer = setTimeout(() => p.kill(), timeoutMs);
    p.on('close', code => { clearTimeout(timer); resolve({ code, out, err }); });
    p.on('error', e => { clearTimeout(timer); resolve({ code: -1, out, err: 'Python çalıştırılamadı: ' + e.message }); });
  });
}

function parseStats(out) {
  const line = out.split(/\r?\n/).reverse().find(l => l.startsWith('STATS '));
  try { return line ? JSON.parse(line.slice(6)) : {}; } catch { return {}; }
}

async function probeJar(jar) {
  const r = await runPython(['--probe', jar], 30000);
  try { return JSON.parse(r.out.trim().split(/\r?\n/).pop()); } catch { return { filter: null }; }
}

// Bayt kodu temizleyici (Skidfuscator tarzı anahtar-değişkeni akışı): tools/skidclean (ASM). Başarısız olursa orijinal jar kullanılır.
const SKID_CP = ['asm-9.7.1.jar', 'asm-tree-9.7.1.jar', 'asm-analysis-9.7.1.jar'].map(j => path.join(ROOT, 'lib', j)).concat(path.join(ROOT, 'tools', 'skidclean', 'build')).join(path.delimiter);
// Ortak Java çalıştırıcı: son "STATS {json}" satırını okur; stderr sonu hata ayıklama için döner
function runJava(cp, mainClass, args, { heap = '2g', timeoutMs = 4 * 60 * 1000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn('java', [`-Xmx${heap}`, '-XX:+UseSerialGC', '-cp', cp, mainClass, ...args], { windowsHide: true });
    let out = '', err = '';
    p.stdout.on('data', d => { if (out.length < 20000) out += d; });
    p.stderr.on('data', d => { if (err.length < 4000) err += d; });
    const timer = setTimeout(() => p.kill(), timeoutMs);
    p.on('close', code => {
      clearTimeout(timer);
      const line = out.split(/\r?\n/).reverse().find(l => l.startsWith('STATS '));
      let st = null; try { st = line ? JSON.parse(line.slice(6)) : null; } catch {}
      resolve({ code, stats: st, err });
    });
    p.on('error', e => { clearTimeout(timer); resolve({ code: -1, stats: null, err: String(e) }); });
  });
}

function runSkidClean(input, output, filter) {
  return runJava(SKID_CP, 'SkidClean', filter ? [input, output, filter] : [input, output]);
}

const PG_CP = ['asm-9.7.1.jar', 'asm-tree-9.7.1.jar', 'asm-analysis-9.7.1.jar', 'asm-commons-9.7.1.jar'].map(j => path.join(ROOT, 'lib', j)).concat(path.join(ROOT, 'tools', 'skidclean', 'build')).join(path.delimiter);
function runProGuardClean(args, timeoutMs = 4 * 60 * 1000) {
  return runJava(PG_CP, 'ProGuardClean', args, { timeoutMs });
}

// Yığın izi anahtarlı string şifrelemesi (ZKM tarzı): orijinal sınıf/metot adlarıyla çözülmeli, bu yüzden adlandırmadan ÖNCE çalışır

// Genel bayt kodu motoru (tools/skidclean/GenericDeobf): parmak izi, ZIP onarımı, sayı/akış/opaque predicate, proxy, string çözme
function runGeneric(args, timeoutMs = 4 * 60 * 1000) {
  return runJava(PG_CP, 'GenericDeobf', args, { timeoutMs });
}

function runStackStr(input, output) {
  return runJava(PG_CP, 'StackStrDec', [input, output], { heap: '1g', timeoutMs: 3 * 60 * 1000 });
}

function runCfrOnce(input, outDir, filter, heapMb, useOpts = true) {
  return new Promise((resolve) => {
    // useOpts=false: CFR varsayılan çıktısı (Method motoru bu biçime göre yazıldı)
    const args = [`-Xmx${heapMb}m`, '-XX:+UseSerialGC', '-Xshare:auto', '-XX:-UsePerfData', '-jar', CFR, input, '--outputdir', outDir, ...(useOpts ? CFR_OPTS : ['--silent', 'true', '--renameillegalidents', 'true'])];
    if (filter) args.push('--jarfilter', filter);
    const p = spawn('java', args, { windowsHide: true });
    let err = '';
    p.stderr.on('data', d => { if (err.length < 20000) err += d; });
    p.stdout.on('data', () => {});
    const timer = setTimeout(() => p.kill(), 25 * 60 * 1000);
    p.on('close', code => { clearTimeout(timer); resolve({ code, err }); });
    p.on('error', e => { clearTimeout(timer); resolve({ code: -1, err: String(e) }); });
  });
}

const CPUS = Math.max(1, (os.availableParallelism ? os.availableParallelism() : os.cpus().length));

// (Ölçüm: CFR'yi sınıf gruplarına bölüp paralel çalıştırmak bu makinede hız kazandırmadı; tek süreç.)
function runCfr(input, outDir) {
  return runCfrOnce(input, outDir, null, 2048);
}

// CFR sonrası: akış deobfuscation (deobf.js), worker thread'lerde paralel
async function postProcess(dir, rawDir) {
  const files = walk(dir).filter(f => f.endsWith('.java'));
  const N = Math.min(CPUS, 8, Math.ceil(files.length / 150)) || 1;
  const chunks = Array.from({ length: N }, () => []);
  files.forEach((f, i) => chunks[i % N].push(f));
  const parts = await Promise.all(chunks.map(list => new Promise((resolve) => {
    const w = new Worker(path.join(ROOT, 'worker.js'), { workerData: { dir, rawDir, files: list } });
    w.once('message', resolve);
    w.once('error', () => resolve({ cleaned: 0, deobfClasses: 0, constants: 0, removedLines: 0, junkFields: 0, renamed: 0, errors: list.length }));
  })));
  const agg = { cleaned: 0, deobfClasses: 0, constants: 0, removedLines: 0, junkFields: 0, renamed: 0, errors: 0 };
  for (const p of parts) for (const k of Object.keys(agg)) agg[k] += p[k] || 0;
  return agg;
}

// Obfuscate sınıf adlarını (AA, GB, dasdasdda ...) koddan türetilen adlarla değiştir; dosyaları yeniden adlandır, eşlemeyi kaydet
function renameOutputClasses(outDir, jobDir) {
  const rels = walk(outDir).filter(f => f.endsWith('.java'));
  const input = new Map();
  for (const r of rels) {
    // CFR --renameillegalidents: sınıf 00 -> _00 olur ama dosya 00.java kalır; dosyayı sınıf adına uydur
    let rel = r.replace(/\\/g, '/');
    const txt = fs.readFileSync(path.join(outDir, r), 'utf8');
    const base = rel.slice(rel.lastIndexOf('/') + 1, -5);
    if (/^\d/.test(base) && new RegExp('\\b(?:class|interface|enum|record)\\s+_' + base.replace(/[$]/g, '\\$') + '\\b').test(txt)) {
      const nr = rel.slice(0, rel.length - base.length - 5) + '_' + base + '.java';
      try { fs.renameSync(path.join(outDir, r), path.join(outDir, nr)); rel = nr; } catch {}
    }
    input.set(rel, txt);
  }
  const res = renameClasses(input, { anyTop: true });
  const map = res.map;
  if (!Object.keys(map).length && !res.renames.length) return 0;
  // önce eski yolları sil (A->B, B->A gibi yer değiştirmelerde yeni dosya silinmesin), sonra yenileri yaz
  for (const oldRel of Object.keys(map)) { try { fs.unlinkSync(path.join(outDir, oldRel)); } catch {} }
  for (const [rel, text] of res.files) {
    const dst = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.writeFileSync(dst, text);
  }
  // ham görünümde eski yola bakılabilsin: yeni yol -> eski yol
  const back = {};
  let prev = {}; try { prev = JSON.parse(fs.readFileSync(path.join(jobDir, 'renames.json'), 'utf8')); } catch {}
  for (const [o, n] of Object.entries(map)) back[n] = prev[o] || o;
  for (const [n, o] of Object.entries(prev)) if (!(n in back) && !(n in map)) back[n] = o;
  fs.writeFileSync(path.join(jobDir, 'renames.json'), JSON.stringify(back));
  return res.renames.length;
}

// FurryHook tarzı (Fabric mod, StrDec/StrCat, SourceFile ile sınıf adı geri yükleme) jar'lar için ek motor: engine/furryhook_deobfuscator.py
async function runFurry(input, dir, outDir, rawDir) {
  const probe = await new Promise((resolve) => {
    const p = spawn(PYTHON, ['-I', path.join(ROOT, 'engine', 'fh_probe.py'), input], { windowsHide: true });
    let o = ''; p.stdout.on('data', d => { o += d; });
    p.on('close', () => { try { resolve(JSON.parse(o.trim().split(/\r?\n/).pop())); } catch { resolve({ furry: false }); } });
    p.on('error', () => resolve({ furry: false }));
  });
  if (!probe.furry) return null;
  const fh = path.join(dir, 'fh');
  const cfr = fs.existsSync(path.join(ROOT, 'lib', 'cfr-skid.jar')) ? path.join(ROOT, 'lib', 'cfr-skid.jar') : CFR;
  const r = await new Promise((resolve) => {
    const p = spawn(PYTHON, ['-I', path.join(ROOT, 'engine', 'furryhook_deobfuscator.py'), input, '-o', fh, '--cfr', cfr, '--java', 'java', '--keep-staging', '-j', String(Math.min(CPUS, 8))], { windowsHide: true });
    let o = '', e = '';
    p.stdout.on('data', d => { if (o.length < 100000) o += d; });
    p.stderr.on('data', d => { if (e.length < 20000) e += d; });
    const timer = setTimeout(() => p.kill(), 10 * 60 * 1000);
    p.on('close', code => { clearTimeout(timer); resolve({ code, out: o, err: e }); });
    p.on('error', er => { clearTimeout(timer); resolve({ code: -1, out: o, err: String(er) }); });
  });
  const src = path.join(fh, 'src', 'main', 'java');
  if (r.code !== 0 || !fs.existsSync(src) || !walk(src).some(f => f.endsWith('.java'))) return { failed: (r.err || r.out).slice(-300) };
  fs.cpSync(src, outDir, { recursive: true });
  const staging = path.join(fh, '_staging_java');
  if (fs.existsSync(staging)) fs.cpSync(staging, rawDir, { recursive: true });
  // yeni yol -> eski yol (ham görünüm için)
  try {
    const cm = JSON.parse(fs.readFileSync(path.join(fh, 'class_mapping.json'), 'utf8'));
    const back = {};
    for (const [o, v] of Object.entries(cm)) if (v.new_fqn) back[v.new_fqn.replace(/\./g, '/') + '.java'] = o.replace(/\./g, '/') + '.java';
    fs.writeFileSync(path.join(dir, 'renames.json'), JSON.stringify(back));
  } catch {}
  const report = path.join(fh, 'DEOBF_REPORT.md');
  if (fs.existsSync(report)) fs.copyFileSync(report, path.join(dir, 'report.md'));
  let summary = {};
  try { summary = JSON.parse(fs.readFileSync(path.join(fh, 'analysis_summary.json'), 'utf8')); } catch {}
  return { ok: true, stats: summary.stats || {}, features: (summary.features || []).length, mixins: (summary.mixins || []).length, commands: (summary.commands || []).length,
    security: summary.security ? { apis: summary.security.apis.length, urls: summary.security.urls.length, ips: summary.security.ips.length } : null, report: fs.existsSync(report) };
}

// ---- Canlı iş takibi (SSE): dosyalar decompile sürerken yan listeye düşer ----
const JOBS = new Map();
function newJob(id) {
  const j = { id, t0: Date.now(), phase: '', log: [], files: [], seen: new Set(), status: 'running', result: null, error: null, subs: new Set() };
  JOBS.set(id, j); return j;
}
function emit(j, type, data) {
  const msg = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const r of j.subs) { try { r.write(msg); } catch {} }
}
function setPhase(j, text) { const t = Date.now() - j.t0; j.phase = text; j.log.push({ t, text }); emit(j, 'phase', { text, t }); }
function pushFiles(j, list) {
  const add = [];
  for (const f of list) if (!j.seen.has(f)) { j.seen.add(f); add.push(f); }
  if (add.length) { j.files.push(...add); emit(j, 'files', { add, total: j.files.length }); }
}
function watchDirs(j, dirs) {
  const tick = () => { for (const d of dirs) { try { if (fs.existsSync(d)) pushFiles(j, walk(d).filter(f => f.endsWith('.java'))); } catch {} } };
  const iv = setInterval(tick, 500);
  return () => { clearInterval(iv); tick(); };
}
function finishJob(j, status, payload) {
  j.status = status;
  if (status === 'done') j.result = payload; else j.error = payload;
  emit(j, status === 'done' ? 'done' : 'fail', payload);
  for (const r of j.subs) { try { r.end(); } catch {} }
  j.subs.clear();
}

async function handleDecompile(req, res, url) {
  const name = (url.searchParams.get('name') || 'input.jar').replace(/[^\w.\-]/g, '_');
  const ext = path.extname(name).toLowerCase();
  if (!['.jar', '.class', '.zip', '.war'].includes(ext))
    return json(res, 400, { error: 'Sadece .jar, .class, .war veya .zip yükleyin.' });

  let body;
  try { body = await readBody(req, MAX_UPLOAD); }
  catch (e) { return json(res, 413, { error: e.message }); }
  if (!body.length) return json(res, 400, { error: 'Boş dosya.' });

  const id = crypto.randomBytes(12).toString('hex');
  const dir = path.join(WORK, id);
  const outDir = path.join(dir, 'out');
  fs.mkdirSync(outDir, { recursive: true });
  const input = path.join(dir, 'input' + (ext === '.class' ? '.class' : '.jar'));
  fs.writeFileSync(input, body);

  const j = newJob(id);
  j.name = name;
  setPhase(j, 'Dosya alındı');
  runDecompile(j, name, ext, input, dir, url.searchParams.get('map'))
    .then(r => finishJob(j, 'done', r))
    .catch(e => finishJob(j, 'fail', { error: e.message || String(e), detail: e.detail || '' }));
  json(res, 202, { id, name });
}

function handleEvents(req, res, url) {
  const id = url.searchParams.get('id');
  const j = isId(id) ? JOBS.get(id) : null;
  if (!j) return json(res, 404, { error: 'İş bulunamadı.' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
  res.write(`event: snapshot\ndata: ${JSON.stringify({ status: j.status, phase: j.phase, log: j.log, files: j.files, result: j.result, error: j.error, ms: Date.now() - j.t0 })}\n\n`);
  if (j.status !== 'running') return res.end();
  j.subs.add(res);
  const hb = setInterval(() => { try { res.write(': hb\n\n'); } catch {} }, 15000);
  req.on('close', () => { clearInterval(hb); j.subs.delete(res); });
}

async function runDecompile(j, name, ext, input, dir, mapIdParam) {
  const outDir = path.join(dir, 'out');
  const id = j.id;
  const t0 = Date.now();
  const rawDir = path.join(dir, 'raw');
  let code, err, method = null, fallback = null;
  const stopWatch = watchDirs(j, [rawDir, path.join(dir, 'fh', '_staging_java')]);
  try {

  // Birleşik motor: 1) CFR (varsayılan çıktı) -> raw/   2) Python boru hattı (string havuzu, indy, unflatten, enum switch, adlandırma, tür çıkarımı)
  // 3) JS motoru (anahtar zinciri, guard, ölü kod, kalıntı temizliği). Python/Java araçları yoksa 2. adım atlanır, JS tek başına çalışır.
  fs.mkdirSync(rawDir, { recursive: true });
  if (ext === '.jar') {
    setPhase(j, 'FurryHook motoru deneniyor');
    const fh = await runFurry(input, dir, outDir, rawDir);
    if (fh && fh.ok) {
      setPhase(j, 'Akış deobf (JS motoru)');
      const ppf = await postProcess(outDir, path.join(dir, 'raw_js'));
      setPhase(j, 'Sınıf adları düzeltiliyor');
      let crF = 0; try { crF = renameOutputClasses(outDir, dir); } catch {}
      const filesF = walk(outDir).filter(f => f.endsWith('.java'));
      return { id, name, files: filesF.sort(), stats: { classes: filesF.length, furry: fh, classRenames: crF, ms: Date.now() - t0, ...ppf } };
    }
    if (fh && fh.failed) var furryNote = fh.failed;
  }
  const probe = { filter: null };   // tüm sınıflar decompile edilir (plugin paketine göre filtre eskiden dosyaların yarısını düşürüyordu)
  // 0) bayt kodu seviyesinde anahtar-değişkeni / guard akışını çöz (Skidfuscator); işe yaramazsa orijinal jar
  let cfrInput = input, skid = null, pg = null, cfrFilter = probe.filter, stackStr = null;
  if (ext === '.jar') {
    setPhase(j, 'Yığın izi anahtarlı string çözümü');
    const sdOut = path.join(dir, 'sd.jar');
    const sd = await runStackStr(input, sdOut);
    if (sd.code === 0 && sd.stats && sd.stats.strings > 0 && fs.existsSync(sdOut)) { cfrInput = sdOut; stackStr = sd.stats; }
  }
  let generic = null;
  if (ext === '.jar') {
    setPhase(j, 'Obfuscator tespiti');
    const dt = await runGeneric(['--detect', cfrInput], 60000);
    const detected = (dt.stats && dt.stats.detected) || [];
    setPhase(j, 'Genel bayt kodu temizliği (sayı, akış, string, proxy)');
    const gOut = path.join(dir, 'generic.jar');
    const gr = await runGeneric([cfrInput, gOut]);
    if (gr.code === 0 && gr.stats && fs.existsSync(gOut)) {
      const g = gr.stats;
      if (g.folded + g.branches + g.dead + g.proxies + g.strings + g.peephole > 0) cfrInput = gOut;
      generic = { ...g, detected };
    } else if (detected.length) generic = { detected };
  }
  const mapId = mapIdParam;
  if (ext !== '.class') {
    setPhase(j, 'ProGuard tespiti');
    // ProGuard tarzı kısa adlar (a, b, c ...) varsa: yerel değişkenleri ayır, adları (mapping varsa birebir, yoksa koddan) geri getir
    const det = await runProGuardClean(['--detect', cfrInput], 60000);
    const d = det.stats;
    const mapFile = mapId && isId(mapId) ? path.join(WORK, 'maps', mapId + '.txt') : null;
    const hasMap = mapFile && fs.existsSync(mapFile);
    if (d && d.total >= 2 && (hasMap || (d.members >= 10 && d.obfMembers / d.members >= 0.5 && d.obfClasses / d.total >= 0.3))) {
      const pgOut = path.join(dir, 'pg.jar');
      const r = await runProGuardClean([cfrInput, pgOut, ...(hasMap ? ['--mapping', mapFile] : [])]);
      if (r.code === 0 && r.stats && fs.existsSync(pgOut)) { cfrInput = pgOut; pg = { ...r.stats, mapping: !!hasMap, detected: d }; }
    }
  }
  if (ext !== '.class') {
    setPhase(j, 'Bayt kodu temizliği (Skidfuscator)');
    const cleaned = path.join(dir, 'cleaned.jar');
    const sk = await runSkidClean(cfrInput, cleaned, cfrFilter || null);
    if (sk.code === 0 && sk.stats && (sk.stats.keyLoads > 0 || sk.stats.folded > 0) && fs.existsSync(cleaned)) { cfrInput = cleaned; skid = sk.stats; }
  }
  setPhase(j, 'CFR decompile — dosyalar yanda akıyor');
  ({ code, err } = await runCfrOnce(cfrInput, rawDir, cfrFilter, 2048, false));
  if (!walk(rawDir).some(f => f.endsWith('.java')))
    throw Object.assign(new Error('Decompile başarısız. Dosya geçerli bir JAR/class mı?'), { detail: err.slice(0, 2000) });
  var tCfr = Date.now() - t0;
  // ProGuard kalıntıları (values() silinmiş sahte enum'lar) Python adımından önce düzeltilir; ham görünüm değişmez
  setPhase(j, 'ProGuard kalıntıları + Python boru hattı');
  const srcDir = path.join(dir, 'src_fixed');
  fs.cpSync(rawDir, srcDir, { recursive: true });
  for (const f of walk(srcDir).filter(x => x.endsWith('.java'))) { const p = path.join(srcDir, f); try { fs.writeFileSync(p, fixProguard(fs.readFileSync(p, 'utf8')).text); } catch {} }
  const py = await runPython(['--src', srcDir, '--out', outDir, ...(ext === '.class' ? [] : ['--jar', input])], 15 * 60 * 1000);
  if (py.code === 0 && walk(outDir).some(f => f.endsWith('.java'))) method = parseStats(py.out);
  else {
    fallback = (py.err || py.out || 'Python çıktısı yok').slice(-300);
    fs.cpSync(srcDir, outDir, { recursive: true });
  }
  setPhase(j, 'Akış deobf (JS motoru)');
  var pp = await postProcess(outDir, path.join(dir, 'raw_js'));
  setPhase(j, 'Sınıf adları düzeltiliyor');
  let classRenames = 0;
  try { classRenames = renameOutputClasses(outDir, dir); } catch (e) { classRenames = -1; }
  const files = walk(outDir).filter(f => f.endsWith('.java'));
  return {
    id, name, files: files.sort(),
    stats: {
      classes: files.length, method, skid, pg, stackStr, generic, fallback, classRenames,
      ms: Date.now() - t0, cfrMs: tCfr, exit: code, ...pp,
      warnings: (err.match(/Exception|failed|error/gi) || []).length,
    },
  };
  } finally { stopWatch(); }
}

// Yapıştırılan (obf'lu) Java kodunu doğrudan deobf et
async function handleText(req, res, url) {
  let body;
  try { body = await readBody(req, 8 * 1024 * 1024); }
  catch (e) { return json(res, 413, { error: 'Metin çok büyük (en fazla 8 MB).' }); }
  const raw = body.toString('utf8').replace(/\r\n/g, '\n');
  if (!raw.trim()) return json(res, 400, { error: 'Metin boş.' });
  const t0 = Date.now();
  try {
    let input = raw, method = null;
    {
      // Python adımı (jar yok: string havuzu / enum switch tablosu kullanılamaz); başarısızsa sadece JS
      const id = crypto.randomBytes(12).toString('hex');
      const dir = path.join(WORK, id), srcDir = path.join(dir, 'src'), outDir = path.join(dir, 'out');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'Kod.java'), raw);
      const py = await runPython(['--src', srcDir, '--out', outDir, '--no-rename'], 5 * 60 * 1000);
      const f = path.join(outDir, 'Kod.java');
      if (py.code === 0 && fs.existsSync(f)) { method = parseStats(py.out); input = fs.readFileSync(f, 'utf8'); }
      fs.rm(dir, { recursive: true, force: true }, () => {});
    }
    const r = deobfuscate(input);
    let s = r.text.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n');
    const mp = mapNames(s); s = mp.text;
    s = fixProguard(s).text;
    const fo = foldOpaque(s);
    if (fo.n > 0) {
      s = fo.text;
      const r2 = deobfuscate(s);
      s = r2.text.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n');
    }
    let text = s, classRenames = 0;
    try {
      const rr = renameClasses(new Map([['Kod.java', text]]), { anyTop: true });
      text = rr.files.values().next().value; classRenames = rr.renames.length;
    } catch {}
    json(res, 200, { text, raw, stats: { ...r.stats, renamed: mp.n, classRenames, method, ms: Date.now() - t0, changed: text !== raw } });
  } catch (e) {
    json(res, 500, { error: 'Deobf sırasında hata: ' + (e.message || e) });
  }
}

function handleFile(res, url) {
  const id = url.searchParams.get('id');
  const rel = url.searchParams.get('path') || '';
  if (!isId(id)) return json(res, 400, { error: 'Geçersiz id.' });
  const outDir = path.join(WORK, id, 'out');
  let full = path.resolve(outDir, rel);
  if (!full.startsWith(outDir + path.sep)) return json(res, 400, { error: 'Geçersiz yol.' });
  if (url.searchParams.get('live') === '1') {          // decompile sürerken: henüz çıktı yok, CFR'nin ham dosyasını ver
    for (const base of [path.join(WORK, id, 'raw'), path.join(WORK, id, 'fh', '_staging_java')]) {
      const f = path.resolve(base, rel);
      if (f.startsWith(base + path.sep) && fs.existsSync(f) && fs.statSync(f).isFile()) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return fs.createReadStream(f).pipe(res);
      }
    }
    return json(res, 404, { error: 'Dosya henüz hazır değil.' });
  }
  if (url.searchParams.get('raw') === '1') {          // ham hal varsa onu, yoksa (değişmemiş) çıktıyı ver
    let rawRel = rel;
    try { const back = JSON.parse(fs.readFileSync(path.join(WORK, id, 'renames.json'), 'utf8')); if (back[rel]) rawRel = back[rel]; } catch {}
    const rawFull = path.resolve(WORK, id, 'raw', rawRel);
    if (rawFull.startsWith(path.join(WORK, id, 'raw') + path.sep) && fs.existsSync(rawFull)) full = rawFull;
  }
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return json(res, 404, { error: 'Bulunamadı.' });
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  fs.createReadStream(full).pipe(res);
}

// Tüm kaynakları tek metin dosyası olarak indir
function handleAll(res, url) {
  const id = url.searchParams.get('id');
  if (!isId(id)) return json(res, 400, { error: 'Geçersiz id.' });
  const outDir = path.join(WORK, id, 'out');
  if (!fs.existsSync(outDir)) return json(res, 404, { error: 'Bulunamadı.' });
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Disposition': 'attachment; filename="decompiled-sources.txt"',
  });
  for (const rel of walk(outDir).filter(f => f.endsWith('.java')).sort())
    res.write(`\n// ===== ${rel} =====\n` + fs.readFileSync(path.join(outDir, rel), 'utf8') + '\n');
  res.end();
}


// Tüm kaynaklarda metin ara (temiz çıktı)
function handleSearch(res, url) {
  const id = url.searchParams.get('id'), q = (url.searchParams.get('q') || '').trim();
  const isRe = url.searchParams.get('re') === '1', cs = url.searchParams.get('cs') === '1';
  if (!isId(id)) return json(res, 400, { error: 'Geçersiz id.' });
  if (q.length < 2) return json(res, 400, { error: 'En az 2 karakter.' });
  const outDir = path.join(WORK, id, 'out');
  if (!fs.existsSync(outDir)) return json(res, 404, { error: 'Bulunamadı.' });
  let re;
  try { re = new RegExp(isRe ? q : q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), cs ? '' : 'i'); }
  catch (e) { return json(res, 400, { error: 'Geçersiz regex.' }); }
  const hits = []; let total = 0, files = 0;
  for (const rel of walk(outDir).filter(f => f.endsWith('.java')).sort()) {
    const lines = fs.readFileSync(path.join(outDir, rel), 'utf8').split('\n');
    let any = false;
    for (let i = 0; i < lines.length; i++) {
      if (!re.test(lines[i])) continue;
      total++; any = true;
      if (hits.length < 300) hits.push({ path: rel, line: i + 1, text: lines[i].trim().slice(0, 200) });
    }
    if (any) files++;
  }
  json(res, 200, { hits, total, files, truncated: total > hits.length });
}

// Saklamalı (store) ZIP: bağımlılık yok
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = CRC_T[(c ^ buf[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function handleZip(res, url) {
  const id = url.searchParams.get('id');
  if (!isId(id)) return json(res, 400, { error: 'Geçersiz id.' });
  const outDir = path.join(WORK, id, 'out');
  if (!fs.existsSync(outDir)) return json(res, 404, { error: 'Bulunamadı.' });
  res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="decompiled-sources.zip"' });
  const central = []; let offset = 0;
  for (const rel of walk(outDir).sort()) {
    const data = fs.readFileSync(path.join(outDir, rel)), nm = Buffer.from(rel), crc = crc32(data);
    const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0x0800, 6);
    h.writeUInt32LE(crc, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(nm.length, 26);
    res.write(h); res.write(nm); res.write(data);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x0800, 8);
    c.writeUInt32LE(crc, 16); c.writeUInt32LE(data.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(nm.length, 28); c.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([c, nm])); offset += 30 + nm.length + data.length;
  }
  const cd = Buffer.concat(central), e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(central.length, 8); e.writeUInt16LE(central.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(offset, 16);
  res.write(cd); res.end(e);
}

// İstatistik: en çok değişen / en büyük dosyalar
function handleOverview(res, url) {
  const id = url.searchParams.get('id');
  if (!isId(id)) return json(res, 400, { error: 'Geçersiz id.' });
  const outDir = path.join(WORK, id, 'out');
  if (!fs.existsSync(outDir)) return json(res, 404, { error: 'Bulunamadı.' });
  let back = {}; try { back = JSON.parse(fs.readFileSync(path.join(WORK, id, 'renames.json'), 'utf8')); } catch {}
  const rows = [];
  for (const rel of walk(outDir).filter(f => f.endsWith('.java'))) {
    const clean = fs.readFileSync(path.join(outDir, rel), 'utf8');
    const rp = path.join(WORK, id, 'raw', back[rel] || rel);
    let rawLines = 0; try { rawLines = fs.readFileSync(rp, 'utf8').split('\n').length; } catch {}
    const cl = clean.split('\n').length;
    rows.push({ path: rel, lines: cl, rawLines, removed: rawLines ? rawLines - cl : 0, strings: (clean.match(/"(?:\\.|[^"\\\n])*"/g) || []).length });
  }
  const top = (k, n = 15) => [...rows].sort((a, b) => b[k] - a[k]).slice(0, n);
  json(res, 200, { files: rows.length, lines: rows.reduce((a, r) => a + r.lines, 0), biggest: top('lines'), mostCleaned: top('removed'), mostStrings: top('strings') });
}

function serveStatic(res, pathname) {
  let p = pathname === '/' ? '/index.html' : pathname;
  const full = path.resolve(PUBLIC, '.' + p);
  if (!full.startsWith(PUBLIC + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    res.writeHead(404); return res.end('404');
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
  fs.createReadStream(full).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/api/report') {
      const rid = url.searchParams.get('id');
      const rp = rid && isId(rid) ? path.join(WORK, rid, 'report.md') : null;
      if (!rp || !fs.existsSync(rp)) return json(res, 404, { error: 'Rapor yok.' });
      res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8', 'Content-Disposition': 'attachment; filename="DEOBF_REPORT.md"' });
      return fs.createReadStream(rp).pipe(res);
    }
    if (req.method === 'POST' && url.pathname === '/api/mapping') {
      const body = await readBody(req, 50 * 1024 * 1024);
      const text = body.toString('utf8');
      if (!/^\S+ -> \S+:\s*$/m.test(text)) return json(res, 400, { error: 'Bu bir ProGuard mapping.txt dosyasına benzemiyor.' });
      fs.mkdirSync(path.join(WORK, 'maps'), { recursive: true });
      const mid = crypto.randomBytes(12).toString('hex');
      fs.writeFileSync(path.join(WORK, 'maps', mid + '.txt'), text);
      return json(res, 200, { id: mid, classes: (text.match(/^\S+ -> \S+:\s*$/gm) || []).length });
    }
    if (req.method === 'POST' && url.pathname === '/api/decompile') return await handleDecompile(req, res, url);
    if (req.method === 'POST' && url.pathname === '/api/deobf-text') return await handleText(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/events') return handleEvents(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/search') return handleSearch(res, url);
    if (req.method === 'GET' && url.pathname === '/api/zip') return handleZip(res, url);
    if (req.method === 'GET' && url.pathname === '/api/overview') return handleOverview(res, url);
    if (req.method === 'GET' && url.pathname === '/api/file') return handleFile(res, url);
    if (req.method === 'GET' && url.pathname === '/api/all') return handleAll(res, url);
    if (req.method === 'GET') return serveStatic(res, url.pathname);
    res.writeHead(405); res.end();
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
});

// Eski işleri temizle
setInterval(() => {
  for (const d of fs.readdirSync(WORK)) {
    const p = path.join(WORK, d);
    if (d === 'maps') {   // mapping dosyaları tek tek TTL ile silinir; klasör kalır
      try { for (const f of fs.readdirSync(p)) { const fp = path.join(p, f); if (Date.now() - fs.statSync(fp).mtimeMs > TTL_MS) fs.rmSync(fp, { force: true }); } } catch {}
      continue;
    }
    try { if (Date.now() - fs.statSync(p).mtimeMs > TTL_MS) { fs.rmSync(p, { recursive: true, force: true }); JOBS.delete(d); } } catch {}
  }
}, 10 * 60 * 1000).unref();

server.listen(PORT, '127.0.0.1', () => console.log(`RextroDeobf: http://localhost:${PORT}`));
