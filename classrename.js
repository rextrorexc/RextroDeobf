'use strict';
/*
 * Obfuscate sınıf adlarını (AA, GB, dasdasdda, uKN7TqO ...) koddan türetilen gerçek adlara çevirir.
 *
 * Kanıtlar (güçlüden zayıfa):
 *   1. string / annotation:  super("Aura", ...), getName() { return "Aura"; }, @M(configRoot="checks.ElytraTargetH"), NAME = "Aura"
 *   2. değişken adı oyları:  başka dosyalarda "private final GB playerManager;" gibi anlamlı alan / parametre adları
 *   3. üst sınıf / arayüz:   extends Check, implements Listener, extends Exception ...
 *   4. tür ve rol:           enum, interface, exception, yalnız statik metotlar (Utils) ...
 * Yeniden adlandırma tüm dosyalarda import / paket / iç sınıf kurallarına göre bağlamsal yapılır
 * (aynı basit ad farklı paketlerde farklı sınıfları gösterebilir).
 */

/* ------------------------------------------------------------ sözlük / "obfuscate mi?" sezgisi */

const WORDS = new Set(`a able about abort absorb abstract accept access account action active actor add admin after alert algo all allow alpha always anchor angle animal animation anti any api app apply arg argument armor array arrow ask assert async attack attribute audio auth auto axe back backup bad ban bar base basic batch bed before behavior bin bind biome bit block blocking blue body bomb book boolean boot border bossbar bot bounds box break bridge broadcast buffer bug build builder bukkit bundle button byte cache calc call callback camera cancel canvas capture card cast cat category cell center chain change channel char chat check chest chunk circle class clean clear click client clock close cloud code collect collection color combat command common compare compat component compress condition config configuration confirm connect connection console constant consume container content context control controller convert cooldown coord copy core count counter crash create creative credit crit critical crypto cube current custom cycle damage data database date debug decode decorator default delay delete delta deny depend deploy desc description destroy detect device diff digest dimension direct direction disable discord dispatch dispatcher display distance divide door double down download drag draw drop dump duration dynamic edit effect element elytra emit empty enable encode encrypt end engine enter entity entry enum env equip error escape event exact exception exec execute exempt exit expand expire export express extend extension fabric factory fail fake fall false fast feature field file fill filter final find finish fire first fix flag flat flight float flow flush fly focus fold follow font force forge format forward frame free friend from full function future game gamemode gate general generate generator get ghost give global glow goal grab gradient graph grid group guard gui guide hand handle handler hash head health heart height help helper hide high hit hold holder home hook horse host hot hotbar http hud icon id idle image impl import in index info init inject input insert inspect install instance int integer interact interface internal interval inventory invert item iterator jar java join json jump key kick kill kit known label lag language last launch layer lazy leave left length level lib library license life light limit line link list listen listener live load loader local lock log logger login logic long look loop loss low lower main make manager map mark mask master match math matrix max measure memory menu merge message meta method metric metrics min mining miss mixin mob mod mode model module monitor motion mount mouse move movement multi name native navigate near nearest need net network new next node none normal note notification notify null num number object observer offset old online open operation option order origin other out output outline override owner pack package packet page pair panel param parent parse particle partner pass password patch path pattern pause payload peek pending perform period permission persist phase physics pick ping pipe pitch pivot place plain platform play player plugin point policy poll pool pop port pos position post potion power predict prefix prepare press preview previous primary print priority private process profile progress project promote prompt property protect protocol provider proxy public pull punish punishment push put query queue quick quit radius random range rate raw ray reach read ready real reason receive record recover rect redirect reduce ref reference refresh region register registry reject relay release reload remote remove render repair repeat replace reply report repository request require reset resolve resolver resource response restart restore result resume retry return reverse revive right ring rise role rollback root rotate rotation round route router rule run runnable runtime safe sample save scale scan scene schedule scheduler scope score screen script scroll search second secret section secure seed select selector self send sender sequence serial server service session set setting settings setup shader shape share shield shoot shop short show shutdown side sign signal silent simple single size skin skip sleep slider slime slot slow small smart snapshot socket solid sort sound source space spawn speed sphere split spoof sprint stack stage standard start state static stats status step stick stop storage store stream strict string strip struct style sub success suffix summary support swap swing switch sync system tab table tag take target task team teleport temp template test text texture thread throw tick time timer title toggle token tool top total touch trace track trade traffic transaction transform translate trap tree trigger true trust try tune turn type ui undo unit unknown unlock update upgrade upload url use user util utility valid validate value vanilla vector velocity vendor verify version vertex view violation visible visual void volume wait walk wall warn watch water wave web webhook weight wheel white whitelist width window wire with wizard word work world wrap wrapper write xp yaw zip zone`.split(/\s+/));

const COMMON3 = new Set(['Box', 'Pos', 'Gui', 'Key', 'Map', 'Set', 'Row', 'Tab', 'Tag', 'Dir', 'Log', 'App', 'API', 'Net', 'Bar', 'Bed', 'Cat', 'Cow', 'Ore', 'Axe', 'Egg', 'Ice', 'Mob', 'Pet', 'Zip', 'URL', 'XYZ', 'RGB', 'UUID', 'GUI', 'NBT', 'Nbt', 'Bot', 'Bit', 'Raw', 'Rot', 'Old', 'New', 'Max', 'Min', 'Sum', 'Run', 'Add', 'Get', 'Put', 'Ban', 'Day', 'Sky', 'Hud', 'HUD', 'Fly', 'Esp', 'ESP', 'Kit', 'Pvp', 'PvP', 'Xp']);
const ACRONYMS = new Set(['URL', 'HTTP', 'HTTPS', 'API', 'GUI', 'JSON', 'UUID', 'XML', 'SQL', 'HUD', 'ESP', 'NBT', 'RGB', 'HSB', 'UTF', 'CPU', 'GPU', 'TPS', 'FPS', 'AES', 'RSA', 'SHA', 'MD5', 'TCP', 'UDP', 'DNS', 'IPV4', 'ABI']);

function segCover(s) {   // küçük harfli dizgenin sözlük kelimeleriyle kapsanma oranı (0..1)
  s = s.toLowerCase().replace(/[^a-z]/g, '');
  const n = s.length;
  if (!n) return 1;
  const best = new Array(n + 1).fill(0);   // best[i] = ilk i karakterde kapsanan en çok karakter
  for (let i = 1; i <= n; i++) {
    best[i] = best[i - 1];
    for (let j = Math.max(0, i - 14); j < i - 1; j++) {
      if (i - j >= 3 && WORDS.has(s.slice(j, i))) best[i] = Math.max(best[i], best[j] + (i - j));
    }
  }
  return best[n] / n;
}

/** yer tutucu / ProGuardClean / jadx / CFR üretimi adlar (Field24, method, class12, var3 ...) — kanıt olarak da kullanılmamalı */
const PLACEHOLDER = /^(?:class|interface|enum|field|method|param|parameter|var|variable|obj|object|clazz|cls|const|constant|func|function|member|unnamed|anon|lambda|c|m|f|v)_?\d*$/i;
const PLACEHOLDER_TAIL = /(?:Field|Method|Class|Param|Var|Obj|Clazz|Cls)_?\d+$/;   // ComputeMethod24, Field24Method24 -> üretilmiş birleşik adlar
/** lowerMode: jar'daki sınıf adlarının büyük kısmı küçük harfle başlıyorsa (aa, matri2x, vulcan1 ...) hepsi obfuscate sayılır */
let LOWER_MODE = false;
function isObfName(name) { return looksObfuscated(name) || (LOWER_MODE && /^[a-z]/.test(name) && name !== 'package-info' && name !== 'module-info'); }

function looksObfuscated(name) {
  if (/^class_\d+$/.test(name)) return true;
  if (PLACEHOLDER.test(name)) return true;
  if (PLACEHOLDER_TAIL.test(name)) return true;
  if (/^[a-z][a-z_]*\d+[a-z0-9_]*$/.test(name) && !/^(?:md5|sha\d+|utf\d+|base\d+|log4j|vec\d\w?|mat\d\w?|int\d+|float\d+|x509|rsa\d*|aes\d*|des\d*|ipv\d)$/.test(name)) return true;   // matri2x, vulcan1, class12
  if (/^_*[A-Za-z]?_*\d*_*$/.test(name) && name.length <= 4) return true;                                 // a_, _1_, _x_
  if (/^[IlLi1oO0]{4,}$/.test(name)) return true;                                                          // IlIlIl, OO0O0
  if (KEYWORDS_RE.test(name)) return true;                                                                  // do, if (CFR _do'ya çevirir)
  if (/^(?:Class|Interface|Enum|Utils|Data|CustomException)\d*$/.test(name)) return true;     // ProGuardClean yer tutucuları
  const n = name.length;
  if (n <= 2) return true;
  if (n === 3) return !COMMON3.has(name);
  if (ACRONYMS.has(name)) return false;
  const hasUp = /[A-Z]/.test(name), hasLow = /[a-z]/.test(name), hasDigit = /\d/.test(name);
  if (hasUp && !hasLow) return n <= 6;                                   // GB, ABCD
  const humps = name.match(/[A-Z][a-z0-9]*|[a-z0-9]+/g) || [name];
  const cover = segCover(name);
  if (!hasUp) return cover < 0.8 && n >= 4;                              // dasdasdda, bdogbrpqfybtkeuq
  if (hasDigit && hasLow && hasUp && n >= 5) return cover < 0.75;       // uKN7TqO
  if (humps.length >= 3 && humps.reduce((a, h) => a + h.length, 0) / humps.length < 3) return true;   // xQdHnZ
  if (n >= 8 && cover < 0.4) return true;
  if (/^[A-Z][a-z]{3,}$/.test(name) && cover < 0.3) {                    // tek hump, sözlükte yok: sesli/sessiz oranına bak
    const v = (name.match(/[aeiouAEIOU]/g) || []).length / n;
    return v < 0.2 || v > 0.7;
  }
  return false;
}

/* ------------------------------------------------------------ metin yardımcıları */

const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** string ve yorumların içini boşluklarla doldurur (uzunluk ve satırlar korunur) */
function mask(src) {
  let out = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { let j = src.indexOf('\n', i); if (j < 0) j = n; out += ' '.repeat(j - i); i = j; }
    else if (c === '/' && d === '*') { let j = src.indexOf('*/', i + 2); j = j < 0 ? n : j + 2; out += src.slice(i, j).replace(/[^\n]/g, ' '); i = j; }
    else if (c === '"' || c === '\'') {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== '\n') { if (src[j] === '\\') j++; j++; }
      j = Math.min(n, j + 1);
      out += c + ' '.repeat(Math.max(0, j - i - 2)) + (src[j - 1] === c ? c : ' ');
      i = j;
    } else { out += c; i++; }
  }
  return out;
}

const pascal = s => s.replace(/[^A-Za-z0-9_ ]+/g, ' ').split(/[\s_]+/).filter(Boolean).map(w => w[0].toUpperCase() + w.slice(1)).join('');
const lcFirst = s => s[0].toLowerCase() + s.slice(1);

const JAVA_LANG = new Set(['String', 'Object', 'Integer', 'Long', 'Double', 'Float', 'Short', 'Byte', 'Character', 'Boolean', 'Number', 'Thread', 'Math', 'System', 'Class', 'Runnable', 'Exception', 'Error', 'Throwable', 'Override', 'Process', 'Runtime', 'Iterable', 'Comparable', 'Record', 'Enum', 'Void', 'StringBuilder', 'Deprecated', 'FunctionalInterface', 'SuppressWarnings', 'SafeVarargs', 'Package', 'Module', 'Compiler', 'Appendable', 'AutoCloseable', 'CharSequence', 'Cloneable', 'ClassLoader', 'ThreadLocal', 'Readable', 'StackTraceElement', 'RuntimeException', 'IllegalStateException', 'IllegalArgumentException']);

/* ------------------------------------------------------------ sınıf bilgisi çıkarma */

const KEYWORDS_RE = /^_?(?:abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|goto|if|implements|import|instanceof|int|interface|long|native|new|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|try|void|volatile|while)$/;
const KEYWORDS = new Set('abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while var record sealed permits non-sealed yield'.split(' '));

function declInfo(text, masked, bodyStart, kindMatch) {
  return null;
}

/** dosyadaki bildirimler: [{name, kind, start(index of keyword), depth, header, bodyStart, bodyEnd, outer}] */
function parseDecls(text) {
  const m = mask(text);
  const decls = [];
  const stack = [];                    // süslü parantez yığını: {decl|null}
  const declRe = /(@interface|\b(?:class|interface|enum|record))\s+([A-Za-z_$][\w$]*)/g;
  const marks = [];
  let mm;
  while ((mm = declRe.exec(m))) {
    // "X.class" kullanımını ve "new Foo() {" gibi anonim sınıfları dışla
    const before = m.slice(Math.max(0, mm.index - 2), mm.index);
    if (/\.\s*$/.test(before)) continue;
    marks.push({ kind: mm[1], name: mm[2], idx: mm.index, nameEnd: mm.index + mm[0].length });
  }
  let mi = 0;
  const pending = [];
  for (let i = 0; i < m.length; i++) {
    while (mi < marks.length && marks[mi].idx === i) { pending.push(marks[mi]); mi++; }
    const c = m[i];
    if (c === '{') {
      const top = stack.length ? stack[stack.length - 1] : null;
      let d = null;
      if (pending.length) {
        const p = pending.shift();
        d = { name: p.name, kind: p.kind, start: p.idx, nameEnd: p.nameEnd, bodyStart: i, bodyEnd: -1, outer: top && top.decl ? top.decl : null };
        d.header = text.slice(p.idx, i);
        decls.push(d);
      }
      stack.push({ decl: d });
    } else if (c === '}') {
      const t = stack.pop();
      if (t && t.decl) t.decl.bodyEnd = i;
    }
  }
  for (const d of decls) if (d.bodyEnd < 0) d.bodyEnd = text.length;
  return decls;
}

/* ------------------------------------------------------------ ana işlev */

const BAD_VAR = /^(?:var\d+.*|n\d*|bl\d*|f\d*|d\d*|l\d*|i\d*|j\d*|k\d*|s\d*|b\d*|c\d*|o\d*|e\d*|t\d*|v\d*|x\d*|y\d*|z\d*|[a-z]{1,2}\d*|obj\w*|object\d*|string\d*|this|that|other\d*|tmp\d*|temp\d*|value\d*|val\d*|result\d*|res\d*|arg\d*|args|param\d*|instance|item\d*|entry\d*|element\d*|data\d*|list\d*|map\d*|set\d*|array\w*|lv\d+|class_\d+|clazz\d*|type\d*|self|thing|stuff|cur\w*|prev\w*|next\w*|old\w*|new\w*|my\w*|the\w*|it|iter\w*)$/i;

function goodVarName(v, typeName) {
  if (!v || v.length < 3) return false;
  if (BAD_VAR.test(v)) return false;
  if (/\d$/.test(v)) return false;                                                            // CFR numaralı değişkenleri (block22)
  if (/^(?:class|interface|enum|utils|data|customexception)\d*$/i.test(v)) return false;
  if (PLACEHOLDER.test(v) || PLACEHOLDER_TAIL.test(v[0].toUpperCase() + v.slice(1))) return false;
  if (looksObfuscated(v[0].toUpperCase() + v.slice(1))) return false;
  if (typeName && v.toLowerCase() === typeName.toLowerCase()) return false;        // CFR'nin türden türettiği ad
  if (/^[a-z]+\d+$/.test(v) && v.length < 7) return false;
  return true;
}

function singular(v) {
  if (/ies$/.test(v) && v.length > 4) return v.slice(0, -3) + 'y';
  if (/(?:ses|xes|ches|shes)$/.test(v)) return v.slice(0, -2);
  if (/s$/.test(v) && !/ss$/.test(v) && v.length > 3) return v.slice(0, -1);
  return v;
}

const ROLES = ['Exception', 'Check', 'Module', 'Command', 'Listener', 'Event', 'Handler', 'Manager', 'Service', 'Task', 'Packet', 'Config', 'Provider', 'Factory', 'Builder', 'Repository', 'Registry', 'Controller', 'Adapter', 'Wrapper', 'Context', 'Session', 'Cache', 'Settings', 'Setting', 'Utils', 'Util', 'Data', 'Entity', 'Plugin', 'Visitor', 'Parser', 'Reader', 'Writer', 'Loader', 'Generator', 'Resolver', 'Validator', 'Detector', 'Tracker', 'Monitor', 'Scheduler', 'Dispatcher', 'Coordinator', 'Policy', 'Strategy', 'Type', 'Mode', 'State', 'Action', 'Result', 'Response', 'Request', 'Callback', 'Consumer', 'Supplier', 'Function', 'Predicate', 'Filter', 'Render', 'Renderer'];

function roleOf(typeName) {
  if (!typeName) return null;
  for (const r of ROLES) if (typeName.endsWith(r) && typeName.length >= r.length) return r;
  return null;
}

function renameClasses(input, opts = {}) {
  /* input: Map(rel -> text)  (rel "a/b/C.java") */
  const files = new Map();
  for (const [rel, text] of input) {
    const t = text.replace(/\r\n/g, '\n');
    const pkgM = /^\s*package\s+([\w.]+)\s*;/m.exec(mask(t));
    const dir = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
    const pkg = pkgM ? pkgM[1] : dir.replace(/\//g, '.');
    let base = rel.slice(rel.lastIndexOf('/') + 1).replace(/\.java$/, '');
    const decls0 = parseDecls(t);
    const tops0 = decls0.filter(d => !d.outer);
    if (tops0.length && !tops0.some(d => d.name === base)) {           // do.java -> class _do / Method2474 gibi uyuşmazlık: dosyanın asıl sınıfı
      const pub = tops0.find(d => /\bpublic\b/.test(d.header)) || tops0[0];
      base = pub.name;
    }
    files.set(rel, { rel, text: t, masked: mask(t), pkg, base, decls: decls0 });
  }

  /* --- sınıf tablosu (FQN anahtarlı) --- */
  const classes = new Map();                // fqn -> {fqn, file, decl, simple, outer: fqn|null, nested: Map(simple->fqn)}
  const pkgClasses = new Map();             // pkg -> Map(simple -> fqn)  (üst düzey)
  for (const f of files.values()) {
    const fqnOf = new Map();
    for (const d of f.decls) {
      const fq = d.outer ? fqnOf.get(d.outer) + '.' + d.name : (f.pkg ? f.pkg + '.' : '') + d.name;
      fqnOf.set(d, fq); d.fqn = fq;
      classes.set(fq, { fqn: fq, file: f, decl: d, simple: d.name, outer: d.outer ? fqnOf.get(d.outer) : null, nested: new Map(), top: !d.outer });
      if (d.outer) classes.get(fqnOf.get(d.outer)).nested.set(d.name, fq);
      else { if (!pkgClasses.has(f.pkg)) pkgClasses.set(f.pkg, new Map()); pkgClasses.get(f.pkg).set(d.name, fq); }
    }
  }

  /* --- hangi sınıflar obfuscate --- */
  const obf = new Set();
  // Kısa ad modu: jar'ın önemli kısmı (>=%5) 1-3 harfli adlardan oluşuyorsa (Matrix: 00, 8s, vf ...) yalnız kısa/yer tutucu adlar
  // yeniden adlandırılır. Sözlük sezgisi gömülü kütüphanelerin gerçek adlarını (HSVLikeImpl, XMaterial ...) bozuyordu.
  const isShort = n => /^_*[^_]{1,3}_*$/.test(n) && !COMMON3.has(n.replace(/^_/, '')) && !/^[A-Z][a-z]{2}$/.test(n) || /^(?:Class|Interface|Enum|Utils|Data|CustomException)\d*$/.test(n) || /^class_\d+$/.test(n);
  let nTop = 0, nShort = 0;
  for (const c of classes.values()) if (c.top) { nTop++; if (isShort(c.simple)) nShort++; }
  const strict = nTop > 0 && nShort >= 50 && nShort / nTop >= 0.05;
  for (const c of classes.values()) {
    if (strict && !isShort(c.simple) && !(LOWER_MODE && c.top && /^[a-z]/.test(c.simple)) && !looksObfuscated(c.simple)) continue;
    if (c.top ? (opts.anyTop || c.simple === c.file.base) && isObfName(c.simple) : looksObfuscated(c.simple)) obf.add(c.fqn);
  }
  if (!obf.size) return { files: input, map: {}, renames: [] };

  /* --- dosya başına bağlamalar --- */
  for (const f of files.values()) {
    f.imports = new Map();       // simple -> fqn (proje sınıfı olanlar)
    f.libNames = new Set();      // proje dışı import edilen basit adlar
    f.wild = [];
    const re = /^[ \t]*import\s+(static\s+)?([\w.]+?)(\.\*)?\s*;/gm;
    let m;
    while ((m = re.exec(f.masked))) {
      if (m[1]) continue;
      if (m[3]) { f.wild.push(m[2]); continue; }
      const fq = m[2], simple = fq.slice(fq.lastIndexOf('.') + 1);
      if (classes.has(fq)) f.imports.set(simple, fq); else f.libNames.add(simple);
    }
  }

  /** bir dosyada basit ad -> proje sınıfı FQN (yoksa null) */
  function resolveSimple(f, name, atIndex) {
    // iç içe bildirim kapsamı: bu dosyada, konumu kapsayan bildirimlerin iç sınıfları
    if (atIndex != null) {
      let best = null;
      for (const d of f.decls) if (d.bodyStart < atIndex && atIndex <= d.bodyEnd) {
        const nx = classes.get(d.fqn).nested.get(name); if (nx) best = nx;
      }
      if (best) return best;
    }
    for (const d of f.decls) if (d.name === name && !d.outer) return (f.pkg ? f.pkg + '.' : '') + name;
    if (f.imports.has(name)) return f.imports.get(name);
    const same = pkgClasses.get(f.pkg);
    if (same && same.has(name) && !f.libNames.has(name)) return same.get(name);
    for (const w of f.wild) { const pc = pkgClasses.get(w); if (pc && pc.has(name)) return pc.get(name); }
    // iç sınıf: bu dosyadaki herhangi bir bildirimin iç sınıfı (kapsam bulunamadıysa)
    for (const d of f.decls) if (d.outer && d.name === name) return d.fqn;
    return null;
  }

  /* --- değişken adı oyları --- */
  const votes = new Map();       // fqn -> Map(name -> weight)
  const addVote = (fq, name, w) => { if (!votes.has(fq)) votes.set(fq, new Map()); const m = votes.get(fq); m.set(name, (m.get(name) || 0) + w); };
  const tokenRe = /\b([A-Z][\w$]*)\b/g;
  for (const f of files.values()) {
    // "Type name" ve "Type<...> name" bildirimleri (alan, parametre, yerel)
    const re = /\b([A-Za-z_][\w$]*)(?:<([^;(){}=]*?)>)?(?:\[\])*\s+([a-z_$][\w$]*)\s*(?=[=;,):])/g;
    let m;
    while ((m = re.exec(f.masked))) {
      if (KEYWORDS.has(m[1]) || KEYWORDS.has(m[3])) continue;
      const w = /^\s*(?:private|public|protected)/.test(f.masked.slice(Math.max(0, m.index - 20), m.index)) ? 3 : 1;
      const tryType = (tn, plural) => {
        const fq = resolveSimple(f, tn, m.index);
        if (!fq || !obf.has(fq)) return;
        let v = m[3];
        if (plural) v = singular(v);
        if (!goodVarName(v, tn)) return;
        addVote(fq, pascal(v), w);
      };
      tryType(m[1], false);
      if (m[2]) for (const g of m[2].split(/[,<>\s?]+/).filter(Boolean)) if (/^[A-Z]/.test(g)) tryType(g, true);
    }
  }

  /* --- sınıf başına kanıtlar --- */
  function bodyOf(c) { return c.file.text.slice(c.decl.start, c.decl.bodyEnd + 1); }
  function directBody(c) {   // iç sınıfların gövdesi çıkarılmış metin
    const d = c.decl; let t = '', pos = d.start;
    for (const x of c.file.decls) if (x.outer === d) { t += c.file.text.slice(pos, x.start); pos = x.bodyEnd + 1; }
    return t + c.file.text.slice(pos, d.bodyEnd + 1);
  }
  function supers(c) {
    const h = c.decl.header.replace(/\s+/g, ' ');
    const ex = /\bextends\s+([\w.]+)/.exec(h), im = /\bimplements\s+([\w.<>, ]+)/.exec(h);
    return { ext: ex ? ex[1].replace(/<.*/, '') : null, impl: im ? im[1].split(',').map(s => s.trim().replace(/<.*/, '').replace(/^.*\./, '')) : [] };
  }
  const STR = /^[A-Za-z][A-Za-z0-9_ \-]{2,28}$/;
  function annoText(c) {            // bildirimin hemen önündeki annotation metni
    const t = c.file.text; const i = c.decl.start;
    const lim = Math.max(0, i - 600);
    let j = i;
    while (j > lim && !/[;{}]/.test(t[j - 1])) j--;
    return t.slice(j, i);
  }
  function stringHint(c) {
    const b = annoText(c) + '\n' + directBody(c);
    let m;
    if ((m = /configRoot\s*=\s*"([^"]+)"/.exec(b))) { const seg = m[1].split('.').pop(); if (STR.test(seg)) return { name: pascal(seg), w: 100, why: 'configRoot' }; }
    if ((m = /\bname\s*=\s*"([^"]+)"/.exec(b)) && STR.test(m[1])) return { name: pascal(m[1]), w: 95, why: 'annotation name' };
    if ((m = /\bsuper\(\s*"([^"]+)"/.exec(b)) && STR.test(m[1])) return { name: pascal(m[1]), w: 90, why: 'super("..")' };
    if ((m = /\bgetName\(\)\s*\{\s*return\s+"([^"]+)"/.exec(b)) && STR.test(m[1])) return { name: pascal(m[1]), w: 85, why: 'getName' };
    if ((m = /\b(?:NAME|ID|TITLE|LABEL)\s*=\s*"([^"]+)"/.exec(b)) && STR.test(m[1])) return { name: pascal(m[1]), w: 70, why: 'NAME const' };
    // Event Handler: @EventHandler void onX(PlayerMoveEvent e) -> PlayerMoveListener
    if ((m = /@EventHandler[\s\S]*?(?:public\s+)?void\s+\w+\(\s*([A-Z]\w*Event)\s+\w+\)/.exec(b))) {
      const ev = m[1].replace(/Event$/, '');
      if (STR.test(ev)) return { name: pascal(ev) + 'Listener', w: 88, why: 'EventHandler(' + m[1] + ')' };
    }
    // Command: cmd.getName().equalsIgnoreCase("speed") -> SpeedCommand
    if ((m = /(?:cmd|command)\.getName\(\)\.equals(?:IgnoreCase)?\(\s*"([^"]+)"\s*\)/.exec(b))) {
      if (STR.test(m[1])) return { name: pascal(m[1]) + 'Command', w: 86, why: 'Command(' + m[1] + ')' };
    }
    if ((m = /@Command\s*\(\s*(?:name\s*=\s*)?"([^"]+)"/.exec(b))) {
      if (STR.test(m[1])) return { name: pascal(m[1]) + 'Command', w: 87, why: '@Command' };
    }
    // GUI / Menu: createInventory(..., "Menu Title")
    if ((m = /createInventory\(\s*(?:this|null)\s*,\s*\d+\s*,\s*"([^"]+)"/.exec(b))) {
      const title = m[1].replace(/[^A-Za-z0-9 ]/g, '').trim();
      if (title && STR.test(title)) return { name: pascal(title) + 'Menu', w: 82, why: 'MenuTitle' };
    }
    // Discord Webhook
    if (/discord(?:app)?\.com\/api\/webhooks/.test(b)) {
      return { name: 'DiscordWebhook', w: 80, why: 'Discord Webhook' };
    }
    return null;
  }

  /* --- ad önerme --- */
  const taken = new Map();            // pkg -> Set(lower-case simple)
  const libTaken = new Set(JAVA_LANG);
  for (const f of files.values()) for (const n of f.libNames) libTaken.add(n);
  for (const c of classes.values()) if (c.top && !obf.has(c.fqn)) { const p = c.file.pkg; if (!taken.has(p)) taken.set(p, new Set()); taken.get(p).add(c.simple.toLowerCase()); }

  const newName = new Map();          // fqn -> yeni basit ad
  const reasons = [];
  const counters = {};
  const order = [...obf].sort((a, b) => {      // güçlü kanıtı olanlar önce adlarını alsın
    const sa = stringHint(classes.get(a)) ? 1 : 0, sb = stringHint(classes.get(b)) ? 1 : 0;
    return sb - sa || a.localeCompare(b);
  });

  function nameFree(c, cand) {
    if (!cand || KEYWORDS.has(cand) || !/^[A-Za-z_]\w*$/.test(cand)) return false;
    if (c.top) {
      if (libTaken.has(cand)) return false;
      const t = taken.get(c.file.pkg); if (t && t.has(cand.toLowerCase())) return false;
    } else {
      const outerSibs = new Set([...classes.get(c.outer).nested.entries()].filter(([s, fq]) => fq !== c.fqn).map(([s, fq]) => (newName.get(fq) || s).toLowerCase()));
      if (outerSibs.has(cand.toLowerCase()) || cand === classes.get(c.outer).simple) return false;
    }
    return true;
  }
  function claim(c, cand, why) {
    let base = cand, k = 1, name = base;
    while (!nameFree(c, name)) { k++; name = base + (k === 2 && !c.top ? '' : '') + k; if (k > 99) break; }
    if (c.top) { const p = c.file.pkg; if (!taken.has(p)) taken.set(p, new Set()); taken.get(p).add(name.toLowerCase()); }
    newName.set(c.fqn, name);
    reasons.push({ from: c.simple, to: name, pkg: c.file.pkg, why });
  }

  function kindFallback(c) {
    const d = c.decl, s = supers(c), body = directBody(c);
    if (d.kind === 'enum') return 'Enum';
    if (d.kind === 'interface' || d.kind === '@interface') return d.kind === '@interface' ? 'Annotation' : 'Interface';
    if (s.ext && /Exception$|Error$|Throwable$/.test(s.ext)) return 'CustomException';
    if (s.ext === 'JavaPlugin' || s.ext === 'Plugin') return 'MainPlugin';
    if (s.impl.includes('Runnable') || s.ext === 'BukkitRunnable' || s.ext === 'TimerTask') return 'Task';
    if (s.impl.includes('Listener') || /@EventHandler/.test(body)) return 'Listener';
    if (s.impl.includes('CommandExecutor') || s.impl.includes('TabCompleter')) return 'Command';
    if (s.impl.includes('InventoryHolder')) return 'Menu';
    if (s.ext && /Decoder$/.test(s.ext)) return 'Decoder';
    if (s.ext && /Encoder$/.test(s.ext)) return 'Encoder';
    if (s.impl.includes('PacketListener') || /PacketPlayIn|PacketPlayOut/.test(body)) return 'PacketHandler';
    if (/@RestController|@Controller/.test(body)) return 'Controller';
    if (/@Service/.test(body)) return 'Service';
    if (/@Repository/.test(body)) return 'Repository';
    if (/@Component|@Configuration/.test(body)) return 'Component';
    if (/\b(?:SELECT|INSERT|UPDATE|DELETE|PreparedStatement|getConnection)\b/i.test(body)) return 'Storage';
    if (/\bCipher\.getInstance\b/.test(body)) return 'Cipher';
    if (/\bMessageDigest\.getInstance\b/.test(body)) return 'Hasher';
    if (/\bgetConfig\(\)\.get|\bloadConfiguration\b/.test(body)) return 'Config';
    const methods = [...body.matchAll(/^\s+(?:public |private |protected )?(static )?(?:final )?[\w<>\[\],.? ]+ \w+\([^)]*\)\s*(?:throws [\w., ]+)?\{/gm)];
    if (methods.length && methods.every(m => m[1])) return 'Utils';
    if (!methods.length && /\bprivate final \w+/.test(body)) return 'Holder';
    if (/\bget\w+\(\)/.test(body) && methods.length <= 8) return 'Data';
    return 'Class';
  }

  /* --- belirteç (token) özellikleri: sınıfın kendi alan / metot / sabit / string sözcükleri --- */
  const STOP = new Set(('method methods field fields clazz lambda anon unnamed get set has on do the and for with from this that null true false new return void int long boolean string object value result list map name type data info instance class static final public private protected abstract exception throw try catch else while switch case break continue default import package super extends implements interface enum record var byte short char float double index count size length key keys values entries entry item items arg args param params obj tmp temp flag flags number ids self other first last next prev current old constant constants can run call apply accept test make create build init start stop update handle process execute check is are was has have will should not all any none some one two three max min add remove put contains clear reset to of in at by as it its').split(' '));
  const GENERIC = new Set(['Data', 'Info', 'Value', 'State', 'Entry', 'Item', 'Holder', 'Helper', 'Base', 'Impl', 'Object', 'Result', 'Context', 'Type', 'Mode', 'Kind', 'Util', 'Utils', 'Class', 'Manager', 'Handler', 'Service', 'Entity']);
  const splitWords = id => id.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(x => x.length >= 3 && !/^\d+$/.test(x));
  const goodWord = w => !STOP.has(w) && !/\d/.test(w) && w.length >= 3 && !/^[bcdfghjklmnpqrstvwxz]+$/.test(w) && /[aeiouy]/.test(w);
  const sigId = id => id.length > 2 && !looksObfuscated(id[0].toUpperCase() + id.slice(1)) && !BAD_VAR.test(id);

  const featOf = new Map();
  const dfMap = new Map();
  const classList = [...classes.values()];
  for (const c of classList) {
    const raw = directBody(c);
    const mk = mask(raw);
    const f = new Map();
    const add = (id, w) => { if (!sigId(id)) return; for (const x of splitWords(id)) if (goodWord(x)) f.set(x, (f.get(x) || 0) + w); };
    let m;
    const fieldRe = /(?:^|\n)[ \t]*(?:(?:private|public|protected|static|final|volatile|transient)\s+)+([\w<>\[\],.? ]+?)\s+([A-Za-z_]\w*)\s*(?:=|;)/g;
    while ((m = fieldRe.exec(mk))) { add(m[2], 3); for (const t of m[1].match(/[A-Za-z_]\w*/g) || []) if (/^[A-Z]/.test(t)) add(t, 1.5); }
    const methRe = /(?:^|\n)[ \t]*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*[\w<>\[\],.? ]+?\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:throws [\w., ]+)?\{/g;
    while ((m = methRe.exec(mk))) if (!KEYWORDS.has(m[1])) add(m[1], 2);
    const callRe = /\.\s*([a-z_]\w*)\s*\(/g;
    while ((m = callRe.exec(mk))) add(m[1], 0.5);
    const typeRe = /\b([A-Z][A-Za-z0-9_]*)\b/g;
    while ((m = typeRe.exec(mk))) add(m[1], 0.7);
    const strRe = /"([^"\\\n]{4,70})"/g;
    while ((m = strRe.exec(raw))) for (const x of m[1].split(/[^A-Za-z]+/)) if (x.length >= 4 && goodWord(x.toLowerCase())) f.set(x.toLowerCase(), (f.get(x.toLowerCase()) || 0) + 1.2);
    featOf.set(c.fqn, f);
    for (const w of f.keys()) dfMap.set(w, (dfMap.get(w) || 0) + 1);
  }
  const NCLS = classList.length;
  function topWords(c, k = 4) {
    const f = featOf.get(c.fqn) || new Map();
    return [...f.entries()].map(([w, s]) => [w, s * Math.log(1 + NCLS / (dfMap.get(w) || 1))]).sort((a, b) => b[1] - a[1]).slice(0, k);
  }

  function structuralRole(c) {
    const d = c.decl, s = supers(c), body = directBody(c);
    if (s.ext && /(?:Exception|Error|Throwable)$/.test(s.ext)) return 'Exception';
    if (s.impl.includes('Runnable') || (s.ext === 'TimerTask' || s.ext === 'BukkitRunnable')) return 'Task';
    const sup = s.ext && s.ext.replace(/^.*\./, '');
    const supN = sup && obf.has(resolveSimple(c.file, sup) || '') ? (newName.get(resolveSimple(c.file, sup)) || null) : sup;
    const r = roleOf(supN) || roleOf(s.impl.find(x => roleOf(x)));
    if (r && !/^(?:Type|Mode|State|Data|Entity|Result|Context|Function|Consumer|Supplier|Predicate|Callback)$/.test(r)) return r;
    if (d.kind === 'class') {
      const methods = [...body.matchAll(/^\s+(?:public |private |protected )?(static )?(?:final )?[\w<>\[\],.? ]+ \w+\([^)]*\)\s*(?:throws [\w., ]+)?\{/gm)];
      const hasInstanceField = /^\s+(?:private|protected|public)?\s*(?:final )?(?!static)[\w<>\[\],.? ]+ \w+\s*(?:=|;)/m.test(body.replace(/\bstatic\b[^;{]*[;{]/g, ''));
      if (methods.length >= 2 && methods.every(m => m[1]) && !hasInstanceField) return 'Utils';
    }
    return '';
  }

  const cleanVote = v => {
    v = v.replace(/By[A-Z]\w*$/, '').replace(/(?:Map|List|Set|Cache|Queue|Array|Collection|Registry|Holder)$/, '').replace(/^(?:Last|Current|Default|Active|Pending|Cached|Target)(?=[A-Z])/, '');
    return v && v.length >= 3 ? v : null;
  };

  for (const fq of order) {
    const c = classes.get(fq);
    const sh = stringHint(c);
    const s = supers(c);
    const superSimple = s.ext ? s.ext.replace(/^.*\./, '') : null;
    const role = structuralRole(c);
    const tw = topWords(c);
    let voteName = null, voteW = 0;
    const v = votes.get(fq);
    if (v) {
      const agg = new Map();
      for (const [n, w] of v) { const cn = cleanVote(n); if (cn) agg.set(cn, (agg.get(cn) || 0) + w); }
      for (const [n, w] of [...agg.entries()].sort((a, b) => b[1] - a[1])) { voteName = n; voteW = w; break; }
    }
    let cands = [], why = '';
    const withRole = n => (role && !n.endsWith(role) ? n + role : n);
    if (sh) { cands.push(sh.name); why = sh.why; }
    if (voteName) {
      let n = voteName;
      if (GENERIC.has(n) && tw.length) n = pascal(tw[0][0]) + n;
      cands.push(withRole(n)); if (!why) why = 'değişken adı (' + voteW + ')';
    }
    if (tw.length) {
      const [t1, t2, t3] = tw;
      const P = x => pascal(x[0]);
      const baseNames = [P(t1)];
      if (t2) baseNames.push(P(t1) + P(t2), P(t2));
      if (t3) baseNames.push(P(t1) + P(t3));
      for (const n of baseNames) cands.push(withRole(n));
      if (!why) why = 'sözcükler: ' + tw.slice(0, 3).map(x => x[0]).join(', ');
    }
    const kf = kindFallback(c);
    cands.push(kf);
    if (!why) why = 'rol';
    cands = cands.map(x => pascal(x).slice(0, 48)).filter(x => x && /^[A-Za-z_]/.test(x));
    // ilk boş adı seç
    let chosen = cands.find(x => nameFree(c, x));
    if (!chosen) chosen = cands[0];
    claim(c, chosen, chosen === cands[0] ? why : why + ' (alternatif)');
  }

  /* --- uygula: dosya içi bağlamsal jeton değiştirme --- */
  const newFqn = new Map();    // eski fqn -> yeni fqn
  for (const [fq, nn] of newName) {
    const c = classes.get(fq);
    newFqn.set(fq, c.outer ? (newFqn.get(c.outer) || c.outer) + '.' + nn : (c.file.pkg ? c.file.pkg + '.' : '') + nn);
  }
  // iç sınıfın dış sınıfı da yeniden adlandırıldıysa FQN sırası: dış önce hesaplanmalı
  for (const [fq, nn] of newName) {
    const c = classes.get(fq);
    if (c.outer) newFqn.set(fq, (newFqn.get(c.outer) || c.outer) + '.' + nn);
  }
  const mapOut = {};
  const out = new Map();
  for (const f of files.values()) {
    const m = f.masked, t = f.text;
    const edits = [];       // [start, end, replacement]
    const idRe = /[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*/g;
    let mm;
    while ((mm = idRe.exec(m))) {
      const chain = mm[0];
      // basit hızlı eleme: zincirde yeniden adlandırılacak bir ad geçmiyor mu?
      const parts = [];
      const pr = /[A-Za-z_$][\w$]*/g; let p;
      while ((p = pr.exec(chain))) parts.push({ s: mm.index + p.index, e: mm.index + p.index + p[0].length, n: p[0] });
      if (!parts.some(x => classRenameCandidates.has(x.n))) continue;
      // import satırı mı? ("import a.b.C;")
      const lineStart = m.lastIndexOf('\n', mm.index) + 1;
      const isImport = /^[ \t]*import\s+(?:static\s+)?$/.test(m.slice(lineStart, mm.index));
      const isPackage = /^[ \t]*package\s+$/.test(m.slice(lineStart, mm.index));
      if (isPackage) continue;
      // zinciri çöz
      let cur = null, i = 0, pkgAcc = '';
      const marked = [];
      if (isImport) {
        // tam yol: paket parçaları + sınıf + iç sınıflar
        let acc = '';
        for (i = 0; i < parts.length; i++) {
          acc = acc ? acc + '.' + parts[i].n : parts[i].n;
          if (classes.has(acc)) { cur = acc; if (newName.has(acc)) marked.push([parts[i], acc]); }
        }
      } else {
        const idx0 = parts[0].s;
        // önceki jeton '.' ise (ör. "foo().Bar") zincirin başı değil → yalnızca metot/alan erişimi: atla
        let pj = idx0 - 1;
        while (pj >= 0 && (m[pj] === ' ' || m[pj] === '\t' || m[pj] === '\n')) pj--;
        if (pj >= 0 && m[pj] === '.') continue;
        const first = resolveSimple(f, parts[0].n, idx0);
        if (first) { cur = first; if (newName.has(first)) marked.push([parts[0], first]); i = 1; }
        else {
          // tam nitelikli: a.b.C
          let acc = parts[0].n; i = 1;
          while (i < parts.length && !classes.has(acc + '.' + parts[i].n) && i < parts.length) { acc += '.' + parts[i].n; i++; }
          if (i < parts.length && classes.has(acc + '.' + parts[i].n)) { cur = acc + '.' + parts[i].n; if (newName.has(cur)) marked.push([parts[i], cur]); i++; }
        }
        // iç sınıf zinciri: Outer.Inner
        while (cur && i < parts.length) {
          const nx = classes.get(cur) && classes.get(cur).nested.get(parts[i].n);
          if (!nx) break;
          cur = nx; if (newName.has(nx)) marked.push([parts[i], nx]); i++;
        }
      }
      for (const [part, fq] of marked) edits.push([part.s, part.e, newName.get(fq)]);
    }
    let nt = t;
    edits.sort((a, b) => b[0] - a[0]);
    for (const [s, e, r] of edits) nt = nt.slice(0, s) + r + nt.slice(e);
    // dosya yolu
    let rel = f.rel;
    const topDecl = f.decls.find(d => !d.outer && d.name === f.base);
    if (topDecl) {
      const fq = (f.pkg ? f.pkg + '.' : '') + f.base;
      const finalName = newName.has(fq) ? newName.get(fq) : f.base;     // uyuşmayan dosya adı (do.java) da sınıf adına çekilir
      const cand = rel.slice(0, rel.lastIndexOf('/') + 1) + finalName + '.java';
      if (cand !== rel && !input.has(cand) && !out.has(cand)) rel = cand;
    }
    out.set(rel, nt);
    if (rel !== f.rel) mapOut[f.rel] = rel;
  }
  return { files: out, map: mapOut, renames: reasons };
}

// hızlı eleme kümesi: yeniden adlandırılacak basit adlar (renameClasses içinde doldurulur)
let classRenameCandidates = new Set();
const _render = renameClasses;
function renameClassesWrapped(input, opts) {
  // ön geçiş: obfuscate görünen tüm bildirim adlarını topla ki zincir taraması hızlı olsun
  classRenameCandidates = new Set();
  let nDecl = 0, nLow = 0; const names = [];
  for (const [rel, text] of input) {
    const re = /(?:@interface|\b(?:class|interface|enum|record))\s+([A-Za-z_$][\w$]*)/g;
    let m; while ((m = re.exec(text))) { names.push(m[1]); nDecl++; if (/^[a-z]/.test(m[1])) nLow++; }
  }
  LOWER_MODE = nLow >= 10 && nLow / Math.max(1, nDecl) >= 0.25;
  for (const n of names) if (isObfName(n)) classRenameCandidates.add(n);
  return _render(input, opts);
}

module.exports = { renameClasses: renameClassesWrapped, looksObfuscated, isObfName };
