(() => {
  const $ = id => document.getElementById(id);
  const hero = $('hero'), workspace = $('workspace'), drop = $('drop'), fileInput = $('file');
  const progress = $('progress'), barWrap = progress.querySelector('.bar'), barFill = $('barfill');
  const progText = $('progtext'), errBox = $('error'), overlay = $('overlay');
  const tree = $('tree'), filter = $('filter'), code = $('code'), curfile = $('curfile');
  const btnCopy = $('btn-copy'), btnDl = $('btn-dl'), btnAll = $('btn-all'), btnNew = $('btn-new'), btnReport = $('btn-report');
  const btnZip = $('btn-zip'), btnSearch = $('btn-search'), btnOverview = $('btn-overview'), btnSplit = $('btn-split');
  const liveBar = $('livebar'), livePhase = $('livephase'), liveCount = $('livecount'), liveTime = $('livetime'), liveLog = $('livelog');
  const searchPane = $('searchpane'), qIn = $('q'), qRe = $('q-re'), qCs = $('q-cs'), qInfo = $('q-info'), qRes = $('qres');
  const modal = $('modal'), modalBody = $('modal-body');

  let job = null;          // {id, name, files, stats, live?, local?}
  let current = null;      // {path, text}
  let rawMode = false;     // false: deobf edilmiş, true: ham CFR çıktısı
  let splitMode = false;   // ham | temiz yan yana
  const btnRaw = $('btn-raw');
  btnRaw.onclick = () => {
    rawMode = !rawMode;
    btnRaw.textContent = rawMode ? 'Ham' : 'Temiz';
    if (current) openFile(current.path);
  };
  btnSplit.onclick = () => {
    splitMode = !splitMode;
    btnSplit.classList.toggle('on', splitMode);
    if (current) openFile(current.path);
  };
  let dragDepth = 0;

  /* ---------- Yükleme ---------- */
  function showError(msg) { errBox.textContent = msg; errBox.hidden = false; }
  function resetUI() {
    errBox.hidden = true; progress.hidden = true; drop.hidden = false;
    barWrap.classList.remove('indeterminate'); barFill.style.width = '0';
  }

  let mapId = null;
  async function uploadMapping(file) {
    try {
      const r = await fetch('/api/mapping', { method: 'POST', body: file });
      const d = await r.json();
      if (!r.ok) { showError(d.error || 'mapping yüklenemedi'); return false; }
      mapId = d.id; errBox.hidden = true;
      const sp = $('drop-sub');
      if (sp) sp.textContent = `mapping.txt yüklendi (${d.classes} sınıf) — şimdi .jar dosyasını bırak`;
      toast(`mapping.txt yüklendi · ${d.classes} sınıf`);
      return true;
    } catch { showError('mapping yüklenemedi'); return false; }
  }

  function upload(file) {
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!['jar', 'class', 'war', 'zip'].includes(ext)) { showError('Sadece .jar, .class, .war veya .zip dosyası bırak.'); return; }
    resetUI();
    drop.hidden = true; progress.hidden = false;
    progText.textContent = `${file.name} yükleniyor…`;

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/decompile?name=' + encodeURIComponent(file.name) + (mapId ? '&map=' + mapId : ''));
    xhr.upload.onprogress = e => {
      if (!e.lengthComputable) return;
      barFill.style.width = (e.loaded / e.total * 100).toFixed(0) + '%';
    };
    xhr.upload.onload = () => { barWrap.classList.add('indeterminate'); progText.textContent = 'Sunucu başlatıyor…'; };
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status !== 202 || !data.id) {
        resetUI();
        showError((data.error || 'Bir hata oluştu.') + (data.detail ? '\n\n' + data.detail : ''));
        return;
      }
      startLive(data);
    };
    xhr.onerror = () => { resetUI(); showError('Sunucuya ulaşılamadı. "node server.js" çalışıyor mu?'); };
    xhr.send(file);
  }

  /* ---------- Canlı decompile (SSE) ---------- */
  let es = null, liveTimer = null, liveDirty = false, liveT0 = 0;
  const openDirs = new Set();
  let freshSet = new Set();

  function stopLive() {
    if (es) { es.close(); es = null; }
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
  }
  function addLog(e) {
    const s = document.createElement('span');
    const b = document.createElement('b'); b.textContent = e.text;
    s.append(b, ' ' + (e.t / 1000).toFixed(1) + ' sn');
    liveLog.appendChild(s);
  }
  function setLivePhase(t) { if (t) livePhase.textContent = t; }
  function addFiles(list) {
    if (!job || !job.live) return;
    for (const f of list) if (!job.seen.has(f)) { job.seen.add(f); job.files.push(f); freshSet.add(f); }
    liveCount.textContent = job.files.length + ' dosya';
    liveDirty = true;
  }

  function startLive(d) {
    stopLive();
    job = { id: d.id, name: d.name, files: [], seen: new Set(), live: true }; resetTabs();
    current = null; freshSet = new Set(); openDirs.clear();
    hero.hidden = true; workspace.hidden = false; document.body.classList.add('working');
    $('meta').textContent = `${d.name} · decompile ediliyor — hazır olan dosyaları soldan açabilirsin (ham CFR çıktısı)`;
    liveBar.hidden = false; liveLog.textContent = ''; livePhase.textContent = 'Başlıyor…'; liveCount.textContent = '0 dosya'; liveTime.textContent = '0 sn';
    filter.value = ''; tree.textContent = ''; delete tree.dataset.done; clearViewer(); closeSearch(); updateButtons();
    liveT0 = Date.now();
    liveTimer = setInterval(() => {
      liveTime.textContent = Math.floor((Date.now() - liveT0) / 1000) + ' sn';
      if (liveDirty) { liveDirty = false; buildTree(job.files); }
    }, 700);
    es = new EventSource('/api/events?id=' + d.id);
    es.addEventListener('snapshot', e => {
      const s = JSON.parse(e.data);
      liveLog.textContent = ''; s.log.forEach(addLog); setLivePhase(s.phase); addFiles(s.files);
      if (s.status === 'done') liveDone(s.result); else if (s.status === 'fail') liveFail(s.error);
    });
    es.addEventListener('phase', e => { const p = JSON.parse(e.data); addLog(p); setLivePhase(p.text); });
    es.addEventListener('files', e => addFiles(JSON.parse(e.data).add));
    es.addEventListener('done', e => liveDone(JSON.parse(e.data)));
    es.addEventListener('fail', e => liveFail(JSON.parse(e.data)));
  }
  function liveDone(result) {
    const keep = current && current.path;
    stopLive(); liveBar.hidden = true;
    openWorkspace(result, keep);
    toast(`Hazır · ${result.files.length} dosya`);
  }
  function liveFail(err) {
    stopLive(); liveBar.hidden = true; job = null;
    document.body.classList.remove('working'); workspace.hidden = true; hero.hidden = false; resetUI();
    showError((err.error || 'Decompile başarısız.') + (err.detail ? '\n\n' + err.detail : ''));
  }

  /* ---------- Sürükle-bırak (tüm pencere) ---------- */
  window.addEventListener('dragenter', e => { e.preventDefault(); dragDepth++; overlay.hidden = false; });
  window.addEventListener('dragleave', e => { e.preventDefault(); if (--dragDepth <= 0) { dragDepth = 0; overlay.hidden = true; } });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => {
    e.preventDefault(); dragDepth = 0; overlay.hidden = true;
    handleFiles([...(e.dataTransfer.files || [])]);
  });
  async function handleFiles(list) {
    const map = list.find(f => /\.(txt|map)$/i.test(f.name));
    const jar = list.find(f => /\.(jar|class|war|zip)$/i.test(f.name));
    if (map) await uploadMapping(map);
    if (jar) upload(jar);
    else if (!map && list[0]) upload(list[0]);
  }
  fileInput.addEventListener('change', () => { handleFiles([...fileInput.files]); fileInput.value = ''; });
  drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });

  /* ---------- Çalışma alanı ---------- */
  function updateButtons() {
    const remote = !!(job && job.id && !job.local), done = remote && !job.live;
    btnZip.hidden = !remote; btnSearch.hidden = !remote; btnOverview.hidden = !remote;
    btnZip.disabled = btnSearch.disabled = btnOverview.disabled = btnAll.disabled = !done;
    btnSplit.hidden = !!(job && job.live);
  }

  function openWorkspace(data, keep) {
    job = data; current = null; stopLive(); liveBar.hidden = true; resetTabs();
    hero.hidden = true; workspace.hidden = false; document.body.classList.add('working');
    const s = data.stats;
    if (data.local) {
      $('meta').textContent = s.changed
        ? `Metin · ${s.ms} ms · ${s.removedLines} çöp satır silindi, ${s.constants} sabit çözüldü`
        : 'Metin · değişiklik yapılamadı (obf izi bulunamadı)';
    } else {
      $('meta').textContent = `${data.name} · ${s.classes} sınıf · ${(s.ms / 1000).toFixed(1)} sn` +
        (s.renamed ? ` · ${s.renamed} Minecraft adı çevrildi` : "") +
        (s.classRenames > 0 ? ` · ${s.classRenames} sınıf adı düzeltildi` : "") +
        (s.furry ? ` · FurryHook motoru: ${s.furry.stats.strings_decrypted || 0} string, ${s.furry.stats.concats_resolved || 0} indy, ${s.furry.stats.classes_remapped || 0} sınıf adı, ${s.furry.features} modül, ${s.furry.mixins} mixin` + (s.furry.security ? `, güvenlik: ${s.furry.security.apis} API/${s.furry.security.urls} URL` : '') : "") +
        (s.generic && s.generic.detected && s.generic.detected.length ? ` · Tespit: ${s.generic.detected.join(', ')}` : '') +
        (s.generic && s.generic.folded !== undefined ? ` · Genel: ${s.generic.folded} sabit katlandı, ${s.generic.branches} opaque dal, ${s.generic.dead} ölü komut, ${s.generic.proxies} proxy, ${s.generic.staticBools || 0} statik predicate, ${s.generic.strings} string çözüldü` + (s.generic.badEntries ? `, ${s.generic.badEntries} bozuk ZIP girdisi` : '') : '') +
        (s.stackStr ? ` · ${s.stackStr.strings} şifreli string çözüldü (yığın izi anahtarlı)` : "") +
        (s.pg ? (s.pg.mapping ? ` · ProGuard: mapping.txt ile ${s.pg.mapped} sınıf adı geri yüklendi` : ` · ProGuard: ${s.pg.classes} sınıf, ${s.pg.fields} alan, ${s.pg.methods} metot adı türetildi, ${s.pg.splitMethods} metotta yerel değişkenler ayrıldı`) : "") +
        (s.skid ? ` · Skidfuscator: ${s.skid.folded} guard katlandı, ${s.skid.unreachable} ölü komut silindi` : "") +
        (s.method ? ` · Method: ${s.method.junk_stmts || 0} çöp ifade, ${s.method.indy || 0} gizli çağrı, ${s.method.pool_strings || 0} string, ${s.method.unflattened || 0} düzleştirme çözüldü` : '') +
        (s.deobfClasses ? ` · ${s.deobfClasses} sınıfta obf çözüldü (${s.removedLines} çöp satır, ${s.constants} sabit)` : '') +
        (s.warnings ? ` · ${s.warnings} uyarı` : '');
    }
    btnAll.textContent = data.local ? 'Kodu indir' : 'Hepsini indir';
    btnReport.hidden = !(s && s.furry && s.furry.report);
    filter.value = ''; freshSet = new Set(); delete tree.dataset.done;
    updateButtons();
    buildTree(data.files);
    clearViewer();
    const first = (keep && data.files.includes(keep)) ? keep : data.files.find(f => f.endsWith('.java'));
    if (first) openFile(first);
  }

  btnNew.onclick = () => {
    stopLive(); liveBar.hidden = true;
    document.body.classList.remove('working'); workspace.hidden = true; hero.hidden = false; resetUI(); job = null;
    closeSearch(); closeModal();
    setMode(!textPane.hidden);
  };
  btnReport.onclick = () => { if (job && job.id) location.href = '/api/report?id=' + job.id; };
  btnZip.onclick = () => { if (job && job.id && !job.live) location.href = '/api/zip?id=' + job.id; };
  btnAll.onclick = () => {
    if (!job) return;
    if (job.local) {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([job.local['Kod.java'].clean], { type: 'text/plain' }));
      a.download = 'deobf.java'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } else location.href = '/api/all?id=' + job.id;
  };

  /* ---------- Metin modu ---------- */
  const tabFile = $('tab-file'), tabText = $('tab-text'), textPane = $('textpane'), textIn = $('textin'), btnText = $('btn-text');
  function setMode(text) {
    tabFile.classList.toggle('active', !text); tabText.classList.toggle('active', text);
    textPane.hidden = !text; drop.hidden = text; errBox.hidden = true;
    if (text) textIn.focus();
  }
  tabFile.onclick = () => setMode(false);
  tabText.onclick = () => setMode(true);

  async function runText() {
    const src = textIn.value;
    if (!src.trim()) { showError('Önce obf\'lu kodu yapıştır.'); return; }
    errBox.hidden = true; btnText.disabled = true; btnText.textContent = 'Çalışıyor…';
    try {
      const r = await fetch('/api/deobf-text', { method: 'POST', body: src });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Bir hata oluştu.');
      openWorkspace({
        id: null, name: 'Kod.java', files: ['Kod.java'], stats: data.stats,
        local: { 'Kod.java': { clean: data.text, raw: data.raw } },
      });
    } catch (e) { showError(e.message); }
    finally { btnText.disabled = false; btnText.textContent = 'Deobf et'; }
  }
  btnText.onclick = runText;
  textIn.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runText(); } });

  /* ---------- Dosya ağacı ---------- */
  function buildTree(files) {
    const scroll = tree.scrollTop;
    tree.textContent = '';
    const root = {};
    for (const f of files) {
      let n = root; const parts = f.split('/');
      parts.forEach((p, i) => {
        if (i === parts.length - 1) (n.__files ||= []).push({ name: p, path: f });
        else n = (n[p] ||= {});
      });
    }
    tree.appendChild(renderDir(root, true, ''));
    if (!tree.dataset.done) {
      tree.dataset.done = '1'; tree.classList.add('stagger');
      [...tree.querySelectorAll('.node')].slice(0, 60).forEach((n, i) => n.style.setProperty('--i', i));
      setTimeout(() => tree.classList.remove('stagger'), 1800);
    }
    if (current) markActive(current.path, false);
    tree.scrollTop = scroll;
    applyFilter();
    freshSet.clear();
  }

  function renderDir(obj, isRoot, prefix) {
    const frag = document.createElement('div');
    if (!isRoot) frag.className = 'children';
    Object.keys(obj).filter(k => k !== '__files').sort().forEach(name => {
      const dirPath = prefix + name + '/';
      const open = openDirs.has(dirPath);
      const node = document.createElement('div'); node.className = 'node' + (open ? '' : ' closed'); node.dataset.dir = dirPath;
      const row = document.createElement('div'); row.className = 'row';
      row.innerHTML = `<span class="ic">${open ? '▾' : '▸'}</span><span></span><span class="cnt"></span>`;
      row.children[1].textContent = name;
      row.onclick = () => {
        node.classList.toggle('closed');
        const c = node.classList.contains('closed');
        row.firstChild.textContent = c ? '▸' : '▾';
        if (c) openDirs.delete(dirPath); else openDirs.add(dirPath);
      };
      const kids = renderDir(obj[name], false, dirPath);
      row.lastChild.textContent = countFiles(obj[name]);
      node.append(row, kids);
      frag.appendChild(node);
    });
    (obj.__files || []).sort((a, b) => a.name.localeCompare(b.name)).forEach(f => {
      const row = document.createElement('div'); row.className = 'row file' + (freshSet.has(f.path) && job && job.live ? ' fresh' : ''); row.dataset.path = f.path;
      row.innerHTML = '<span class="ic">☕</span><span></span>';
      row.lastChild.textContent = f.name;
      row.onclick = () => openFile(f.path);
      const node = document.createElement('div'); node.className = 'node'; node.appendChild(row);
      frag.appendChild(node);
    });
    // Tek dallı paket zincirlerini otomatik aç (yalnızca kullanıcı hiç klasör açmadıysa)
    if (isRoot && !openDirs.size) autoOpen(frag);
    return frag;
  }
  function countFiles(o) {
    let n = (o.__files || []).length;
    for (const k of Object.keys(o)) if (k !== '__files') n += countFiles(o[k]);
    return n;
  }

  function autoOpen(el) {
    let nodes = [...el.children].filter(c => c.classList.contains('node') && c.classList.contains('closed'));
    let depth = 0;
    while (nodes.length === 1 && el.children.length === 1 && depth < 8) {
      const n = nodes[0]; n.classList.remove('closed'); n.firstChild.firstChild.textContent = '▾'; openDirs.add(n.dataset.dir);
      el = n.querySelector('.children'); if (!el) break;
      nodes = [...el.children].filter(c => c.classList.contains('node') && c.classList.contains('closed'));
      depth++;
    }
  }

  function applyFilter() {
    const q = filter.value.trim().toLowerCase();
    tree.querySelectorAll('.node').forEach(n => { n.style.display = ''; });
    if (!q) return;
    tree.querySelectorAll('.row.file').forEach(r => {
      const hit = r.dataset.path.toLowerCase().includes(q);
      r.parentElement.style.display = hit ? '' : 'none';
    });
    // klasörleri: içinde görünen dosya yoksa gizle, varsa aç
    const dirs = [...tree.querySelectorAll('.node')].filter(n => n.querySelector(':scope > .children')).reverse();
    dirs.forEach(d => {
      const visible = [...d.querySelectorAll('.row.file')].some(r => r.parentElement.style.display !== 'none');
      d.style.display = visible ? '' : 'none';
      if (visible) { d.classList.remove('closed'); d.firstChild.firstChild.textContent = '▾'; }
    });
  }
  filter.addEventListener('input', applyFilter);

  /* ---------- Kod görüntüleyici ---------- */
  function clearViewer() {
    code.className = 'code';
    code.innerHTML = '<div class="empty">Soldaki listeden bir .java dosyası seç.</div>';
    curfile.textContent = 'Bir sınıf seç'; btnCopy.disabled = btnDl.disabled = true;
  }

  function markActive(p, expand) {
    tree.querySelectorAll('.row.active').forEach(r => r.classList.remove('active'));
    const row = [...tree.querySelectorAll('.row.file')].find(r => r.dataset.path === p);
    if (!row) return;
    row.classList.add('active');
    for (let n = row.parentElement; n && n !== tree; n = n.parentElement) {
      if (n.classList && n.classList.contains('node') && n.classList.contains('closed')) {
        n.classList.remove('closed'); n.firstChild.firstChild.textContent = '▾'; if (n.dataset.dir) openDirs.add(n.dataset.dir);
      }
    }
    if (expand) row.scrollIntoView({ block: 'nearest' });
  }

  async function getText(p, raw) {
    if (job.local) return raw ? job.local[p].raw : job.local[p].clean;
    const r = await fetch(`/api/file?id=${job.id}&path=${encodeURIComponent(p)}${job.live ? '&live=1' : (raw ? '&raw=1' : '')}`);
    if (!r.ok) throw new Error(job.live ? 'Bu dosya henüz hazır değil, birazdan tekrar dene.' : 'Dosya okunamadı');
    return r.text();
  }

  let openSeq = 0;
  async function openFile(p, line) {
    if (!job) return;
    const seq = ++openSeq;
    markActive(p, true);
    curfile.textContent = p;
    if (job.live) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = 'ham CFR · canlı'; curfile.append(' ', b); }
    code.className = 'code'; code.innerHTML = '<div class="empty loading">Yükleniyor…</div>';
    try {
      if (splitMode && !job.live) {
        const [rawT, cleanT] = await Promise.all([getText(p, true), getText(p, false)]);
        if (seq !== openSeq) return;
        current = { path: p, text: cleanT };
        renderSplit(rawT, cleanT);
      } else {
        const text = await getText(p, rawMode);
        if (seq !== openSeq) return;
        current = { path: p, text };
        render(text, line);
      }
      btnCopy.disabled = btnDl.disabled = false;
      addTab(p); updateStatus();
    } catch (e) {
      if (seq !== openSeq) return;
      current = null;
      code.className = 'code'; code.innerHTML = ''; const d = document.createElement('div'); d.className = 'empty'; d.textContent = e.message; code.appendChild(d);
    }
  }

  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const KW = 'abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null var record';
  const RX = new RegExp(
    '(\\/\\*[\\s\\S]*?\\*\\/|\\/\\/[^\\n]*)' +                 // 1 yorum
    '|("(?:\\\\.|[^"\\\\\\n])*"|\'(?:\\\\.|[^\'\\\\\\n])*\')' +  // 2 string
    '|(@\\w+)' +                                               // 3 annotation
    '|\\b(0x[0-9a-fA-F]+|\\d[\\d_]*(?:\\.\\d+)?[fFdDlL]?)\\b' + // 4 sayı
    '|\\b(' + KW.split(' ').join('|') + ')\\b' +               // 5 anahtar kelime
    '|\\b([A-Z][A-Za-z0-9_]*)\\b', 'g');                       // 6 tip

  function highlight(text) {
    let out = '', last = 0, m; RX.lastIndex = 0;
    while ((m = RX.exec(text))) {
      out += esc(text.slice(last, m.index));
      const cls = m[1] ? 'c' : m[2] ? 's' : m[3] ? 'a' : m[4] ? 'n' : m[5] ? 'k' : 't';
      out += `<span class="${cls}">${esc(m[0])}</span>`;
      last = RX.lastIndex;
    }
    return out + esc(text.slice(last));
  }

  function makePane(text) {
    const lines = text.split('\n').length;
    const gutter = document.createElement('pre'); gutter.className = 'gutter';
    if (lines > 20000) gutter.textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
    else gutter.innerHTML = Array.from({ length: lines }, (_, i) => `<span data-l="${i + 1}">${i + 1}</span>`).join('');
    const src = document.createElement('pre'); src.className = 'src';
    if (text.length > 250000) src.textContent = text; else src.innerHTML = highlight(text);
    return [gutter, src];
  }

  const PAD = 14;
  let fontPx = +(localStorage.getItem('rd-fs') || 13), wrapOn = localStorage.getItem('rd-wrap') === '1';
  const lineH = () => fontPx * 1.6;
  function render(text, line) {
    code.className = 'code' + (wrapOn ? ' wrap' : '');
    code.textContent = ''; code.append(...makePane(text)); code.scrollTop = 0;
    if (line) highlightLine(line, true);
  }
  function highlightLine(line, scroll) {
    code.querySelectorAll('.linehl').forEach(e => e.remove());
    const hl = document.createElement('div'); hl.className = 'linehl'; hl.style.top = (PAD + (line - 1) * lineH()) + 'px';
    code.appendChild(hl);
    if (scroll) code.scrollTop = Math.max(0, PAD + (line - 1) * lineH() - code.clientHeight / 3);
  }
  code.addEventListener('click', e => {
    const l = e.target.dataset && e.target.dataset.l;
    if (l && !wrapOn && !code.classList.contains('split')) { highlightLine(+l); $('st-sel').textContent = 'Satır ' + l; }
  });

  function renderSplit(rawText, cleanText) {
    code.className = 'code split'; code.textContent = '';
    for (const [label, t] of [['Ham (CFR)', rawText], ['Temiz (deobf)', cleanText]]) {
      const col = document.createElement('div'); col.className = 'col';
      const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;align-items:flex-start;min-width:100%';
      const head = document.createElement('div'); head.className = 'colhead';
      head.textContent = `${label} · ${t.split('\n').length} satır`;
      const inner = document.createElement('div'); inner.style.cssText = 'display:flex;flex-direction:column;min-width:100%';
      const body = document.createElement('div'); body.style.cssText = 'display:flex;align-items:flex-start';
      body.append(...makePane(t));
      inner.append(head, body); col.appendChild(inner); code.appendChild(col);
    }
    // iki sütunu birlikte kaydır
    const cols = [...code.querySelectorAll('.col')]; let lock = false;
    cols.forEach((c, i) => c.addEventListener('scroll', () => {
      if (lock) return; lock = true; cols[1 - i].scrollTop = c.scrollTop; lock = false;
    }));
  }

  btnCopy.onclick = async () => {
    if (!current) return;
    try { await navigator.clipboard.writeText(current.text); btnCopy.textContent = 'Kopyalandı ✓'; toast('Kod panoya kopyalandı'); }
    catch { btnCopy.textContent = 'Kopyalanamadı'; toast('Kopyalanamadı', true); }
    setTimeout(() => btnCopy.textContent = 'Kopyala', 1400);
  };
  btnDl.onclick = () => {
    if (!current) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([current.text], { type: 'text/plain' }));
    a.download = current.path.split('/').pop(); a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };

  /* ---------- Tüm kodda arama ---------- */
  function openSearch() {
    if (!job || job.live || job.local) return;
    searchPane.hidden = false; tree.hidden = true; filter.hidden = true; btnSearch.classList.add('on');
    qIn.focus(); qIn.select();
  }
  function closeSearch() {
    searchPane.hidden = true; tree.hidden = false; filter.hidden = false; btnSearch.classList.remove('on');
  }
  btnSearch.onclick = () => (searchPane.hidden ? openSearch() : closeSearch());

  async function runSearch() {
    const q = qIn.value.trim();
    if (q.length < 2 || !job || !job.id) return;
    qInfo.textContent = 'aranıyor…'; qRes.textContent = '';
    try {
      const r = await fetch(`/api/search?id=${job.id}&q=${encodeURIComponent(q)}${qRe.checked ? '&re=1' : ''}${qCs.checked ? '&cs=1' : ''}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Arama başarısız');
      qInfo.textContent = `${d.total} eşleşme · ${d.files} dosya` + (d.truncated ? ' (ilk 300)' : '');
      let hre = null;
      try { hre = new RegExp(qRe.checked ? q : q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), qCs.checked ? 'g' : 'gi'); } catch {}
      const frag = document.createDocumentFragment();
      for (const h of d.hits) {
        const el = document.createElement('div'); el.className = 'hit';
        const hp = document.createElement('div'); hp.className = 'hp'; hp.textContent = `${h.path}:${h.line}`;
        const ht = document.createElement('div'); ht.className = 'ht';
        if (hre) {
          hre.lastIndex = 0; let last = 0, m, guard = 0;
          while ((m = hre.exec(h.text)) && guard++ < 20) {
            if (m[0] === '') { hre.lastIndex++; continue; }
            ht.append(h.text.slice(last, m.index));
            const mk = document.createElement('mark'); mk.textContent = m[0]; ht.appendChild(mk);
            last = m.index + m[0].length;
          }
          ht.append(h.text.slice(last));
        } else ht.textContent = h.text;
        el.append(hp, ht);
        el.onclick = () => { rawMode = false; btnRaw.textContent = 'Temiz'; splitMode = false; btnSplit.classList.remove('on'); openFile(h.path, h.line); };
        frag.appendChild(el);
      }
      qRes.appendChild(frag);
    } catch (e) { qInfo.textContent = e.message; }
  }
  qIn.addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); if (e.key === 'Escape') closeSearch(); });

  /* ---------- Özet penceresi ---------- */
  function closeModal() { modal.hidden = true; modalBody.textContent = ''; }
  $('modal-x').onclick = closeModal;
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });

  function table(title, rows, col, unit) {
    const h = document.createElement('h3'); h.textContent = title;
    const t = document.createElement('table');
    const max = Math.max(1, ...rows.map(r => r[col]));
    for (const r of rows) {
      const tr = document.createElement('tr');
      const a = document.createElement('td'); a.textContent = r.path;
      a.onclick = () => { closeModal(); openFile(r.path); };
      const b = document.createElement('td'); b.className = 'num'; b.textContent = r[col] + (unit || '');
      const g = document.createElement('i'); g.className = 'bargrow'; g.style.width = (r[col] / max * 100) + '%';
      a.prepend(g);
      tr.append(a, b); t.appendChild(tr);
    }
    return [h, t];
  }
  btnOverview.onclick = async () => {
    if (!job || !job.id || job.live) return;
    modal.hidden = false; modalBody.textContent = 'Hesaplanıyor…';
    try {
      const r = await fetch('/api/overview?id=' + job.id);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Özet alınamadı');
      const wrap = document.createElement('div'); wrap.className = 'ov';
      const k = document.createElement('div'); k.className = 'kpis';
      const s = job.stats || {};
      for (const [lab, val] of [['sınıf', d.files], ['toplam satır', d.lines.toLocaleString('tr')], ['süre', ((s.ms || 0) / 1000).toFixed(1) + ' sn'], ['obf çözülen sınıf', s.deobfClasses || 0], ['silinen çöp satır', s.removedLines || 0]]) {
        const e = document.createElement('div'); e.className = 'kpi'; e.style.animationDelay = k.children.length * 70 + 'ms';
        const b = document.createElement('b'); b.textContent = val; e.append(b, lab); k.appendChild(e);
      }
      wrap.append(k, ...table('En çok temizlenen sınıflar (ham → temiz satır farkı)', d.mostCleaned.filter(x => x.removed > 0), 'removed', ' satır'),
        ...table('En büyük sınıflar', d.biggest, 'lines', ' satır'),
        ...table('En çok string içeren sınıflar', d.mostStrings, 'strings', ' string'));
      modalBody.textContent = ''; modalBody.appendChild(wrap);
    } catch (e) { modalBody.textContent = e.message; }
  };

  /* ---------- Kısayollar ---------- */
  window.addEventListener('keydown', e => {
    const typing = /^(INPUT|TEXTAREA)$/.test((e.target.tagName || ''));
    if (e.key === 'Escape' && !modal.hidden) { closeModal(); return; }
    if (e.key === 'Escape' && !palette.hidden) { closePalette(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); palette.hidden ? openPalette() : closePalette(); return; }
    if (e.key === '?' && !typing) { e.preventDefault(); showKeys(); return; }
    if (workspace.hidden) return;
    if (e.key === '/' && !typing) { e.preventDefault(); closeSearch(); filter.focus(); }
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'f') { e.preventDefault(); openSearch(); }
  });

  /* =====================================================================
     Yeni özellikler: bildirim, parçacık arka planı, konfeti, komut paleti,
     dosya sekmeleri, durum çubuğu, yazı boyutu / kaydırma, vurgu rengi
     ===================================================================== */
  const root = document.documentElement;

  /* ---- Bildirim ---- */
  function toast(msg, err) {
    const box = $('toasts'), t = document.createElement('div');
    t.className = 'toast' + (err ? ' err' : ''); t.innerHTML = '<i></i><span></span>'; t.lastChild.textContent = msg;
    box.appendChild(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 400); }, 2600);
    while (box.children.length > 4) box.firstChild.remove();
  }

  /* ---- Açık dosya sekmeleri ---- */
  const ftabs = $('filetabs'); let openTabs = [];
  function resetTabs() { openTabs = []; ftabs.hidden = true; ftabs.textContent = ''; $('statusbar').hidden = true; }
  function addTab(p) {
    if (!openTabs.includes(p)) openTabs.push(p);
    if (openTabs.length > 12) openTabs.shift();
    renderTabs();
  }
  function renderTabs() {
    ftabs.hidden = openTabs.length < 2; ftabs.textContent = '';
    for (const p of openTabs) {
      const t = document.createElement('div'); t.className = 'ft' + (current && current.path === p ? ' active' : ''); t.title = p;
      const n = document.createElement('span'); n.textContent = p.split('/').pop();
      const x = document.createElement('b'); x.textContent = '×';
      x.onclick = e => {
        e.stopPropagation(); const i = openTabs.indexOf(p); openTabs.splice(i, 1);
        if (current && current.path === p) { const nx = openTabs[Math.min(i, openTabs.length - 1)]; nx ? openFile(nx) : (renderTabs(), clearViewer()); } else renderTabs();
      };
      t.onclick = () => openFile(p); t.append(n, x); ftabs.appendChild(t);
    }
    const act = ftabs.querySelector('.active'); if (act) act.scrollIntoView({ inline: 'nearest', block: 'nearest' });
  }

  /* ---- Durum çubuğu ---- */
  function updateStatus() {
    const sb = $('statusbar'); if (!current) { sb.hidden = true; return; }
    sb.hidden = false;
    $('st-lines').textContent = current.text.split('\n').length.toLocaleString('tr') + ' satır';
    $('st-chars').textContent = current.text.length.toLocaleString('tr') + ' karakter';
    $('st-sel').textContent = ''; $('st-mode').textContent = job && job.live ? 'ham CFR · canlı' : (splitMode ? 'yan yana' : rawMode ? 'ham' : 'deobf');
  }

  /* ---- Yazı boyutu + satır kaydırma ---- */
  function applyFont() { root.style.setProperty('--fs', fontPx + 'px'); }
  applyFont();
  function setFont(d) { fontPx = Math.max(10, Math.min(22, fontPx + d)); localStorage.setItem('rd-fs', fontPx); applyFont(); if (current) openFile(current.path); }
  $('btn-fminus').onclick = () => setFont(-1); $('btn-fplus').onclick = () => setFont(1);
  const btnWrap = $('btn-wrap');
  function applyWrap() { btnWrap.classList.toggle('on', wrapOn); code.classList.toggle('wrap', wrapOn); }
  btnWrap.onclick = () => { wrapOn = !wrapOn; localStorage.setItem('rd-wrap', wrapOn ? '1' : '0'); applyWrap(); code.querySelectorAll('.linehl').forEach(e => e.remove()); };
  applyWrap();

  /* ---- Komut paleti ---- */
  const palette = $('palette'), pin = $('pin'), plist = $('plist'); let pitems = [], psel = 0;
  function cmds() {
    const c = [
      { t: 'Kısayolları göster', k: 'komut', run: showKeys },
    ];
    if (!workspace.hidden) {
      c.unshift(
        { t: 'Ham / Temiz arasında geç', k: 'komut', run: () => btnRaw.click() },
        { t: 'Yan yana görünümü aç/kapat', k: 'komut', run: () => !btnSplit.hidden && btnSplit.click() },
        { t: 'Satır kaydırmayı aç/kapat', k: 'komut', run: () => btnWrap.click() },
        { t: 'Tüm kodda ara', k: 'komut', run: openSearch },
        { t: 'Özet / istatistikler', k: 'komut', run: () => btnOverview.click() },
        { t: 'Yeni dosya', k: 'komut', run: () => btnNew.click() },
      );
    }
    return c;
  }
  function score(q, s) {
    if (!q) return 1; s = s.toLowerCase(); const i = s.indexOf(q); if (i >= 0) return 100 - i * .1 + (s.endsWith('/' + q) ? 5 : 0);
    let j = 0, sc = 0; for (const ch of s) if (ch === q[j]) { j++; sc += 1; if (j === q.length) return sc / (s.length + 1); } return 0;
  }
  function renderPalette() {
    const q = pin.value.trim().toLowerCase(); const list = [];
    for (const c of cmds()) { const sc = score(q, c.t); if (sc) list.push({ ...c, sc: sc + (q ? 0 : 0.5) }); }
    if (job) for (const f of job.files) { const sc = score(q, f); if (sc) list.push({ t: f.split('/').pop(), p: f, k: 'sınıf', sc, run: () => openFile(f) }); }
    list.sort((a, b) => b.sc - a.sc); pitems = list.slice(0, 40); psel = 0; plist.textContent = '';
    if (!pitems.length) { plist.innerHTML = '<div class="pnone">Sonuç yok</div>'; return; }
    pitems.forEach((it, i) => {
      const el = document.createElement('div'); el.className = 'pi' + (i ? '' : ' sel');
      const tg = document.createElement('span'); tg.className = 'pt'; tg.textContent = it.k;
      const nm = document.createElement('span'); nm.textContent = it.t;
      el.append(tg, nm);
      if (it.p) { const pp = document.createElement('span'); pp.className = 'pp'; pp.textContent = it.p; el.appendChild(pp); }
      el.onclick = () => runPalette(it); el.onmousemove = () => selPalette(i); plist.appendChild(el);
    });
  }
  function selPalette(i) {
    psel = i; [...plist.children].forEach((c, n) => c.classList.toggle('sel', n === i));
    const c = plist.children[i]; if (c) c.scrollIntoView({ block: 'nearest' });
  }
  function runPalette(it) { closePalette(); setTimeout(() => it.run(), 60); }
  function openPalette() { palette.hidden = false; pin.value = ''; renderPalette(); pin.focus(); }
  function closePalette() { palette.hidden = true; }
  pin.addEventListener('input', renderPalette);
  pin.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); selPalette(Math.min(pitems.length - 1, psel + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); selPalette(Math.max(0, psel - 1)); }
    else if (e.key === 'Enter' && pitems[psel]) { e.preventDefault(); runPalette(pitems[psel]); }
  });
  palette.addEventListener('mousedown', e => { if (e.target === palette) closePalette(); });
  $('btn-palette').onclick = openPalette;

  function showKeys() {
    modal.hidden = false; modalBody.textContent = '';
    const w = document.createElement('div'); w.className = 'ov'; const h = document.createElement('h3'); h.textContent = 'Klavye kısayolları';
    const g = document.createElement('div'); g.className = 'keys';
    for (const [k, d] of [['Ctrl + K', 'Komut paleti — sınıf ara, komut çalıştır'], ['Ctrl + Shift + F', 'Tüm kodda ara'], ['/', 'Sınıf listesinde filtrele'], ['Ctrl + Enter', 'Metin modunda deobf et'], ['?', 'Bu pencere'], ['Esc', 'Pencereyi / paleti kapat']]) {
      const a = document.createElement('kbd'); a.textContent = k; const b = document.createElement('span'); b.textContent = d; g.append(a, b);
    }
    w.append(h, g); modalBody.appendChild(w);
  }
})();
