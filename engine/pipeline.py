"""Generic "method" deobfuscation pipeline (no product specific data).

usage: python pipeline.py --src <dir with decompiled .java> --out <dir> [--jar <original jar>] [--no-rename]

Steps (each one is optional and fails soft):
  1. string pool of the jar is located by its magic header, decrypted with Dump.java (needs --jar)
  2. junk code is stripped, integer constants folded, strings restored, hidden invokedynamic calls rebuilt
  3. state-machine loops are unflattened, javac enum switches ($SwitchMap$) are restored (needs --jar)
  4. cosmetics: aliases, casts, enums, records, monitors, undeclared decompiler variables
  5. field / method renaming derived from the code itself, local type inference
Prints a last line "STATS {json}".
"""
import argparse
import collections
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import deobf  # noqa: E402
import fields  # noqa: E402
import infer  # noqa: E402
import javamodel  # noqa: E402
import methods  # noqa: E402
import switchmap  # noqa: E402
import unflatten  # noqa: E402

POOL_MAGIC = 1213484879  # first int of the encrypted string pool (Dump.java checks the same value)


def find_pool_entry(jar):
    with zipfile.ZipFile(jar) as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size < 8 or info.file_size > 64 * 1024 * 1024:
                continue
            if not info.filename.startswith('META-INF/'):
                continue
            with z.open(info) as f:
                head = f.read(4)
            if len(head) == 4 and struct.unpack('>i', head)[0] == POOL_MAGIC:
                return info.filename
    return None


def build_pool(jar, work):
    entry = find_pool_entry(jar)
    if not entry:
        return None, None
    pool_bin = os.path.join(work, 'pool.bin')
    with zipfile.ZipFile(jar) as z:
        with open(pool_bin, 'wb') as f:
            f.write(z.read(entry))
    cache = os.path.join(HERE, '.cache', 'dump')
    os.makedirs(cache, exist_ok=True)
    if not os.path.exists(os.path.join(cache, 'Dump.class')):
        shutil.copyfile(os.path.join(HERE, 'Dump.java'), os.path.join(cache, 'Dump.java'))
        subprocess.run(['javac', 'Dump.java'], cwd=cache, check=True, capture_output=True)
    tsv = os.path.join(work, 'pool.tsv')
    subprocess.run(['java', '-cp', cache, 'Dump', pool_bin, tsv], check=True, capture_output=True)
    return tsv, entry


# static entry points of the obfuscator runtime class; the class itself gets a random name in every build
RT_METHODS = ('sVfnkmVk', 'rY5nPgBX', 'z0lZMovd', 'gJ1Cd2J6', 'pVERVEbg', 'uqCIFUEP', 'cVxlN1Ph', 'glejYs8c', 'uE0b3uFZ')
RT_DEF = re.compile(r'static [\w\[\]<>.]+ (?:sVfnkmVk|rY5nPgBX)\(')


def normalize_runtime(files, stats):
    """call sites use <RandomName>.sVfnkmVk(...): rewrite the owner to StringDeobfuscator, drop the runtime class"""
    alt = '|'.join(RT_METHODS)
    use = re.compile(r'(?:\b\w+\.)*\b([A-Za-z_]\w*)\.(?:%s)\(' % alt)
    owners = collections.Counter()
    for t in files.values():
        for m in use.finditer(t):
            owners[m[1]] += 1
    out = {}
    for rel, t in files.items():
        if RT_DEF.search(t):
            stats['runtime_class_skipped'] += 1
            continue
        out[rel] = t
    for owner, n in owners.items():
        if n < 3 or owner == 'StringDeobfuscator':
            continue
        call = re.compile(r'(?:\b\w+\.)*\b%s\.(%s)\(' % (re.escape(owner), alt))
        imp = re.compile(r'(?m)^import [\w.]*\b%s;[ \t]*\n' % re.escape(owner))
        for rel in out:
            out[rel] = imp.sub('', call.sub(r'StringDeobfuscator.\1(', out[rel]))
        stats['runtime_owner'] = owner
    return out


# ---- paralel işleme: dosya başı aşamalar CPU'ya yayılır (fork: küresel durum çocuklara kopyalanır) ----
import multiprocessing  # noqa: E402
import time  # noqa: E402

_CTX = {}


def _stage_worker(keys):
    """keys: rel listesi; _CTX['fn'](rel, text, local_stats) -> text"""
    st = collections.Counter()
    fn, texts = _CTX['fn'], _CTX['texts']
    out = {}
    for k in keys:
        out[k] = fn(k, texts[k], st)
    return out, st


def pmap_texts(fn, texts, stats):
    """fn(rel, text, stats) her dosyaya uygulanır; yeterince dosya varsa süreçlere bölünür. Sırayı korur."""
    keys = list(texts)
    n = min(os.cpu_count() or 1, int(os.environ.get('RXD_WORKERS', '8')))
    if n < 2 or len(keys) < 60 or 'fork' not in multiprocessing.get_all_start_methods():
        out, st = _stage_worker_serial(fn, texts)
        stats.update(st)
        return out
    _CTX['fn'], _CTX['texts'] = fn, texts
    try:
        # büyük dosyalar önce: boyuta göre dağıt (en kötü yük dengesizliğini azaltır)
        order = sorted(keys, key=lambda k: -len(texts[k]))
        chunks = [order[i::n] for i in range(n)]
        with multiprocessing.get_context('fork').Pool(n) as pool:
            parts = pool.map(_stage_worker, chunks, chunksize=1)
    except Exception:
        out, st = _stage_worker_serial(fn, texts)
        stats.update(st)
        return out
    finally:
        _CTX.clear()
    res = {}
    for o, st in parts:
        res.update(o); stats.update(st)
    return {k: res[k] for k in keys}


def _stage_worker_serial(fn, texts):
    st = collections.Counter()
    return {k: fn(k, t, st) for k, t in texts.items()}, st


def _prof(label, t0):
    if os.environ.get('RXD_PROF'):
        sys.stderr.write('PROF %-10s %6.1fs\n' % (label, time.time() - t0))
    return time.time()


def guarded(name, fn, text, stats, *args):
    try:
        return fn(text, *args)
    except Exception:
        stats['err:' + name] += 1
        return text


def run(files, jar, rename, stats):
    files = normalize_runtime({k: v.replace('\r\n', '\n') for k, v in files.items()}, stats)
    work = tempfile.mkdtemp(prefix='rxdeobf_')
    pool_ok = False
    sm_table = {}
    if jar:
        try:
            tsv, entry = build_pool(jar, work)
            if tsv:
                deobf.load_pool_file(tsv)
                pool_ok = True
                stats['pool_strings'] = len(deobf.POOL)
        except Exception as e:  # javac / java missing, corrupted pool ...
            stats['pool_error'] = str(e)[:200]
        try:
            sm_table = switchmap.build(jar, os.path.join(work, 'sm'))
            stats['enum_switch_maps'] = len(sm_table)
        except Exception as e:
            stats['switchmap_error'] = str(e)[:200]

    for t in files.values():
        for m in re.finditer(r'static /\* synthetic \*/ boolean (\w+)\(int n\) \{\s*return StringDeobfuscator\.uE0b3uFZ\(n\);', t):
            deobf.GLOBAL_NAMES.append(m[1])

    t0 = time.time()
    todo = {}
    for rel, t in files.items():
        if os.path.basename(rel) == 'StringDeobfuscator.java':
            stats['runtime_class_skipped'] += 1
            continue
        todo[rel] = t.replace('\r\n', '\n')

    def stage1(rel, t, st):
        t = guarded('phase1', deobf.phase1, t, st, st)
        t = guarded('switches', deobf.simplify_switches, t, st, st)
        t = guarded('phase2b', deobf.phase2b, t, st, st)
        if pool_ok:
            t = guarded('indy', deobf.convert_indy, t, st, st)
        t = guarded('unflatten', unflatten.unflatten, t, st, st)
        if sm_table:
            t = guarded('switchmap', switchmap.apply, t, st, sm_table)
        return t
    texts = pmap_texts(stage1, todo, stats)
    t0 = _prof('stage1', t0)

    # global predicate helpers nobody calls any more
    blob = '\n'.join(texts.values())
    for name in deobf.GLOBAL_NAMES:
        if len(re.findall(r'\b%s\b' % re.escape(name), blob)) != 1:
            continue
        for rel, t in texts.items():
            ms = [x for x in re.finditer(r'[ \t]*(?:private|public) static /\* synthetic \*/ \w+ (\w+)\([^)]*\) \{', t) if x[1] == name]
            if ms:
                bc = deobf.match(t, ms[0].end() - 1, '{', '}')
                e = bc + 1
                while t[e:e + 1] == '\n':
                    e += 1
                st = deobf.with_note_comment(t, ms[0].start())
                texts[rel] = t[:st].rstrip(' \t') + t[e:]
                stats['global_syn_removed'] += 1

    texts = pmap_texts(lambda rel, t, st: guarded('phase4', deobf.phase4, t, st, st), texts, stats)
    t0 = _prof('phase4', t0)

    final = dict(texts)
    if rename and final:
        try:
            final, unresolved = fields.rename_fields(final, None)
            stats['field_unresolved'] = len(unresolved)
        except Exception:
            stats['err:fields'] += 1
        try:
            report = []
            final, method_map = methods.rename_methods(final, None, report)
            stats['methods_renamed'] = len(method_map)
        except Exception:
            stats['err:methods'] += 1

    t0 = _prof('rename', t0)
    boolnames, otherfields = set(), set()
    for t in final.values():
        try:
            for c in javamodel.model(t):
                for f in c.allfields:
                    (boolnames if f['type'] == 'boolean' else otherfields).add(f['name'])
        except Exception:
            pass
    boolonly = boolnames - otherfields
    try:
        type_index = infer.build_index(final)
    except Exception:
        type_index = {}
    def stage_final(rel, t, st):
        t = guarded('records', deobf.fix_records, t, st)
        t = guarded('boolean', deobf.boolean_fix, t, st, boolonly)
        t = guarded('objargs', deobf.strip_object_args, t, st)
        t = guarded('infer', infer.infer_locals, t, st, os.path.basename(rel)[:-5], type_index, st)
        t = re.sub(r'(?m)^([ \t]*)([\w.]+) \+= 1;', r'\1\2++;', t)
        t = re.sub(r'(?m)^([ \t]*)([\w.]+) -= 1;', r'\1\2--;', t)
        return t
    out = pmap_texts(stage_final, final, stats)
    _prof('final', t0)
    shutil.rmtree(work, ignore_errors=True)
    return out


def probe_jar(jar):
    """CFR --jarfilter regex that keeps the plugin's own packages and skips bundled/shaded libraries"""
    with zipfile.ZipFile(jar) as z:
        names = set(z.namelist())
        for yml in ('plugin.yml', 'paper-plugin.yml', 'bungee.yml'):
            if yml not in names:
                continue
            m = re.search(r'(?m)^main:\s*([\w.$]+)', z.read(yml).decode('utf-8', 'replace'))
            if not m:
                continue
            parts = m[1].split('.')
            root = parts[:2] if len(parts) >= 4 else parts[:-1]
            if root:
                return {'main': m[1], 'filter': r'^%s\.(?!.*\blibs\b)' % r'\.'.join(re.escape(p) for p in root)}
    return {'main': None, 'filter': None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src')
    ap.add_argument('--out')
    ap.add_argument('--jar')
    ap.add_argument('--probe', help='print {"filter": ...} for a jar and exit')
    ap.add_argument('--no-rename', action='store_true')
    a = ap.parse_args()
    if a.probe:
        print(json.dumps(probe_jar(a.probe)))
        return
    if not a.src or not a.out:
        ap.error('--src and --out are required')
    src = os.path.abspath(a.src)
    files = {}
    for dp, _, fn in os.walk(src):
        for f in fn:
            if f.endswith('.java'):
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, src).replace(os.sep, '/')
                with open(p, encoding='utf-8', errors='replace', newline='') as fh:
                    files[rel] = fh.read()
    stats = collections.Counter()
    stats['files'] = len(files)
    result = run(files, a.jar, not a.no_rename, stats)
    for rel, t in result.items():
        dst = os.path.join(a.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(t)
    stats['written'] = len(result)
    print('STATS ' + json.dumps(dict(stats)))


if __name__ == '__main__':
    main()
