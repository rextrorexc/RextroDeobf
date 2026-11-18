"""Rename the obfuscated (1-4 letter) methods.

1. transfer the real name from the 2.0.4 build when class, signature and body evidence agree
2. otherwise derive a descriptive name from the method itself (getter/setter/signature)

Obfuscated method names are globally unique (an interface and its implementations share one
name), so a rename is one token mapping old -> new applied to every declaration, call and
method reference.
"""
import re
from collections import Counter, defaultdict

import javamodel
import ref_stub as refmod
from lexutil import _skip

REAL_SHORT = {'name', 'all', 'text', 'id', 'get', 'uuid', 'user', 'help', 'data', 'add', 'put', 'ms', 'slot',
              'ping', 'x', 'y', 'z', 'vl', 'tps', 'seq', 'bps', 'yaw', 'url', 'key', 'bool', 'run', 'set',
              'call', 'test', 'apply', 'accept', 'close', 'tick', 'pitch', 'main', 'size', 'sort', 'list',
              'send', 'kick', 'load', 'save', 'stop', 'item', 'type', 'sound', 'world',
              'of', 'is', 'to', 'as', 'at', 'in', 'or', 'by', 'on', 'no', 'go', 'up', 'be', 'me', 'an', 'it', 'so',
              'map', 'max', 'min', 'abs', 'now', 'copy', 'from', 'cast', 'pop', 'peek', 'poll', 'push', 'join', 'wait',
              'sum', 'log', 'pow', 'mod', 'div', 'not', 'xor', 'and', 'next', 'last', 'prev', 'last', 'with', 'new',
              'has', 'can', 'use', 'pair', 'bar', 'len', 'row', 'col', 'rgb', 'hex', 'seed'}
PRIMS = {'int', 'long', 'double', 'float', 'boolean', 'byte', 'short', 'char', 'void', 'String', 'Object'}
NOISE = {'get', 'put', 'size', 'isEmpty', 'toString', 'equals', 'hashCode', 'valueOf', 'intValue', 'longValue',
         'doubleValue', 'booleanValue', 'contains', 'add', 'remove', 'getKey', 'getValue', 'iterator', 'next',
         'hasNext', 'length', 'max', 'min', 'abs', 'format', 'of', 'nanoTime', 'currentTimeMillis', 'orElse'}
RISKY = {'getName', 'getDescription', 'getUsage', 'getAliases', 'getLabel', 'isEnabled', 'getPlugin', 'getLogger',
         'getServer', 'getConfig', 'hashCode', 'toString', 'equals', 'run', 'close', 'get', 'apply', 'accept',
         'test', 'execute', 'tabComplete', 'onEnable', 'onDisable', 'getIdentifier', 'getAuthor', 'getVersion',
         'persist', 'getPriority', 'compare', 'call', 'getHandlers', 'cancel', 'values', 'valueOf', 'name',
         'ordinal', 'clone', 'finalize', 'getClass', 'notify', 'wait', 'getHandlerList'}


KEYWORDS = {'do', 'if', 'for', 'new', 'int', 'try', 'case', 'else', 'goto', 'enum', 'this', 'byte', 'char', 'long', 'void', 'break', 'class', 'const', 'final', 'float', 'short', 'super', 'throw', 'while', 'catch', 'double', 'native', 'return', 'static', 'switch', 'import', 'public', 'assert', 'extends', 'finally', 'package', 'private', 'boolean', 'default', 'continue'}


API_NAMES = set()


def is_obf(name):
    if name in API_NAMES:
        return False
    return bool(re.fullmatch(r'_?[a-z]{1,3}', name)) and name not in REAL_SHORT


def cap(s):
    return s[:1].upper() + s[1:]


def lower_first(s):
    return s[:1].lower() + s[1:]


def evidence(nm, rm, obf_names, ref_names):
    a = {c for c in nm.calls if c not in obf_names and c not in NOISE and len(c) > 2}
    b = {c for c in rm.calls if c not in ref_names and c not in NOISE and len(c) > 2}
    if not a or not b:
        return None
    return len(a & b) / min(len(a), len(b))


def specific(m):
    return any(t.rstrip('[]') not in PRIMS for t in m.params + [m.ret])


def match_pair(nc, rc, obf_names, ref_names, report):
    rmeths = [m for m in rc.methods if not refmod.junk_method(m)]
    nmeths = [m for m in nc.methods if m.name not in ('values', 'valueOf')]

    def keys(rm):
        ks = [(rm.ret, tuple(rm.params), rm.static)]
        if rm.params and rm.params[-1] == 'int':
            ks.append((rm.ret, tuple(rm.params[:-1]), rm.static))
        return ks
    cand = defaultdict(list)
    rcand = defaultdict(list)
    for nm in nmeths:
        for rm in rmeths:
            if nm.sig in keys(rm):
                cand[id(nm)].append(rm)
                rcand[id(rm)].append(nm)
    # class level agreement on names that are already real
    anchors = same = 0
    for nm in nmeths:
        if not is_obf(nm.name) and cand[id(nm)]:
            anchors += 1
            if any(rm.name == nm.name for rm in cand[id(nm)]):
                same += 1
    if anchors >= 3 and same / anchors < 0.5:
        report.append(('skipped-pair', nc.qual, rc.qual, anchors, same))
        return {}
    out = {}
    scored = []
    for nm in nmeths:
        if not is_obf(nm.name):
            continue
        for rm in cand[id(nm)]:
            ev = evidence(nm, rm, obf_names, ref_names)
            scored.append((nm, rm, ev))
    taken_n, taken_r = set(), set()
    # 1. mutually unique signature
    for nm, rm, ev in scored:
        if len(cand[id(nm)]) == 1 and len(rcand[id(rm)]) == 1 or (
                len([x for x in cand[id(nm)] if is_obf(nm.name)]) == 1 and len([x for x in rcand[id(rm)] if is_obf(x.name)]) == 1):
            if specific(nm) or specific(rm) or (ev is not None and ev >= 0.3) or len(nm.params) >= 2:
                if ev is None or ev > 0 or specific(nm):
                    out[nm] = rm
                    taken_n.add(id(nm)); taken_r.add(id(rm))
    # 2. several with the same signature: best evidence, clear margin
    rest = [(nm, rm, ev) for nm, rm, ev in scored if id(nm) not in taken_n and id(rm) not in taken_r and ev is not None]
    rest.sort(key=lambda x: -x[2])
    for nm, rm, ev in rest:
        if id(nm) in taken_n or id(rm) in taken_r or ev < 0.5:
            continue
        others = [e for n2, r2, e in rest if (n2 is nm) != (r2 is rm) and e is not None and id(n2) not in taken_n and id(r2) not in taken_r]
        if others and max(others) > ev - 0.15:
            continue
        out[nm] = rm
        taken_n.add(id(nm)); taken_r.add(id(rm))
    return out


def derive_name(m, cls):
    body = (m.body or '').strip()
    gm = re.fullmatch(r'return (?:this\.)?(\w+);', body)
    if gm and not m.params and gm[1] in {f['name'] for f in cls.allfields}:
        f = gm[1]
        if m.ret == 'boolean':
            return f if re.match(r'(is|has|can|should)[A-Z]', f) else 'is' + cap(f)
        return 'get' + cap(f)
    sm = re.fullmatch(r'(?:this\.)?(\w+) = \w+;', body)
    if sm and len(m.params) == 1 and m.ret == 'void':
        return 'set' + cap(sm[1])
    subj = None
    for t in m.params:
        b = t.rstrip('[]')
        if b not in PRIMS and len(b) > 2:
            subj = b
            break
    if subj is None:
        base = re.sub(r'(Rules|Logic|Util|Utils|Check|Manager|Service|Handler)$', '', cls.name.split('.')[-1])
        subj = base if base else cls.name
    subj = cap(re.sub(r'^[A-Z]{1,2}(?=[A-Z][a-z])', '', subj)) if len(subj) > 3 else cap(subj)
    if m.ret == 'boolean':
        verb = 'check' if m.params else 'is'
    elif m.ret == 'void':
        verb = 'handle' if m.params else 'update'
    else:
        verb = 'compute' if m.params else 'get'
    return verb + subj


def rename_methods(texts, ref_obj, report):
    models = {}
    for rel, t in texts.items():
        try:
            models[rel] = javamodel.model(t)
        except Exception:
            models[rel] = []
    all_new = [(rel, c) for rel, cs in models.items() for c in cs]
    app_classes = {c.name for _, c in all_new}
    api_names = set()
    for t in texts.values():
        for cm in re.finditer(r'(?<![\w.])([A-Z]\w*)\.(\w+)\(', t):
            if cm[1] not in app_classes and not cm[1].isupper():
                api_names.add(cm[2])
    global API_NAMES
    API_NAMES = api_names | (ref_obj.method_names if ref_obj else set())
    obf_names = {m.name for _, c in all_new for m in c.methods if is_obf(m.name)}
    ref_names = ref_obj.method_names if ref_obj else set()

    chosen = defaultdict(Counter)   # old -> Counter(new)
    transferred = 0
    if ref_obj:
        for rel, nc in all_new:
            for rc in ref_obj.lookup(nc.qual):
                for nm, rm in match_pair(nc, rc, obf_names, ref_names, report).items():
                    chosen[nm.name][rm.name] += 1
                    transferred += 1
    mapping = {}
    for old, cnt in chosen.items():
        mapping[old] = cnt.most_common(1)[0][0]
        if len(cnt) > 1:
            report.append(('conflict', old, dict(cnt)))

    # fallback for everything still obfuscated
    decl = defaultdict(list)
    for rel, c in all_new:
        for m in c.methods:
            if is_obf(m.name):
                decl[m.name].append((c, m))
    derived = 0
    for old, lst in sorted(decl.items()):
        if old in mapping:
            continue
        c, m = lst[0]
        base = derive_name(m, c)
        mapping[old] = base
        derived += 1
    # uniqueness inside every declaring class (+ keep overload-free for equal signatures)
    used_in_class = defaultdict(set)
    for rel, c in all_new:
        for m in c.methods:
            if not is_obf(m.name):
                used_in_class[id(c)].add((m.name, tuple(m.params)))
    final = {}
    for old in sorted(mapping):
        new = mapping[old]
        if new in RISKY and old not in chosen:
            new = new + 'Value'
        cands = [c for c, m in decl.get(old, [])]
        n, k = new, 2
        def clash(nn):
            for c, m in decl.get(old, []):
                if (nn, tuple(m.params)) in used_in_class[id(c)]:
                    return True
            return nn in global_taken_other(old, nn)
        while clash(n):
            n = '%s%d' % (new, k); k += 1
        for c, m in decl.get(old, []):
            used_in_class[id(c)].add((n, tuple(m.params)))
        final[old] = n
        taken_global[n].add(old)
    for k in list(final):
        if k.startswith('_') and k[1:] in KEYWORDS:
            final[k[1:]] = final[k]
    report.append(('transferred', transferred, 'derived', derived))

    out = {}
    for rel, t in texts.items():
        out[rel] = apply_mapping(t, final)
    return out, final


taken_global = defaultdict(set)


def global_taken_other(old, nn):
    s = taken_global.get(nn, set())
    return {nn} if (s and old not in s and False) else set()


def apply_mapping(text, mapping):
    out = []
    i, n = 0, len(text)
    ident = re.compile(r'[A-Za-z_$][\w$]*')
    while i < n:
        c = text[i]
        if c in '"\'/':
            k = _skip(text, i)
            if k is not None:
                out.append(text[i:k]); i = k; continue
        if c.isdigit():
            m = re.compile(r'\d[\w]*(?:\.\d[\w]*)?').match(text, i)
            out.append(m[0]); i = m.end(); continue
        m = ident.match(text, i)
        if not m:
            out.append(c); i += 1; continue
        w = m[0]
        if w in mapping:
            j = m.end()
            while j < n and text[j] in ' \t':
                j += 1
            is_call = j < n and text[j] == '('
            is_ref = text[max(0, i - 2):i] == '::'
            if w in KEYWORDS:
                is_call = is_call and text[max(0, i - 1):i] == '.'
                is_ref = False
            if is_call or is_ref:
                w = mapping[w]
        out.append(w)
        i = m.end()
    return ''.join(out)
