"""Give `Object x;` locals (decompiler lost the type) the type of what is assigned to them."""
import re
from collections import defaultdict

import javamodel
from deobf import match, enclosing_end

STRING_CALLS = re.compile(r'(?:\.toString\(\)|\.trim\(\)|\.toLowerCase\(|\.toUpperCase\(|\.substring\(|\.replace\(|'
                          r'\.replaceAll\(|\.getName\(\)|\.name\(\)|\.getMessage\(\))$')


def build_index(texts):
    idx = defaultdict(lambda: defaultdict(set))
    for rel, t in texts.items():
        try:
            for c in javamodel.model(t):
                for m in c.methods:
                    idx[c.name][m.name].add((m.ret, len(m.params)))
        except Exception:
            pass
    return idx


def split_top(e, ch):
    d = 0
    i = 0
    while i < len(e):
        c = e[i]
        if c == '"':
            i += 1
            while i < len(e) and e[i] != '"':
                i += 2 if e[i] == '\\' else 1
        elif c in '([{':
            d += 1
        elif c in ')]}':
            d -= 1
        elif c == ch and d == 0:
            return e[:i], e[i + 1:]
        i += 1
    return None


def infer_expr(e, cls, idx):
    e = e.strip()
    while e.startswith('(') and e.endswith(')') and match_balanced(e):
        e = e[1:-1].strip()
    if e == 'null' or not e:
        return None
    q = split_top(e, '?')
    if q:
        rest = q[1]
        br = split_top(rest, ':')
        if br:
            a, b = infer_expr(br[0], cls, idx), infer_expr(br[1], cls, idx)
            return a or b if (a is None or b is None or a == b) else None
    m = re.match(r'^\(([A-Z][\w.<>\[\]]*)\)\s*\S', e)
    if m:
        return re.sub(r'<.*>', '', m[1])
    if re.match(r'^"(?:[^"\\]|\\.)*"$', e) or re.match(r'^"(?:[^"\\]|\\.)*"\s*\+', e):
        return 'String'
    m = re.match(r'^new ([A-Z][\w.]*)', e)
    if m:
        return m[1].split('.')[-1]
    if e.startswith('Files.readString(') or e.startswith('String.valueOf(') or e.startswith('String.format('):
        return 'String'
    if STRING_CALLS.search(e):
        return 'String'
    m = re.match(r'^([A-Z]\w*)\.(\w+)\(', e)
    if m and m[1] in idx and m[2] in idx[m[1]]:
        rets = {r for r, n in idx[m[1]][m[2]] if r != 'void'}
        if len(rets) == 1:
            return rets.pop()
    m = re.match(r'^this\.(\w+)\(', e)
    if m and cls in idx and m[1] in idx[cls]:
        rets = {r for r, n in idx[cls][m[1]] if r != 'void'}
        if len(rets) == 1:
            return rets.pop()
    return None


def match_balanced(e):
    d = 0
    for i, c in enumerate(e):
        if c == '(':
            d += 1
        elif c == ')':
            d -= 1
            if d == 0 and i != len(e) - 1:
                return False
    return d == 0


DECL = re.compile(r'(?m)^([ \t]*)(?:final )?Object (\w+)(?: = ([^;\n]*))?;')


def infer_locals(text, cls, idx, stats):
    out = text
    pos = 0
    while True:
        m = DECL.search(out, pos)
        if not m:
            return out
        pos = m.end()
        name = m[2]
        end = enclosing_end(out, m.end())
        scope = out[m.start():end]
        cands = []
        if m[3]:
            init = m[3]
            while True:
                am = re.match(r'(\w+) = (.*)$', init)
                if not am:
                    break
                init = am[2]
            cands.append(init)
        for am in re.finditer(r'(?<![\w.=!<>])%s = ([^;]+);' % re.escape(name), scope):
            cands.append(am[1])
        for am in re.finditer(r'(?<![\w.])%s = (\w+) = ([^;]+);' % re.escape(name), scope):
            cands.append(am[2])
        types = set()
        for c in cands:
            if c.count('(') != c.count(')'):
                continue   # 'x = a()) instanceof ...' : not a plain assignment
            t = infer_expr(c, cls, idx)
            if t:
                types.add(t)
        if len(types) == 1:
            t = types.pop()
            out = out[:m.start()] + out[m.start():m.end()].replace('Object ' + name, t + ' ' + name, 1) + out[m.end():]
            stats['object_local_typed'] += 1
