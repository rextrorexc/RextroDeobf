"""Tiny Java source model (classes, fields, methods) built with brace matching on masked text."""
import re
from fields import mask, parse_classes, depth_array, innermost
from deobf import match

MODS = r'(?:public|private|protected|static|final|abstract|synchronized|native|default|volatile|transient)'
METHOD_RE = re.compile(
    r'(?m)^[ \t]*((?:@\w+(?:\([^)]*\))?\s+)*)((?:' + MODS + r'\s+)*)(<[^>]+>\s+)?'
    r'([A-Za-z_][\w.]*(?:<[^;(){}=]*?>)?(?:\[\])*)\s+(\w+)\(([^)]*)\)\s*(?:throws [\w., ]+)?\s*([{;])')
FIELD_RE2 = re.compile(
    r'(?m)^[ \t]*((?:@\w+(?:\([^)]*\))?\s+)*)((?:' + MODS + r'\s+)*)([A-Za-z_][\w.]*(?:<[^;(){}=]*?>)?(?:\[\])*)\s+(\w+)\s*(=|;)')
NOT_TYPES = {'return', 'new', 'else', 'throw', 'case', 'package', 'import', 'goto'}


def simple(t):
    t = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', t).strip()
    t = t.replace('...', '[]')
    dims = '[]' * t.count('[]')
    t = t.replace('[]', '')
    t = re.sub(r'<.*>', '', t)
    t = t.split('.')[-1].strip()
    t = re.sub(r'^final\s+', '', t)
    return t + dims


def split_params(p):
    out, d, cur = [], 0, ''
    for ch in p:
        if ch in '<(':
            d += 1
        elif ch in '>)':
            d -= 1
        if ch == ',' and d == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    types = []
    for x in out:
        x = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', x).strip()
        x = re.sub(r'^final\s+', '', x)
        x = re.sub(r'\s+\w+$', '', x)
        types.append(simple(x))
    return types


class Method:
    def __init__(self, name, ret, params, static, abstract, start, end, body, line):
        self.name, self.ret, self.params, self.static = name, ret, params, static
        self.abstract, self.start, self.end, self.body, self.line = abstract, start, end, body, line
        self.calls = set(re.findall(r'(?:\.|::)(\w+)\s*\(?', body)) if body else set()
        self.ncalls = len(re.findall(r'(?:\.|::)\w+\s*\(', body or ''))
        self.size = len(body or '')

    @property
    def sig(self):
        return (self.ret, tuple(self.params), self.static)


def model(text):
    m = mask(text)
    classes = parse_classes(text, m)
    depth = depth_array(m)
    for c in classes:
        c.methods = []
        c.allfields = []
        c.kind = None
    for mm in METHOD_RE.finditer(m):
        typ, name = mm[4], mm[5]
        if typ in NOT_TYPES or name in NOT_TYPES:
            continue
        pos = mm.start(5)
        c = innermost(classes, pos)
        if c is None or depth[pos] != depth[c.start] + 1:
            continue
        if name == c.name:
            continue
        body = ''
        end = mm.end()
        if mm[7] == '{':
            try:
                e = match(m, mm.end() - 1, '{', '}')
                body = text[mm.end():e]
                end = e
            except Exception:
                pass
        mods = mm[2]
        c.methods.append(Method(name, simple(typ), split_params(mm[6]), 'static' in mods,
                                'abstract' in mods or mm[7] == ';', pos, end, body,
                                text.count('\n', 0, pos) + 1))
    for fm in FIELD_RE2.finditer(m):
        typ, name = fm[3], fm[4]
        if typ in NOT_TYPES:
            continue
        pos = fm.start(4)
        c = innermost(classes, pos)
        if c is None or depth[pos] != depth[c.start] + 1:
            continue
        c.allfields.append(dict(name=name, type=simple(typ), static='static' in fm[2], final='final' in fm[2]))
    return classes
