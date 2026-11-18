"""Give the obfuscated fields (f0, f1, ...) readable names.

Name sources, best first:
  1. record component names (ObjectMethods.bootstrap "a;b;c", "f0", "f1", ...)
  2. real getter names (`public T name() { return this.f3; }`)
  3. usage (counter / timestamp) + declared type
"""
import re
from collections import defaultdict
from deobf import skip_lex, match

FIELD_RE = re.compile(r'\bf(\d+)\b')
CLASS_RE = re.compile(r'(?<![.\w])(class|interface|enum|record)\s+(\w+)\b')
DECL_RE = re.compile(
    r'(?:(?<=[;{}])|^)\s*((?:(?:public|private|protected|static|final|volatile|transient)\s+)*)'
    r'([A-Za-z_][\w.]*(?:<[^;(){}=]*>)?(?:\[\])*)\s+(f\d+)\s*(=|;)')
REAL_GETTERS = {'id', 'seq', 'key', 'all', 'bool'}


def mask(s):
    out = list(s)
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in '"\'/':
            try:
                k = skip_lex(s, i)
            except Exception:
                k = None
            if k is not None:
                for j in range(i, k):
                    if out[j] != '\n':
                        out[j] = ' '
                i = k
                continue
        i += 1
    return ''.join(out)


class Cls:
    def __init__(self, name, start, end, parent):
        self.name, self.start, self.end, self.parent = name, start, end, parent
        self.fields = {}   # 'f3' -> dict(type, static, final, init)
        self.declpos = set()
        self.exact = set()
        self.names = {}    # 'f3' -> new name
        self.qual = name if parent is None else parent.qual + '.' + name


def parse_classes(text, m):
    classes = []
    for cm in CLASS_RE.finditer(m):
        j = cm.end()
        # header up to '{'
        depth = 0
        k = j
        while k < len(m):
            ch = m[k]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == '{' and depth == 0:
                break
            elif ch == ';' and depth == 0:
                k = -1
                break
            k += 1
        if k < 0 or k >= len(m):
            continue
        try:
            e = match(m, k, '{', '}')
        except Exception:
            continue
        classes.append(Cls(cm[2], k, e, None))
    classes.sort(key=lambda c: (c.start, -c.end))
    stack = []
    for c in classes:
        while stack and not (stack[-1].start < c.start < stack[-1].end):
            stack.pop()
        c.parent = stack[-1] if stack else None
        c.qual = c.name if c.parent is None else c.parent.qual + '.' + c.name
        stack.append(c)
    return classes


def innermost(classes, pos):
    best = None
    for c in classes:
        if c.start < pos < c.end and (best is None or c.start > best.start):
            best = c
    return best


def depth_array(m):
    d = [0] * (len(m) + 1)
    cur = 0
    for i, ch in enumerate(m):
        d[i] = cur
        if ch == '{':
            cur += 1
        elif ch == '}':
            cur -= 1
    d[len(m)] = cur
    return d


def lower_first(s):
    return s[:1].lower() + s[1:]


def strip_generics(t):
    return re.sub(r'<.*>', '', t)


def generic_args(t):
    m = re.search(r'<(.*)>', t)
    if not m:
        return []
    out, d, cur = [], 0, ''
    for ch in m[1]:
        if ch == '<':
            d += 1
        elif ch == '>':
            d -= 1
        if ch == ',' and d == 0:
            out.append(cur.strip()); cur = ''
        else:
            cur += ch
    out.append(cur.strip())
    return out


VALUE_NAMES = {'Boolean': 'flag', 'Long': 'time', 'Integer': 'count', 'Double': 'value', 'String': 'text',
               'Float': 'value', 'Object': 'value'}


def elem_name(t):
    t = strip_generics(t).split('.')[-1]
    if t in VALUE_NAMES:
        return VALUE_NAMES[t]
    if len(t) <= 2:
        return 'data'
    return lower_first(t)


def type_name(t, static_final, counter, stamp, context):
    base = strip_generics(t).split('.')[-1]
    args = generic_args(t)
    if base in ('Map', 'ConcurrentHashMap', 'HashMap', 'LinkedHashMap', 'ConcurrentMap') and len(args) == 2:
        if args[0] == 'UUID':
            return elem_name(args[1]) + 'ByPlayer'
        return elem_name(args[1]) + 'By' + elem_name(args[0]).capitalize()
    if base in ('List', 'ArrayList', 'LinkedList', 'Collection', 'Deque', 'Queue') and args:
        return elem_name(args[0]) + 's'
    if base in ('Set', 'HashSet', 'LinkedHashSet', 'EnumSet') and args:
        return 'playerIds' if args[0] == 'UUID' else elem_name(args[0]) + 's'
    if base in ('Cache', 'LoadingCache') and args:
        return elem_name(args[-1]) + 'Cache'
    if static_final and base in ('int', 'long', 'double', 'float', 'String', 'boolean'):
        return base.upper() + '_CONSTANT'
    if base == 'boolean':
        return 'flag'
    if base == 'AtomicBoolean':
        return 'atomicFlag'
    if base in ('AtomicLong', 'AtomicInteger'):
        return 'counter'
    if base == 'int':
        return 'count' if counter else 'intValue'
    if base == 'long':
        return 'timestamp' if stamp else ('count' if counter else 'longValue')
    if base == 'double':
        return 'doubleValue'
    if base == 'float':
        return 'floatValue'
    if base == 'String':
        return 'text'
    if base == 'PluginContext':
        return 'context'
    if base in ('Logger', 'Object', 'Thread', 'Timer'):
        return lower_first(base)
    if base == 'Object':
        return 'lock'
    if len(base) <= 2:
        return 'data'
    if base.endswith('[]'):
        return elem_name(base[:-2]) + 'Array'
    return lower_first(base)


def is_real_getter(n):
    return n in REAL_GETTERS or (len(n) >= 4 and n.isalpha() and n not in ('hashCode', 'toString', 'equals'))


def collect(rel, text):
    m = mask(text)
    classes = parse_classes(text, m)
    depth = depth_array(m)
    for dm in DECL_RE.finditer(m):
        pos = dm.start(3)
        c = innermost(classes, pos)
        if c is None or depth[pos] != depth[c.start] + 1:
            continue
        mods, typ, name = dm[1], dm[2], dm[3]
        init = ''
        if dm[4] == '=':
            e = dm.end()
            d = 0
            j = e
            while j < len(m):
                if m[j] in '({[':
                    d += 1
                elif m[j] in ')}]':
                    d -= 1
                elif m[j] == ';' and d == 0:
                    break
                j += 1
            init = text[e:j]
        c.declpos.add(pos)
        c.fields[name] = dict(type=typ, static='static' in mods, final='final' in mods, init=init)
    return m, classes


def name_class(c, text, used):
    body = text[c.start:c.end]
    # 0. the real name from the 2.0.4 build (order preserving type alignment)
    for f, n in getattr(c, 'refnames', {}).items():
        if f in c.fields and re.fullmatch(r'[A-Za-z_]\w*', n):
            c.names[f] = n
            c.exact.add(f)
    # 1. record components
    for rm in re.finditer(r'"([A-Za-z_][\w;]*)",\s*((?:"f\d+"(?:,\s*)?)+)', body):
        comps = rm[1].split(';')
        refs = re.findall(r'"(f\d+)"', rm[2])
        if len(comps) == len(refs):
            for f, n in zip(refs, comps):
                c.names.setdefault(f, n)
                c.exact.add(f)
    # 2. getters
    for gm in re.finditer(r'(?:public |private |protected )?(?:static )?(?:final )?[\w<>\[\], .?]+ (\w+)\(\) \{\s*return (?:this\.)?(f\d+);\s*\}', body):
        if gm[2] in c.fields and is_real_getter(gm[1]):
            if gm[2] not in c.names:
                c.names[gm[2]] = gm[1]
                c.exact.add(gm[2])
    # 3. usage + type
    for f, info in c.fields.items():
        if f in c.names:
            continue
        counter = bool(re.search(r'(?:\bthis\.|\b)%s(?:\+\+| \+= 1;)|\+\+(?:this\.)?%s\b' % (f, f), body))
        stamp = bool(re.search(r'%s = (?:\(long\))?System\.(?:nanoTime|currentTimeMillis)\(\)' % f, body))
        c.names[f] = type_name(info['type'], info['static'] and info['final'], counter, stamp, c)
    # make unique
    taken = set(used)
    final = {}
    exact = set(c.exact)
    local = set()
    for f in sorted(c.fields, key=lambda x: int(x[1:])):
        base = c.names[f]
        n, k = base, 2
        if f in exact:
            while n in local:
                n = '%s%d' % (base, k)
                k += 1
            local.add(n)
            taken.add(n)
            final[f] = n
            continue
        while n in taken or n in local:
            n = '%s%d' % (base, k)
            k += 1
        taken.add(n)
        local.add(n)
        final[f] = n
    c.names = final


def var_type(m, text, ident, pos):
    last = None
    for dm in re.finditer(r'\b([A-Z][\w.]*)(?:<[^;(){}]*?>)?(?:\[\])?\s+%s\b(?!\s*\()' % re.escape(ident), m[:pos]):
        last = dm[1]
    return last


def is_local(mm, depth, c, pos, name):
    k = depth[c.start] + 1
    a = pos
    while a > c.start:
        ch = mm[a]
        if (ch == ';' and depth[a] == k) or (ch == '}' and depth[a + 1] == k):
            break
        a -= 1
    b = pos
    n = len(mm)
    while b < min(c.end, n):
        ch = mm[b]
        if (ch == ';' and depth[b] == k) or (ch == '}' and depth[b + 1] == k):
            break
        b += 1
    seg = mm[a:b]
    for dm in re.finditer(r'([\w>\]]+)\s+%s\b\s*[=;,):]' % re.escape(name), seg):
        if dm[1] not in ('return', 'throw', 'else', 'new', 'case', 'assert', 'yield'):
            return True
    return False


def rename_fields(texts, ref_obj=None):
    info = {}
    depth_of = {}
    allnames = {}
    top = {}
    for rel, text in texts.items():
        if not FIELD_RE.search(text):
            continue
        mm, classes = collect(rel, text)
        info[rel] = (mm, classes)
        depth_of[rel] = depth_array(mm)
        words = set(re.findall(r'[A-Za-z_]\w*', mm))
        refnames = {}
        if ref_obj is not None:
            try:
                import javamodel
                for jc in javamodel.model(text):
                    full = [(f['name'], f['type']) for f in jc.allfields]
                    got = ref_obj.field_names(jc.qual, full)
                    refnames[jc.qual] = {k: v for k, v in got.items() if re.fullmatch(r'f\d+', k)}
            except Exception:
                pass
        for c in classes:
            c.refnames = refnames.get(c.qual, {})
            name_class(c, text, words)
        for c in classes:
            if c.parent is None:
                top[c.name] = (rel, c)
    unresolved = []
    out = {}
    for rel, text in texts.items():
        if rel not in info:
            out[rel] = text
            continue
        mm, classes = info[rel]
        byname = defaultdict(list)
        for c in classes:
            byname[c.name].append(c)

        def find_class(tname, ctx_cls):
            tname = strip_generics(tname)
            parts = tname.split('.')
            cur = None
            if parts[0] in byname:
                cs = byname[parts[0]]
                cur = (rel, cs[0])
                # prefer a class nested in the current top class chain
                for cc in cs:
                    if ctx_cls is not None and cc.qual.startswith(ctx_cls.qual.split('.')[0]):
                        cur = (rel, cc)
            elif parts[0] in top:
                cur = top[parts[0]]
            if cur is None:
                return None
            for p in parts[1:]:
                nxt = [c for c in info.get(cur[0], (None, []))[1] if c.parent is cur[1] and c.name == p]
                if not nxt:
                    return None
                cur = (cur[0], nxt[0])
            return cur[1]

        def resolve_expr(expr, pos, ctx):
            parts = expr.split('.')
            if parts[0] == 'this':
                cur = ctx
                rest = parts[1:]
            elif parts[0] in byname or parts[0] in top:
                cur = find_class(parts[0], ctx)
                rest = parts[1:]
            else:
                t = var_type(mm, text, parts[0], pos)
                if not t:
                    return None
                cur = find_class(t, ctx)
                rest = parts[1:]
            for p in rest:
                if cur is None:
                    return None
                if p in cur.fields:
                    cur = find_class(cur.fields[p]['type'], cur)
                else:
                    return None
            return cur

        edits = []
        for fm in FIELD_RE.finditer(mm):
            pos = fm.start()
            name = 'f' + fm[1]
            before = mm[:pos].rstrip()
            ctx = innermost(classes, pos)
            target = None
            if before.endswith('.'):
                em = re.search(r'([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*)\.$', before)
                cm = re.search(r'\(\(([A-Za-z_][\w.]*)\)\s*[\w.]+\)\.$', before)
                if cm:
                    target = find_class(cm[1], ctx)
                    em = em or cm
                elif not em:
                    unresolved.append((rel, name, 'complex receiver'))
                    continue
                else:
                    target = resolve_expr(em[1], pos, ctx)
                if target is None or name not in target.names:
                    # lambda parameters have no declared type: accept the only candidate
                    cands = [c for c in classes if name in c.names]
                    if len(cands) == 1:
                        target = cands[0]
                    else:
                        unresolved.append((rel, name, em[1]))
                        continue
            else:
                c = ctx
                while c is not None and name not in c.names:
                    c = c.parent
                target = c
                if target is None:
                    continue
                if pos not in target.declpos and is_local(mm, depth_of[rel], target, pos, name):
                    continue
            edits.append((pos, pos + len(fm[0]), target.names[name]))
        for bm in re.finditer(r'ObjectMethods\.bootstrap\(', mm):
            try:
                bc = match(text, bm.end() - 1, '(', ')')
            except Exception:
                continue
            bctx = innermost(classes, bm.start())
            if bctx is None:
                continue
            for sm in re.finditer(r'"(f\d+)"', text[bm.end():bc]):
                if sm[1] in bctx.names:
                    a = bm.end() + sm.start(1)
                    edits.append((a, a + len(sm[1]), bctx.names[sm[1]]))
        for tm in re.finditer(r'"([A-Z]\w*)\[(f\d+)=', text):
            tctx = innermost(classes, tm.start())
            if tctx is None:
                continue
            line_end = text.find('\n', tm.end())
            edits.append((tm.start(1), tm.end(1), tctx.name))
            for sm in re.finditer(r'(?:\[|, )(f\d+)=', text[tm.start():line_end]):
                if sm[1] in tctx.names:
                    a = tm.start() + sm.start(1)
                    edits.append((a, a + len(sm[1]), tctx.names[sm[1]]))
        s = text
        for a, b, n in sorted(set(edits), reverse=True):
            s = s[:a] + n + s[b:]
        out[rel] = s
    return out, unresolved
