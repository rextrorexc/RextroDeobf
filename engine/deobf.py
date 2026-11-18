import re, sys, os, glob, collections
import base64

POOL = {}


def load_pool_file(path):
    for line in open(path, 'rb').read().decode('ascii').split('\n'):
        if line:
            i, _, v = line.partition('\t')
            POOL[int(i)] = base64.b64decode(v).decode('utf-8')
SD = r'StringDeobfuscator\.'
M32 = 0xFFFFFFFF


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def rotr(x, n):
    x &= M32; n &= 31
    return ((x >> n) | (x << (32 - n))) & M32


# ---------------------------------------------------------------- lexical helpers
def skip_lex(s, i):
    """If a literal/comment starts at i return index after it, else None."""
    c = s[i]
    if c == '"':
        j = i + 1
        while s[j] != '"':
            j += 2 if s[j] == '\\' else 1
        return j + 1
    if c == "'":
        j = i + 1
        while s[j] != "'":
            j += 2 if s[j] == '\\' else 1
        return j + 1
    if c == '/' and s.startswith('/*', i):
        return s.index('*/', i + 2) + 2
    if c == '/' and s.startswith('//', i):
        j = s.find('\n', i)
        return len(s) if j < 0 else j
    return None


def match(s, i, o, c):
    d = 0
    n = len(s)
    while i < n:
        k = skip_lex(s, i)
        if k is not None:
            i = k
            continue
        if s[i] == o:
            d += 1
        elif s[i] == c:
            d -= 1
            if d == 0:
                return i
        i += 1
    raise ValueError('unbalanced')


def split_args(s):
    """split top level comma separated list"""
    out = []; d = 0; cur = 0; i = 0
    while i < len(s):
        k = skip_lex(s, i)
        if k is not None:
            i = k
            continue
        c = s[i]
        if c in '([{<' and c != '<':
            d += 1
        elif c in ')]}':
            d -= 1
        elif c == ',' and d == 0:
            out.append(s[cur:i].strip()); cur = i + 1
        i += 1
    last = s[cur:].strip()
    if last or out:
        out.append(last)
    return out


# ---------------------------------------------------------------- string escape
def jstr(v):
    r = ['"']
    for ch in v:
        o = ord(ch)
        if ch == '"': r.append('\\"')
        elif ch == '\\': r.append('\\\\')
        elif ch == '\n': r.append('\\n')
        elif ch == '\r': r.append('\\r')
        elif ch == '\t': r.append('\\t')
        elif o < 32 or o == 0x7f: r.append('\\u%04x' % o)
        else: r.append(ch)
    r.append('"')
    return ''.join(r)


# ---------------------------------------------------------------- phase 1: pure folding
NUM = r'(?:\(int\))?(-?(?:0x[0-9A-Fa-f]+|\d+))'
NUMX = r'(?:\(int\))?-?(?:0x[0-9A-Fa-f]+|\d+)'


def pn(t):
    return s32(int(t, 16)) if t.lower().lstrip('-').startswith('0x') else int(t)


JUNK_STMT = re.compile(r'^[ \t]*StringDeobfuscator\.(?:gJ1Cd2J6|z0lZMovd|pVERVEbg)\(' + NUMX + r'(?:,\s*' + NUMX + r')?\);[ \t]*\r?\n', re.M)
SYNTH_FIELD = re.compile(r'^[ \t]*private static final /\* synthetic \*/ int \w+ = -?\d+;[ \t]*\r?\n', re.M)


def fold_calls(s):
    s = re.sub(r'StringDeobfuscator\.uqCIFUEP\(' + NUM + r',\s*' + NUM + r',\s*' + NUM + r',\s*' + NUM + r'\)',
               lambda m: str(s32(rotr(pn(m[1]) ^ pn(m[3]), pn(m[4])) ^ pn(m[2]))), s)
    s = re.sub(r'StringDeobfuscator\.cVxlN1Ph\(' + NUM + r',\s*' + NUM + r',\s*' + NUM + r'\)',
               lambda m: str(s32(pn(m[1]) ^ pn(m[2]))), s)
    s = re.sub(r'\b1 != 0\b', 'true', s)
    s = re.sub(r'\b0 != 0\b', 'false', s)

    def strrep(m):
        return jstr(POOL[int(m[1])]) if int(m[1]) in POOL else m[0]
    s = re.sub(r'StringDeobfuscator\.sVfnkmVk\("s",\s*(\d+)\)', strrep, s)
    # (String)((Object)"lit") -> "lit"
    s = re.sub(r'\(String\)\(\(Object\)("(?:[^"\\\n]|\\.)*")\)', r'\1', s)
    return s


# ---------------------------------------------------------------- phase 2: switches
CASE_HEAD = re.compile(r'\s*(case\s+[^:\n]+?|default)\s*:\s*')


def parse_switch_body(body):
    """returns list of (label, text) or None if unparseable"""
    cases = []
    i = 0; n = len(body)
    while True:
        m = CASE_HEAD.match(body, i)
        if not m:
            if body[i:].strip() == '':
                return cases
            return None
        i = m.end()
        label = m[1].strip()
        if i < n and body[i] == '{':
            e = match(body, i, '{', '}')
            cases.append((label, body[i + 1:e]))
            i = e + 1
        else:
            # unbraced: up to next case/default at depth 0
            j = i; d = 0
            while j < n:
                k = skip_lex(body, j)
                if k is not None:
                    j = k; continue
                if body[j] in '{(':
                    d += 1
                elif body[j] in '})':
                    d -= 1
                elif d == 0 and re.match(r'(case\s|default\s*:)', body[j:j + 8]) and (j == 0 or not body[j - 1].isalnum()):
                    break
                j += 1
            cases.append((label, body[i:j]))
            i = j


def strip_trailing_break(t):
    return re.sub(r'\s*\bbreak;\s*$', '', t.strip())


def is_empty_case(t):
    return strip_trailing_break(t).strip() == ''


SW = re.compile(r'(?m)^([ \t]*)switch \(')


def simplify_switches(s, stats):
    pos = len(s)
    changed = True
    while changed:
        changed = False
        ms = list(SW.finditer(s))
        for m in reversed(ms):
            try:
                po = m.end() - 1
                pc = match(s, po, '(', ')')
                sel = s[po + 1:pc].strip()
                bo = s.index('{', pc)
                if s[pc + 1:bo].strip() != '':
                    continue
                bc = match(s, bo, '{', '}')
                cases = parse_switch_body(s[bo + 1:bc])
                if cases is None:
                    stats['switch_unparsed'] += 1
                    continue
            except Exception:
                stats['switch_err'] += 1
                continue
            end = bc + 1
            # trailing newline
            if s[end:end + 2] == '\r\n': end += 2
            elif s[end:end + 1] == '\n': end += 1
            all_empty = all(is_empty_case(t) for _, t in cases)
            repl = None
            if all_empty:
                repl = ''
            elif re.fullmatch(r'-?\d+', sel):
                v = int(sel)
                chosen = None
                for lab, t in cases:
                    if lab.startswith('case') and re.fullmatch(r'-?\d+', lab[4:].strip()) and int(lab[4:].strip()) == v:
                        chosen = t; break
                if chosen is None:
                    for lab, t in cases:
                        if lab == 'default':
                            chosen = t; break
                if chosen is not None:
                    body = strip_trailing_break(chosen)
                    if re.search(r'\bbreak\b', body) or 'continue' in body:
                        continue
                    repl = body.strip('\n') + '\n' if body.strip() else ''
                    # fall through semantics ignored: cfr emits explicit break
            if repl is None:
                continue
            s = s[:m.start()] + repl + s[end:]
            stats['switch_removed' if repl == '' else 'switch_inlined'] += 1
            changed = True
            break  # restart scan (positions shifted)
    return s



# ---------------------------------------------------------------- phase 3: hidden (indy) calls
PRIM = {'Z': 'boolean', 'B': 'byte', 'C': 'char', 'S': 'short', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double', 'V': 'void'}


def parse_desc(d):
    i = 1; params = []
    def one(i):
        dims = 0
        while d[i] == '[':
            dims += 1; i += 1
        if d[i] == 'L':
            j = d.index(';', i)
            t = d[i + 1:j].replace('/', '.').split('.')[-1].replace('$', '.')
            i = j + 1
        else:
            t = PRIM[d[i]]; i += 1
        return t + '[]' * dims, i
    while d[i] != ')':
        t, i = one(i); params.append(t)
    ret, _ = one(i + 1)
    return params, ret


SIMPLE = re.compile(r'^(?:this|[A-Za-z_]\w*)(?:\.[A-Za-z_]\w*)*$')
CAST = re.compile(r'^\(([A-Za-z_][\w.<>\[\]?, ]*)\)(.+)$', re.S)


def strip_cast(expr, want=None):
    m = CAST.match(expr)
    if m and SIMPLE.match(m[2].strip()):
        if want is None or m[1].split('.')[-1] == want:
            return m[2].strip(), True
    return expr, False


INDY = 'StringDeobfuscator.rY5nPgBX('


def convert_indy(s, stats):
    while True:
        st = s.rfind(INDY)
        if st < 0:
            return s
        po = st + len(INDY) - 1
        pc = match(s, po, '(', ')')
        args = split_args(s[po + 1:pc])
        o, n, d, k = int(args[1]), int(args[2]), int(args[3]), int(args[4])
        rest = args[5:]
        owner = POOL[o].split('.')[-1].replace('$', '.')
        name = POOL[n]
        params, ret = parse_desc(POOL[d])
        clean = []
        for idx, a in enumerate(rest):
            pt = params[idx - (1 if k == 1 else 0)] if (idx - (1 if k == 1 else 0)) >= 0 and (idx - (1 if k == 1 else 0)) < len(params) else None
            a2, _ = strip_cast(a, pt.split('.')[-1] if pt else None) if pt else (a, False)
            clean.append(a2)
        if k == 1:
            recv, ok = strip_cast(rest[0], owner.split('.')[-1])
            if not ok:
                recv = rest[0]
                m = CAST.match(recv)
                if m:
                    recv = '((%s)%s)' % (m[1], m[2])
            call = '%s.%s(%s)' % (recv, name, ', '.join(clean[1:]))
        else:
            call = '%s.%s(%s)' % (owner, name, ', '.join(clean))
        a, b = st, pc + 1
        # remove redundant (T)((Object)CALL) wrappers
        pre = s[:a]
        for pat, suf in ((r'(?<![\w])\(\((%s)\)\(\(Object\)$', '))'), (r'\((%s)\)\(\(Object\)$', ')')):
            mm = re.search(pat % re.escape(ret.split('.')[-1]), pre)
            if mm and s.startswith(suf, b):
                a = mm.start(); b += len(suf); break
        # declaration type
        mm = re.search(r'CallSite (\w+) = $', s[:a])
        if mm:
            call = call
            s = s[:mm.start()] + ret + ' ' + mm[1] + ' = ' + call + s[b:]
        else:
            s = s[:a] + call + s[b:]
        stats['indy'] += 1


# ---------------------------------------------------------------- phase 2b: leftover junk blocks
SYN_DEF = re.compile(r'[ \t]*private static /\* synthetic \*/ \w+ (\w+)\([^)]*\) \{')
NOTE_LINE = re.compile(r'[ \t]*\*[ \t]*(?:WARNING - |Enabled |Converted monitor|Lifted jumps|Loose catch|Removed try catching|Exception decompiling|Handled impossible)[^\n]*')


def with_note_comment(s, st):
    """start index of the decompiler note comment right above position st (or st itself)"""
    head = s[:st]
    m = re.search(r'([ \t]*/\*\n(?:[ \t]*\*[^\n/]*\n)+[ \t]*\*/\n)$', head)
    if m and all(NOTE_LINE.fullmatch(l) for l in m[1].split('\n')[1:-2]):
        return m.start(1)
    return st


GLOBAL_NAMES = []


def syn_names(s):
    return [m[1] for m in SYN_DEF.finditer(s)] + GLOBAL_NAMES


def make_res(names):
    nm = '|'.join(map(re.escape, names)) or r'(?!)'
    pred = (r'(?:StringDeobfuscator\.glejYs8c\(' + NUMX + r'\) [<>]=? 0|(?:\w+\.)?(?:' + nm + r')\(' + NUMX + r'\)|StringDeobfuscator\.uE0b3uFZ\(' + NUMX + r'\))')
    return re.compile(r'^[ \t]*if \(' + pred + r'\) \{\s*\}[ \t]*\r?\n', re.M)


RE_EMPTY_TRY = re.compile(r'^[ \t]*try \{\s*\}\s*catch \(\w+ \w+\) \{\s*\}[ \t]*\r?\n', re.M)
RE_JUNK_VAR = re.compile(r'(?:^([ \t]*)int (\w+);\s*)?^([ \t]*)try \{\s*(\w+) = StringDeobfuscator\.glejYs8c\(' + NUMX + r'\);\s*\}\s*catch \(\w+ \w+\) \{\s*\4 = 0;\s*\}[ \t]*\r?\n', re.M)


def enclosing_end(s, i):
    d = 0
    while i < len(s):
        k = skip_lex(s, i)
        if k is not None:
            i = k; continue
        if s[i] == '{': d += 1
        elif s[i] == '}':
            if d == 0: return i
            d -= 1
        i += 1
    return len(s)


def drop_junk_vars(s, stats):
    out = []; last = 0
    for m in RE_JUNK_VAR.finditer(s):
        var = m[4]
        if m[2] and m[2] != var:
            continue
        out.append(s[last:m.start()]); last = m.end(); stats['junkvar'] += 1
    out.append(s[last:])
    return ''.join(out)


def drop_syn_methods(s, stats):
    # remove unused synthetic helper methods
    for m in reversed(list(SYN_DEF.finditer(s))):
        name = m[1]
        if len(re.findall(r'\b%s\b' % re.escape(name), s)) != 1:
            continue
        bo = m.end() - 1
        bc = match(s, bo, '{', '}')
        e = bc + 1
        while s[e:e + 1] in ('\r', '\n'):
            e += 1
        st = with_note_comment(s, m.start())
        s = s[:st].rstrip(' \t') + s[e:]
        stats['syn_removed'] += 1
    return s


def phase2b(s, stats):
    re_if = make_res(syn_names(s))
    for _ in range(5):
        s = drop_junk_vars(s, stats)
        s, a = re_if.subn('', s)
        s, b = RE_EMPTY_TRY.subn('', s)
        stats['empty_if'] += a; stats['empty_try'] += b
        if not (a or b):
            break
    s = drop_syn_methods(s, stats)
    return s


# ---------------------------------------------------------------- phase 4: cosmetics
CFR_NOTE = (r'(?:WARNING - [^\n]*|Enabled [^\n]*|Converted monitor[^\n]*|Lifted jumps[^\n]*|'
            r'Loose catch[^\n]*|Removed try catching[^\n]*|Exception decompiling[^\n]*|Handled impossible[^\n]*)')


def strip_noise(s):
    """remove analyser / decompiler comment noise and restore commented-out annotations"""
    s = s.replace('\r\n', '\n')
    s = re.sub(r'^[ \t]*\* \[SECURITY THREAT\][^\n]*\n', '', s, flags=re.M)
    s = re.sub(r'^[ \t]*/\*\n(?:[ \t]*\*[ \t]*' + CFR_NOTE + r'\n)+[ \t]*\*/[ \t]*\n', '', s, flags=re.M)
    s = re.sub(r'^[ \t]*/\*\n(?:[ \t]*\*[ \t]*\n)*[ \t]*\*/[ \t]*\n', '', s, flags=re.M)
    s = re.sub(r'^([ \t]*)// (@M\(.*\)) // Commented:[^\n]*\n', r'\1\2\n', s, flags=re.M)
    return s


def simplify_casts(s):
    """(T)((Object)expr) -> (T)expr ; (Object)((Object)x) -> (Object)x ; boolean locals = 0/1 -> false/true"""
    pat = re.compile(r'\(\(Object\)')
    pos = 0
    while True:
        m = pat.search(s, pos)
        if not m:
            break
        # must be the argument of a cast: preceded by "(T)"
        pre = s[:m.start()]
        cm = re.search(r'\((?:[A-Za-z_][\w.<>\[\]?, ]*)\)$', pre)
        if not cm:
            pos = m.end(); continue
        po = m.start()
        pc = match(s, po, '(', ')')
        inner = s[m.end():pc]
        s = s[:po] + inner + s[pc + 1:]
        pos = max(0, po - 1)
    s = re.sub(r'\(Object\)\(Object\)', '(Object)', s)
    for name in set(re.findall(r'\bboolean (\w+)\b', s)):
        s = re.sub(r'\b%s = 1;' % re.escape(name), name + ' = true;', s)
        s = re.sub(r'\b%s = 0;' % re.escape(name), name + ' = false;', s)
    s = re.sub(r'(?<=[(!&| ])([\w.]+(?:\([^()]*\))?) != false\b', r'\1', s)
    s = re.sub(r'(?<=[(&| ])([\w.]+(?:\([^()]*\))?) == false\b', r'!\1', s)
    return s


def drop_dead_blocks(s):
    """leftovers of decompiled junk: empty spin loops, empty labelled blocks, lbl comments"""
    s = re.sub(r'^[ \t]*// (?:// \*\*[^\n]*|/\* lbl\d+: \*/|\s*/\* \d+ sources? \*/)[ \t]*\n', '', s, flags=re.M)
    s = re.sub(r'^[ \t]*while \(true\) \{\s*(?:continue;\s*)?break;\s*\}[ \t]*\n', '', s, flags=re.M)
    for _ in range(6):
        s, n = re.subn(r'^[ \t]*block\d+: \{\s*(?:break block\d+;\s*)*\}[ \t]*\n', '', s, flags=re.M)
        if not n:
            break
    return s



ALIAS = re.compile(r'(?m)^([ \t]*)(?:final )?([A-Z][\w.]*(?:<[^;=()]*>)?(?:\[\])*) (\w+) = ([a-z]\w*);[ \t]*\n')


def drop_aliases(s, stats):
    """`State b2 = b;` -> use b directly (decompiler copies of an unchanged local)"""
    pos = 0
    while True:
        m = ALIAS.search(s, pos)
        if not m:
            return s
        pos = m.end()
        typ, x2, x = m[2], m[3], m[4]
        if x2 == x or x == 'null':
            continue
        end = enclosing_end(s, m.end())
        head = s[max(0, m.start() - 6000):m.start()]
        # x must be a local/parameter of the same declared type, x2 must not be shadowing anything we rename
        if not re.search(r'\b%s(?:<[^;=()]*>)?(?:\[\])* %s\b' % (re.escape(typ.split('<')[0]), re.escape(x)), head):
            continue
        rest = s[m.end():end]
        if re.search(r'(?<![\w.])%s\s*(?:=(?!=)|\+\+|--|\+=|-=)' % re.escape(x), rest):
            continue
        if re.search(r'(?<![\w.])%s\s*(?:=(?!=)|\+\+|--|\+=|-=)' % re.escape(x2), rest):
            continue
        if re.search(r'\b%s\b' % re.escape(x2), s[m.end():end]) is None:
            s = s[:m.start()] + s[m.end():]
            pos = m.start()
            stats['alias'] += 1
            continue
        new_rest = re.sub(r'(?<![\w.])%s\b(?!\s*\()' % re.escape(x2), x, rest)
        s = s[:m.start()] + new_rest + s[end:]
        pos = m.start()
        stats['alias'] += 1


RECORD_METHOD = re.compile(
    r'(?:@Override\s+)?public (?:final )?(?:String|int|boolean) (toString|hashCode|equals)\(([^)]*)\)\s*\{\s*'
    r'return (?:\((?:int|boolean)\))?ObjectMethods\.bootstrap\("\w+",\s*new MethodHandle\[\]\{(\w+)\.class,\s*"([^"]*)"((?:,\s*"\w+")*)\}[^;]*;\s*\}')


def fix_records(s):
    """CFR prints record toString/hashCode/equals as ObjectMethods.bootstrap(...) which is not compilable Java"""
    def rep(m):
        kind, cls = m[1], m[3]
        names = re.findall(r'"(\w+)"', m[5])
        ind = '        '
        if kind == 'toString':
            body = ' + ", " + '.join('"%s=" + %s' % (n, n) for n in names) if names else ''
            ret = 'return "%s[" + %s + "]";' % (cls, body) if names else 'return "%s[]";' % cls
            return 'public String toString() {\n%s%s\n    }' % (ind + '    ', ret)
        if kind == 'hashCode':
            ret = 'return java.util.Objects.hash(%s);' % ', '.join(names) if names else 'return 0;'
            return 'public int hashCode() {\n%s%s\n    }' % (ind + '    ', ret)
        arg = re.sub(r'^.*\s', '', m[2].strip()) or 'object'
        conds = ' && '.join('java.util.Objects.equals(%s, other.%s)' % (n, n) for n in names) or 'true'
        return ('public boolean equals(Object %s) {\n%sif (this == %s) {\n%s    return true;\n%s}\n'
                '%sif (%s == null || getClass() != %s.getClass()) {\n%s    return false;\n%s}\n'
                '%s%s other = (%s)%s;\n%sreturn %s;\n    }') % (
            arg, ind + '    ', arg, ind + '    ', ind + '    ', ind + '    ', arg, arg, ind + '    ', ind + '    ',
            ind + '    ', cls, cls, arg, ind + '    ', conds)
    return RECORD_METHOD.sub(rep, s)


ENUM_HEAD = re.compile(
    r'(?m)^([ \t]*)((?:(?:public|private|protected|static|final)\s+)*)class (\w+)\s*\n?\s*extends Enum<\3>(\s*implements [^{]*?)?\s*\{')


def fix_enums(s):
    """CFR prints some enums as `class X extends Enum<X>` with synthetic $VALUES plumbing"""
    while True:
        m = ENUM_HEAD.search(s)
        if not m:
            return s
        ind, mods, name = m[1], m[2], m[3]
        impl = (' ' + m[4].strip()) if m[4] else ''
        bo = m.end() - 1
        bc = match(s, bo, '{', '}')
        body = s[bo + 1:bc]
        consts = re.findall(r'(?m)^[ \t]*public static final /\* enum \*/ %s (\w+) = new %s\((.*)\);[ \t]*\n' % (name, name), body)
        body = re.sub(r'(?m)^[ \t]*public static final /\* enum \*/ %s \w+ = new %s\(.*\);[ \t]*\n' % (name, name), '', body)
        body = re.sub(r'(?m)^[ \t]*private static final /\* synthetic \*/ %s\[\] \$VALUES;[ \t]*\n' % name, '', body)
        for pat in (r'[ \t]*public static %s\[\] values\(\) \{', r'[ \t]*public static %s valueOf\(String \w+\) \{',
                    r'[ \t]*private static /\* synthetic \*/ %s\[\] \w+\(\) \{', r'[ \t]*static \{'):
            for mm in list(re.finditer(pat % name if '%s' in pat else pat, body)):
                try:
                    e = match(body, mm.end() - 1, '{', '}')
                except Exception:
                    continue
                blk = body[mm.start():e + 1]
                if pat.endswith(r'static \{') and '$VALUES' not in blk:
                    continue
                body = body[:mm.start()] + body[e + 1:].lstrip('\n')
                break
        # the loop above removes one block per pattern; repeat until stable
        for pat in (r'[ \t]*private static /\* synthetic \*/ %s\[\] \w+\(\) \{',):
            while True:
                mm = re.search(pat % name, body)
                if not mm:
                    break
                e = match(body, mm.end() - 1, '{', '}')
                body = body[:mm.start()] + body[e + 1:].lstrip('\n')
        mods2 = re.sub(r'\b(final|static)\s+', '', mods)
        names = ',\n'.join('%s    %s%s' % (ind, n, '(%s)' % a if a.strip() else '') for n, a in consts)
        head = '%s%senum %s%s {\n%s%s' % (ind, mods2, name, impl, names, ';\n' if consts else ';\n')
        s = s[:m.start()] + head + body.rstrip() + '\n' + ind + '}' + s[bc + 1:]


CFR_VAR = re.compile(r'\b(var\d+_\d+|v\d+)\b')
NOT_TYPES = {'return', 'throw', 'else', 'new', 'case', 'assert', 'yield', 'instanceof'}


def _literal_type(e):
    e = e.strip()
    if re.fullmatch(r'-?\d+', e) or re.fullmatch(r'-?0x[0-9A-Fa-f]+', e):
        return 'int'
    if re.fullmatch(r'-?\d+[lL]', e):
        return 'long'
    if re.fullmatch(r'-?\d+\.\d*[fF]', e):
        return 'float'
    if re.fullmatch(r'-?\d+\.\d*[dD]?', e):
        return 'double'
    if e in ('true', 'false'):
        return 'boolean'
    return None


def fix_cfr_vars(s, stats):
    """variables the decompiler used but never declared (var3_3, v3 ...): declare them at the top of the method"""
    from fields import mask, parse_classes, depth_array, innermost
    from infer import infer_expr
    names = sorted(set(CFR_VAR.findall(s)))
    if not names:
        return s
    # tek geçişte "Tür ad" ile bildirilmiş CFR değişkenleri (eskiden her ad için tüm metin ayrı taranıyordu: büyük dosyalarda dakikalar)
    declared_set = set()
    m = mask(s)
    alt = '|'.join(re.escape(x) for x in names)
    for dm in re.finditer(r'([\w>\]]+)\s+(%s)\b\s*(?:=(?!=)|;|,|\)|:)' % alt, m):
        if dm[1] not in NOT_TYPES:
            declared_set.add(dm[2])
    dirty = False
    classes = depth = None
    for nm in names:
        if nm in declared_set:
            continue
        if dirty or classes is None:
            m = mask(s)
        first = re.search(r'\b%s\b' % re.escape(nm), m)
        if not first:
            continue
        if dirty or classes is None:
            classes = parse_classes(s, m)
            depth = depth_array(m)
            dirty = False
        c = innermost(classes, first.start())
        if c is None:
            continue
        k = depth[c.start] + 1
        i = first.start()
        while i > c.start and not (m[i] == '{' and depth[i] == k):
            i -= 1
        if i <= c.start:
            continue
        try:
            close = match(m, i, '{', '}')
        except Exception:
            continue
        body = s[i:close]
        # header = text from the previous member boundary up to the opening brace
        hs = i
        while hs > c.start and not (m[hs] in ';}{' and depth[hs] <= k):
            hs -= 1
        header = s[hs + 1:i]
        types = set()
        for am in re.finditer(r'(?<![\w.])%s = ([^;]+);' % re.escape(nm), body):
            rhs = am[1].strip()
            rm = re.match(r'(var\d+_\d+|v\d+|\w+)$', rhs)
            t = _literal_type(rhs) or infer_expr(rhs, '', {})
            if t is None and rm:
                dm = re.search(r'([\w<>\[\]., ?]+?)\s+%s\b' % re.escape(rm[1]), header + body[:am.start()])
                if dm and dm[1].split():
                    t = dm[1].split()[-1]
            if t:
                types.add(t)
        typ = types.pop() if len(types) == 1 else 'Object'
        init = {'int': '0', 'long': '0L', 'short': '0', 'byte': '0', 'char': "'\\0'", 'float': '0f', 'double': '0.0',
                'boolean': 'false'}.get(typ, 'null')
        ind = re.search(r'\n([ \t]*)\S', s[i:]) or None
        indent = ind[1] if ind else '        '
        s = s[:i + 1] + '\n%s%s %s = %s;' % (indent, typ, nm, init) + s[i + 1:]
        stats['cfr_var_declared'] += 1
        dirty = True
    return s


def strip_object_args(s):
    """`, (Object)value` (CFR) breaks generic method calls"""
    s = re.sub(r'(?<=[,(] )\(Object\)(?=[A-Za-z_(!][^;]*)', '', s)
    s = re.sub(r'\(\(Object\)(?=[A-Za-z_][\w.]*\))', '(', s)
    return s


def boolean_fix(s, boolonly):
    """`flag = a || b ? 1 : 0;` / `flag = 1;` on boolean fields and locals"""
    def lhs_ok(lhs):
        last = lhs.split('.')[-1]
        return last in boolonly
    def r1(m):
        return '%s%s = %s;' % (m[1], m[2], m[3]) if lhs_ok(m[2]) else m[0]
    s = re.sub(r'(?m)^([ \t]*)((?:this\.)?[\w.]+) = (.+?) \? 1 : 0;', r1, s)
    def r2(m):
        return '%s%s = %s;' % (m[1], m[2], 'true' if m[3] == '1' else 'false') if lhs_ok(m[2]) else m[0]
    s = re.sub(r'(?m)^([ \t]*)((?:this\.)?[\w.]+) = ([01]);', r2, s)
    # declarations:  boolean X = cond ? 1 : 0;
    s = re.sub(r'(?m)^([ \t]*(?:(?:private|public|protected|static|final)\s+)*boolean \w+ = )(.+?) \? 1 : 0;', r'\1\2;', s)
    return s


def fix_monitors(s):
    """// MONITORENTER : x ... // MONITOREXIT : x  ->  synchronized (x) { ... }

    The decompiler repeats MONITOREXIT on every early exit; the region ends at the last exit before the next
    MONITORENTER of the same variable. Only done when braces stay balanced and no local escapes the block."""
    enter = re.compile(r'(?m)^([ \t]*)// MONITORENTER : (\w+)[ \t]*\n')
    out = []
    pos = 0
    while True:
        m = enter.search(s, pos)
        if not m:
            break
        var = m[2]
        exit_rx = re.compile(r'(?m)^[ \t]*// MONITOREXIT : %s[ \t]*\n' % re.escape(var))
        nxt = enter.search(s, m.end())
        limit = nxt.start() if nxt and nxt[2] == var else len(s)
        exits = [e for e in exit_rx.finditer(s, m.end(), limit)]
        if not exits:
            out.append(s[pos:m.start()])
            pos = m.end()
            continue
        last = exits[-1]
        body = s[m.end():last.start()]
        body_clean = exit_rx.sub('', body)
        masked = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', body_clean)
        balanced = masked.count('{') == masked.count('}')
        declared = re.findall(r'(?m)^[ \t]*(?:final )?[\w<>\[\],.? ]+ (\w+)(?: = |;)', body_clean)
        rest = s[last.end():]
        escapes = any(re.search(r'\b%s\b' % re.escape(d), rest) for d in declared)
        out.append(s[pos:m.start()])
        if balanced and not escapes:
            ind = ''.join(('    ' + l if l.strip() else l) for l in body_clean.splitlines(True))
            out.append('%ssynchronized (%s) {\n%s%s}\n' % (m[1], var, ind, m[1]))
        else:
            out.append(body_clean)
        pos = last.end()
    out.append(s[pos:])
    return exit_cleanup(''.join(out))


def exit_cleanup(s):
    return re.sub(r'(?m)^[ \t]*// MONITOR(?:ENTER|EXIT) : \w+[ \t]*\n', '', s)


def phase4(s, stats):
    s = strip_noise(s)
    s = fix_monitors(s)
    s = drop_aliases(s, stats)
    s = fix_enums(s)
    s = fix_cfr_vars(s, stats)
    s = re.sub(r'(?m)^([ \t]*)reference (\w+) = ', r'\1var \2 = ', s)
    s = drop_dead_blocks(s)
    s = simplify_casts(s)
    s = re.sub(r'^import [\w.]*StringDeobfuscator;[ \t]*\n', '', s, flags=re.M)
    # decompiler / analyser comment noise
    s = re.sub(r'^[ \t]*/\*\n(?:[ \t]*\*[ \t]*' + CFR_NOTE + r'\n)+[ \t]*\*/[ \t]*\n', '', s, flags=re.M)
    s = re.sub(r'^/\*\n \* Could not load the following classes:\n(?: \*[^\n]*\n)*? \*/\n', '', s, flags=re.M)
    s = re.sub(r'^/\*\n \* \[SECURITY THREAT\][^\n]*\n \*/\n', '', s, flags=re.M)
    # CFR typed every indy result as CallSite
    s = re.sub(r'\(\(CallSite\)(\w+)\)\.length', r'\1.length', s)
    s = re.sub(r'\bCallSite (\w+) = null;', r'Object \1 = null;', s)
    s = re.sub(r'\bCallSite (\w+) = ', r'var \1 = ', s)
    s = re.sub(r'\bCallSite (\w+);', r'Object \1;', s)
    s = re.sub(r'<CallSite\b', '<String', s)
    s = re.sub(r', CallSite>', ', String>', s)
    s = re.sub(r'\bCallSite>', 'String>', s)
    s = re.sub(r'\(CallSite\)', '(Object)', s)
    if not re.search(r'\bCallSite\b', re.sub(r'^import .*$', '', s, flags=re.M)):
        s = re.sub(r'^import java\.lang\.invoke\.CallSite;[ \t]*\n', '', s, flags=re.M)
    # CFR names every indy-typed local "callSite"
    if re.search(r'\bcallSite\d*\b', s):
        base = 'value' if not re.search(r'\bvalue\d*\b', s) else 'tmp'
        if re.search(r'\b%s\d*\b' % base, s):
            base = 'indyValue'
        s = re.sub(r'\bcallSite(\d*)\b', base + r'\1', s)
    s = re.sub(r'\n[ \t]*\n([ \t]*\})', r'\n\1', s)
    s = re.sub(r'\n{3,}', '\n\n', s)
    s = drop_dead_blocks(s)
    s = drop_dead_blocks(s)
    return s.lstrip('\n')


# ---------------------------------------------------------------- driver
def phase1(s, stats):
    s = re.sub(r'/\*\n[ \t]*/\*\n', '/*\n', s)  # damaged double comment opener in some inputs
    s = SYNTH_FIELD.sub('', s)
    s = fold_calls(s)
    n0 = len(JUNK_STMT.findall(s))
    s = JUNK_STMT.sub('', s)
    stats['junk_stmts'] += n0
    return s


if __name__ == '__main__':
    stats = collections.Counter()
    src = sys.argv[1]
    t = open(src, encoding='utf-8', errors='replace', newline='').read()
    t = phase1(t, stats)
    t = simplify_switches(t, stats)
    t = phase2b(t, stats)
    t = convert_indy(t, stats)
    sys.stdout.write(t)
    sys.stderr.write(str(dict(stats)) + '\n')
