"""Control-flow unflattening for CFR output of the obfuscator's state-machine loops."""
import re
from deobf import match, parse_switch_body, skip_lex

SITE = re.compile(r'(?m)^([ \t]*)int (\w+) = (-?\d+);\n(?:[ \t]*\w[\w<>\[\]]* \w+( = [^;\n]*)?;\n)*?[ \t]*boolean (\w+) = true;\n[ \t]*(block\d+): while \(true\) \{')
SIMPLE_SITE = re.compile(r'(?m)^([ \t]*)int (\w+) = (-?\d+);\n(?:[ \t]*\w[\w<>\[\]]* \w+( = [^;\n]*)?;\n)*?[ \t]*(?:(block\d+):\s*)?while \(true\) \{\s*switch \(\2\) \{')


def dedent(code, n):
    out = []
    for l in code.split('\n'):
        out.append(l[n:] if l[:n].strip() == '' else l.lstrip())
    return '\n'.join(out)


def analyse(s, m):
    """returns (start, end, replacement) or None"""
    ind, S, init, _, flag, L1 = m.group(1), m[2], int(m[3]), m[4], m[5], m[6]
    ob = m.end() - 1
    oc = match(s, ob, '{', '}')
    body = s[ob + 1:oc]
    em = re.match(r'\s*if \(!' + flag + r' \|\| \(' + flag + r' = false\) \|\| !true\) \{', body)
    entry = ''
    rest = body
    if em:
        eo = em.end() - 1
        ec = match(body, eo, '{', '}')
        entry = body[eo + 1:ec]
        rest = body[ec + 1:]
    wm = re.match(r'\s*(block\d+): while \(true\) \{\s*switch \(' + re.escape(S) + r'\) \{', rest)
    if not wm:
        return None
    L2 = wm[1]
    so = wm.end() - 1
    sc = match(rest, so, '{', '}')
    cases = parse_switch_body(rest[so + 1:sc])
    if cases is None:
        return None
    states = {}
    default = None
    for lab, t in cases:
        if lab == 'default':
            default = t
        else:
            states[int(lab.split()[1])] = t
    assign = re.compile(r'\b' + re.escape(S) + r' = (-?\d+);')

    def step(t):
        """-> (code, next_state or None for terminal) or raise"""
        t2 = t.rstrip()
        t2 = re.sub(r'\n?[ \t]*continue ' + L2 + r';\s*$', '', t2)
        am = list(assign.finditer(t2))
        if not am:
            if re.search(r'\b' + re.escape(S) + r'\b', t2) or re.search(r'continue block\d+', t2):
                raise ValueError('complex')
            return t2, None
        if len(am) != 1 or t2[am[0].end():].strip():
            raise ValueError('nonlinear')
        code = t2[:am[0].start()].rstrip()
        if re.search(r'continue block\d+|\b' + re.escape(S) + r'\b', code):
            raise ValueError('complex')
        return code, int(am[0][1])

    out = []
    # entry
    try:
        if em:
            code, nxt = step(entry)
        else:
            code, nxt = '', init
    except ValueError as e:
        return str(e)
    out.append(code)
    seen = set()
    while nxt is not None:
        if nxt in seen:
            return 'loop'
        seen.add(nxt)
        if nxt == init and nxt in states and re.fullmatch(r'\s*continue ' + L1 + r';\s*', states[nxt]):
            return 'revisit'
        t = states.get(nxt, default)
        if t is None:
            return 'nostate'
        try:
            code, nxt = step(t)
        except ValueError as e:
            return str(e)
        out.append(code)
    chunks = []
    for c in out:
        lines = c.strip('\n').split('\n')
        if not any(l.strip() for l in lines):
            continue
        k = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
        chunks.append('\n'.join((ind + l[k:]) if l.strip() else '' for l in lines))
    text = '\n'.join(chunks)
    # the declaration lines (int S / boolean flag) are replaced
    return (m.start(), oc + 1, text)


def analyse_simple(s, m):
    ind, S, init, _, L = m.group(1), m.group(2), int(m.group(3)), m.group(4), m.group(5)
    so = m.end() - 1
    sc = match(s, so, '{', '}')
    cases = parse_switch_body(s[so + 1:sc])
    if cases is None:
        return None
    wm = re.search(r'while \(true\) \{', s[m.start():m.end()])
    if not wm:
        return None
    w_start = m.start() + wm.end() - 1
    w_end = match(s, w_start, '{', '}')

    states = {}
    default = None
    for lab, t in cases:
        if lab == 'default':
            default = t
        else:
            states[int(lab.split()[1])] = t
    assign = re.compile(r'\b' + re.escape(S) + r' = (-?\d+);')
    L_label = L if L else 'block'

    def step(t):
        t2 = t.rstrip()
        t2 = re.sub(r'\n?[ \t]*break;\s*$', '', t2)
        t2 = re.sub(r'\n?[ \t]*continue(?: ' + re.escape(L_label) + r')?;\s*$', '', t2)
        am = list(assign.finditer(t2))
        if not am:
            if re.search(r'\b' + re.escape(S) + r'\b', t2):
                raise ValueError('complex')
            return t2, None
        if len(am) != 1 or t2[am[0].end():].strip():
            raise ValueError('nonlinear')
        code = t2[:am[0].start()].rstrip()
        if re.search(r'\b' + re.escape(S) + r'\b', code):
            raise ValueError('complex')
        return code, int(am[0][1])

    out = []
    nxt = init
    seen = set()
    while nxt is not None:
        if nxt in seen:
            return 'loop'
        seen.add(nxt)
        t = states.get(nxt, default)
        if t is None:
            return 'nostate'
        try:
            code, nxt = step(t)
        except ValueError as e:
            return str(e)
        out.append(code)
    chunks = []
    for c in out:
        lines = c.strip('\n').split('\n')
        if not any(l.strip() for l in lines):
            continue
        k = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
        chunks.append('\n'.join((ind + l[k:]) if l.strip() else '' for l in lines))
    text = '\n'.join(chunks)
    return (m.start(), w_end + 1, text)


def unflatten(s, stats):
    while True:
        done = False
        for m in SITE.finditer(s):
            r = analyse(s, m)
            if isinstance(r, tuple):
                st, en, text = r
                ind = m[1]
                # keep other declarations between S decl and flag decl
                decls = re.findall(r'(?m)^[ \t]*(?!int ' + re.escape(m[2]) + r' )(?!boolean ' + re.escape(m[5]) + r' )(\w[\w<>\[\]]* \w+(?: = [^;\n]*)?;)$', s[m.start():m.end()])
                head = ''.join(ind + d + '\n' for d in decls)
                # re-indent body lines relative to the loop-body depth (4 spaces deeper than ind+8)
                s = s[:st] + head + text.strip('\n') + s[en:]
                stats['unflattened'] += 1
                done = True
                break
            else:
                stats['unflatten_fail:' + str(r)] += 1
        if not done:
            for m in SIMPLE_SITE.finditer(s):
                r = analyse_simple(s, m)
                if isinstance(r, tuple):
                    st, en, text = r
                    ind = m[1]
                    decls = re.findall(r'(?m)^[ \t]*(?!int ' + re.escape(m[2]) + r' )(\w[\w<>\[\]]* \w+(?: = [^;\n]*)?;)$', s[m.start():m.end()])
                    head = ''.join(ind + d + '\n' for d in decls)
                    s = s[:st] + head + text.strip('\n') + s[en:]
                    stats['unflattened'] += 1
                    done = True
                    break
                else:
                    stats['unflatten_fail:' + str(r)] += 1
        if not done:
            return s
