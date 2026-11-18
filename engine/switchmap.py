"""Restore enum switches.

javac compiles `switch (enumValue)` into `switch (Holder.$SwitchMap$pkg$Enum[enumValue.ordinal()])` with a synthetic
holder class; the decompiler leaves that form behind. The number -> constant table is read from the holder's
static initialiser (javap -c) and the switch is rewritten back to `switch (enumValue) { case CONSTANT: ... }`.
"""
import os
import re
import subprocess
import zipfile

from deobf import match

PKG = ''   # any application package


def build(jar, workdir):
    """returns {'$SwitchMap$...': {number: 'CONSTANT'}}"""
    os.makedirs(workdir, exist_ok=True)
    with zipfile.ZipFile(jar) as z:
        names = [n for n in z.namelist()
                 if n.startswith(PKG) and '$' in n and '/libs/' not in n and n.endswith('.class')]
        outs = []
        for n in names:
            data = z.read(n)
            if b'$SwitchMap$' not in data:
                continue
            p = os.path.join(workdir, n.replace('/', '_'))
            open(p, 'wb').write(data)
            outs.append(p)
    table = {}
    for p in outs:
        txt = subprocess.run(['javap', '-c', '-p', p], capture_output=True, text=True, encoding='utf-8',
                             errors='replace').stdout
        field = const = None
        ldcs = []
        for line in txt.splitlines():
            m = re.search(r'getstatic\s+#\d+\s+// Field (\$SwitchMap\$[\w$]+):\[I', line)
            if m:
                field = m[1]
                ldcs = []
                continue
            m = re.search(r'getstatic\s+#\d+\s+// Field [\w/$]+\.(\w+):L', line)
            if m and field:
                const = m[1]
                ldcs = []
                continue
            m = re.search(r'ldc\s+#\d+\s+// int (-?\d+)', line)
            if m:
                ldcs.append(int(m[1]))
                continue
            n = None
            if 'uqCIFUEP' in line and len(ldcs) >= 4:
                e, first, second, rot = ldcs[-4:]
                x = (e ^ second) & 0xFFFFFFFF
                rot &= 31
                x = ((x >> rot) | (x << (32 - rot))) & 0xFFFFFFFF
                n = (x ^ first) & 0xFFFFFFFF
                n = n - (1 << 32) if n & 0x80000000 else n
            else:
                m = re.search(r'(?:iconst_(\d)|bipush\s+(\d+)|sipush\s+(\d+))\s*$', line.strip())
                if m:
                    n = int(next(g for g in m.groups() if g is not None))
            if n is not None and field and const:
                table.setdefault(field, {})[n] = const
                const = None
    return table


SWITCH = re.compile(r'switch \((?:[\w.]+\.)?(\$SwitchMap\$[\w$]+)\[(.+?)\.ordinal\(\)\]\) \{')


def apply(text, table):
    pos = 0
    while True:
        m = SWITCH.search(text, pos)
        if not m:
            return text
        field = m[1]
        pos = m.end()
        tab = table.get(field)
        if not tab:
            continue
        bo = m.end() - 1
        try:
            bc = match(text, bo, '{', '}')
        except Exception:
            continue
        body = text[bo:bc + 1]

        def lab(cm):
            n = int(cm[1])
            return 'case %s:' % tab[n] if n in tab else cm[0]
        body = re.sub(r'(?<![\w.])case (\d+):', lab, body)
        head = 'switch (%s) {' % m[2]
        text = text[:m.start()] + head + body[1:] + text[bc + 1:]
        pos = m.start() + len(head)
