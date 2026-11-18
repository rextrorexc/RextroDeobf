"""Small lexical helper shared by the method engine (string / char / comment skipper)."""


def _skip(s, i):
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
    if s.startswith('/*', i):
        return s.index('*/', i + 2) + 2
    if s.startswith('//', i):
        j = s.find('\n', i)
        return len(s) if j < 0 else j
    return None
