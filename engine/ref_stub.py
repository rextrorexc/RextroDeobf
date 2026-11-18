"""Generic helpers that methods.py expects from a reference module (no reference build is used here)."""

VOWELS = set('aeiouAEIOU')


def junk_method(m):
    """heuristic: byte[] key/table accessors, xor helpers and consonant-only long names are obfuscator filler"""
    if m.ret == 'byte[]' and not m.params:
        return True
    if 'byte[]' in m.params:
        return True
    if m.static and m.ret == 'int' and m.params == ['int', 'int']:
        return True
    n = m.name
    if n.islower() and len(n) >= 9:
        v = sum(1 for ch in n if ch in VOWELS)
        if v / len(n) < 0.25:
            return True
    return False
