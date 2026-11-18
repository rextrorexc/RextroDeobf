"""jar içinde FurryHook izi var mı? (fabric.mod.json id/paket adı) -> {"furry": bool}"""
import json
import sys
import zipfile

try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        names = z.namelist()
        hit = any(n.startswith('com/furryhook') for n in names)
        if not hit and 'fabric.mod.json' in names:
            try:
                hit = 'furryhook' in z.read('fabric.mod.json').decode('utf-8', 'replace').lower()
            except Exception:
                pass
        if not hit:
            for n in names:
                if n.endswith('.mixins.json') and 'furryhook' in n.lower():
                    hit = True
                    break
    print(json.dumps({'furry': bool(hit)}))
except Exception:
    print(json.dumps({'furry': False}))
