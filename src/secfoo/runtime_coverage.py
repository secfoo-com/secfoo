import json, sys
from pathlib import Path

def _watch(p):
    d = json.loads(Path(p).read_text()); items = d.get('symbols', d) if isinstance(d, dict) else d
    return [(x, None) if isinstance(x, str) else (x.get('symbol') or x.get('name'), x.get('file')) for x in items]

def _match(s, f, n, p):
    return (s == n or n.endswith('.' + s) or s.endswith('.' + n)) and (not f or f in p)

def _line(p, o):
    try: return Path(p).read_text().count('\n', 0, o) + 1
    except OSError: return 0

def _py(p, w):
    fs = json.loads(Path(p).read_text()).get('files', {})
    if not any('site-packages' in x or 'dist-packages' in x for x in fs):
        raise ValueError('coverage.py report has no dependency files; collect with --source or [run] include so site-packages are included')
    t = e = 0; r = []
    for p, i in fs.items():
        a = not any(x in p for x in ('site-packages', 'dist-packages', 'node_modules')); fn = i.get('functions', {})
        if a: t += len(fn); e += sum(1 for x in fn.values() if x.get('executed_lines'))
        for n, x in fn.items():
            if any(_match(s, f, n, p) for s, f in w) and x.get('executed_lines'): r.append((n, p, x['executed_lines'][0]))
    return t, e, r

def _node(p, w):
    t = e = 0; r = []
    for fp in Path(p).glob('*.json'):
        for s in json.loads(fp.read_text()).get('result', []):
            u = s.get('url', '')
            if not u.startswith('file://'): continue
            p = u[7:]; fn = s.get('functions', []); a = 'node_modules' not in p
            if a: t += len(fn); e += sum(1 for x in fn if any(y.get('count', 0) > 0 for y in x.get('ranges', [])))
            for x in fn:
                if any(_match(sym, f, x.get('functionName', ''), p) for sym, f in w) and any(y.get('count', 0) > 0 for y in x.get('ranges', [])):
                    r.append((x.get('functionName', ''), p, _line(p, x['ranges'][0]['startOffset'])))
    return t, e, r

def cli(argv):
    import argparse
    ap = argparse.ArgumentParser(prog='secfoo runtime import-coverage'); ap.add_argument('file'); ap.add_argument('--watchlist', required=True); ap.add_argument('-o', '--output', default='-')
    a = ap.parse_args(argv); w = _watch(a.watchlist)
    try: t, e, r = _node(a.file, w) if Path(a.file).is_dir() else _py(a.file, w)
    except Exception as ex: print(f'secfoo: {ex}', file=sys.stderr); return 1
    out = [json.dumps({'type': 'session', 'app_functions_total': t, 'app_functions_executed': e, 'entry_frame': None, 'stack_sample': None})]
    out += [json.dumps({'type': 'evidence', 'symbol': s, 'file': p, 'line': l, 'entry_frame': None, 'stack_sample': None}) for s, p, l in r]
    text = '\n'.join(out) + '\n'
    if a.output == '-': sys.stdout.write(text)
    else: Path(a.output).write_text(text)
    return 0
