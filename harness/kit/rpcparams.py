#!/usr/bin/env python3
"""rpcparams.py — every JSON-RPC call the harness sends to derod, checked against the Go handler's json tags (r26, dero-rft
§7 B104 tooling half).

B104 (R25 measurement, own probe ~07:14): a GetBlockHeadersRange sent with `start`/`end` instead of the handler's
`start_topoheight`/`end_topoheight` json tags decoded both as 0 (Go's json ignores unknown keys), read topoheight 0 below
the prune point and answered -32098; derod logged nothing. A probe must take its param names from the Go json tags.

What is read (all static, no RPC is sent):
  Go     cmd/derod/rpc/websocket_server.go `servicemux` "DERO" map: method name -> handler func; the handler's
         `func F(ctx context.Context, p [rpc.]T)` in cmd/derod/rpc/*.go (no `p` = the method takes no params); struct T's
         `json:"..."` tags in rpc/*.go or cmd/derod/rpc/*.go (non-test files).
  Python every call in harness/**/*.py and tools/**/*.py with a literal 'DERO.<Method>' argument followed by a literal
         dict of params, every tuple/list literal ('DERO.<Method>', {...}) and every dict literal
         {'method': 'DERO.<Method>', 'params': {...}}. Params built at run time are not literal and not checked (the
         count of literal calls is printed, so a shrinking coverage is visible).

A problem is: an unknown method; a param key that is not one of the handler's json tags (exact spelling); params sent to a
method that takes none.

  python3 -I harness/kit/rpcparams.py [--root DIR]     # exit 0 = every call matches · 4 = a problem (listed)
"""
import argparse, ast, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCAN = ('harness', 'tools')
SKIP_PARTS = {'__pycache__', 'vendor', 'node_modules'}

MAP_RX = re.compile(r'"(\w+)":\s*(?:handler\.New|typed_new)\((\w+)\)')  # r27: typed_new wraps handler.New (B132)
FUNC_RX = re.compile(r'^func (\w+)\(ctx context\.Context(?:, \w+ (\[\]\w+|(?:rpc\.)?\w+))?\)', re.M)
ALIAS_RX = re.compile(r'^type (\w+) (?:rpc\.)?(\w+)\s*(?://.*)?$', re.M)   # type GasEstimate_Params Transfer_Params
STRUCT_RX = re.compile(r'^\s*(?:type\s+)?(\w+)\s+struct\s*\{', re.M)
TAG_RX = re.compile(r'`json:"([^",]*)')


POSITIONAL = 'positional'     # a handler taking a slice (Echo): a params LIST, never an object


def go_methods(root):
    """{'DERO.<Name>': handler func name} from the servicemux "DERO" block. Pure on the file."""
    t = (Path(root) / 'cmd/derod/rpc/websocket_server.go').read_text(encoding='utf-8')
    i = t.index('var servicemux')
    j = t.index('"DERO": handler.Map{', i)
    k = t.index('},', j)
    return {f'DERO.{m}': f for m, f in MAP_RX.findall(t[j:k])}


def go_sources(root):
    out = []
    for d in ('rpc', 'cmd/derod/rpc'):
        out += [p for p in sorted((Path(root) / d).glob('*.go')) if not p.name.endswith('_test.go')]
    return out


def struct_tags(text):
    """{struct name: [json tags]} of the struct literals in one Go file (a nested `struct {` field is skipped). Pure."""
    out = {}
    for m in STRUCT_RX.finditer(text):
        depth, i, tags = 1, m.end(), []
        line_start = i
        while i < len(text) and depth:
            c = text[i]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
            elif c == '\n':
                line = text[line_start:i]
                if depth == 1:
                    tm = TAG_RX.search(line)
                    if tm and tm.group(1) not in ('', '-'):
                        tags.append(tm.group(1))
                line_start = i + 1
            i += 1
        if depth == 0:                       # the closing line ('Field T `json:"x"` }' on one line)
            tm = TAG_RX.search(text[line_start:i])
            if tm and tm.group(1) not in ('', '-') and tm.group(1) not in tags:
                tags.append(tm.group(1))
        out.setdefault(m.group(1), tags)
    return out


def go_params(root):
    """{'DERO.<Name>': sorted json tags, or None when the handler takes no params}. Methods whose param struct is not
    found map to the string '?<Type>' (reported as a problem by check())."""
    funcs, structs, alias = {}, {}, {}
    for p in go_sources(root):
        t = p.read_text(encoding='utf-8', errors='replace')
        for f, typ in FUNC_RX.findall(t):
            funcs.setdefault(f, typ.removeprefix('rpc.') if typ else None)
        for k, v in struct_tags(t).items():
            structs.setdefault(k, v)
        for k, v in ALIAS_RX.findall(t):
            alias.setdefault(k, v)
    out = {}
    for meth, f in go_methods(root).items():
        typ = funcs.get(f, '?')
        for _ in range(4):                   # type A B: A has B's fields
            if typ in alias and typ not in structs:
                typ = alias[typ]
        if typ is None:
            out[meth] = None
        elif typ.startswith('[]'):
            out[meth] = POSITIONAL
        elif typ in structs:
            out[meth] = sorted(structs[typ])
        else:
            out[meth] = f'?{typ}'
    return out


def _const(n):
    return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None


def _keys(d):
    """the literal string keys of a dict literal, or None when one is not a literal (a ** spread, a variable key)"""
    ks = [_const(k) if k is not None else None for k in d.keys]
    return None if any(k is None for k in ks) else ks


def calls_in(src, name='<src>'):
    """[(line, method, keys)] of the RPC calls in one Python source. Pure."""
    out = []
    try:
        tree = ast.parse(src, filename=name)
    except SyntaxError:
        return out
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            args = list(n.args) + [k.value for k in n.keywords]
            for i, a in enumerate(args):
                m = _const(a)
                if m and re.fullmatch(r'DERO\.\w+', m):
                    rest = [x for x in args[i + 1:] if isinstance(x, ast.Dict)]
                    if rest:
                        ks = _keys(rest[0])
                        if ks is not None:
                            out.append((n.lineno, m, ks))
                    break
        elif isinstance(n, (ast.Tuple, ast.List)):        # a probe table: ('DERO.X', {...})
            for i, a in enumerate(n.elts[:-1]):
                m = _const(a)
                if m and re.fullmatch(r'DERO\.\w+', m) and isinstance(n.elts[i + 1], ast.Dict):
                    ks = _keys(n.elts[i + 1])
                    if ks is not None:
                        out.append((n.lineno, m, ks))
        elif isinstance(n, ast.Dict):
            ks = _keys(n)
            if ks and 'method' in ks and 'params' in ks:
                m = _const(n.values[ks.index('method')])
                pv = n.values[ks.index('params')]
                if m and re.fullmatch(r'DERO\.\w+', m) and isinstance(pv, ast.Dict):
                    pk = _keys(pv)
                    if pk is not None:
                        out.append((n.lineno, m, pk))
    return out


def harness_calls(root):
    out = []
    for d in SCAN:
        for p in sorted((Path(root) / d).rglob('*.py')):
            if SKIP_PARTS & set(p.parts):
                continue
            rel = str(p.relative_to(root))
            out += [(rel, ln, m, ks) for ln, m, ks in calls_in(p.read_text(encoding='utf-8', errors='replace'), rel)]
    return out


def check(calls, params):
    """[problem strings] for (file, line, method, keys) calls against {method: tags | None | '?T'}. Pure."""
    bad = []
    for f, ln, m, ks in calls:
        where = f'{f}:{ln} {m}'
        if m not in params:
            bad.append(f'{where}: unknown method (not in the servicemux DERO map)')
            continue
        tags = params[m]
        if tags == POSITIONAL:
            if ks:
                bad.append(f'{where}: sends an object {sorted(ks)} but the handler takes a positional list')
            continue
        if isinstance(tags, str):
            bad.append(f'{where}: param struct {tags[1:]} not found in rpc/ or cmd/derod/rpc/')
            continue
        if tags is None:
            if ks:
                bad.append(f'{where}: sends {sorted(ks)} but the handler takes no params')
            continue
        unknown = [k for k in ks if k not in tags]
        if unknown:
            bad.append(f'{where}: {unknown} not among the json tags {tags} (Go ignores an unknown key: it decodes as 0)')
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description='check every harness RPC call against the derod handlers\' json tags (B104)')
    ap.add_argument('--root', default=str(ROOT))
    a = ap.parse_args(argv)
    root = Path(a.root)
    params, calls = go_params(root), harness_calls(root)
    bad = check(calls, params)
    for b in bad:
        print('PROBLEM', b)
    print(f'rpcparams: {len(calls)} literal RPC calls in {", ".join(SCAN)} against {len(params)} DERO methods · '
          f'{len(bad)} problem(s)')
    return 4 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
