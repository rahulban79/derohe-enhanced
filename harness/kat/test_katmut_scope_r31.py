#!/usr/bin/env python3
"""test_katmut_scope_r31.py — r31 (rft §7 B252d, B272): the katmut mutation-scoping rule (harness/kit/katmut.py
top_defs / enclosing_def / Tracer / static_closure / scope). A mutation inside top-level def F re-runs only the KATs
that entered F in a traced pristine run (plus declared subprocess reach); a module-level mutation re-runs all. The
coupling check stays valid because a KAT that never enters F runs identical code under the mutation.

  KS1 top_defs / enclosing_def: a find text in a function body, on its decorator or def line, in a nested function
      or lambda, and in a class method maps to its TOP-LEVEL def; a module-level constant and an absent text map to None
  KS2 Tracer: entering f (which calls a nested function and g) records {f, g}, not h; module-level code is not a def;
      a file loaded through a symlinked path (macOS /var -> /private/var) is still matched; the previous profile hook
      is restored on exit
  KS3 scope: a module-level mutation runs every KAT; a KAT with unknown deps (None, or no entry for the mutated file)
      always runs; otherwise only the KATs whose traced defs hold F
  KS4 static_closure: every def reachable by bare-name reference from the entries (transitively, callbacks included),
      no other
  KS5 end to end on a toy KAT file: for every toy mutation the scoped run gives the SAME verdict and coupled list as
      the full run, while running fewer KATs
  KS6 (B272-W1) file_scope / canary_plan / checked_reach / canary_text: scope by a declared file reach; per KAT the
      mutated files outside it are stubbed; a failed canary falls back to full; the stub raises and carries no text
  KS7 (B272-W1) Workspace: one clone; restore() undoes a changed, removed and new file and a new / removed directory
  KS8 (B272-W1) end to end on a toy KAT file running a tool as a SUBPROCESS: a correct declaration gives the full run's
      verdicts with fewer KAT runs; a wrong one fails its canary and falls back to full

  python3 -I harness/kat/test_katmut_scope_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, os, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'km': 'harness/kit/katmut.py'}

TOY = '''LIMIT = 3


def deco(f):
    return f


@deco
def f(x):
    def inner(y):
        return g(y) + 1
    return inner(x) + (lambda z: z)(0)


def g(y):
    return y * 2


def h(y):
    return y - LIMIT


class C:
    def m(self):
        return 7
'''


def load(over):
    path = Path(over.get('km') or (ROOT / PATHS['km']))
    spec = importlib.util.spec_from_file_location(f'km31_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def toy_mod(path, text=TOY):
    Path(path).write_text(text)
    spec = importlib.util.spec_from_file_location(f'toy_{uuid.uuid4().hex[:6]}', str(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_ks1(over):
    K = load(over)
    cases = {'return g(y) + 1': 'f', '@deco': 'f', 'def f(x):': 'f', '(lambda z: z)': 'f', 'return y * 2': 'g',
             'return 7': 'C', 'LIMIT = 3': None, 'not in the file': None, 'return y - LIMIT': 'h'}
    got = {k: K.enclosing_def(TOY, k) for k in cases}
    return got == cases, {k: v for k, v in got.items() if cases[k] != v}


def kat_ks2(over):
    K = load(over)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        real = Path(d).resolve()
        link = Path(d) / 'via'
        os.symlink(real, link)
        p = link / 'toy.py'                         # loaded through a symlink: co_filename is not the resolved path
        m = toy_mod(p)
        before = sys.getprofile()
        with K.Tracer({'toy': p}) as t:
            m.f(1)
        if sys.getprofile() is not before:
            bad.append('profile hook not restored')
        if t.called.get('toy') != {'f', 'g'}:
            bad.append(f"called {t.called}")
        with K.Tracer({'toy': real / 'toy.py'}) as t2:
            m.h(1)
        if t2.called.get('toy') != {'h'}:
            bad.append(f'resolved-path map {t2.called}')
    return not bad, '; '.join(bad) or 'f,g traced; symlink matched; hook restored'


def kat_ks3(over):
    K = load(over)
    kats = ['A', 'B', 'C', 'D']
    deps = {'A': {'x': {'f'}}, 'B': {'x': {'g'}}, 'C': None, 'D': {'y': {'f'}}}
    got = (K.scope(kats, deps, 'x', None), K.scope(kats, deps, 'x', 'f'), K.scope(kats, deps, 'x', 'g'), K.scope(kats, deps, 'y', 'f'))
    # D has no 'x' entry and A/B no 'y' entry: unknown for that file, so they always run for it
    want = (kats, ['A', 'C', 'D'], ['B', 'C', 'D'], kats)
    return got == want, got


def kat_ks4(over):
    K = load(over)
    src = 'def a():\n    return b()\n\ndef b():\n    return list(map(c, [1]))\n\ndef c(x):\n    return x\n\ndef d():\n    return a()\n'
    got = (K.static_closure(src, ['a']), K.static_closure(src, ['c']), K.static_closure(src, ['zz']))
    return got == ({'a', 'b', 'c'}, {'c'}, set()), got


def kat_ks5(over):
    K = load(over)
    toy_muts = [('return y * 2', 'return y * 3'), ('return y - LIMIT', 'return y'), ('LIMIT = 3', 'LIMIT = 4'),
                ('return inner(x) + (lambda z: z)(0)', 'return inner(x)'), ('return 7', 'return 8')]
    kats = {'K1': lambda m: m.f(1) == 3, 'K2': lambda m: m.h(5) == 2, 'K3': lambda m: m.f(2) == 5 and m.h(3) == 0,
            'K4': lambda m: m.C().m() == 7}
    owners = {0: ['K1'], 1: ['K2'], 2: ['K2'], 3: ['K1'], 4: ['K4']}
    bad, ran_scoped, ran_full = [], 0, 0
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'toy.py'
        trace = {}
        for name, fn in kats.items():
            m = toy_mod(p)
            assert fn(m), f'toy KAT {name} fails on the pristine toy'
            with K.Tracer({'toy': p}) as t:
                fn(m)
            trace[name] = t.called
        for i, (a, b) in enumerate(toy_muts):
            text = TOY.replace(a, b, 1)
            full = [n for n, fn in kats.items() if not fn(toy_mod(p, text))]
            only = K.scope(list(kats), trace, 'toy', K.enclosing_def(TOY, a))
            scoped = [n for n in only if not kats[n](toy_mod(p, text))]
            ran_full += len(kats)
            ran_scoped += len(only)
            if K.classify(full, owners[i]) != K.classify(scoped, owners[i]):
                bad.append(f'mutation {i}: full {K.classify(full, owners[i])} scoped {K.classify(scoped, owners[i])}')
    if ran_scoped >= ran_full:
        bad.append(f'no KAT skipped ({ran_scoped}/{ran_full})')
    return not bad, '; '.join(bad) or f'verdicts equal; KAT runs {ran_scoped}/{ran_full}'


def kat_ks6(over):
    """B272-W1: file_scope runs the KATs whose declared reach names the file, plus every KAT with an unknown reach;
    canary_plan stubs, per KAT, exactly the mutated files outside its reach; checked_reach drops a declaration whose
    canary did not pass (or never ran); canary_text raises at import and carries none of the file's text"""
    K = load(over)
    reach = {'A': ['x.py'], 'B': ['y.py', 'x.py'], 'C': None}
    bad = []
    if K.file_scope(['A', 'B', 'C', 'D'], reach, 'y.py') != ['B', 'C', 'D']:
        bad.append(f"file_scope y.py {K.file_scope(['A', 'B', 'C', 'D'], reach, 'y.py')}")
    if K.file_scope(['A', 'B', 'C'], reach, 'x.py') != ['A', 'B', 'C']:
        bad.append('file_scope x.py')
    plan = K.canary_plan(['A', 'B', 'C'], reach, ['x.py', 'y.py', 'z.py'])
    if plan != {'A': ['y.py', 'z.py'], 'B': ['z.py']}:
        bad.append(f'canary_plan {plan}')
    cr = K.checked_reach(reach, {'A': True, 'B': False})
    if cr != {'A': ['x.py'], 'B': None, 'C': None}:
        bad.append(f'checked_reach {cr}')
    t = K.canary_text('harness/kit/x.py')
    try:
        exec(compile(t, 'stub', 'exec'), {})
        bad.append('the canary stub does not raise')
    except RuntimeError:
        pass
    if 'def ' in t or 'import' in t:
        bad.append('the canary stub carries code')
    return not bad, '; '.join(bad) or 'scope by declared reach; canary plan; failed canary falls back to full'


def kat_ks7(over):
    """B272-W1: Workspace makes one clone and restore() puts it back to the pristine copy: a changed, a removed, a new
    file and a new directory are each undone (bytes equal the base again), and a clean tree needs no restore"""
    K = load(over)
    with tempfile.TemporaryDirectory() as d:
        base = Path(d) / 'base'
        (base / 'harness/kit').mkdir(parents=True)
        (base / 'harness/kit/a.py').write_text('A = 1\n')
        (base / 'harness/b.txt').write_text('bee\n')
        (base / 'home').mkdir()
        W = K.Workspace(base, Path(d) / 'w')
        w = Path(W.work)
        if W.restore() != 0:
            return False, 'a pristine clone needed a restore'
        W.write('harness/kit/a.py', 'A = 2\n')
        (w / 'harness/b.txt').unlink()
        (w / 'home/new.log').write_text('x')
        (w / 'harness/kit/new.py').write_text('NEW = 1\n')       # a new file in a directory of the base
        (w / 'tmp/deep').mkdir(parents=True)
        (w / 'tmp/deep/f').write_text('y')
        shutil_rm = __import__('shutil').rmtree
        shutil_rm(w / 'home')
        n = W.restore()
        got = {str(p.relative_to(w)): p.read_bytes() for p in w.rglob('*') if p.is_file()}
        want = {str(p.relative_to(base)): p.read_bytes() for p in base.rglob('*') if p.is_file()}
        dirs_ok = (w / 'home').is_dir() and not (w / 'tmp').exists()
        ok = got == want and dirs_ok and n >= 4 and W.restore() == 0
        return ok, (n, sorted(got), dirs_ok)


TOOL = 'import sys\nprint(int(sys.argv[1]) * 2)\n'


def kat_ks8(over):
    """B272-W1 end to end on a toy KAT file whose KATs run a tool as a SUBPROCESS (invisible to the Tracer) and read a
    data file: with a correct declaration every scoped verdict equals the full run's while fewer KATs run; a wrong
    declaration (a KAT that runs the tool declares only the data file) fails its canary and falls back to full"""
    import subprocess
    K = load(over)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        base = Path(d) / 'base'
        base.mkdir()
        (base / 'tool.py').write_text(TOOL)
        (base / 'data.txt').write_text('7\n')
        W = K.Workspace(base, Path(d) / 'w')
        w = Path(W.work)
        run = lambda: subprocess.run([sys.executable, '-I', str(w / 'tool.py'), '3'], capture_output=True, text=True).stdout.strip()
        kats = {'T1': lambda: run() == '6', 'T2': lambda: (w / 'data.txt').read_text().strip() == '7',
                'T3': lambda: run() == '6' and (w / 'data.txt').read_text().strip() == '7'}
        muts = [('tool.py', '* 2', '* 3', ['T1']), ('data.txt', '7', '8', ['T2'])]

        def runk(names):
            out = []
            for k in names:
                try:
                    out.append((k, bool(kats[k]())))
                except Exception:                                  # noqa: BLE001
                    out.append((k, False))
            return out

        def session(reach):
            files = sorted({m[0] for m in muts})
            ok = {}
            for k, stub in K.canary_plan(list(kats), reach, files).items():
                for f in stub:
                    W.write(f, K.canary_text(f))
                ok[k] = all(o for _, o in runk([k]))
                W.restore()
            ok.update({k: True for k in reach if k not in ok})
            cr = K.checked_reach(reach, ok)
            verdicts, ran = [], 0
            for f, a, b, owners in muts:
                sel = K.file_scope(list(kats), cr, f)
                W.write(f, (base / f).read_text().replace(a, b, 1))
                failed = [k for k, o in runk(sel) if not o]
                W.restore()
                ran += len(sel)
                verdicts.append(K.classify(failed, owners))
            return verdicts, ran, cr

        full, ran_full, _ = session({})
        good, ran_good, _ = session({'T1': ['tool.py'], 'T2': ['data.txt'], 'T3': ['tool.py', 'data.txt']})
        wrong, ran_wrong, crw = session({'T1': ['data.txt'], 'T2': ['data.txt'], 'T3': ['tool.py', 'data.txt']})
        if good != full or not ran_good < ran_full:
            bad.append(f'correct declaration: {good} vs full {full} ({ran_good}/{ran_full} runs)')
        if crw.get('T1') is not None or wrong != full:
            bad.append(f'wrong declaration not caught by the canary: {crw} {wrong} vs {full}')
    return not bad, '; '.join(bad) or f'verdicts equal; KAT runs {ran_good}/{ran_full}; a wrong declaration falls back'


KATS = [('KS1', kat_ks1), ('KS2', kat_ks2), ('KS3', kat_ks3), ('KS4', kat_ks4), ('KS5', kat_ks5),
        ('KS6', kat_ks6), ('KS7', kat_ks7), ('KS8', kat_ks8)]
# KS5 is the end-to-end proof (it uses every helper); def_at is shared by enclosing_def and the Tracer
OWNERS = {'B252d where': ['KS1', 'KS2', 'KS5'], 'B252d trace': ['KS2', 'KS5'], 'B252d scope': ['KS3', 'KS5'], 'B252d closure': ['KS4'],
          # r31 B272-W1: KS8 is the end-to-end proof of the file-level helpers (it uses each of them)
          'B272 file-scope': ['KS6', 'KS8'], 'B272 canary': ['KS6', 'KS8'], 'B272 workspace': ['KS7', 'KS8']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('km', "    return next((nm for nm, a, b in defs if a <= line <= b), None)", "    return next((nm for nm, a, b in defs if a < line <= b), None)",
     'B252d where: a find on the def line is module level'),
    ('km', "            first = min([n.lineno] + [d.lineno for d in n.decorator_list])", "            first = n.lineno",
     'B252d where: a decorator is module level'),
    ('km', "    return def_at(top_defs(source), source.count('\\n', 0, i) + 1)", "    return def_at(top_defs(source), source.count('\\n', 0, i))",
     'B252d where: the line is off by one'),
    ('km', "                nm = def_at(self.defs[path], frame.f_code.co_firstlineno)", "                nm = frame.f_code.co_name",
     'B252d trace: a nested function is recorded by its own name'),
    ('km', "                path = self._real[fn] = str(_resolve(fn)) if fn and not fn.startswith('<') else ''",
     "                path = self._real[fn] = fn", 'B252d trace: a symlinked path is not matched'),
    ('km', "        _sys.setprofile(self._old)", "        pass", 'B252d trace: the profile hook is left installed'),
    ('km', "    if fn is None:\n        return list(kats)", "    if fn is None:\n        return []", 'B252d scope: a module-level mutation runs no KAT'),
    ('km', "        if d is None or d.get(key) is None or fn in d.get(key, set()):", "        if d is not None and fn in d.get(key, set()):",
     'B252d scope: a KAT with unknown deps is skipped'),
    ('km', "            if isinstance(x, _ast.Name) and x.id in defs and x.id not in seen:\n                todo.append(x.id)",
     "            pass", 'B252d closure: not transitive'),
    # r31 B272-W1
    ('km', "    return [k for k in kats if (reach or {}).get(k) is None or rel in reach[k]]", "    return [k for k in kats if (reach or {}).get(k) is not None and rel in reach[k]]",
     'B272 file-scope: a KAT with an unknown reach is skipped'),
    ('km', "        stub = sorted(f for f in set(files) if f not in r)", "        stub = []", 'B272 canary: nothing is stubbed (every declaration passes)'),
    ('km', "    return {k: (v if canary_ok.get(k) is True else None) for k, v in (reach or {}).items()}", "    return dict(reach or {})",
     'B272 canary: a failed canary keeps its wrong declaration'),
    ('km', "CANARY = \"raise RuntimeError('katmut canary: {rel} lies outside the declared reach of the KAT that loaded it')\\n\"",
     "CANARY = \"# katmut canary: {rel}\\n\"", 'B272 canary: the stub does not raise'),
    ('km', "            if files.get(rel) != st:", "            if rel not in files:", 'B272 workspace: a changed file is not restored'),
    ('km', "        for rel in sorted(set(files) - set(self.files)):\n            _os.remove(self.path(rel))\n            n += 1\n", "",
     'B272 workspace: a new file survives the restore'),
    ('km', "        for rel in sorted(self.dirs - dirs, key=len):\n            _os.makedirs(self.path(rel), exist_ok=True)\n            n += 1\n", "",
     'B272 workspace: a removed directory is not put back'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ks31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        finally:
            sys.setprofile(None)                                  # a mutant Tracer may leave its hook
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 katmut-scope KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ks31-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID   {why}: mutant does not load ({e})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 katmut-scope KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
