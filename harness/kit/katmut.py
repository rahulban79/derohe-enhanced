#!/usr/bin/env python3
"""katmut.py — mutation independence for the stand-alone harness KATs (r27 tools-kats; dero-rft §0.9 rule 1).

A KAT file's mutation runner applies one mutation (it undoes one fix), re-runs EVERY KAT of the file and calls the
mutation 'proved' when any KAT fails. That hid two faults (R26 measurement, harness/kat/test_harness_tooling_r26.py):
  * coupling: HT12 called the real out-of-repo scrubber through the mutant's own ROOT, so EVERY tooling_intel mutation
    also failed HT12 ([HT8,HT12], [HT10,HT12]); had HT8 stopped testing --help, HT12 would still have 'proved' it;
  * a mutation caught only by ANOTHER defect's KAT proves nothing about the KAT that claims the defect.
So each mutation names its defect (the 'B<n>' that starts its reason, or an explicit owner) and the file maps every
defect to the KAT(s) that own it. classify() then says:
  proved     a KAT that owns the defect failed (other KATs may fail too: they are listed as coupled)
  MISSED     no KAT failed
  WRONG-KAT  only KATs of OTHER defects failed: the owning KAT does not test what it claims
and the summary line 'mutations proved P/N · mutations coupled C' is what tooling_intel reads (KAT_MUT_RX,
KAT_COUPLED_RX). A coupled mutation is a finding (target 0), not a failure of the defect's own proof.

  python3 harness/kit/katmut.py --help
r31 (B252d / B272): mutation scoping (top_defs, enclosing_def, Tracer, static_closure, scope): a mutation inside
top-level def F re-runs only the KATs that called F in a traced pristine run (plus declared subprocess reach); the
coupling check stays valid (see the section comment). KAT harness/kat/test_katmut_scope_r31.py.
r31 (B272-W1): file-level scope for KATs that run tools as subprocesses (canary_text, file_scope, canary_plan,
checked_reach, tree_manifest, Workspace): a declared per-KAT file reach, checked by a canary run, and one working
clone restored after every run. KAT harness/kat/test_katmut_scope_r31.py KS6-KS8.
Library only (no command): imported by harness/kat/test_*.py.
"""
import re

DEFECT_RX = re.compile(r'^\s*(B\d+[a-z]?|r\d+[a-z]?(?:\s+[\w-]+)?)\b')


def defect_of(why):
    """the defect id a mutation reason starts with: 'B98: ...' -> 'B98', 'B119 class: ...' -> 'B119', 'r27 TK3: ...'
    -> 'r27 TK3'; None when it names none. Pure."""
    m = DEFECT_RX.match(str(why or ''))
    return m.group(1) if m else None


def classify(failed, owners):
    """(verdict, coupled) for one mutation: `failed` = the KAT ids that failed under it, `owners` = the KAT ids that own
    its defect. Pure."""
    failed, owners = set(failed or ()), set(owners or ())
    if not failed:
        return 'MISSED', []
    if not owners or not failed & owners:
        return 'WRONG-KAT', sorted(failed)
    return 'proved', sorted(failed - owners)


def summary(label, n_kats, n_mut, missed, coupled):
    """the file's last line; 'mutations proved X/Y' and 'mutations coupled C' are parsed by tooling_intel. Pure."""
    return (f'{label}: {n_kats}/{n_kats} ok · mutations proved {n_mut - missed}/{n_mut} · mutations coupled {coupled}')


# ───────────────────────────── r31 (B252d / B272): mutation scoping ─────────────────────────────
# A KAT file re-ran EVERY KAT for every mutation: test_round_pause_r30 spent 31 x 13 KAT runs (481 s contended), most of
# them in KATs that never call the mutated function. Scope rule: a mutation whose find text lies inside top-level def F
# of file X re-runs only the KATs that CALLED F (any def of X reached from F's body counts as F: a nested function or a
# lambda maps to the top-level def that encloses it) in a traced pristine run, plus the KATs whose X-dependencies are
# declared unknown (None: always run) — and a mutation at module level re-runs every KAT. Why the coupling check stays
# valid: a KAT that never entered F executes the same code in the mutant until it first calls F, which it never does,
# so it cannot fail under the mutation; leaving it out changes neither the verdict nor the coupled count. Code reached
# in a SUBPROCESS is invisible to the tracer: the KAT file declares it (static_closure of the subprocess entry).
import ast as _ast
import sys as _sys


def top_defs(source):
    """[(name, first line, last line)] of the module's top-level functions and classes (decorators included). Pure."""
    out = []
    for n in _ast.parse(source).body:
        if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            first = min([n.lineno] + [d.lineno for d in n.decorator_list])
            out.append((n.name, first, n.end_lineno))
    return out


def def_at(defs, line):
    """the top-level def whose span holds `line`, else None (module level). Pure."""
    return next((nm for nm, a, b in defs if a <= line <= b), None)


def enclosing_def(source, find):
    """the top-level def that contains the FIRST character of `find` in `source` (None: module level, or not found). Pure."""
    i = source.find(find)
    if i < 0:
        return None
    return def_at(top_defs(source), source.count('\n', 0, i) + 1)


class Tracer:
    """with Tracer({key: path}) as t: ... -> t.called = {key: {top-level def names entered}}. A profile hook (calls
    only), restored on exit; files are matched by their resolved path."""

    def __init__(self, files):
        self.files = {str(_resolve(p)): k for k, p in files.items()}
        self.defs = {}
        for path, k in self.files.items():
            try:
                self.defs[path] = top_defs(open(path, encoding='utf-8').read())
            except (OSError, SyntaxError):
                self.defs[path] = []
        self.called = {k: set() for k in files}
        self._old = None
        self._real = {}

    def _hook(self, frame, ev, arg):
        if ev == 'call':
            fn = frame.f_code.co_filename
            path = self._real.get(fn)
            if path is None:
                path = self._real[fn] = str(_resolve(fn)) if fn and not fn.startswith('<') else ''
            k = self.files.get(path)
            if k is not None:
                nm = def_at(self.defs[path], frame.f_code.co_firstlineno)
                if nm:
                    self.called[k].add(nm)

    def __enter__(self):
        self._old = _sys.getprofile()
        _sys.setprofile(self._hook)
        return self

    def __exit__(self, *exc):
        _sys.setprofile(self._old)
        return False


def _resolve(p):
    from pathlib import Path as _P
    return _P(p).resolve()


def static_closure(source, entries):
    """the top-level defs reachable from `entries` by bare-name references inside their bodies (calls, callbacks).
    Pure; used for code a KAT runs in a subprocess, which the tracer cannot see."""
    defs = {n.name: n for n in _ast.parse(source).body if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef))}
    seen, todo = set(), [e for e in entries if e in defs]
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        for x in _ast.walk(defs[f]):
            if isinstance(x, _ast.Name) and x.id in defs and x.id not in seen:
                todo.append(x.id)
    return seen


def scope(kats, deps, key, fn):
    """the KATs to re-run for a mutation of file `key` inside top-level def `fn` (None = module level: all). `deps` =
    {kat: {file key: set of defs} | None}; a KAT with None deps, or no entry, always runs. Pure."""
    if fn is None:
        return list(kats)
    out = []
    for k in kats:
        d = deps.get(k)
        if d is None or d.get(key) is None or fn in d.get(key, set()):
            out.append(k)
    return out


# ───────────────────────────── r31 (B272-W1): clone once + file-level scope, declared reach checked by a canary ─────
# test_tools_kats_r28 (613 s quiet) and test_miners_r28 (496 s) clone the tree for every mutation and run their tools
# as SUBPROCESSES, which the Tracer cannot see. Rule: each KAT DECLARES its file reach ({kat: [repo-relative files it
# executes or reads]}, None = unknown: always run); a mutation of file X re-runs only the KATs whose reach names X.
# The declaration is CHECKED before any mutation by a canary run: for each KAT, every mutated file outside its declared
# reach is replaced by a stub that raises at import (and holds none of the file's text, so a KAT that reads the file as
# data fails too); a KAT that does not pass under its canary has a wrong declaration and falls back to full (None).
# Why the coupling check stays valid: a KAT that passes with X replaced by a stub that cannot run and carries no text
# neither executes X nor reads it, so the mutated X cannot change its result; leaving it out changes neither the verdict
# nor the coupled count. The run is checked against --no-scope verdict for verdict (rft §7 B272). The working clone is
# made once and restored after every run from a pristine copy (Workspace), instead of a fresh clone per mutation.
import os as _os
import shutil as _shutil
import subprocess as _subprocess

CANARY = "raise RuntimeError('katmut canary: {rel} lies outside the declared reach of the KAT that loaded it')\n"


def canary_text(rel):
    """the stub that replaces a file outside a KAT's declared reach: raises at import, none of the file's text. Pure."""
    return CANARY.format(rel=rel)


def file_scope(kats, reach, rel):
    """the KATs to re-run for a mutation of file `rel`: those whose declared reach names it, plus every KAT with an
    unknown reach (None, or no entry). Pure."""
    return [k for k in kats if (reach or {}).get(k) is None or rel in reach[k]]


def canary_plan(kats, reach, files):
    """{kat: [files to stub]}: for each KAT with a declared reach, the mutated files outside it (a KAT with an unknown
    reach, or none to stub, needs no canary). Pure."""
    out = {}
    for k in kats:
        r = (reach or {}).get(k)
        if r is None:
            continue
        stub = sorted(f for f in set(files) if f not in r)
        if stub:
            out[k] = stub
    return out


def checked_reach(reach, canary_ok):
    """the reach the run may use: a KAT whose canary did not pass (False, or never ran: missing) gets None (full).
    Pure."""
    return {k: (v if canary_ok.get(k) is True else None) for k, v in (reach or {}).items()}


def tree_manifest(root):
    """({rel file: (size, mtime_ns)}, {rel dir}) of a tree (no symlink is followed; __pycache__ is skipped)."""
    root = str(root)
    files, dirs = {}, set()
    for dp, dns, fns in _os.walk(root):
        dns[:] = [d for d in dns if d != '__pycache__']
        rd = _os.path.relpath(dp, root)
        if rd != '.':
            dirs.add(rd)
        for f in fns:
            full = _os.path.join(dp, f)
            st = _os.lstat(full)
            files[_os.path.normpath(_os.path.join(rd, f))] = (st.st_size, st.st_mtime_ns)
    return files, dirs


class Workspace:
    """ONE working clone `work` of a pristine copy `base`, restored after every run: a file that changed is copied
    back from base, a new file or directory is removed, a removed one is put back. `copy(src, dst)` makes the clone
    (default cp -cR, an APFS clone). w.write(rel, text) mutates; w.restore() -> number of paths it had to restore."""

    def __init__(self, base, work, copy=None):
        self.base, self.work = str(base), str(work)
        if copy is not False:                      # copy=False: `work` already exists and equals `base`
            (copy or _clone)(self.base, self.work)
        self.files, self.dirs = tree_manifest(self.work)

    @classmethod
    def from_work(cls, work, base):
        """adopt a working clone built in place (e.g. after a tool wrote absolute paths into it): its pristine copy is
        cloned to `base`, and every restore puts `work` back to that copy at the same path"""
        _clone(str(work), str(base))
        return cls(base, work, copy=False)

    def path(self, rel):
        return _os.path.join(self.work, rel)

    def write(self, rel, text):
        with open(self.path(rel), 'w', encoding='utf-8') as f:
            f.write(text)

    def restore(self):
        files, dirs = tree_manifest(self.work)
        n = 0
        for rel in sorted(set(files) - set(self.files)):
            _os.remove(self.path(rel))
            n += 1
        for rel in sorted(dirs - self.dirs, key=len, reverse=True):
            _shutil.rmtree(self.path(rel), ignore_errors=True)
            n += 1
        for rel in sorted(self.dirs - dirs, key=len):
            _os.makedirs(self.path(rel), exist_ok=True)
            n += 1
        for rel, st in self.files.items():
            if files.get(rel) != st:
                dst = self.path(rel)
                _os.makedirs(_os.path.dirname(dst), exist_ok=True)
                if _os.path.lexists(dst):
                    _os.remove(dst)
                _shutil.copy2(_os.path.join(self.base, rel), dst, follow_symlinks=False)
                st2 = _os.lstat(dst)
                self.files[rel] = (st2.st_size, st2.st_mtime_ns)
                n += 1
        for pc in [d for d in tree_pycache(self.work)]:
            _shutil.rmtree(pc, ignore_errors=True)
        return n


def tree_pycache(root):
    return sorted((_os.path.join(dp, d) for dp, dns, _ in _os.walk(root) for d in dns if d == '__pycache__'), reverse=True)


def _clone(src, dst):
    r = _subprocess.run(['cp', '-cR', str(src), str(dst)], capture_output=True, text=True)
    if r.returncode != 0:
        _shutil.copytree(src, dst, symlinks=True)


if __name__ == '__main__':
    import sys
    print(__doc__)                         # '--help', '-h' or nothing: the usage; a library has no other command
    sys.exit(0 if not sys.argv[1:] or {'-h', '--help'} & set(sys.argv[1:]) else 2)
