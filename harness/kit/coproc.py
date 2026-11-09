#!/usr/bin/env python3
"""coproc.py — r29 (rft §5 long-job liveness, hang class 1): a line-oriented co-process that cannot pipe-deadlock.

B182 (2026-11-08, topo 150,600): the deep fetch wrote a whole batch to its decoder's stdin and only then read stdout;
once both exceeded the pipe buffers each side blocked writing to the other, for 35 minutes, while the progress file kept
refreshing. Here a feeder thread writes while the caller reads, and a reader thread turns stdout into a queue, so a
reply that does not arrive in time raises CoProcTimeout (and the co-process is stopped: its stream is out of step) and
a co-process that exits raises CoProcEOF — never a wait without end.

  cp = CoProc([binary]);  replies = cp.roundtrip(lines, n_replies, timeout=600);  cp.close()
Library only (no command).
"""
import queue, subprocess, threading, time


class CoProcEOF(RuntimeError):
    pass


class CoProcTimeout(RuntimeError):
    pass


class CoProc:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
        self.q, self.dead = queue.Queue(), False
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)                                   # EOF marker

    def _feed(self, lines, errs):
        try:
            for ln in lines:
                self.p.stdin.write(ln if ln.endswith('\n') else ln + '\n')
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError, OSError) as e:
            errs.append(e)                                 # the co-process died: the reader sees EOF and raises

    def roundtrip(self, lines, n, timeout=None):
        """write `lines` (feeder thread) and return the next `n` reply lines (stripped)."""
        if self.dead:
            raise CoProcEOF('co-process stopped earlier')
        errs = []
        w = threading.Thread(target=self._feed, args=(list(lines), errs), daemon=True)
        w.start()
        out, end = [], None if timeout is None else time.monotonic() + timeout
        while len(out) < n:
            left = None if end is None else max(0.0, end - time.monotonic())
            try:
                line = self.q.get(timeout=left)
            except queue.Empty:
                self.kill()
                raise CoProcTimeout(f'{len(out)}/{n} replies after {timeout:g} s') from None
            if line is None:
                self.dead = True
                raise CoProcEOF(f'co-process exited after {len(out)}/{n} replies (rc {self.p.poll()})')
            out.append(line.rstrip('\n'))
        w.join()
        return out

    def kill(self):
        self.dead = True
        try:
            self.p.kill()
        except OSError:
            pass

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:                                  # noqa: BLE001 — closing must not raise
            self.kill()
