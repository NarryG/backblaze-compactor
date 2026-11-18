"""Observe transient writer-process starts during one snapshot capture.

The observer is a temporary WMI ``Win32_ProcessStartTrace`` subscription created
before the caller records writer state or a VSS shadow copy. It records only
process name and PID; no service, process, audit-policy, registry or live
Backblaze state is changed. The observer must run in an elevated administrator
process because ``Win32_ProcessStartTrace`` requires it; a non-elevated start
raises instead of returning an empty result.

``WriterWatch.start()`` returns only after ``watch_writers.ps1`` reports READY,
so the caller can capture its first writer state immediately afterwards.
``WriterWatch.stop()`` sends the stop command, waits for the drained summary and
always cleans up the child process. The result is a finite dict::

    {'complete': True, 'drained': True, 'started': ['bztransmit.exe:1234']}

``complete`` requires observed queue quiescence after the stop request; this
does not guarantee against WMI provider loss or indefinitely delayed delivery.
It is False (with an ``error`` string) when the subscription could not
start, observation or draining failed, or the child did not stop; it is never an empty
pass. Default names cover every installed Backblaze component, including the
installer, restore, downloader, CLI and UI processes that can trigger a
migration or configuration change. ``names`` overrides the watched basenames
for a benign smoke probe.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from pathlib import Path

DEFAULT_NAMES = (
    'bzserv.exe', 'bztransmit.exe', 'bzfilelist.exe', 'bzfclean.exe',
    'bzdoinstall.exe', 'bzrestore.exe', 'bzdownloader.exe', 'bzcli.exe',
    'bzbui.exe', 'bzbuitray.exe',
)
SCRIPT = Path(__file__).resolve().with_name('watch_writers.ps1')
_INVALID_NAME_CHARS = set('\\/:*?"<>|,')


class WriterWatch:
    """Temporary WMI process-start observer with an explicit start/stop protocol."""

    def __init__(self, names=None, *, grace_seconds=0.75, ready_timeout=30.0,
                 shutdown_timeout=None):
        if names is None:
            selected = DEFAULT_NAMES
        elif isinstance(names, str):
            selected = (names,)
        else:
            selected = tuple(names)
        cleaned = []
        for name in selected:
            value = str(name).strip()
            if (not value or any(character in _INVALID_NAME_CHARS or ord(character) < 32
                                 for character in value)):
                raise ValueError(f'not a process basename: {name!r}')
            if all(value.lower() != existing.lower() for existing in cleaned):
                cleaned.append(value)
        if not cleaned:
            raise ValueError('at least one process name is required')
        self.names = tuple(cleaned)
        self.grace_seconds = max(0.0, float(grace_seconds))
        self.ready_timeout = max(1.0, float(ready_timeout))
        self.shutdown_timeout = max(1.0, float(
            shutdown_timeout if shutdown_timeout is not None else self.grace_seconds + 15.0))
        self._process = None
        self._stdout = queue.Queue()
        self._stderr = []
        self._stderr_lock = threading.Lock()
        self._threads = []
        self._result = None
        self._start_error = None

    def start(self):
        """Spawn the observer and wait for READY; raise on any startup failure."""
        if self._process is not None or self._start_error is not None or self._result is not None:
            raise RuntimeError('writer watch is single-use')
        if not SCRIPT.is_file():
            raise RuntimeError(f'watch script is missing: {SCRIPT}')
        ready_ms = min(120000, max(1000, int((self.ready_timeout - 5.0) * 1000)))
        environment = dict(os.environ)
        environment['BZCOMPACTOR_WATCH_NAMES'] = ','.join(self.names)
        command = [
            'powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', str(SCRIPT),
            '-GraceMilliseconds', str(min(60000, max(0, int(self.grace_seconds * 1000)))),
            '-ReadyTimeoutMilliseconds', str(ready_ms),
        ]
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace', bufsize=1, env=environment)
        except OSError as error:
            raise RuntimeError(f'could not start writer watch: {error}') from error
        self._process = process
        reader = threading.Thread(target=self._pump_stdout, args=(process.stdout,), daemon=True)
        drainer = threading.Thread(target=self._pump_stderr, args=(process.stderr,), daemon=True)
        self._threads = [reader, drainer]
        for thread in self._threads:
            thread.start()
        try:
            line = self._stdout.get(timeout=self.ready_timeout)
        except queue.Empty:
            self._fail('writer watch did not report readiness in time')
        if line is None:
            self._fail(f'writer watch exited before readiness (exit={process.poll()})')
        line = line.strip().lstrip('\ufeff')
        if line == 'READY':
            return self
        self._fail(self._startup_detail(line))

    def stop(self):
        """Stop observation and return completion, drain status, and observed starts."""
        if self._result is not None:
            return self._result_copy()
        process = self._process
        if process is None:
            self._result = {'complete': False, 'drained': False, 'started': [],
                            'error': self._start_error or 'writer watch was not started'}
            return self._result_copy()

        if process.poll() is None:
            try:
                process.stdin.write('STOP\n')
                process.stdin.flush()
            except (OSError, ValueError):
                pass

        try:
            line = self._stdout.get(timeout=self.shutdown_timeout)
        except queue.Empty:
            self._terminate()
            self._result = {'complete': False, 'drained': False, 'started': [],
                            'error': 'writer watch did not stop in time'}
            return self._result_copy()

        payload = None
        summary_error = None
        if line is None:
            summary_error = f'writer watch exited without a summary (exit={process.poll()})'
        else:
            try:
                payload = json.loads(line.strip().lstrip('\ufeff'))
            except (TypeError, ValueError):
                summary_error = 'writer watch returned malformed output'
            else:
                if not isinstance(payload, dict):
                    payload = None
                    summary_error = 'writer watch returned malformed output'

        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._terminate()
                summary_error = 'writer watch did not exit after its summary'
        self._join_threads()
        self._close_streams()

        result = {'complete': False, 'drained': False, 'started': []}
        if payload is not None:
            result['drained'] = payload.get('drained') is True
            started = payload.get('started')
            if isinstance(started, list) and all(isinstance(item, str) for item in started):
                result['started'] = list(started)
            else:
                summary_error = summary_error or 'writer watch returned an invalid process list'
            error_text = payload.get('error')
            if error_text:
                result['complete'] = False
                result['error'] = str(error_text)
            elif payload.get('complete') is True and result['drained'] and summary_error is None:
                result['complete'] = True
            elif summary_error is None:
                result['error'] = 'writer watch did not report a complete drain'
        if summary_error is not None:
            result['complete'] = False
            if 'error' not in result:
                result['error'] = summary_error
        if self._start_error:
            result['complete'] = False
            result['error'] = self._start_error
        self._result = result
        return self._result_copy()

    def _result_copy(self):
        result = dict(self._result)
        result['started'] = list(result.get('started', []))
        return result

    def __enter__(self):
        return self.start()

    def __exit__(self, exception_type, exception, traceback):
        try:
            self.stop()
        except Exception:
            pass
        return False

    def _startup_detail(self, line):
        try:
            payload = json.loads(line.lstrip('\ufeff'))
        except (TypeError, ValueError):
            payload = None
        if isinstance(payload, dict) and payload.get('error'):
            return f"writer watch failed: {payload['error']}"
        detail = f'writer watch did not become ready (exit={self._process.poll()})'
        tail = self._stderr_text()
        return f'{detail}: {tail}' if tail else detail

    def _fail(self, message):
        tail = self._stderr_text()
        self._start_error = f'{message}: {tail}' if tail else message
        self._terminate()
        raise RuntimeError(self._start_error)

    def _pump_stdout(self, stream):
        try:
            for line in stream:
                self._stdout.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._stdout.put(None)

    def _pump_stderr(self, stream):
        try:
            for line in stream:
                with self._stderr_lock:
                    self._stderr.append(line.rstrip())
                    del self._stderr[:-20]
        except (OSError, ValueError):
            pass

    def _stderr_text(self):
        with self._stderr_lock:
            tail = ' | '.join(self._stderr[-5:])
        return tail[:1000]

    def _close_streams(self):
        process = self._process
        if process is None:
            return
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

    def _join_threads(self):
        for thread in self._threads:
            thread.join(timeout=5)

    def _terminate(self):
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self._join_threads()
        self._close_streams()
