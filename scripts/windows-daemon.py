"""Windowless Windows supervisor, launched by Task Scheduler using pythonw.exe."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import time


class BasicLimits(ctypes.Structure):
    _fields_ = [
        ('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
        ('flags', wintypes.DWORD), ('minimum_working_set', ctypes.c_size_t),
        ('maximum_working_set', ctypes.c_size_t), ('active_process_limit', wintypes.DWORD),
        ('affinity', ctypes.c_size_t), ('priority_class', wintypes.DWORD),
        ('scheduling_class', wintypes.DWORD),
    ]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes',
    )]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ('basic', BasicLimits), ('io', IoCounters),
        ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
        ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t),
    ]


class ProcessJob:
    """Kill the complete child process tree if this supervisor exits or crashes."""

    def __init__(self):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, pid: int):
        # PROCESS_SET_QUOTA | PROCESS_TERMINATE, required by job assignment.
        process = self.kernel.OpenProcess(0x0101, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel.CloseHandle(process)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def run(config_path: Path):
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    log_root = Path(config['LogRoot'])
    log_root.mkdir(parents=True, exist_ok=True)
    Path(config['OutputRoot']).mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger('tosub2-supervisor')
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_root / 'supervisor.log', maxBytes=5 * 1024 * 1024,
                                  backupCount=1, encoding='utf-8')
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
    logger.addHandler(handler)
    env = dict(os.environ, NODE_ENV='production', TOSUB2_PYTHON=config['PythonPath'],
               ONBOARDING_OUTPUT_ROOT=config['OutputRoot'], ONBOARDING_HOST=config['Host'])
    env['PATH'] = str(Path(config['NodePath']).parent) + os.pathsep + env.get('PATH', '')
    command = [config['NodePath'], 'src/console-server.mjs',
               '--host', config['Host'], '--port', str(config['Port'])]
    logger.info('Windowless supervisor started (PID %s).', os.getpid())
    while True:
        job = None
        child = None
        try:
            for name in ('console-out.log', 'console-error.log'):
                current = log_root / name
                if current.exists():
                    current.replace(log_root / (name + '.previous'))
            job = ProcessJob()
            with (log_root / 'console-out.log').open('wb') as stdout, \
                    (log_root / 'console-error.log').open('wb') as stderr:
                child = subprocess.Popen(
                    command, cwd=config['ProjectRoot'], env=env,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    # Unlike WindowStyle Hidden, no console is created at all.
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                job.assign(child.pid)
                logger.info('Started node PID %s on %s:%s without a console.',
                            child.pid, config['Host'], config['Port'])
                code = child.wait()
                logger.warning('Node PID %s exited with code %s; restarting in 5 seconds.',
                               child.pid, code)
        except Exception:
            logger.exception('Launch failed; retrying in 5 seconds.')
        finally:
            if job is not None:
                job.close()
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait()
        time.sleep(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    run(parser.parse_args().config)
