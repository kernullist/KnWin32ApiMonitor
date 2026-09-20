"""Run build commands in an owned Windows job with bounded output and lifetime."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


class BasicLimits(c.Structure):
    _fields_ = [("processTime", c.c_longlong), ("jobTime", c.c_longlong), ("flags", w.DWORD),
                ("minWorkingSet", c.c_size_t), ("maxWorkingSet", c.c_size_t), ("activeLimit", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class ExtendedLimits(c.Structure):
    _fields_ = [("basic", BasicLimits), ("io", c.c_ulonglong * 6), ("processMemory", c.c_size_t),
                ("jobMemory", c.c_size_t), ("peakProcessMemory", c.c_size_t), ("peakJobMemory", c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [("times", c.c_longlong * 4), ("pageFaults", w.DWORD), ("total", w.DWORD),
                ("active", w.DWORD), ("terminated", w.DWORD)]


def run(command, cwd, log, environment, timeout=900, log_limit=32 * 1024 * 1024):
    if os.name != "nt":
        raise RuntimeError("The source build producer requires Windows.")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    for name, restype, argtypes in (
        ("CreateJobObjectW", w.HANDLE, [c.c_void_p, w.LPCWSTR]),
        ("SetInformationJobObject", w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]),
        ("AssignProcessToJobObject", w.BOOL, [w.HANDLE, w.HANDLE]),
        ("TerminateJobObject", w.BOOL, [w.HANDLE, w.UINT]),
        ("QueryInformationJobObject", w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]),
        ("CloseHandle", w.BOOL, [w.HANDLE]),
    ):
        function = getattr(kernel, name)
        function.restype, function.argtypes = restype, argtypes
    job, output = None, None
    process, reader = None, None
    assigned = False
    overflow, errors = threading.Event(), []
    request = log.with_suffix(".command.json")
    with request.open("x", encoding="utf-8") as stream:
        json.dump({"command": [str(value) for value in command], "cwd": str(cwd)}, stream, ensure_ascii=True)
    started = time.monotonic()
    try:
        output = log.open("xb")
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise c.WinError(c.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000
        if not kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)):
            raise c.WinError(c.get_last_error())
        process = subprocess.Popen([sys.executable, "-X", "utf8", str(Path(__file__).resolve()), "--child", str(request)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   cwd=cwd, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
        # The child waits on stdin before it can launch any build process.
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            raise c.WinError(c.get_last_error())
        assigned = True

        def drain():
            try:
                count = 0
                while True:
                    block = process.stdout.read1(65536)
                    if not block:
                        break
                    remaining = log_limit - count
                    output.write(block[:remaining])
                    output.flush()
                    count += len(block)
                    if count > log_limit:
                        overflow.set()
                        break
            except BaseException as error:
                errors.append(error)
                overflow.set()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        process.stdin.write(b"\x01")
        process.stdin.close()
        deadline = started + timeout
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                raise RuntimeError("Owned command exceeded its log or time bound.")
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
    finally:
        cleanup_error = None
        if assigned:
            if not kernel.TerminateJobObject(job, 99):
                cleanup_error = c.WinError(c.get_last_error())
            deadline = time.monotonic() + 5
            while True:
                accounting = Accounting()
                if not kernel.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None):
                    cleanup_error = c.WinError(c.get_last_error())
                    break
                if accounting.active == 0:
                    break
                if time.monotonic() >= deadline:
                    cleanup_error = RuntimeError("Owned command job did not drain.")
                    break
                time.sleep(0.01)
        if job:
            kernel.CloseHandle(job)
        if process is not None:
            if not assigned and process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        if reader is not None:
            reader.join(timeout=5)
            if reader.is_alive():
                cleanup_error = RuntimeError("Owned command output reader did not stop.")
        if process is not None and process.stdout:
            process.stdout.close()
        if output is not None:
            output.close()
        if cleanup_error is not None:
            raise cleanup_error
    if errors:
        raise errors[0]
    if overflow.is_set() or process.returncode != 0:
        raise RuntimeError(f"Owned command failed ({process.returncode}); see {log}")
    data = log.read_bytes()
    return {"exitCode": process.returncode, "elapsedMs": round((time.monotonic() - started) * 1000),
            "logSha256": hashlib.sha256(data).hexdigest(), "logBytes": len(data)}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--child" or sys.stdin.buffer.read(1) != b"\x01":
        raise RuntimeError("Owned command child requires its startup gate.")
    with Path(sys.argv[2]).open("rb") as stream:
        request = stream.read(128 * 1024 + 1)
    if len(request) > 128 * 1024:
        raise RuntimeError("Owned command request is oversized.")
    request = json.loads(request)
    sys.exit(subprocess.run(request["command"], cwd=request["cwd"], stdin=subprocess.DEVNULL).returncode)
