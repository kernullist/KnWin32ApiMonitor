"""Own and sample a Windows desktop process tree, including nested WebView jobs."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
import socket
import time


class Startup(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
                ("x", w.DWORD), ("y", w.DWORD), ("width", w.DWORD), ("height", w.DWORD),
                ("charsX", w.DWORD), ("charsY", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                ("show", w.WORD), ("reservedSize", w.WORD), ("reservedBytes", c.c_void_p),
                ("input", w.HANDLE), ("output", w.HANDLE), ("error", w.HANDLE)]


class ProcessInfo(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class BasicLimits(c.Structure):
    _fields_ = [("processTime", c.c_longlong), ("jobTime", c.c_longlong), ("flags", w.DWORD),
                ("minWorkingSet", c.c_size_t), ("maxWorkingSet", c.c_size_t), ("activeLimit", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class ExtendedLimits(c.Structure):
    _fields_ = [("basic", BasicLimits), ("io", c.c_ulonglong * 6), ("processMemory", c.c_size_t),
                ("jobMemory", c.c_size_t), ("peakProcessMemory", c.c_size_t), ("peakJobMemory", c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [("user", c.c_longlong), ("kernel", c.c_longlong), ("periodUser", c.c_longlong),
                ("periodKernel", c.c_longlong), ("pageFaults", w.DWORD), ("total", w.DWORD),
                ("active", w.DWORD), ("terminated", w.DWORD)]


class ProcessIds(c.Structure):
    _fields_ = [("assigned", w.DWORD), ("count", w.DWORD), ("ids", c.c_size_t * 128)]


class Memory(c.Structure):
    _fields_ = [("cb", w.DWORD), ("faults", w.DWORD), ("peakRss", c.c_size_t), ("rss", c.c_size_t),
                ("peakPagedPool", c.c_size_t), ("pagedPool", c.c_size_t), ("peakNonPagedPool", c.c_size_t),
                ("nonPagedPool", c.c_size_t), ("pageFile", c.c_size_t), ("peakPageFile", c.c_size_t), ("private", c.c_size_t)]


class TcpRow(c.Structure):
    _fields_ = [(name, w.DWORD) for name in ("state", "address", "port", "remoteAddress", "remotePort", "pid")]


class Tcp6Row(c.Structure):
    _fields_ = [("address", c.c_ubyte * 16), ("scope", w.DWORD), ("port", w.DWORD),
                ("remoteAddress", c.c_ubyte * 16), ("remoteScope", w.DWORD), ("remotePort", w.DWORD),
                ("state", w.DWORD), ("pid", w.DWORD)]


def api():
    if os.name != "nt":
        raise RuntimeError("Desktop resource evidence requires Windows.")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    for name, result, args in (
        ("CreateJobObjectW", w.HANDLE, [c.c_void_p, w.LPCWSTR]),
        ("SetInformationJobObject", w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]),
        ("QueryInformationJobObject", w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]),
        ("AssignProcessToJobObject", w.BOOL, [w.HANDLE, w.HANDLE]),
        ("IsProcessInJob", w.BOOL, [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]),
        ("TerminateJobObject", w.BOOL, [w.HANDLE, w.UINT]),
        ("TerminateProcess", w.BOOL, [w.HANDLE, w.UINT]),
        ("CreateProcessW", w.BOOL, [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                    c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(ProcessInfo)]),
        ("ResumeThread", w.DWORD, [w.HANDLE]),
        ("OpenProcess", w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
        ("CloseHandle", w.BOOL, [w.HANDLE]),
        ("GetExitCodeProcess", w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
        ("WaitForSingleObject", w.DWORD, [w.HANDLE, w.DWORD]),
        ("GetProcessTimes", w.BOOL, [w.HANDLE, *([c.POINTER(w.FILETIME)] * 4)]),
        ("GetProcessHandleCount", w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
        ("QueryFullProcessImageNameW", w.BOOL, [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]),
        ("K32GetProcessMemoryInfo", w.BOOL, [w.HANDLE, c.POINTER(Memory), w.DWORD]),
    ):
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, args
    return kernel


def check(value):
    if not value:
        raise c.WinError(c.get_last_error())
    return value


def filetime(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class Job:
    def __init__(self):
        self.api = api()
        self.handle = check(self.api.CreateJobObjectW(None, None))
        self.children = []
        limits = ExtendedLimits()
        limits.basic.flags = 0x2008  # Kill only this owned tree and bound its process count.
        limits.basic.activeLimit = 64
        try:
            check(self.api.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)))
        except BaseException:
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise

    def spawn(self, command, cwd, environment):
        executable = Path(command[0]).resolve(strict=True)
        if not executable.is_file() or not self.handle:
            raise ValueError("A live Job and an absolute executable file are required.")
        command = [str(executable), *[str(value) for value in command[1:]]]
        if any("\0" in value for value in command) or len(subprocess.list2cmdline(command).encode("utf-16-le")) >= 65532:
            raise ValueError("Invalid or oversized child command line.")
        block = "\0".join(f"{key}={value}" for key, value in sorted(environment.items(), key=lambda row: row[0].upper())) + "\0\0"
        if any("\0" in key or "\0" in value or "=" in key for key, value in environment.items()):
            raise ValueError("Invalid child environment.")
        startup, process = Startup(), ProcessInfo()
        startup.cb, startup.flags, startup.show = c.sizeof(startup), 1, 0
        try:
            check(self.api.CreateProcessW(str(executable), c.create_unicode_buffer(subprocess.list2cmdline(command)),
                                          None, None, False, 0x08000404, c.create_unicode_buffer(block),
                                          str(Path(cwd).resolve(strict=True)), c.byref(startup), c.byref(process)))
            check(self.api.AssignProcessToJobObject(self.handle, process.process))
            if self.api.ResumeThread(process.thread) == 0xFFFFFFFF:
                raise c.WinError(c.get_last_error())
            child = {"handle": process.process, "pid": process.pid, "command": command, "cwd": str(Path(cwd).resolve())}
            self.children.append(child)
            process.process = None
            return child
        finally:
            if process.thread:
                self.api.CloseHandle(process.thread)
            if process.process:
                # A failed assignment leaves a suspended process with no descendants.
                try:
                    check(self.api.TerminateProcess(process.process, 99))
                    if self.api.WaitForSingleObject(process.process, 5000) != 0:
                        raise RuntimeError("Failed startup process did not exit.")
                finally:
                    self.api.CloseHandle(process.process)

    def exit_code(self, child):
        status = self.api.WaitForSingleObject(child["handle"], 0)
        if status == 0x102:
            return None
        if status != 0:
            raise RuntimeError("Cannot wait for owned process exit.")
        result = w.DWORD()
        check(self.api.GetExitCodeProcess(child["handle"], c.byref(result)))
        return result.value

    def accounting(self):
        result = Accounting()
        check(self.api.QueryInformationJobObject(self.handle, 1, c.byref(result), c.sizeof(result), None))
        return {"user100ns": result.user, "kernel100ns": result.kernel, "totalProcesses": result.total,
                "activeProcesses": result.active, "terminatedProcesses": result.terminated}

    def pids(self):
        result = ProcessIds()
        check(self.api.QueryInformationJobObject(self.handle, 3, c.byref(result), c.sizeof(result), None))
        if result.assigned > 128 or result.count != result.assigned:
            raise RuntimeError("Owned process list was truncated.")
        return list(result.ids[:result.count])

    def sample_process(self, pid):
        handle = self.api.OpenProcess(0x1000, False, pid)
        if not handle:
            error = c.get_last_error()
            if pid in self.pids():
                raise OSError(error, "Cannot sample a live owned process.")
            return {"pid": pid, "status": "exited-before-open", "win32": error}
        try:
            belongs = w.BOOL()
            check(self.api.IsProcessInJob(handle, self.handle, c.byref(belongs)))
            if not belongs.value:
                raise RuntimeError("Process identity left the owned Job.")
            created, exited, kernel, user = (w.FILETIME() for _ in range(4))
            check(self.api.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)))
            if filetime(exited):
                return {"pid": pid, "created100ns": str(filetime(created)), "status": "exited"}
            name, size = c.create_unicode_buffer(32768), w.DWORD(32768)
            check(self.api.QueryFullProcessImageNameW(handle, 0, name, c.byref(size)))
            memory, handles = Memory(), w.DWORD()
            memory.cb = c.sizeof(memory)
            if not self.api.K32GetProcessMemoryInfo(handle, c.byref(memory), c.sizeof(memory)) or not self.api.GetProcessHandleCount(handle, c.byref(handles)):
                error = c.get_last_error()
                check(self.api.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)))
                if filetime(exited):
                    return {"pid": pid, "created100ns": str(filetime(created)), "status": "exited"}
                raise OSError(error, "Cannot read live owned process counters.")
            return {"pid": pid, "created100ns": str(filetime(created)), "status": "sampled", "image": name.value,
                    "rssBytes": memory.rss, "privateBytes": memory.private, "handles": handles.value,
                    "user100ns": filetime(user), "kernel100ns": filetime(kernel)}
        finally:
            self.api.CloseHandle(handle)

    def sample(self):
        return {"processes": [self.sample_process(pid) for pid in self.pids()], "job": self.accounting()}

    def listener(self, port):
        library = c.WinDLL("iphlpapi", use_last_error=True)
        query = library.GetExtendedTcpTable
        query.restype, query.argtypes = w.DWORD, [c.c_void_p, c.POINTER(w.DWORD), w.BOOL, w.ULONG, c.c_int, w.ULONG]
        buffer = c.create_string_buffer(1024 * 1024)
        size = w.DWORD(c.sizeof(buffer))
        def table(family, row_type):
            size.value = c.sizeof(buffer)
            result = query(buffer, c.byref(size), False, family, 3, 0)
            if result != 0:
                raise OSError(result, "Cannot verify the owned CDP listener.")
            count = w.DWORD.from_buffer(buffer).value
            if 4 + count * c.sizeof(row_type) > min(size.value, c.sizeof(buffer)):
                raise RuntimeError("Invalid TCP owner table size.")
            rows = [row_type.from_buffer_copy(buffer, 4 + index * c.sizeof(row_type)) for index in range(count)]
            return [row for row in rows if socket.ntohs(row.port & 0xFFFF) == port]
        listeners = table(2, TcpRow)
        if len(listeners) != 1 or listeners[0].address != 0x0100007F:
            raise RuntimeError("CDP must have exactly one loopback-only IPv4 listener.")
        for row in table(23, Tcp6Row):
            if bytes(row.address) != bytes(15) + b"\x01" or row.pid != listeners[0].pid:
                raise RuntimeError("CDP port has an unexpected IPv6 listener.")
        owner = self.sample_process(listeners[0].pid)
        if owner["status"] != "sampled" or Path(owner["image"]).name.lower() != "msedgewebview2.exe":
            raise RuntimeError("CDP listener is not the owned WebView runtime.")
        return owner

    def windows(self, child, close=False):
        if self.exit_code(child) is not None:
            return []
        user = c.WinDLL("user32", use_last_error=True)
        callback_type = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        user.EnumWindows.argtypes = [callback_type, w.LPARAM]
        user.EnumWindows.restype = w.BOOL
        user.GetWindowThreadProcessId.argtypes = [w.HWND, c.POINTER(w.DWORD)]
        user.GetWindowThreadProcessId.restype = w.DWORD
        user.ShowWindowAsync.argtypes, user.ShowWindowAsync.restype = [w.HWND, c.c_int], w.BOOL
        user.IsWindowVisible.argtypes, user.IsWindowVisible.restype = [w.HWND], w.BOOL
        user.GetWindowTextW.argtypes, user.GetWindowTextW.restype = [w.HWND, w.LPWSTR, c.c_int], c.c_int
        user.PostMessageW.argtypes, user.PostMessageW.restype = [w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL
        result = []

        @callback_type
        def visit(window, _):
            pid = w.DWORD()
            user.GetWindowThreadProcessId(window, c.byref(pid))
            if pid.value == child["pid"] and self.exit_code(child) is None:
                title = c.create_unicode_buffer(256)
                user.GetWindowTextW(window, title, len(title))
                if title.value != "KN Win32 API Monitor":
                    return True
                if close:
                    result.append({"postedClose": bool(user.PostMessageW(window, 0x10, 0, 0))})
                else:
                    user.ShowWindowAsync(window, 0)
                    deadline = time.monotonic() + 1
                    while user.IsWindowVisible(window) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    result.append({"visible": bool(user.IsWindowVisible(window))})
            return True

        check(user.EnumWindows(visit, 0))
        return result

    def close(self):
        if not self.handle:
            return {"activeProcesses": 0}
        try:
            check(self.api.TerminateJobObject(self.handle, 99))
            deadline = time.monotonic() + 5
            while True:
                result = self.accounting()
                if result["activeProcesses"] == 0:
                    return result
                if time.monotonic() >= deadline:
                    raise RuntimeError("Owned desktop Job did not drain.")
                time.sleep(0.01)
        finally:
            self.api.CloseHandle(self.handle)
            self.handle = None
            for child in self.children:
                self.api.CloseHandle(child["handle"])
                child["handle"] = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
