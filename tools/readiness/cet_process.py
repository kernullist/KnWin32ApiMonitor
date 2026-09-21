"""Launch an owned x64 test target with an explicit shadow-stack creation policy."""
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import subprocess

from desktop_processes import Job, Startup, ProcessInfo, check
from source_evidence import require


class ExtendedStartup(c.Structure):
    _fields_ = [("startup", Startup), ("attributes", c.c_void_p)]


class CetJob(Job):
    def __init__(self):
        super().__init__()
        for name, result, arguments in (
            ("InitializeProcThreadAttributeList", w.BOOL, [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)]),
            ("UpdateProcThreadAttribute", w.BOOL, [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]),
            ("DeleteProcThreadAttributeList", None, [c.c_void_p]),
            ("GetProcessMitigationPolicy", w.BOOL, [w.HANDLE, c.c_int, c.c_void_p, c.c_size_t]),
        ):
            function = getattr(self.api, name)
            function.restype, function.argtypes = result, arguments

    def spawn_policy(self, command, cwd, environment, strict):
        require(type(strict) is bool and bool(self.handle), "A live CET Job and explicit policy are required.")
        executable = Path(command[0]).resolve(strict=True)
        require(executable.is_file(), "CET target is not a file.")
        command = [str(executable), *map(str, command[1:])]
        line = subprocess.list2cmdline(command)
        require(not any("\0" in part for part in command) and len(line.encode("utf-16-le")) < 65532,
                "Invalid CET target command line.")
        require(not any("\0" in key or "\0" in value or "=" in key for key, value in environment.items()),
                "Invalid CET target environment.")
        block = "\0".join(f"{key}={value}" for key, value in sorted(environment.items(), key=lambda row: row[0].upper())) + "\0\0"
        directory = str(Path(cwd).resolve(strict=True))
        startup, process = ExtendedStartup(), ProcessInfo()
        startup.startup.cb, startup.startup.flags, startup.startup.show = c.sizeof(startup), 1, 0
        size = c.c_size_t()
        self.api.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        require(0 < size.value <= 65536, "Invalid CET startup attribute size.")
        attributes = c.create_string_buffer(size.value)
        initialized = False
        mitigation = (c.c_ulonglong * 2)(0, (3 if strict else 2) << 28)
        try:
            check(self.api.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)))
            initialized = True
            check(self.api.UpdateProcThreadAttribute(attributes, 0, 0x20007, mitigation, c.sizeof(mitigation), None, None))
            startup.attributes = c.addressof(attributes)
            check(self.api.CreateProcessW(str(executable), c.create_unicode_buffer(line), None, None, False,
                                         0x08080404, c.create_unicode_buffer(block), directory,
                                         c.cast(c.byref(startup), c.POINTER(Startup)), c.byref(process)))
            check(self.api.AssignProcessToJobObject(self.handle, process.process))
            assigned = w.BOOL()
            check(self.api.IsProcessInJob(process.process, self.handle, c.byref(assigned)))
            require(assigned.value, "CET target ownership was not established.")
            if self.api.ResumeThread(process.thread) == 0xFFFFFFFF:
                raise c.WinError(c.get_last_error())
            child = {"handle": process.process, "pid": process.pid, "tid": process.tid,
                     "command": command, "cwd": directory, "requestedPolicy": mitigation[1]}
            self.children.append(child)
            process.process = None
            return child
        finally:
            if process.thread:
                self.api.CloseHandle(process.thread)
            if process.process:
                try:
                    check(self.api.TerminateProcess(process.process, 99))
                    require(self.api.WaitForSingleObject(process.process, 5000) == 0, "CET failed-start target did not exit.")
                finally:
                    self.api.CloseHandle(process.process)
            if initialized:
                self.api.DeleteProcThreadAttributeList(attributes)

    def policy(self, child):
        require(child in self.children and self.exit_code(child) is None, "CET policy target is not a live owned child.")
        snapshot = self.sample_process(child["pid"])
        require(snapshot["status"] == "sampled", "CET target exited during observation.")
        flags = w.DWORD()
        queried = bool(self.api.GetProcessMitigationPolicy(child["handle"], 15, c.byref(flags), c.sizeof(flags)))
        error = 0 if queried else c.get_last_error()
        require(self.exit_code(child) is None, "CET target exited during policy query.")
        return {"pid": child["pid"], "tid": child["tid"], "created100ns": snapshot["created100ns"],
                "image": snapshot["image"], "requestedPolicy": child["requestedPolicy"],
                "queried": queried, "flags": flags.value, "error": error, "alive": True}
