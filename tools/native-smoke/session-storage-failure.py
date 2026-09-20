"""Verify storage-start and atomic-replacement failures using owned sample processes."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


parser = argparse.ArgumentParser()
parser.add_argument("--helper", type=Path, required=True)
args = parser.parse_args()
helper = args.helper.resolve(strict=True)
root = Path(tempfile.mkdtemp(prefix="storage-failure-", dir=Path("build").resolve()))
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
invalid = ctypes.c_void_p(-1).value

with (root / "target.stdout").open("wb") as target_output, (root / "target.stderr").open("wb") as target_error:
    target = subprocess.Popen([str(helper.parent / "knmon-sample-fileio.exe"), "--attach-loop",
                               "--iterations", "2000", "--delay-ms", "20"],
                              stdout=target_output, stderr=target_error, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        blocked_root = root / "a-file"
        blocked_root.write_text("owned fixture", encoding="utf-8")
        for mode in ("startup", "replace"):
            session = blocked_root / "session.knapm" if mode == "startup" else root / "live.knapm"
            operation = "storage-" + uuid.uuid4().hex
            held = invalid
            with (root / f"{mode}.stdout").open("wb") as output, (root / f"{mode}.stderr").open("wb") as error:
                command = [str(helper), "attach-session", "--pid", str(target.pid), "--duration-ms", "15000",
                           "--timeout-ms", "7000", "--api-selection", "kernel32.dll!CreateFileW;kernel32.dll!WriteFile",
                           "--operation-id", operation, "--session-id", operation, "--stream-batches",
                           "--write-knapm", str(session), "--knapm-compression", "zstd"]
                child = subprocess.Popen(command, stdout=output, stderr=error, creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    if mode == "replace":
                        deadline = time.monotonic() + 12
                        while held == invalid and child.poll() is None and time.monotonic() < deadline:
                            # Deny delete sharing deliberately, unlike normal helper readers.
                            held = kernel.CreateFileW(str(session / "index.json"), 0x80000000, 3, None, 3, 0x80, None)
                            if held == invalid:
                                time.sleep(0.005)
                        assert held != invalid, "Could not hold the index replacement fault barrier."
                    child.wait(timeout=25)
                finally:
                    if held != invalid:
                        kernel.CloseHandle(held)
                    if child.poll() is None:
                        child.kill()
                    child.wait()
            frames = [json.loads(line) for line in (root / f"{mode}.stdout").read_text(encoding="utf-8").splitlines()]
            result = next(frame["captureResult"] for frame in frames if frame["frameType"] == "capture_result")
            assert child.returncode != 0 and not result["success"]
            assert result["operation"] == "session_storage_failed", result["message"]
            if mode == "startup":
                assert not result["handshake"]["received"], "Storage startup failure must not inject an agent."
            else:
                manifest = json.loads((session / "manifest.json").read_text(encoding="utf-8"))
                assert manifest["writerState"] == "failed" and manifest["finalized"] is False
                assert "32" in manifest["writerError"], manifest["writerError"]
                assert result["agentCleanupSucceeded"], "Storage failure must still restore hooks."
            assert target.poll() is None, "Storage failure terminated the attached target."
            print(f"{mode}: explicit storage failure, owned target alive, evidence={root}")
    finally:
        if target.poll() is None:
            target.terminate()
        target.wait(timeout=10)
