"""Exercise archive boundaries, executed-test accounting and owned process cleanup."""
import copy
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
from owned_command import run
from rebuild_source import COMMON_TESTS, validate_tests
from source_archive import MAX_FILE, extract_archive, inspect_archive, parse_manifest, require, validate_container, validate_name, verify_tree

ROOT = Path(__file__).resolve().parents[2]


def rejected(function, label):
    try:
        function()
    except (ValueError, RuntimeError, OSError, zipfile.BadZipFile):
        print(f"Rejected: {label}", flush=True)
    else:
        raise RuntimeError(f"Negative source control accepted: {label}")


def make_archive(path, payload, manifest, link=False):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in payload.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK if link else stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
        archive.writestr("SOURCE-MANIFEST.json", json.dumps(manifest))


def main():
    (ROOT / "build").mkdir(exist_ok=True)
    temporary = tempfile.mkdtemp(prefix="source-negative-", dir=ROOT / "build")
    try:
        root = Path(temporary)
        require(root.resolve().is_relative_to((ROOT / "build").resolve()), "Temporary fixture escaped its build directory.")
        payload = {"README.md": b"Source fixture.\n"}
        manifest = {"schemaVersion": 1, "revision": "1" * 40, "dirtySnapshot": False,
                    "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in payload.items()}}
        valid = root / "valid.zip"
        make_archive(valid, payload, manifest)
        extracted = root / "valid-source"
        require(extract_archive(valid, extracted) == manifest, "Valid archive failed.")
        malformed_container = root / "bad-directory.zip"
        altered = bytearray(valid.read_bytes())
        altered[-10:-6] = (5 * 1024 * 1024).to_bytes(4, "little")
        malformed_container.write_bytes(altered)
        rejected(lambda: validate_container(malformed_container), "oversized central directory")
        invalid_manifest = copy.deepcopy(manifest)
        invalid_manifest["schemaVersion"] = True
        rejected(lambda: parse_manifest(json.dumps(invalid_manifest).encode()), "boolean manifest version")
        for label in ("wrong hash", "wrong length", "dirty provenance", "missing payload", "unlisted payload", "link entry", "case collision"):
            values, record = copy.deepcopy(payload), copy.deepcopy(manifest)
            if label == "wrong hash":
                record["files"]["README.md"]["sha256"] = "0" * 64
            elif label == "wrong length":
                record["files"]["README.md"]["bytes"] += 1
            elif label == "dirty provenance":
                record["dirtySnapshot"] = True
            elif label == "missing payload":
                values.clear()
            elif label == "unlisted payload":
                values["extra.txt"] = b"extra"
            elif label == "case collision":
                values["readme.md"] = values["README.md"]
                record["files"]["readme.md"] = record["files"]["README.md"]
            candidate = root / (label.replace(" ", "-") + ".zip")
            make_archive(candidate, values, record, link=label == "link entry")
            rejected(lambda: extract_archive(candidate, candidate.with_suffix("")), label)
        for name in ("../escape", "/absolute", "C:/outside", "file:stream", "dir\\escape", "NUL.txt", "file.", "folder/ ",
                     ".git/config", "docs/do-not-commit/private.md", "AGENTS.md", "crates/knmon-tauri/Cargo.lock"):
            rejected(lambda: validate_name(name), "unsafe path " + name)
        rejected(lambda: parse_manifest(b'{"schemaVersion":1,"schemaVersion":1}'), "duplicate manifest key")
        with zipfile.ZipFile(valid) as archive:
            archive.getinfo("README.md").file_size = MAX_FILE + 1
            rejected(lambda: inspect_archive(archive), "oversized ZIP entry")
        (extracted / "unlisted.cpp").write_bytes(b"Unlisted source.\n")
        rejected(lambda: verify_tree(extracted, manifest), "unlisted source tree input")
        second_tree = root / "second-source"
        extract_archive(valid, second_tree)
        (second_tree / "README.md").write_bytes(b"Changed after build.")
        rejected(lambda: verify_tree(second_tree, manifest), "modified source tree")
        expected = COMMON_TESTS | {"pe-hardening-knmon-agent64"}
        report = ET.Element("testsuite", tests=str(len(expected)), failures="0", skipped="0", disabled="0")
        for name in sorted(expected):
            ET.SubElement(report, "testcase", name=name, status="run")
        test_file = root / "ctest.xml"
        ET.ElementTree(report).write(test_file)
        require(len(validate_tests(test_file, "x64")) == 23, "Valid CTest fixture failed.")
        for status in ("notrun", "skipped", "failure"):
            changed = copy.deepcopy(report)
            if status == "notrun":
                changed[0].set("status", "notrun")
            else:
                ET.SubElement(changed[0], status)
            ET.ElementTree(changed).write(test_file)
            rejected(lambda: validate_tests(test_file, "x64"), "CTest " + status)
        changed = copy.deepcopy(report)
        changed.set("errors", "1")
        ET.ElementTree(changed).write(test_file)
        rejected(lambda: validate_tests(test_file, "x64"), "CTest aggregate error")
        environment = dict(os.environ)
        result = run([sys.executable, "-c", "print('Owned process positive control.')"], root, root / "positive.log", environment, timeout=10)
        require(result["exitCode"] == 0, "Owned process positive control failed.")
        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.GetProcessHandleCount.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        before, after = w.DWORD(), w.DWORD()
        require(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), c.byref(before)), "Cannot sample fixture handle count.")
        for attempt in range(3):
            rejected(lambda: run([sys.executable, "-c", "print(1)"], root, root / "positive.log", environment, timeout=10), "duplicate command request")
        require(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), c.byref(after)) and after.value == before.value,
                "Rejected command requests leaked Windows job handles.")
        marker = root / "unexpected-command.txt"
        (root / "existing.log").write_bytes(b"Preserve existing output.\n")
        rejected(lambda: run([sys.executable, "-c", "from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('executed')"],
                             root, root / "existing.log", environment, timeout=10), "existing output file")
        require(not marker.exists() and (root / "existing.log").read_bytes() == b"Preserve existing output.\n", "Command ran without exclusive log ownership.")
        rejected(lambda: run([sys.executable, "-c", "raise SystemExit(7)"], root, root / "exit.log", environment, timeout=10), "nonzero command exit")
        rejected(lambda: run([sys.executable, "-c", "print('x' * 1000000)"], root, root / "output.log", environment, timeout=10, log_limit=1024), "command log overflow")
        require((root / "output.log").stat().st_size <= 1024, "Command output was not bounded.")
        heartbeat = root / "child-heartbeat.txt"
        child = "import pathlib,time\np=pathlib.Path(" + repr(str(heartbeat)) + ")\nwhile True:\n p.write_text(str(time.time()))\n time.sleep(0.05)"
        parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," + repr(child) + "]); time.sleep(30)"
        try:
            run([sys.executable, "-c", parent], root, root / "timeout.log", environment, timeout=10)
        except RuntimeError as error:
            require("exceeded its log or time bound" in str(error), "Timeout fixture failed before reaching its deadline: " + str(error))
            print("Rejected: owned process tree timeout", flush=True)
        else:
            raise RuntimeError("Owned timeout command unexpectedly completed.")
        require(heartbeat.exists(), "Timeout child did not execute its positive control.")
        last = heartbeat.read_bytes()
        time.sleep(0.2)
        require(heartbeat.read_bytes() == last, "An owned descendant survived job termination.")
    except BaseException:
        print(f"Source negative evidence retained: {temporary}", flush=True)
        raise
    print(f"Source archive, CTest accounting and owned process adversarial validation PASS: {temporary}")


if __name__ == "__main__":
    main()
