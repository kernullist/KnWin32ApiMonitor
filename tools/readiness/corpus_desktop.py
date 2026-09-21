"""Measure the independent paced corpus through the real desktop capture path."""
import argparse
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
from desktop_processes import Job, Accounting, check
from desktop_evidence import page_endpoint, source_hashes
from desktop_check import machine
from source_evidence import ROOT, contained, digest_file, read_json, require
from native_profile_costs import MODES, ARCHITECTURES, ITERATIONS, REPETITIONS, MANIFEST, pinned_node, same

DELAY_MS = 30
WAIT_MS = 30000
PRODUCERS = ("tools/readiness/corpus_desktop.py", "tools/readiness/corpus_desktop_driver.mjs",
             "tools/readiness/corpus_desktop_check.py", "tools/readiness/corpus_desktop_pack.py", "tools/readiness/verify_corpus_desktop.py",
             "tools/readiness/desktop_processes.py", "tools/readiness/desktop_evidence.py", "tools/readiness/desktop_check.py",
             "tools/readiness/source_evidence.py", "tools/readiness/native_profile_costs.py",
             "tools/source/owned_command.py", "tools/source/source_archive.py", "tools/source/rebuild_source.py", MANIFEST, "toolchain.json")


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


class Counters(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ("readOperations", "writeOperations", "otherOperations",
                                                "readBytes", "writeBytes", "otherBytes")]


class JobIo(c.Structure):
    _fields_ = [("basic", Accounting), ("io", Counters)]


class Control:
    def __init__(self):
        self.api = c.WinDLL("kernel32", use_last_error=True)
        for name, result, arguments in (
            ("QueryPerformanceCounter", w.BOOL, [c.POINTER(c.c_longlong)]),
            ("QueryPerformanceFrequency", w.BOOL, [c.POINTER(c.c_longlong)]),
            ("CreateEventW", w.HANDLE, [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]),
            ("SetEvent", w.BOOL, [w.HANDLE]),
            ("WaitForSingleObject", w.DWORD, [w.HANDLE, w.DWORD]),
            ("CloseHandle", w.BOOL, [w.HANDLE]),
        ):
            function = getattr(self.api, name)
            function.restype, function.argtypes = result, arguments
        self.id = uuid.uuid4().hex
        self.handles = []
        frequency = c.c_longlong()
        check(self.api.QueryPerformanceFrequency(c.byref(frequency)))
        self.frequency = frequency.value
        try:
            for suffix in ("ready", "start", "done", "release"):
                handle = self.api.CreateEventW(None, True, False, "Local\\KNMon.Corpus." + self.id + "." + suffix)
                error = c.get_last_error()
                check(handle)
                self.handles.append(handle)
                require(error != 183, "Corpus coordination event already exists.")
        except BaseException:
            self.close()
            raise

    def qpc(self):
        value = c.c_longlong()
        check(self.api.QueryPerformanceCounter(c.byref(value)))
        return value.value

    def signaled(self, index):
        value = self.api.WaitForSingleObject(self.handles[index], 0)
        require(value in (0, 258), "Cannot read a corpus coordination event.")
        return value == 0

    def signal(self, index):
        before = self.qpc()
        check(self.api.SetEvent(self.handles[index]))
        return {"beforeQpc": str(before), "afterQpc": str(self.qpc())}

    def close(self):
        for handle in self.handles:
            self.api.CloseHandle(handle)
        self.handles = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def resources(job):
    snapshot = job.sample()
    io = JobIo()
    check(job.api.QueryInformationJobObject(job.handle, 8, c.byref(io), c.sizeof(io), None))
    snapshot["io"] = {name: getattr(io.io, name) for name, _ in Counters._fields_}
    return snapshot


def binaries_for(architecture):
    native, suffix, _ = ARCHITECTURES[architecture]
    triple = "x86_64" if architecture == "x64" else "i686"
    return [ROOT / f"apps/knmon-ui/src-tauri/target/{triple}-pc-windows-msvc/release/knmon-ui.exe",
            *[ROOT / "build" / native / "Debug" / name for name in
              ("knmon-native-helper.exe", "knmon-collector.exe", "knmon-agent" + suffix + ".dll", "knmon-comparison-target.exe")]]


def stage(directory, architecture):
    directory.mkdir(parents=True)
    result = {}
    for source in binaries_for(architecture):
        require(machine(source) == ARCHITECTURES[architecture][2], "Desktop corpus binary architecture differs.")
        digest = digest_file(source)
        destination = directory / source.name
        shutil.copyfile(source, destination)
        require(digest_file(destination) == digest_file(source) == digest, "Desktop corpus binary changed during staging.")
        result[source.name] = {"source": str(source), "sha256": digest}
    return result


def execute(directory, architecture, mode, portable, node):
    directory.mkdir(parents=True)
    profile, temporary, corpus = (directory / name for name in ("profile", "tmp", "corpus"))
    for child in (profile, temporary, corpus):
        child.mkdir()
    detail, frames = MODES[mode]
    report = {"schemaVersion": 1, "status": "failed", "architecture": architecture, "mode": mode,
              "configuration": {"iterations": ITERATIONS, "delayMs": DELAY_MS, "waitMs": WAIT_MS,
                                "captureDetail": detail, "stackFrames": frames, "desktop": "Release", "native": "Debug",
                                "samplingIntervalMs": 100, "presentation": "hidden"}}
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith(("WEBVIEW2_", "KNMON_", "TAURI_"))}
    environment.update(TEMP=str(temporary), TMP=str(temporary))
    app_environment = {**environment, "WEBVIEW2_USER_DATA_FOLDER": str(profile),
                       "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--remote-debugging-port=0 --remote-debugging-address=127.0.0.1"}
    images = {}
    with Control() as control, Job() as app_job, Job() as target_job, Job() as driver_job:
        report.update(controlId=control.id, qpcFrequency=str(control.frequency), commands={}, environment={
            "TEMP": str(temporary), "TMP": str(temporary), "WEBVIEW2_USER_DATA_FOLDER": str(profile),
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": app_environment["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]})
        app, target, driver = None, None, None
        started = time.monotonic()
        phase = "startup"
        pending = None
        query_sequence = 0
        finished = False
        try:
            report["commands"]["application"] = {"argv": [str(portable / "knmon-ui.exe")], "cwd": str(portable)}
            app = app_job.spawn(report["commands"]["application"]["argv"], portable, app_environment)
            report["appPid"] = app["pid"]
            report["appIdentity"] = app_job.sample_process(app["pid"])
            with (directory / "resources.jsonl").open("x", encoding="utf-8") as stream:
                while time.monotonic() - started < 90:
                    require(app_job.exit_code(app) is None, "Desktop exited during the corpus scenario.")
                    app_job.windows(app)
                    before = control.qpc()
                    sample = {"beforeQpc": str(before), "phase": phase,
                              "application": resources(app_job), "target": resources(target_job)}
                    sample["afterQpc"] = str(control.qpc())
                    for scope in ("application", "target"):
                        for process in sample[scope]["processes"]:
                            if process["status"] == "sampled" and process["image"] not in images:
                                images[process["image"]] = digest_file(Path(process["image"]))
                    if driver is None:
                        endpoint = page_endpoint(profile, app_job)
                        if endpoint is not None:
                            if target is None:
                                report["commands"]["target"] = {"argv": [str(portable / "knmon-comparison-target.exe"), str(corpus), str(ITERATIONS),
                                    "--coordinated", control.id, str(DELAY_MS), str(WAIT_MS)], "cwd": str(corpus)}
                                target = target_job.spawn(report["commands"]["target"]["argv"], corpus, environment)
                                report.update(targetPid=target["pid"], targetIdentity=target_job.sample_process(target["pid"]))
                            require(target_job.exit_code(target) is None, "Corpus exited before attach readiness.")
                            if control.signaled(0):
                                report["targetReadyObservedQpc"] = str(control.qpc())
                                report["cdp"] = endpoint
                                request = {"endpoint": endpoint["endpoint"], "targetPid": target["pid"],
                                           "targetPath": str(portable / "knmon-comparison-target.exe"), "mode": mode,
                                           "captureDetail": detail or "preview", "stackFrames": frames, "controlId": control.id,
                                           "allowlist": sorted("kernel32.dll!" + api for api in read_json(ROOT / MANIFEST)["apis"])}
                                write_json(directory / "request.json", request)
                                report["commands"]["driver"] = {"argv": [str(node), str(ROOT / "tools/readiness/corpus_desktop_driver.mjs"),
                                    str(directory / "request.json")], "cwd": str(ROOT)}
                                driver = driver_job.spawn(report["commands"]["driver"]["argv"], ROOT, environment)
                    else:
                        marker = directory / "phase.txt"
                        if marker.exists():
                            text = marker.read_text(encoding="ascii")
                            if text.endswith("\n"):
                                phase = text.splitlines()[-1]
                                if phase == "workload-ready" and "start" in report:
                                    phase = "workload"
                        if phase == "workload-ready" and "start" not in report:
                            require(control.signaled(0) and not control.signaled(2), "Corpus ordering failed before start.")
                            report["start"] = control.signal(1)
                            phase = "workload"
                        if "start" in report and not finished:
                            if control.signaled(2) and "doneObservedQpc" not in report:
                                require((corpus / "oracle.json").is_file(), "Corpus completion preceded its oracle.")
                                report["doneObservedQpc"] = str(control.qpc())
                            reply_path = directory / f"reply-{pending['sequence']:06d}.json" if pending is not None else None
                            if reply_path is not None and reply_path.exists():
                                reply = read_json(reply_path)
                                if reply["sequence"] == pending["sequence"]:
                                    sample["ui"] = {**pending, "receivedQpc": str(control.qpc()), "reply": reply}
                                    pending = None
                                    counts = re.search(r"(?:^|\n)Events: (\d+)/(\d+)(?:\n|$)", reply["snapshot"]["status"])
                                    expected = 0 if mode == "original" else ITERATIONS * 7 + 2
                                    if "doneObservedQpc" in report and counts and int(counts[1]) == int(counts[2]) == expected:
                                        write_json(directory / "finish.json", {"controlId": control.id})
                                        report["drainedObservedQpc"] = str(control.qpc())
                                        finished = True
                            if pending is None and not finished:
                                query_sequence += 1
                                pending = {"sequence": query_sequence, "requestedQpc": str(control.qpc())}
                                require(query_sequence <= 150, "UI observation request count exceeded its bound.")
                                write_json(directory / f"query-{query_sequence:06d}.json", {"sequence": query_sequence})
                        driver_exit = driver_job.exit_code(driver)
                        if driver_exit is not None:
                            report["driverExit"] = driver_exit
                            require(driver_exit == 0 and finished, "Desktop corpus driver failed; inspect driver.json.")
                            if "release" not in report:
                                require(target_job.exit_code(target) is None and control.signaled(2), "Corpus did not survive desktop detach.")
                                report["targetAliveAfterDetach"] = True
                                report["release"] = control.signal(3)
                            if target_job.exit_code(target) is not None:
                                report["targetExit"] = target_job.exit_code(target)
                                require(report["targetExit"] == 0, "Corpus failed after detach/release.")
                                sample["phase"] = "completed"
                                stream.write(json.dumps(sample) + "\n")
                                break
                        elif target_job.exit_code(target) is not None:
                            raise ValueError("Corpus exited before desktop completion.")
                    stream.write(json.dumps(sample) + "\n")
                    stream.flush()
                    time.sleep(0.1)
                else:
                    raise ValueError("Desktop corpus scenario exceeded its deadline.")
            report["applicationBeforeClose"] = app_job.accounting()
            report["targetFinal"] = target_job.accounting()
            app_job.windows(app, close=True)
            deadline = time.monotonic() + 10
            while app_job.exit_code(app) is None and time.monotonic() < deadline:
                time.sleep(0.1)
            report["appExit"] = app_job.exit_code(app)
            require(report["appExit"] == 0, "Desktop did not close normally.")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                endings = {"application": app_job.accounting(), "target": target_job.accounting(), "driver": driver_job.accounting()}
                if all(value["activeProcesses"] == 0 for value in endings.values()):
                    break
                time.sleep(0.1)
            require(all(value["activeProcesses"] == 0 for value in endings.values()), "Owned processes required forced termination.")
            report["naturalJobEnd"] = endings
            require(all(digest_file(Path(name)) == digest for name, digest in images.items()), "An observed process image changed.")
            report["observedImages"] = images
            report["status"] = "executed"
        except Exception as error:
            report["failure"] = type(error).__name__ + ": " + str(error)
        finally:
            report["cleanup"] = {"application": app_job.close(), "target": target_job.close(), "driver": driver_job.close()}
            write_json(directory / "execution.json", report)
    require(report["status"] == "executed", report.get("failure", "Desktop corpus execution failed."))
    return report


def main():
    from corpus_desktop_check import verify_trial
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--architecture", choices=tuple(ARCHITECTURES))
    parser.add_argument("--mode", choices=tuple(MODES))
    args = parser.parse_args()
    require(not args.check or not args.probe, "Check and probe modes are mutually exclusive.")
    require(args.probe or not args.architecture and not args.mode, "Architecture/mode selection is only allowed for a diagnostic probe.")
    if not args.probe:
        from corpus_desktop_pack import produce, verify
        if args.check:
            verify(args.check)
            print("Desktop corpus evidence recheck PASS: " + str(args.check), flush=True)
        else:
            produce()
        return 0
    args.architecture, args.mode = args.architecture or "x64", args.mode or "preview"
    directory = Path(tempfile.mkdtemp(prefix="desktop-corpus-probe-", dir=ROOT / "build"))
    print("Desktop corpus probe: " + str(directory), flush=True)
    node = pinned_node()
    source = source_hashes()
    portable = directory / "binaries" / args.architecture
    binaries = stage(portable, args.architecture)
    report = {"schemaVersion": 1, "status": "failed", "scope": "probe", "sources": source, "binaries": binaries}
    try:
        trial = directory / "trial"
        execute(trial, args.architecture, args.mode, portable, node)
        report["summary"] = verify_trial(trial, args.architecture, args.mode)
        require(source_hashes() == source, "Product sources changed during the desktop probe.")
        report["status"] = "probe_passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    write_json(directory / "evidence.json", report)
    print(json.dumps({"status": report["status"], "failure": report.get("failure"), "directory": str(directory)}), flush=True)
    return 0 if report["status"] == "probe_passed" else 1


if __name__ == "__main__":
    sys.exit(main())
