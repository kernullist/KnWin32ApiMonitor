import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time

import frida

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests/corpus/windows-api-v1.json"
FIELDS = ("api", "success", "error", "byteCount", "preview")


def read_json(path, expected_sha256=None):
    with path.open("rb") as file:
        data = file.read(32 * 1024 * 1024 + 1)
    assert len(data) <= 32 * 1024 * 1024, "JSON evidence exceeds the document budget."
    if expected_sha256 is not None:
        assert hashlib.sha256(data).hexdigest() == expected_sha256, f"Changed JSON evidence: {path.name}"
    return json.loads(data.decode("utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    return {str(path.relative_to(ROOT)).replace("\\", "/"):
            hashlib.sha256(path.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")).hexdigest()
            for path in [MANIFEST, *sorted((ROOT / "tools/comparison").glob("*.py")),
                         *sorted((ROOT / "tools/comparison").glob("*.js")),
                         *sorted((ROOT / "tools/comparison").glob("*.mjs")),
                         ROOT / "tools/comparison/requirements.txt",
                         *sorted((ROOT / "native/samples").glob("*.*"))]}


def binary_machine(path):
    import struct
    with path.open("rb") as file:
        header = file.read(64)
        assert header[:2] == b"MZ"
        offset = struct.unpack_from("<I", header, 0x3c)[0]
        assert 64 <= offset <= 1024 * 1024
        file.seek(offset)
        pe = file.read(6)
        assert pe[:4] == b"PE\0\0"
        return struct.unpack_from("<H", pe, 4)[0]


def checked_run(arguments, timeout=45):
    result = subprocess.run([str(value) for value in arguments], capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {arguments[0]}\n{result.stderr.decode(errors='replace')[:2000]}")
    return result.stdout


def native_source_hash():
    return checked_run(["node", "-e", "import('./tools/abi-proof/proof.mjs').then(m => process.stdout.write(m.sourceSnapshot().sha256))"]).decode("ascii")


def semantic(event):
    return {key: event[key] for key in FIELDS}


def compare(expected, actual):
    from collections import Counter
    encode = lambda event: json.dumps(semantic(event), sort_keys=True)
    left, right = Counter(map(encode, expected)), Counter(map(encode, actual))
    return {"missing": sum((left - right).values()), "unexpected": sum((right - left).values()),
            "orderMismatches": sum(semantic(a) != semantic(b) for a, b in zip(expected, actual)),
            "expected": len(expected), "observed": len(actual)}


def assert_oracle(oracle, manifest, iterations):
    assert oracle["correct"] is True
    assert oracle["iterations"] == iterations
    order = manifest["iterationOrder"] * iterations + manifest["trailingFailureOrder"]
    assert [event["api"] for event in oracle["events"]] == order
    assert [event["sequence"] for event in oracle["events"]] == list(range(len(order)))
    assert all(event["success"] for event in oracle["events"][:-2])
    assert all(not event["success"] for event in oracle["events"][-2:])
    assert [event["error"] for event in oracle["events"][-2:]] == [6, 2]
    begin, end = int(oracle["startQpc"]), int(oracle["endQpc"])
    assert 0 < begin <= end and int(oracle["qpcFrequency"]) > 0
    for index, event in enumerate(oracle["events"]):
        assert type(event["success"]) is bool and type(event["error"]) is int and 0 <= event["error"] <= 0xffffffff
        assert begin <= int(event["startQpc"]) <= int(event["endQpc"]) <= end
        has_data = index < iterations * 7 and index % 7 in (1, 2)
        assert event["byteCount"] == (manifest["ioBytes"] if has_data else 0)
        assert event["preview"] == (manifest["previewHex"] if has_data else "")


def knmon_events(capture, oracle):
    selected = [event for event in capture["capturedEvents"] if event["pid"] == oracle["pid"] and event["tid"] == oracle["tid"] and
                int(oracle["startQpc"]) <= int(event["timing"]["startQpc"]) <= int(event["timing"]["endQpc"]) <= int(oracle["endQpc"])]
    events = []
    for event in selected:
        raw = int(event["rawReturnValue"])
        success = raw != (1 << event["rawReturnBits"]) - 1 if event["api"] == "CreateFileW" else raw != 0
        count = 0
        preview = ""
        if event["api"] in ("ReadFile", "WriteFile"):
            count = int(event["arguments"][3]["decodedValue"]) if success else 0
            preview = event["bufferPreview"].replace(" ", "")
        events.append({"api": event["api"], "success": success, "error": event["rawLastErrorCode"],
                       "byteCount": count, "preview": preview})
    return events


def frida_run(executable, directory, iterations, extra_args=()):
    device = frida.get_local_device()
    pid = device.spawn([str(executable), str(directory), str(iterations), *extra_args])
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    handle = kernel.OpenProcess(0x101001, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        device.kill(pid)
        raise OSError(error, "Cannot retain spawned target ownership.")
    detached = threading.Event()
    ready = threading.Event()
    messages = []
    session = None
    try:
        session = device.attach(pid)
        session.on("detached", lambda *args: detached.set())
        script = session.create_script((ROOT / "tools/comparison/frida-observer.js").read_text(encoding="utf-8"))

        def message(value, data):
            messages.append(value)
            if value.get("payload", {}).get("kind") == "ready":
                ready.set()

        script.on("message", message)
        script.load()
        assert ready.wait(10), "Frida observer did not become ready."
        device.resume(pid)
        assert detached.wait(30), "Frida target did not exit."
        assert kernel.WaitForSingleObject(handle, 5000) == 0, "Frida detach preceded target termination."
        exit_code = ctypes.c_uint32()
        assert kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        assert exit_code.value == 0, f"Frida target exit code: {exit_code.value}"
        (directory / "frida-messages.json").write_text(json.dumps(messages, indent=2), encoding="utf-8")
        assert not any(value["type"] == "error" for value in messages), messages
        result = [value["payload"] for value in messages if value.get("payload", {}).get("kind") == "corpus"]
        assert len(result) == 1, "Missing/duplicate Frida completion batch."
        assert result[0]["errors"] == [], result[0]["errors"]
        return result[0]["events"]
    finally:
        if kernel.WaitForSingleObject(handle, 0) == 0x102:
            kernel.TerminateProcess(handle, 1)
            kernel.WaitForSingleObject(handle, 5000)
        kernel.CloseHandle(handle)
        if session is not None and not detached.is_set():
            session.detach()
        (directory / "frida-messages.json").write_text(json.dumps(messages, indent=2), encoding="utf-8")


def quantiles(values):
    values = sorted(values)
    return {name: values[max(0, math.ceil(percentile * len(values)) - 1)]
            for name, percentile in (("median", 0.5), ("p95", 0.95), ("p99", 0.99))}


def oracle_metrics(oracle):
    frequency = int(oracle["qpcFrequency"])
    assert frequency > 0
    return {"events": len(oracle["events"]),
            "workloadUs": (int(oracle["endQpc"]) - int(oracle["startQpc"])) * 1e6 / frequency,
            "callLatencyUs": quantiles([(int(e["endQpc"]) - int(e["startQpc"])) * 1e6 / frequency for e in oracle["events"]]),
            "cpu100ns": int(oracle["kernelCpu100ns"]) + int(oracle["userCpu100ns"]),
            "workingSetBytes": oracle["workingSetBytes"], "peakWorkingSetBytes": oracle["peakWorkingSetBytes"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=64)
    parser.add_argument("--build-x64", default="build/native-msvc/Debug")
    parser.add_argument("--build-x86", default="build/native-msvc-x86/Debug")
    options = parser.parse_args()
    assert 1 <= options.repetitions <= 100 and 1 <= options.iterations <= 10000
    os.chdir(ROOT)
    manifest = read_json(MANIFEST)
    assert frida.__version__ == manifest["baseline"]["version"]
    root = Path(tempfile.mkdtemp(prefix="comparison-", dir=ROOT / "build"))
    runs = []
    sources = source_hashes()
    summary = {"schemaVersion": 1, "corpus": manifest["id"], "windowsVersion": platform.version(),
               "observedAtUtc": datetime.now(timezone.utc).isoformat(), "iterations": options.iterations,
               "repetitions": options.repetitions, "sourceHashEncoding": "utf8-LF",
               "measurement": "Fresh processes, rotated mode order, no warmup discard. Caller QPC intervals include wrapper work; RSS is target working set. CPU accounting may round short runs to zero.",
               "python": platform.python_version(), "fridaVersion": frida.__version__, "cpu": platform.processor(),
               "manifestSha256": digest(MANIFEST), "fridaBinarySha256": digest(Path(frida.__file__).parent / "_frida.pyd"),
               "sourceHashes": sources, "nativeSourceSha256": native_source_hash(), "kernelEtwProbes": [], "runs": runs}
    try:
        for architecture, build in (("x64", options.build_x64), ("x86", options.build_x86)):
            directory = (ROOT / build).resolve()
            assert directory.name in ("Debug", "Release")
            build_log = checked_run(["cmake", "--build", directory.parent, "--config", directory.name, "--parallel", "4"], timeout=180)
            (root / f"{architecture}-build.log").write_bytes(build_log)
            target = directory / "knmon-comparison-target.exe"
            binaries = {name: digest(directory / name) for name in ("knmon-comparison-target.exe", "knmon-native-helper.exe",
                        "knmon-etw-corpus-reader.exe", f"knmon-agent{'64' if architecture == 'x64' else '32'}.dll")}
            assert all(binary_machine(directory / name) == (0x8664 if architecture == "x64" else 0x14c) for name in binaries)
            probe = json.loads(checked_run([directory / "knmon-etw-corpus-reader.exe", "--probe-kernel", root / f"{architecture}-kernel-probe.etl"]))
            summary["kernelEtwProbes"].append({"architecture": architecture, **probe})
            for repetition in range(options.repetitions):
                order = ["original", "knmon", "frida", "etw"]
                order = order[repetition % 4:] + order[:repetition % 4]
                baseline = None
                group = []
                for mode in order:
                    trial = root / f"{architecture}-{repetition:02}-{mode}"
                    trial.mkdir()
                    start = time.perf_counter_ns()
                    observed = None
                    if mode == "frida":
                        observed = frida_run(target, trial, options.iterations)
                    elif mode == "knmon":
                        capture_text = checked_run([directory / "knmon-native-helper.exe", "capture-sample", "--target", target,
                            "--target-args", subprocess.list2cmdline([str(trial), str(options.iterations)]), "--timeout-ms", "30000",
                            "--api-selection", ";".join("kernel32.dll!" + api for api in manifest["apis"]),
                            "--write-session", trial / "session"])
                        (trial / "capture.json").write_bytes(capture_text)
                        capture = json.loads(capture_text)
                        assert capture["success"] and capture["targetExitCode"] == 0
                        assert capture["transportDroppedEvents"] == 0, "Normal-load transport loss."
                    else:
                        checked_run([target, trial, options.iterations] + (["--etw-private"] if mode == "etw" else []))
                    finish = time.perf_counter_ns()
                    oracle = read_json(trial / "oracle.json")
                    assert_oracle(oracle, manifest, options.iterations)
                    if mode == "original":
                        baseline = oracle["events"]
                        observed = oracle["events"]
                    elif mode == "knmon":
                        observed = knmon_events(capture, oracle)
                    elif mode == "etw":
                        etw_text = checked_run([directory / "knmon-etw-corpus-reader.exe", trial / "corpus.etl"])
                        (trial / "etw.json").write_bytes(etw_text)
                        observed = json.loads(etw_text)["events"]
                        assert observed == oracle["events"]
                    metrics = compare(oracle["events"], observed)
                    item = {"architecture": architecture, "mode": mode, "repetition": repetition, "configuration": directory.name,
                            "binaries": binaries, "artifacts": {str(file.relative_to(trial)).replace("\\", "/"): digest(file)
                                                               for file in sorted(trial.rglob("*")) if file.is_file()},
                            "comparison": metrics, "targetExitCode": 0, "directory": trial.name, "controllerStartNs": str(start), "controllerEndNs": str(finish),
                            "processWallMs": (finish - start) / 1e6, **oracle_metrics(oracle)}
                    runs.append(item)
                    group.append(oracle["events"])
                    assert metrics["missing"] == metrics["unexpected"] == metrics["orderMismatches"] == 0, item
                assert all(list(map(semantic, events)) == list(map(semantic, baseline)) for events in group), "Instrumentation changed caller-observed semantics."
                print(f"Comparison PASS: {architecture}, round {repetition}, {len(baseline)} events per mode", flush=True)
            assert all(digest(directory / name) == sha256 for name, sha256 in binaries.items()), "Binaries changed during execution."
        assert source_hashes() == sources, "Corpus sources changed during execution."
        assert native_source_hash() == summary["nativeSourceSha256"], "Native sources changed during execution."
        summary["status"] = "passed"
    except BaseException as error:
        summary["status"] = "failed"
        summary["failure"] = str(error)
        raise
    finally:
        (root / "comparison.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Comparison evidence: {root}", flush=True)


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Evidence validation must run without Python optimization flags.")
    main()
