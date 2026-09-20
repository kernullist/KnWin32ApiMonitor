"""Measure native capture-policy costs on the independent six-API caller corpus."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_evidence import ROOT, contained, digest_file, read_bytes, read_json, require, unique_object
from desktop_check import machine
from owned_command import run

MODES = {"original": (None, 0), "metadata": ("metadata", 0), "arguments": ("arguments", 0),
         "preview": ("preview", 0), "metadata-stack32": ("metadata", 32), "preview-stack32": ("preview", 32)}
ARCHITECTURES = {"x64": ("native-msvc", "64", 0x8664), "x86": ("native-msvc-x86", "32", 0x14C)}
MANIFEST = "tests/corpus/windows-api-v1.json"
PRODUCERS = ("tools/readiness/native_profile_costs.py", "tools/readiness/verify_native_profile_costs.py", "tools/readiness/source_evidence.py",
             "tools/readiness/desktop_check.py", "tools/source/owned_command.py", "tools/source/source_archive.py",
             "tools/source/rebuild_source.py", "tools/abi-proof/proof.mjs", "toolchain.json", MANIFEST)
SCOPE = "Native Debug six-API caller costs; collector, desktop, disk and UI latency remain separate"
ITERATIONS = 64
REPETITIONS = 10
SIGNATURES = {
    "CreateFileW": (("lpFileName", "LPCWSTR"), ("dwDesiredAccess", "DWORD"), ("dwShareMode", "DWORD"),
                    ("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"), ("dwCreationDisposition", "DWORD"),
                    ("dwFlagsAndAttributes", "DWORD"), ("hTemplateFile", "HANDLE")),
    "WriteFile": (("hFile", "HANDLE"), ("lpBuffer", "LPCVOID"), ("nNumberOfBytesToWrite", "DWORD"),
                  ("lpNumberOfBytesWritten", "LPDWORD"), ("lpOverlapped", "LPOVERLAPPED")),
    "ReadFile": (("hFile", "HANDLE"), ("lpBuffer", "LPVOID"), ("nNumberOfBytesToRead", "DWORD"),
                 ("lpNumberOfBytesRead", "LPDWORD"), ("lpOverlapped", "LPOVERLAPPED")),
    "CloseHandle": (("hObject", "HANDLE"),),
    "VirtualAlloc": (("lpAddress", "LPVOID"), ("dwSize", "SIZE_T"), ("flAllocationType", "DWORD"), ("flProtect", "DWORD")),
    "VirtualFree": (("lpAddress", "LPVOID"), ("dwSize", "SIZE_T"), ("dwFreeType", "DWORD")),
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def natural(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(same(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def pinned_node():
    return (ROOT / ("build/deps/node-v" + read_json(ROOT / "toolchain.json")["node"] + "-win-x64/node.exe")).resolve(strict=True)


def decimal(value):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None and int(value) < 1 << 64,
            "Invalid canonical counter or clock value.")
    return int(value)


def sources():
    return {name: digest_file(ROOT / name) for name in PRODUCERS}


def native_source(node):
    require(node == pinned_node(), "Native profile requires the pinned local Node executable.")
    command = [str(node), "--input-type=module", "-e",
               "import {sourceSnapshot} from './tools/abi-proof/proof.mjs'; process.stdout.write(sourceSnapshot().sha256);"]
    result = subprocess.run(command, cwd=ROOT, env=environment(node), capture_output=True, timeout=30)
    require(result.returncode == 0 and re.fullmatch(rb"[0-9a-f]{64}", result.stdout) is not None,
            "Native source fingerprint command failed.")
    return result.stdout.decode("ascii")


def environment(node):
    value = {key: value for key, value in os.environ.items()
             if not key.upper().startswith(("KNMON_", "NODE_", "WEBVIEW2_", "TAURI_", "LIBTEST_"))}
    value["PATH"] = str(node.parent) + os.pathsep + value["PATH"]
    value["PYTHONDONTWRITEBYTECODE"] = "1"
    return value


def binary_names(architecture):
    return ("knmon-comparison-target.exe", "knmon-native-helper.exe", "knmon-agent" + ARCHITECTURES[architecture][1] + ".dll")


def command_for(directory, architecture, mode):
    binaries = directory.parent / architecture / "bin"
    target = binaries / "knmon-comparison-target.exe"
    arguments = [str(directory), str(ITERATIONS)]
    if mode == "original":
        return [str(target), *arguments]
    detail, frames = MODES[mode]
    manifest = read_json(ROOT / MANIFEST)
    return [str(binaries / "knmon-native-helper.exe"), "capture-sample", "--target", str(target),
            "--target-args", subprocess.list2cmdline(arguments), "--timeout-ms", "30000",
            "--api-selection", ";".join("kernel32.dll!" + name for name in manifest["apis"]),
            "--capture-detail", detail, "--stack-frames", str(frames), "--write-session", str(directory / "session")]


def quantiles(values):
    require(values and all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in values),
            "Invalid latency population.")
    ordered = sorted(values)
    return {name: ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]
            for name, percentile in (("median", 0.5), ("p95", 0.95), ("p99", 0.99))}


def oracle_metrics(oracle):
    manifest = read_json(ROOT / MANIFEST)
    require(oracle["schemaVersion"] == 1 and type(oracle["schemaVersion"]) is int and oracle["correct"] is True and
            type(oracle["iterations"]) is int and oracle["iterations"] == ITERATIONS,
            "Independent caller oracle failed or used a different workload.")
    require(natural(oracle["pid"], 0xFFFFFFFF) and oracle["pid"] > 0 and natural(oracle["tid"], 0xFFFFFFFF) and oracle["tid"] > 0,
            "Invalid caller process identity.")
    require(oracle["etwEnabled"] is False and all(type(oracle[key]) is int and oracle[key] == 0
            for key in ("etwStatus", "etwWriteFailures", "etwEventsLost", "etwBuffersLost")), "Unexpected caller ETW instrumentation.")
    begin, end, frequency = (decimal(oracle[key]) for key in ("startQpc", "endQpc", "qpcFrequency"))
    require(0 < begin <= end and frequency > 0, "Invalid caller workload clock.")
    order = manifest["iterationOrder"] * ITERATIONS + manifest["trailingFailureOrder"]
    events = oracle["events"]
    require(type(events) is list and [row["api"] for row in events] == order, "Caller workload order or count differs.")
    durations = []
    previous_end = begin
    for index, event in enumerate(events):
        require(type(event["sequence"]) is int and event["sequence"] == index and type(event["success"]) is bool and
                natural(event["error"], 0xFFFFFFFF) and natural(event["byteCount"], 0xFFFFFFFF), "Invalid caller event fields.")
        start, finish = decimal(event["startQpc"]), decimal(event["endQpc"])
        require(previous_end <= start <= finish <= end, "Caller event clock is reversed or outside the workload.")
        previous_end = finish
        data = index < ITERATIONS * 7 and index % 7 in (1, 2)
        require(event["byteCount"] == (manifest["ioBytes"] if data else 0) and
                event["preview"] == (manifest["previewHex"] if data else ""), "Caller output bytes changed.")
        require(event["success"] == (index < len(events) - 2), "Caller success behavior changed.")
        if index >= len(events) - 2:
            require(event["error"] == (6 if index == len(events) - 2 else 2), "Caller failure error changed.")
        durations.append((finish - start) * 1e6 / frequency)
    require(natural(oracle["workingSetBytes"]) and natural(oracle["peakWorkingSetBytes"]) and
            0 < oracle["workingSetBytes"] <= oracle["peakWorkingSetBytes"], "Invalid caller working set.")
    return {"events": len(events), "workloadUs": (end - begin) * 1e6 / frequency,
            "callLatencyUs": quantiles(durations),
            "apiLatencyUs": {api: quantiles([value for value, event in zip(durations, events) if event["api"] == api]) for api in manifest["apis"]},
            "targetCpu100ns": decimal(oracle["kernelCpu100ns"]) + decimal(oracle["userCpu100ns"]),
            "targetWorkingSetBytes": oracle["workingSetBytes"], "targetPeakWorkingSetBytes": oracle["peakWorkingSetBytes"]}


def semantic(oracle):
    return [{key: row[key] for key in ("api", "success", "error", "byteCount", "preview")} for row in oracle["events"]]


def check_stack(event, frames, architecture):
    stack = event["stack"]
    require(type(stack) is list, "Invalid profile stack array.")
    if frames == 0:
        require(event["stackSource"] == "not_captured" and stack == [] and "stackCapture" not in event,
                "Disabled profile stack contains observations.")
    else:
        capture = event["stackCapture"]
        bits = 64 if architecture == "x64" else 32
        require(event["stackSource"] == "native_backtrace" and 0 < len(stack) <= frames and
                capture == {"method": "rtl_capture_stack_back_trace", "phase": "post_call", "addressBits": bits,
                            "requestedFrames": frames, "status": "captured", "limitReached": len(stack) == frames, "exceptionCode": 0} and
                type(capture["addressBits"]) is int and type(capture["requestedFrames"]) is int and
                type(capture["limitReached"]) is bool and type(capture["exceptionCode"]) is int,
                "Enabled profile stack provenance or extent differs.")
        require(all(type(address) is str and re.fullmatch(r"0x[0-9a-f]{" + str(bits // 4) + "}", address) is not None and
                    int(address, 16) > 0 for address in stack), "Invalid profile stack address.")


def hex_value(value, bits):
    require(type(value) is str and re.fullmatch(r"0x[0-9a-f]{" + str(bits // 4) + "}", value) is not None,
            "Invalid fixed-width argument value.")
    return int(value, 16)


def check_arguments(events, index, architecture):
    event = events[index]
    api, arguments = event["api"], event["arguments"]
    signature = SIGNATURES[api]
    require(len(arguments) == len(signature) and all(type(arg["index"]) is int and arg["index"] == position and
            (arg["name"], arg["type"]) == expected and type(arg["rawValue"]) is str and type(arg["decodedValue"]) is str
            for position, (arg, expected) in enumerate(zip(arguments, signature))), "Native profile argument signature is incomplete or changed.")
    if api not in ("ReadFile", "WriteFile"):
        require(all(arg["decodeStatus"] == "decoded" for arg in arguments), "Native profile scalar or string observation failed.")
    values = [arg["rawValue"] for arg in arguments]
    bits = 64 if architecture == "x64" else 32
    if api == "CreateFileW":
        failure = index == ITERATIONS * 7 + 1
        require(Path(values[0]).name == ("missing-file.bin" if failure else "corpus.bin") and
                arguments[0]["decodedValue"] == values[0] and
                hex_value(values[1], 32) == (0x80000000 if failure else 0xC0000000) and
                hex_value(values[2], 32) == 0 and hex_value(values[3], bits) == 0 and
                hex_value(values[4], 32) == (3 if failure else 2) and
                hex_value(values[5], 32) == (0 if failure else 0x100) and hex_value(values[6], bits) == 0,
                "Native profile CreateFileW arguments differ from the independent workload.")
    elif api in ("ReadFile", "WriteFile", "CloseHandle"):
        failure = index == ITERATIONS * 7
        handle = (1 << bits) - 1 if failure else decimal(events[index // 7 * 7]["rawReturnValue"])
        require(hex_value(values[0], bits) == handle, "Native profile file handle chain differs.")
        if api != "CloseHandle":
            require(hex_value(values[1], bits) > 0 and values[2] == ("16" if failure else "64") and
                    hex_value(values[3], bits) > 0 and hex_value(values[4], bits) == 0,
                    "Native profile I/O input arguments differ.")
    elif api == "VirtualAlloc":
        require(hex_value(values[0], bits) == 0 and values[1] == "4096" and hex_value(values[2], 32) == 0x3000 and
                hex_value(values[3], 32) == 4, "Native profile allocation arguments differ.")
    elif api == "VirtualFree":
        require(hex_value(values[0], bits) == decimal(events[index - 1]["rawReturnValue"]) and values[1] == "0" and
                hex_value(values[2], 32) == 0x8000, "Native profile free arguments differ.")


def check_capture(capture, oracle, mode, architecture):
    detail, frames = MODES[mode]
    events = capture["capturedEvents"]
    require(capture["success"] is True and type(capture["targetExitCode"]) is int and capture["targetExitCode"] == 0 and
            capture["cancelRequested"] is False and capture["cancelObserved"] is False and
            capture["targetProcessId"] == oracle["pid"] and capture["targetThreadId"] == oracle["tid"] and
            capture["architecture"] == architecture and capture["hookCleanupOutcome"] == "released_by_process_exit",
            "Native profile capture failed or lost target identity.")
    require(type(events) is list and len(events) == len(oracle["events"]) and
            all(type(capture[key]) is int and capture[key] == len(events) for key in
                ("transportRecordsProduced", "transportRecordsConsumed", "recordsStreamed", "lastTransportSequence")) and
            all(type(capture[key]) is int and capture[key] == 0 for key in
                ("transportAbortedRecords", "transportDroppedEvents", "droppedEvents")), "Native profile has loss, omissions or an undrained tail.")
    require(type(capture["transportCapacity"]) is int and capture["transportCapacity"] == 1024 and
            natural(capture["transportHighWaterMark"], min(1024, len(events))) and capture["transportHighWaterMark"] > 0,
            "Native profile queue configuration differs.")
    for index, (event, expected) in enumerate(zip(events, oracle["events"])):
        require(event["api"] == expected["api"] and event["module"].lower() == "kernel32.dll" and
                event["pid"] == oracle["pid"] and event["tid"] == oracle["tid"] and
                event["operationId"] == capture["operationId"] and decimal(event["recordSequence"]) == index and
                decimal(event["callId"]) == index + 1 and decimal(event["parentCallId"]) == 0 and
                type(event["callDepth"]) is int and event["callDepth"] == 0,
                "Native profile event identity, sequence or order differs.")
        timing = event["timing"]
        require(event["timeSource"] == "qpc" and decimal(timing["qpcFrequency"]) == decimal(oracle["qpcFrequency"]) and
                decimal(expected["startQpc"]) <= decimal(timing["startQpc"]) <= decimal(timing["endQpc"]) <= decimal(expected["endQpc"]),
                "Native profile call clock is outside its independent caller interval.")
        bits = event["rawReturnBits"]
        expected_bits = 64 if architecture == "x64" and event["api"] in ("CreateFileW", "VirtualAlloc") else 32
        require(type(bits) is int and bits == expected_bits, "Invalid native profile return width.")
        raw = decimal(event["rawReturnValue"])
        require(raw < 1 << bits, "Native profile return exceeds its width.")
        success = raw != (1 << bits) - 1 if event["api"] == "CreateFileW" else raw != 0
        require(success == expected["success"] and type(event["rawLastErrorCode"]) is int and
                event["rawLastErrorCode"] == expected["error"], "Native profile return or error behavior differs.")
        require(event["captureDetail"] == detail and type(event["arguments"]) is list and
                type(event["bufferPreview"]) is str and (detail != "metadata" or event["arguments"] == []) and
                (detail == "preview" or event["bufferPreview"] == ""), "Native profile collection policy differs.")
        check_stack(event, frames, architecture)
        if detail != "metadata":
            check_arguments(events, index, architecture)
        if detail != "metadata" and event["api"] in ("ReadFile", "WriteFile"):
            require(len(event["arguments"]) == 5, "Native profile I/O arguments are incomplete.")
            buffer, count = event["arguments"][1], event["arguments"][3]
            if success:
                require(count["decodeStatus"] == "decoded" and count["decodedValue"] == str(expected["byteCount"]),
                        "Native profile transferred count differs.")
            else:
                require(count["decodeStatus"] == "not_captured", "Failed I/O invented an output count.")
            if detail == "arguments":
                observed = buffer["capture"]
                require(buffer["decodeStatus"] == "not_captured" and observed["phase"] == "none" and
                        observed["readStatus"] == "not_captured" and type(observed["capturedBytes"]) is int and
                        observed["capturedBytes"] == 0 and observed["truncationReason"] == "capture_detail",
                        "Arguments profile contains a disabled buffer observation.")
            else:
                require(event["bufferPreview"].replace(" ", "") == expected["preview"], "Preview profile bytes differ.")
    return {"delivered": len(events), "dropped": 0, "queueCapacity": 1024, "queueHighWaterMark": capture["transportHighWaterMark"]}


def check_replay(replay, capture):
    require(replay["success"] is True and replay["captureMode"] == "session-replay" and
            len(replay["traceEvents"]) == len(capture["capturedEvents"]), "Native profile session replay failed or lost events.")
    fields = ("api", "module", "pid", "tid", "timing", "rawReturnValue", "rawReturnBits", "rawLastErrorCode",
              "recordSequence", "callId", "captureDetail", "arguments", "bufferPreview", "stack", "stackSource")
    for index, (saved, captured) in enumerate(zip(replay["traceEvents"], capture["capturedEvents"])):
        require(type(saved["eventId"]) is int and saved["eventId"] == index + 1 and
                all(same(saved[key], captured[key]) for key in fields) and same(saved.get("stackCapture"), captured.get("stackCapture")),
                "Native profile session replay changed observations.")


def check_session(trial, capture, replay):
    session = contained(trial, "session")
    manifest = read_json(contained(session, "manifest.json"))
    names = {"audit": "audit.jsonl", "agentEvents": "agent-events.jsonl", "traceEvents": "trace-events.jsonl"}
    require(manifest["files"] == names and manifest["sessionId"] == manifest["operationId"] == capture["operationId"] and
            manifest["shutdownEvidence"] == "released_by_process_exit" and type(manifest["droppedEvents"]) is int and
            manifest["droppedEvents"] == 0 and manifest["target"]["pid"] == capture["targetProcessId"] and
            manifest["target"]["tid"] == capture["targetThreadId"] and manifest["target"]["architecture"] == capture["architecture"],
            "Native profile saved session identity or lifecycle differs.")
    rows = {}
    for key, name in names.items():
        data = read_bytes(contained(session, name), 16 * 1024 * 1024)
        lines = data.splitlines()
        require(len(lines) <= 2000 and all(lines), "Native profile session stream exceeds its bound or has empty records.")
        rows[key] = [json.loads(line, object_pairs_hook=unique_object,
                     parse_constant=lambda value: require(False, "Non-finite session number.")) for line in lines]
        require(type(manifest["eventCounts"][key]) is int and manifest["eventCounts"][key] == len(rows[key]),
                "Native profile saved session counts differ.")
    require(same(rows["traceEvents"], replay["traceEvents"]) and same(rows["audit"], capture["auditEvents"]) and
            same([row for row in rows["agentEvents"] if row["messageType"] == "api_call"], capture["capturedEvents"]),
            "Native profile raw saved session differs from capture or replay.")
    require(type(manifest["eventCounts"]["capturedEvents"]) is int and
            manifest["eventCounts"]["capturedEvents"] == len(capture["capturedEvents"]), "Saved profile captured count differs.")


def artifact_hashes(directory):
    files, pending, entries = [], [directory], 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                require(entries <= 3000, "Native profile artifact tree exceeds its bound.")
                path = Path(child.path)
                require(not path.is_symlink() and (getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT) == 0,
                        "Native profile artifact is a reparse link.")
                contained(directory, path.relative_to(directory).as_posix())
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif child.is_file(follow_symlinks=False) and path != directory / "evidence.json":
                    files.append(path)
                    require(len(files) <= 2000, "Native profile artifact count exceeds its bound.")
    total = 0
    hashes = {}
    binaries = {architecture + "/bin/" + name for architecture in ARCHITECTURES for name in binary_names(architecture)}
    for path in sorted(files):
        relative = path.relative_to(directory).as_posix()
        contained(directory, relative)
        size = path.stat().st_size
        total += size
        limit = (128 if relative in binaries else 64) * 1024 * 1024
        require(size <= limit and total <= 1024 * 1024 * 1024, "Native profile artifact exceeds its byte bound: " + relative)
        hashes[relative] = digest_file(path)
    return hashes


def check_step(directory, label, command, record):
    require(record["command"] == command and type(record["exitCode"]) is int and record["exitCode"] == 0 and
            natural(record["elapsedMs"], 60000), "Native profile command or exit status differs.")
    require(read_json(directory / (label + ".command.json")) == {"command": command, "cwd": str(ROOT)},
            "Owned native profile command request differs.")
    payload = read_bytes(directory / (label + ".log"), 32 * 1024 * 1024)
    require(type(record["logBytes"]) is int and record["logBytes"] == len(payload) and
            record["logSha256"] == hashlib.sha256(payload).hexdigest(), "Native profile command output changed.")


def summarize(runs):
    summary = {}
    for architecture in ARCHITECTURES:
        groups = {}
        for mode in MODES:
            rows = [row for row in runs if row["architecture"] == architecture and row["mode"] == mode]
            require(len(rows) == REPETITIONS, "Native profile repetition matrix is incomplete.")
            metrics = {key: statistics.median(row["metrics"][key] for row in rows)
                       for key in ("workloadUs", "targetCpu100ns", "targetWorkingSetBytes", "targetPeakWorkingSetBytes")}
            metrics["medianRunCallLatencyUs"] = {key: statistics.median(row["metrics"]["callLatencyUs"][key] for row in rows)
                                                for key in ("median", "p95", "p99")}
            metrics["wholeCommandMs"] = statistics.median(row["steps"][0]["elapsedMs"] for row in rows)
            groups[mode] = metrics
        summary[architecture] = groups
    return summary


def verify(directory, record=None):
    directory = directory.resolve(strict=True)
    evidence = read_json(contained(directory, "evidence.json")) if record is None else record
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed" and
            evidence["scope"] == SCOPE and evidence["configuration"] == "Debug" and
            type(evidence["iterations"]) is int and evidence["iterations"] == ITERATIONS and
            type(evidence["repetitions"]) is int and evidence["repetitions"] == REPETITIONS, "Native profile execution scope is incomplete or changed.")
    require(evidence["producers"] == sources(), "Native profile producer inputs changed.")
    require(set(evidence["tools"]) == {"node", "python"} and evidence["tools"]["node"]["path"] == str(pinned_node()) and
            evidence["tools"]["python"]["path"] == sys.executable and evidence["tools"]["python"]["version"] == sys.version,
            "Native profile tool set or configured paths differ.")
    require(evidence["windowsVersion"] == str(sys.getwindowsversion()) and type(evidence["cpuCount"]) is int and
            evidence["cpuCount"] == os.cpu_count() and datetime.fromisoformat(evidence["observedAtUtc"]).utcoffset().total_seconds() == 0,
            "Native profile host description differs.")
    node = Path(evidence["tools"]["node"]["path"])
    for tool in evidence["tools"].values():
        require(digest_file(Path(tool["path"])) == tool["sha256"], "Native profile tool identity changed.")
    require(native_source(node) == evidence["nativeSourceSha256"], "Native profile product sources changed.")
    require(evidence["artifacts"] == artifact_hashes(directory), "Native profile artifact set or bytes changed.")
    require(set(evidence["binaries"]) == set(ARCHITECTURES), "Native profile architecture binaries are incomplete.")
    for architecture, binaries in evidence["binaries"].items():
        require(set(binaries) == set(binary_names(architecture)), "Native profile binary set is incomplete.")
        for name, binary in binaries.items():
            original = ROOT / "build" / ARCHITECTURES[architecture][0] / "Debug" / name
            staged = contained(directory, architecture + "/bin/" + name)
            require(binary["source"] == str(original) and binary["path"] == str(staged) and
                    digest_file(original) == digest_file(staged) == binary["sha256"] and
                    machine(staged) == ARCHITECTURES[architecture][2], "Native profile binary identity or architecture changed.")
    expected_order = [(architecture, mode, repeat) for architecture in ARCHITECTURES for repeat in range(REPETITIONS)
                      for mode in [*MODES][repeat % len(MODES):] + [*MODES][:repeat % len(MODES)]]
    require([(row["architecture"], row["mode"], row["repetition"]) for row in evidence["runs"]] == expected_order,
            "Native profile matrix or rotated order differs.")
    behavior = {}
    for row in evidence["runs"]:
        architecture, mode, repeat = row["architecture"], row["mode"], row["repetition"]
        require(type(repeat) is int, "Native profile repetition is not an integer.")
        name = f"{architecture}-{repeat:02}-{mode}"
        require(row["directory"] == name, "Native profile trial directory differs.")
        trial = contained(directory, name)
        oracle = read_json(trial / "oracle.json")
        metrics = oracle_metrics(oracle)
        require(same(row["metrics"], metrics), "Native profile metrics differ from raw caller observations.")
        require(read_bytes(trial / "corpus.bin", 65) == bytes(range(32, 96)), "Native profile output file differs.")
        behavior.setdefault((architecture, repeat), []).append(semantic(oracle))
        steps = row["steps"]
        require(type(steps) is list and len(steps) == (1 if mode == "original" else 2), "Native profile command sequence is incomplete.")
        check_step(trial, "execute", command_for(trial, architecture, mode), steps[0])
        if mode == "original":
            require(row["delivery"] is None and not (trial / "session").exists(), "Original profile contains monitor observations.")
        else:
            capture = read_json(trial / "execute.log")
            require(same(row["delivery"], check_capture(capture, oracle, mode, architecture)), "Native profile delivery summary differs.")
            command = [str(directory / architecture / "bin/knmon-native-helper.exe"), "replay-session", "--session", str(trial / "session")]
            check_step(trial, "replay", command, steps[1])
            replay = read_json(trial / "replay.log")
            check_replay(replay, capture)
            check_session(trial, capture, replay)
    require(all(all(value == values[0] for value in values) for values in behavior.values()),
            "Capture policy changed independent caller behavior.")
    require(same(evidence["summary"], summarize(evidence["runs"])), "Native profile aggregate differs from individual runs.")
    require(evidence["artifacts"] == artifact_hashes(directory) and evidence["producers"] == sources() and
            evidence["nativeSourceSha256"] == native_source(node), "Native profile inputs changed during verification.")
    return evidence


def produce(node):
    directory = Path(tempfile.mkdtemp(prefix="native-profile-", dir=ROOT / "build"))
    print("Native profile evidence: " + str(directory), flush=True)
    evidence = {"schemaVersion": 1, "status": "failed", "scope": SCOPE, "configuration": "Debug",
                "observedAtUtc": datetime.now(timezone.utc).isoformat(), "windowsVersion": str(sys.getwindowsversion()),
                "cpuCount": os.cpu_count(), "iterations": ITERATIONS, "repetitions": REPETITIONS,
                "binaries": {}, "runs": []}
    try:
        evidence.update({"producers": sources(), "nativeSourceSha256": native_source(node),
                         "tools": {"node": {"path": str(node), "sha256": digest_file(node)},
                                   "python": {"path": sys.executable, "sha256": digest_file(Path(sys.executable)), "version": sys.version}}})
        for architecture in ARCHITECTURES:
            binaries = directory / architecture / "bin"
            binaries.mkdir(parents=True)
            evidence["binaries"][architecture] = {}
            for name in binary_names(architecture):
                source = ROOT / "build" / ARCHITECTURES[architecture][0] / "Debug" / name
                digest = digest_file(source)
                require(machine(source) == ARCHITECTURES[architecture][2], "Wrong native profile input architecture.")
                target = binaries / name
                shutil.copyfile(source, target)
                require(digest_file(target) == digest_file(source) == digest, "Native profile binary changed during staging.")
                evidence["binaries"][architecture][name] = {"source": str(source), "path": str(target), "sha256": digest}
            for repeat in range(REPETITIONS):
                order = list(MODES)
                order = order[repeat % len(order):] + order[:repeat % len(order)]
                for mode in order:
                    trial = directory / f"{architecture}-{repeat:02}-{mode}"
                    trial.mkdir()
                    row = {"architecture": architecture, "mode": mode, "repetition": repeat, "directory": trial.name, "steps": []}
                    evidence["runs"].append(row)
                    command = command_for(trial, architecture, mode)
                    row["steps"].append({"command": command, **run(command, ROOT, trial / "execute.log", environment(node), timeout=60)})
                    oracle = read_json(trial / "oracle.json")
                    row["metrics"] = oracle_metrics(oracle)
                    row["delivery"] = None
                    if mode != "original":
                        capture = read_json(trial / "execute.log")
                        row["delivery"] = check_capture(capture, oracle, mode, architecture)
                        command = [str(binaries / "knmon-native-helper.exe"), "replay-session", "--session", str(trial / "session")]
                        row["steps"].append({"command": command, **run(command, ROOT, trial / "replay.log", environment(node), timeout=60)})
                        replay = read_json(trial / "replay.log")
                        check_replay(replay, capture)
                        check_session(trial, capture, replay)
                print(f"Native profiles PASS: {architecture}, round {repeat}, {len(order)} configurations", flush=True)
        evidence["summary"] = summarize(evidence["runs"])
        evidence["artifacts"] = artifact_hashes(directory)
        evidence["status"] = "passed"
        verify(directory, evidence)
    except BaseException as error:
        evidence["status"] = "failed"
        evidence["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        write_json(directory / "evidence.json", evidence)
    print("Native profile matrix PASS: " + str(directory), flush=True)
    return directory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    parser.add_argument("--node", type=Path, default=pinned_node())
    args = parser.parse_args()
    if args.check:
        result = verify(args.check)
        print("Native profile replay PASS: " + str(len(result["runs"])) + " runs", flush=True)
    else:
        produce(args.node.resolve(strict=True))


if __name__ == "__main__":
    main()
