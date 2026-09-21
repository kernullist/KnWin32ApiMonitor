"""Produce and verify source-bound local hardware CET and native compatibility evidence."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
from source_evidence import ROOT, require, digest_file, read_bytes, read_json, contained
from owned_command import run
from cet_process import CetJob
from corpus_desktop import Control
from desktop_check import machine, json_value
from native_profile_costs import MODES, ITERATIONS, MANIFEST, pinned_node, environment, native_source, same, semantic, oracle_metrics, decimal, natural
from cet_check import SCOPE, ASSURANCE, EXPECTED_CALLS, schedule, trial_name, probe, cleanup_control, capture, target_policy

PRODUCERS = ("tools/readiness/cet_evidence.py", "tools/readiness/cet_check.py", "tools/readiness/cet_process.py",
             "tools/readiness/verify_cet_evidence.py", "tools/readiness/cet_probe/CMakeLists.txt",
             "tools/readiness/cet_probe/Probe.cpp", "tools/readiness/cet_probe/Returns.asm",
             "tools/readiness/desktop_processes.py", "tools/readiness/corpus_desktop.py", "tools/readiness/desktop_evidence.py",
             "tools/readiness/desktop_check.py", "tools/readiness/source_evidence.py", "tools/readiness/native_profile_costs.py",
             "tools/source/owned_command.py", "tools/source/source_archive.py", "tools/source/rebuild_source.py",
             "tools/abi-proof/proof.mjs", "native/cmake/CheckPeHardening.cmake", "toolchain.json", MANIFEST)
NAMES = ("knmon-comparison-target.exe", "knmon-native-helper.exe", "knmon-agent64.dll")
WAIT_MS, DELAY_MS, DURATION_MS = 30000, 1, 4000


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def producers():
    return {name: digest_file(ROOT / name) for name in PRODUCERS}


def artifacts(directory):
    pending, files, total = [directory], {}, 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            attributes = path.lstat().st_file_attributes
            require(not attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT, "CET evidence contains a reparse point.")
            if path in (directory / "probe-build", directory / "evidence.json"):
                continue
            if path.is_dir():
                pending.append(path)
            else:
                relative = path.relative_to(directory).as_posix()
                size = path.stat().st_size
                total += size
                require(path.is_file() and size <= 128 * 1024 * 1024 and total <= 1024 * 1024 * 1024 and len(files) < 512,
                        "CET evidence exceeds its file or byte limit.")
                files[relative] = digest_file(contained(directory, relative))
    return files


def frames(path, partial=False):
    if partial and not path.exists():
        return []
    data = read_bytes(path, 16 * 1024 * 1024)
    require(partial or data.endswith(b"\n"), "CET helper output has an incomplete final frame.")
    lines = data.split(b"\n")[:-1]
    require(len(lines) <= 32 and all(line.strip() for line in lines), "CET helper frame count or empty line differs.")
    return [json_value(line) for line in lines]


def command_for(directory, strict, mode, stop, execution):
    binaries = directory.parent / "binaries"
    target = [str(binaries / NAMES[0]), str(directory), str(ITERATIONS), "--coordinated", execution["controlId"], str(DELAY_MS), str(WAIT_MS)]
    if mode == "original":
        return {"target": target}
    detail, count = MODES[mode]
    operation = execution["operationId"]
    selection = ";".join("kernel32.dll!" + name for name in read_json(ROOT / MANIFEST)["apis"])
    helper = [str(binaries / NAMES[1]), "attach-session", "--pid", str(execution["policies"]["before"]["pid"]),
              "--operation-id", operation, "--session-id", operation, "--duration-ms", str(DURATION_MS), "--timeout-ms", "7000",
              "--api-selection", selection, "--capture-detail", detail, "--stack-frames", str(count)]
    result = {"target": target, "helper": helper}
    if stop == "cancel":
        result["cancel"] = [str(binaries / NAMES[1]), "cancel-operation", "--operation-id", operation]
    return result


def step(directory, name, command, env, timeout=60):
    return {"command": command, **run(command, directory, directory / (name + ".log"), env, timeout=timeout, log_limit=16 * 1024 * 1024)}


def check_step(directory, name, command, record, maximum=60000):
    require(same(record["command"], command) and type(record["exitCode"]) is int and record["exitCode"] == 0 and
            natural(record["elapsedMs"], maximum), "CET command or execution accounting differs.")
    require(read_json(contained(directory, name + ".command.json")) == {"command": command, "cwd": str(directory)},
            "CET owned command request differs.")
    data = read_bytes(contained(directory, name + ".log"), 16 * 1024 * 1024)
    require(type(record["logBytes"]) is int and record["logBytes"] == len(data) and record["logSha256"] == hashlib.sha256(data).hexdigest(),
            "CET command output changed.")


def execute(directory, strict, mode, stop, env):
    directory.mkdir()
    execution = {"schemaVersion": 1, "status": "failed", "strict": strict, "mode": mode, "stop": stop,
                 "policies": {}, "steps": {}, "operationId": "cet-" + uuid.uuid4().hex}
    with Control() as control, CetJob() as job:
        future = None
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            execution.update(controlId=control.id, qpcFrequency=str(control.frequency))
            commands = command_for(directory, strict, "original", stop, execution)
            target = job.spawn_policy(commands["target"], directory, env, strict)

            def wait_for(predicate, timeout, message, helper_active=False):
                deadline = time.monotonic() + timeout
                while not predicate():
                    require(job.exit_code(target) is None and time.monotonic() < deadline and
                            (not helper_active or not future.done()), message)
                    time.sleep(0.02)

            wait_for(lambda: control.signaled(0), 10, "CET caller did not become ready.")
            execution["readyObservedQpc"] = str(control.qpc())
            execution["policies"]["before"] = job.policy(target)
            commands = command_for(directory, strict, mode, stop, execution)
            execution["commands"] = commands
            if mode != "original":
                future = pool.submit(step, directory, "helper", commands["helper"], env, 25)
                wait_for(lambda: any(row.get("frameType") == "session_state" and row["session"]["sessionState"] == "running"
                                     for row in frames(directory / "helper.log", partial=True)),
                         10, "CET attach did not become ready.", True)
                execution["runningObservedQpc"] = str(control.qpc())
                execution["policies"]["attached"] = job.policy(target)
            execution["start"] = control.signal(1)
            wait_for(lambda: control.signaled(2), 8, "CET caller did not complete.", mode != "original")
            execution["doneObservedQpc"] = str(control.qpc())
            execution["policies"]["captured"] = job.policy(target)
            if mode != "original":
                if stop == "cancel":
                    execution["steps"]["cancel"] = step(directory, "cancel", commands["cancel"], env, 8)
                execution["steps"]["helper"] = future.result(timeout=15)
                execution["policies"]["detached"] = job.policy(target)
                execution["detachObservedQpc"] = str(control.qpc())
            execution["release"] = control.signal(3)
            deadline = time.monotonic() + 8
            while job.exit_code(target) is None and time.monotonic() < deadline:
                time.sleep(0.02)
            execution["targetExitCode"] = job.exit_code(target)
            require(execution["targetExitCode"] == 0, "CET caller did not exit normally after release.")
            execution["exitObservedQpc"] = str(control.qpc())
            deadline = time.monotonic() + 5
            while job.accounting()["activeProcesses"] and time.monotonic() < deadline:
                time.sleep(0.02)
            execution["beforeClose"] = job.accounting()
            require(execution["beforeClose"]["activeProcesses"] == 0, "CET caller left a live descendant after normal exit.")
            execution["status"] = "observed"
        except BaseException as error:
            execution["failure"] = str(error)
            raise
        finally:
            try:
                execution["cleanup"] = job.close()
            finally:
                pool.shutdown(wait=True)
                if future is not None and future.done():
                    try:
                        execution["steps"]["helper"] = future.result()
                    except BaseException as error:
                        execution["helperFailure"] = str(error)
                write_json(directory / "execution.json", execution)
    return verify_trial(directory, strict, mode, stop)


def verify_trial(directory, strict, mode, stop):
    execution, oracle = (read_json(contained(directory, name)) for name in ("execution.json", "oracle.json"))
    require(type(execution["schemaVersion"]) is int and execution["schemaVersion"] == 1 and execution["status"] == "observed" and
            execution["strict"] is strict and execution["mode"] == mode and execution["stop"] == stop and
            re.fullmatch(r"[0-9a-f]{32}", execution["controlId"]) is not None and
            re.fullmatch(r"cet-[0-9a-f]{32}", execution["operationId"]) is not None,
            "CET compatibility execution identity or configuration differs.")
    oracle_metrics(oracle)
    require(read_bytes(contained(directory, "corpus.bin"), 65) == bytes(range(32, 96)), "CET caller output file changed.")
    require(type(execution["targetExitCode"]) is int and execution["targetExitCode"] == 0 and
            decimal(execution["qpcFrequency"]) == decimal(oracle["qpcFrequency"]), "CET caller exit or clock differs.")
    coordination = oracle["coordination"]
    require(coordination["id"] == execution["controlId"] and type(coordination["delayMs"]) is int and coordination["delayMs"] == DELAY_MS and
            type(coordination["waitTimeoutMs"]) is int and coordination["waitTimeoutMs"] == WAIT_MS,
            "CET caller synchronization configuration differs.")
    start, release = execution["start"], execution["release"]
    require(0 < decimal(coordination["readyQpc"]) <= decimal(execution["readyObservedQpc"]) <= decimal(start["beforeQpc"]) <= decimal(start["afterQpc"]) and
            decimal(start["beforeQpc"]) <= decimal(coordination["startGateQpc"]) <= decimal(oracle["startQpc"]) <= decimal(oracle["endQpc"]) <=
            decimal(execution["doneObservedQpc"]) <= decimal(release["beforeQpc"]) <= decimal(release["afterQpc"]) <= decimal(execution["exitObservedQpc"]),
            "CET caller coordination clock or survival ordering differs.")
    for key in ("beforeClose", "cleanup"):
        accounting = execution[key]
        require(all(natural(value) for value in accounting.values()) and type(accounting["activeProcesses"]) is int and
                accounting["activeProcesses"] == 0 and accounting["totalProcesses"] > 0 and accounting["terminatedProcesses"] == 0,
                "CET caller cleanup required termination or left live processes.")
    policies = execution["policies"]
    require(set(policies) == ({"before", "captured"} if mode == "original" else {"before", "attached", "captured", "detached"}),
            "CET target policy observation sequence is incomplete.")
    target = directory.parent / "binaries" / NAMES[0]
    for row in policies.values():
        target_policy(row, strict, target, oracle)
        require(same(row, policies["before"]), "CET target identity or policy changed during capture/detach.")
    commands = command_for(directory, strict, mode, stop, execution)
    require(same(commands, execution["commands"]), "CET compatibility command differs.")
    expected_steps = set(commands) - {"target"}
    require(set(execution["steps"]) == expected_steps, "CET compatibility command sequence differs.")
    for name in expected_steps:
        check_step(directory, name, commands[name], execution["steps"][name], 35000)
    delivery = None
    if mode != "original":
        require(decimal(execution["readyObservedQpc"]) <= decimal(execution["runningObservedQpc"]) <= decimal(start["beforeQpc"]) and
                decimal(execution["doneObservedQpc"]) <= decimal(execution["detachObservedQpc"]) <= decimal(release["beforeQpc"]),
                "CET work preceded hook readiness or release preceded detach.")
        delivery = capture(frames(contained(directory, "helper.log")),
                           {**oracle, "cetCreated100ns": policies["before"]["created100ns"], "cetDirectory": str(directory)},
                           mode, stop, execution["operationId"], target, directory.parent / "binaries" / NAMES[2])
        if stop == "cancel":
            cancel = read_json(contained(directory, "cancel.log"))
            require(cancel["success"] is True and type(cancel["win32ErrorCode"]) is int and cancel["win32ErrorCode"] == 0 and
                    cancel["operationId"] == execution["operationId"] and cancel["operation"] == "cancel_operation",
                    "CET explicit detach request failed.")
    else:
        require(not (directory / "helper.log").exists(), "CET original run contains a monitor capture.")
    return {"strict": strict, "mode": mode, "stop": stop, "calls": len(oracle["events"]), "delivery": delivery}


def build_commands(directory, cmake, linker):
    return {
        "configure": [str(cmake), "-S", str(ROOT / "tools/readiness/cet_probe"), "-B", str(directory / "probe-build"),
                      "-G", "Visual Studio 17 2022", "-A", "x64"],
        "build": [str(cmake), "--build", str(directory / "probe-build"), "--config", "Debug", "--parallel", "4"],
        "hardening": [str(cmake), "-DIMAGE_PATH=" + str(directory / "binaries/knmon-cet-probe.exe"), "-DLINKER=" + str(linker),
                      "-DPOINTER_BYTES=8", "-P", str(ROOT / "native/cmake/CheckPeHardening.cmake")],
    }


def tool_record(path):
    path = path.resolve(strict=True)
    return {"path": str(path), "sha256": digest_file(path)}


def check_build_config(directory, tools):
    cache = read_bytes(contained(directory, "cmake-cache.txt")).decode("utf-8").replace("\r\n", "\n")
    compiler = read_bytes(contained(directory, "cxx-compiler.txt")).decode("utf-8")
    expected = {"CMAKE_LINKER:FILEPATH": Path(tools["link"]["path"]).as_posix(),
                "CMAKE_ASM_MASM_COMPILER:FILEPATH": Path(tools["ml64"]["path"]).as_posix(),
                "CMAKE_GENERATOR:INTERNAL": "Visual Studio 17 2022", "CMAKE_GENERATOR_PLATFORM:INTERNAL": "x64",
                "CMAKE_HOME_DIRECTORY:INTERNAL": (ROOT / "tools/readiness/cet_probe").as_posix(),
                "knmon_cet_probe_BINARY_DIR:STATIC": (directory / "probe-build").as_posix()}
    for key, value in expected.items():
        require(re.findall(r"^" + re.escape(key) + r"=(.*)$", cache, re.MULTILINE) == [value],
                "CET configured compiler, generator or source directory differs.")
    for key, value in {"CMAKE_CXX_COMPILER": Path(tools["cl"]["path"]).as_posix(), "CMAKE_CXX_COMPILER_ID": "MSVC",
                       "CMAKE_CXX_PLATFORM_ID": "Windows", "CMAKE_CXX_SIZEOF_DATA_PTR": "8"}.items():
        require(re.findall(r'set\(' + key + r' "([^"]*)"\)', compiler) == [value], "CET configured compiler identity differs.")


def verify(directory, record=None):
    directory = directory.resolve(strict=True)
    initial = digest_file(contained(directory, "evidence.json"))
    evidence = read_json(directory / "evidence.json") if record is None else record
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["scope"] == SCOPE and
            evidence["assurance"] == ASSURANCE and evidence["configuration"] == "Debug" and
            evidence["status"] in ("passed", "not_verified"), "CET evidence scope or completion state differs.")
    require(evidence["windowsVersion"] == str(sys.getwindowsversion()) and type(evidence["cpuCount"]) is int and evidence["cpuCount"] == os.cpu_count() and
            datetime.fromisoformat(evidence["observedAtUtc"]).utcoffset().total_seconds() == 0, "CET host scope or observation time differs.")
    require(evidence["producers"] == producers() and evidence["nativeSourceSha256"] == native_source(pinned_node()), "CET producer or native product sources changed.")
    require(set(evidence["tools"]) == {"node", "python", "cmake", "link", "cl", "ml64"}, "CET tool identity inventory differs.")
    for name, tool in evidence["tools"].items():
        require(tool == tool_record(Path(tool["path"])), "CET tool bytes changed.")
        require(Path(tool["path"]).name.lower() == {"node": "node.exe", "python": "python.exe"}.get(name, name + ".exe"), "CET tool name differs.")
    require(evidence["tools"]["node"] == tool_record(pinned_node()) and evidence["tools"]["python"] == tool_record(Path(sys.executable)),
            "CET runtime configuration changed.")
    require(evidence["artifacts"] == artifacts(directory), "CET artifact set or bytes changed.")
    check_build_config(directory, evidence["tools"])
    require(set(evidence["binaries"]) == set(NAMES) | {"knmon-cet-probe.exe"}, "CET binary inventory differs.")
    for name, binary in evidence["binaries"].items():
        path = contained(directory, "binaries/" + name)
        source = directory / "probe-build/Debug" / name if name == "knmon-cet-probe.exe" else ROOT / "build/native-msvc/Debug" / name
        require(binary == {"source": str(source), "sha256": digest_file(source)} and digest_file(path) == binary["sha256"] and machine(path) == 0x8664,
                "CET binary changed or has a different architecture.")
    commands = build_commands(directory, Path(evidence["tools"]["cmake"]["path"]), Path(evidence["tools"]["link"]["path"]))
    require(set(evidence["buildSteps"]) == set(commands), "CET build or PE inspection step is missing.")
    for name, command in commands.items():
        check_step(directory, name, command, evidence["buildSteps"][name], 180000)
    require(b"PE hardening passed:" in read_bytes(directory / "hardening.log"), "CET PE inspection did not pass.")
    require(set(evidence["probeSteps"]) == {"enforcement", "timeout", "output"}, "CET executed probe controls are incomplete.")
    for name, extra in (("enforcement", []), ("timeout", ["--timeout-control"]), ("output", ["--output-control"])):
        check_step(directory, name, [str(directory / "binaries/knmon-cet-probe.exe"), *extra], evidence["probeSteps"][name])
    enforcement = probe(read_json(contained(directory, "enforcement.log")))
    for name in ("timeout", "output"):
        cleanup_control(read_json(contained(directory, name + ".log")), name)
    require(same(enforcement, evidence["enforcement"]) and enforcement["status"] == evidence["status"], "CET enforcement summary differs from its raw controls.")
    runs = evidence["runs"]
    expected = schedule() if enforcement["status"] == "passed" else []
    require(type(runs) is list and same([(row["strict"], row["mode"], row["stop"]) for row in runs], expected),
            "CET compatibility matrix is incomplete or differs.")
    behavior, identities = [], []
    for row, (strict, mode, stop) in zip(runs, expected):
        name = trial_name(strict, mode, stop)
        require(row["directory"] == name, "CET trial directory differs.")
        trial = contained(directory, name)
        require(same(row["summary"], verify_trial(trial, strict, mode, stop)), "CET compatibility summary differs from raw evidence.")
        behavior.append(semantic(read_json(trial / "oracle.json")))
        identity = read_json(trial / "execution.json")["policies"]["before"]
        identities.append((identity["pid"], identity["created100ns"]))
    require(all(value == behavior[0] for value in behavior) and len(identities) == len(set(identities)), "CET modes changed caller behavior or reused a process.")
    require(evidence["artifacts"] == artifacts(directory) and evidence["producers"] == producers() and
            evidence["nativeSourceSha256"] == native_source(pinned_node()) and digest_file(directory / "evidence.json") == initial,
            "CET evidence inputs changed during verification.")
    return evidence


def produce():
    directory = Path(tempfile.mkdtemp(prefix="cet-evidence-", dir=ROOT / "build"))
    print("CET evidence: " + str(directory), flush=True)
    evidence = {"schemaVersion": 1, "status": "failed", "scope": SCOPE, "assurance": ASSURANCE, "configuration": "Debug",
                "observedAtUtc": datetime.now(timezone.utc).isoformat(), "windowsVersion": str(sys.getwindowsversion()),
                "cpuCount": os.cpu_count(),
                "tools": {}, "binaries": {}, "buildSteps": {}, "probeSteps": {}, "runs": []}
    try:
        evidence.update(producers=producers(), nativeSourceSha256=native_source(pinned_node()))
        env = {**environment(pinned_node()), "VSLANG": "1033"}
        cmake = Path(shutil.which("cmake") or "absent-cmake").resolve(strict=True)
        evidence["tools"] = {name: tool_record(path) for name, path in (("node", pinned_node()), ("python", Path(sys.executable)), ("cmake", cmake))}
        commands = build_commands(directory, cmake, Path("unused"))
        evidence["buildSteps"]["configure"] = step(directory, "configure", commands["configure"], env, 120)
        cache = (directory / "probe-build/CMakeCache.txt").read_text(encoding="utf-8")
        for name, variable in (("link", "CMAKE_LINKER"), ("ml64", "CMAKE_ASM_MASM_COMPILER")):
            matches = re.findall(r"^" + variable + r":FILEPATH=(.+)$", cache, re.MULTILINE)
            require(len(matches) == 1, "CET build tool path is ambiguous.")
            evidence["tools"][name] = tool_record(Path(matches[0]))
        compiler_files = list((directory / "probe-build/CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
        require(len(compiler_files) == 1, "CET compiler configuration is ambiguous.")
        compiler = re.findall(r'set\(CMAKE_CXX_COMPILER "([^"]+)"\)', compiler_files[0].read_text(encoding="utf-8"))
        require(len(compiler) == 1, "CET C++ compiler path is absent.")
        evidence["tools"]["cl"] = tool_record(Path(compiler[0]))
        for source, name in ((directory / "probe-build/CMakeCache.txt", "cmake-cache.txt"), (compiler_files[0], "cxx-compiler.txt")):
            shutil.copyfile(source, directory / name)
        evidence["buildSteps"]["build"] = step(directory, "build", commands["build"], env, 120)
        (directory / "binaries").mkdir()
        for name in (*NAMES, "knmon-cet-probe.exe"):
            source = directory / "probe-build/Debug" / name if name == "knmon-cet-probe.exe" else ROOT / "build/native-msvc/Debug" / name
            fingerprint = digest_file(source)
            shutil.copyfile(source, directory / "binaries" / name)
            require(digest_file(source) == digest_file(directory / "binaries" / name) == fingerprint, "CET binary changed during staging.")
            evidence["binaries"][name] = {"source": str(source), "sha256": fingerprint}
        commands = build_commands(directory, cmake, Path(evidence["tools"]["link"]["path"]))
        evidence["buildSteps"]["hardening"] = step(directory, "hardening", commands["hardening"], env)
        for name, extra in (("enforcement", []), ("timeout", ["--timeout-control"]), ("output", ["--output-control"])):
            evidence["probeSteps"][name] = step(directory, name, [str(directory / "binaries/knmon-cet-probe.exe"), *extra], env)
        evidence["enforcement"] = probe(read_json(directory / "enforcement.log"))
        for name in ("timeout", "output"):
            cleanup_control(read_json(directory / (name + ".log")), name)
        if evidence["enforcement"]["status"] == "passed":
            for strict, mode, stop in schedule():
                name = trial_name(strict, mode, stop)
                summary = execute(directory / name, strict, mode, stop, env)
                evidence["runs"].append({"strict": strict, "mode": mode, "stop": stop, "directory": name, "summary": summary})
                print("CET compatibility: " + name + " passed", flush=True)
        require(evidence["producers"] == producers(), "CET producer changed during execution.")
        evidence["status"] = evidence["enforcement"]["status"]
        evidence["artifacts"] = artifacts(directory)
        write_json(directory / "evidence.json", evidence)
        verify(directory)
        return directory, evidence
    except BaseException as error:
        evidence.update(status="failed", failure=str(error), artifacts=artifacts(directory))
        write_json(directory / "evidence.json", evidence)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        directory, evidence = args.verify, verify(args.verify)
    else:
        directory, evidence = produce()
    print(json.dumps({"status": evidence["status"], "scope": SCOPE, "directory": str(directory), "runs": len(evidence["runs"])}), flush=True)
    return 0 if evidence["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
