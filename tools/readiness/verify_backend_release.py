"""Adversarial controls for Release backend artifacts and complete test execution."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
from backend_release import (ROOT, TESTS, TEST_ARGUMENTS, compiler_artifact, decoded, encoded, environment, native_names,
                             test_results, verify, verify_architecture, verify_binary, verify_record)
from source_evidence import digest_file, read_bytes, read_json, require
from owned_command import run


def rejected(function, label, expected):
    try:
        function()
    except (ValueError, RuntimeError, OSError) as error:
        require(expected in str(error), "Backend negative failed at an unintended boundary: " + label + ": " + str(error))
        print("Rejected: " + label, flush=True)
    else:
        raise RuntimeError("Backend negative control accepted: " + label)


def rewrite_paths(value, old, new):
    if isinstance(value, dict):
        return {key: rewrite_paths(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [rewrite_paths(item, old, new) for item in value]
    if isinstance(value, str):
        return value.replace(str(old), str(new))
    return value


def retained_fixture(source, destination):
    shutil.copytree(source, destination)
    for path in destination.rglob("*.json"):
        path.write_bytes(encoded(rewrite_paths(read_json(path), source, destination)))
    evidence = read_json(destination / "evidence.json")
    for architecture in evidence["runs"]:
        path = destination / architecture / "execution.json"
        execution = read_json(path)
        execution["environmentSha256"] = digest_file(destination / architecture / "environment.json")
        path.write_bytes(encoded(execution))
        evidence["executionSha256"][architecture] = digest_file(path)
    (destination / "evidence.json").write_bytes(encoded(evidence))
    verify(destination)
    return evidence


def parser_controls(directory):
    listing, output = read_bytes(directory / "x64/list.log"), read_bytes(directory / "x64/tests.log")
    test_results(listing, output)
    name = b"security_tests::actual_helper_stream_finishes_and_retains_launch_identity"
    passed = str(len(TESTS)).encode() + b" passed"
    for label, changed_listing, changed_output, expected in (
        ("omitted inventory entry", b"".join(line for line in listing.splitlines(keepends=True) if not line.startswith(name + b": test")), output, "inventory"),
        ("unexpected inventory entry", listing + b"extra::test: test\n", output, "inventory"),
        ("ignored real helper", listing, output.replace(name + b" ... ok", name + b" ... ignored"), "missing, duplicated, ignored or failed"),
        ("failed real helper", listing, output.replace(name + b" ... ok", name + b" ... FAILED"), "missing, duplicated, ignored or failed"),
        ("duplicate result", listing, output.replace(name + b" ... ok", name + b" ... ok\ntest " + name + b" ... ok"), "missing, duplicated, ignored or failed"),
        ("false pass count", listing, output.replace(passed, b"0 passed"), "summary"),
        ("filtered tests", listing, output.replace(b"0 filtered out", b"1 filtered out"), "summary"),
        ("empty results", listing, b"\n", "missing, duplicated, ignored or failed"),
        ("truncated output", listing, output.rstrip(b"\r\n"), "framing"),
        ("truncated inventory", listing.rstrip(b"\r\n"), output, "framing"),
    ):
        require(changed_listing != listing or changed_output != output, "Negative test mutation was ineffective: " + label)
        rejected(lambda: test_results(changed_listing, changed_output), label, expected)
    data = read_bytes(directory / "x64/build.log", 16 * 1024 * 1024)
    compiler_artifact(data, "x64")
    messages = [decoded(line) for line in data.splitlines() if line.lstrip().startswith(b"{")]
    artifact = next(index for index, value in enumerate(messages) if value.get("reason") == "compiler-artifact" and
                    value.get("target", {}).get("name") == "knmon_tauri" and value.get("executable"))
    for label, edit, expected in (
        ("missing build completion", lambda value: value.pop(), "did not finish"),
        ("failed build", lambda value: value[-1].update(success=False), "did not finish"),
        ("boolean build success", lambda value: value[-1].update(success=1), "did not finish"),
        ("duplicate artifact", lambda value: value.insert(artifact, copy.deepcopy(value[artifact])), "duplicate backend"),
        ("wrong package", lambda value: value[artifact].update(package_id="fixture#0.1.0"), "package or test target"),
        ("wrong source file", lambda value: value[artifact]["target"].update(src_path="C:/fixture/lib.rs"), "package or test target"),
        ("Debug profile", lambda value: value[artifact]["profile"].update(opt_level="0", debug_assertions=True), "optimized Release"),
        ("ordinary library artifact", lambda value: value[artifact]["profile"].update(test=False), "optimized Release"),
        ("boolean debug information", lambda value: value[artifact]["profile"].update(debuginfo=False), "optimized Release"),
        ("wrong target architecture", lambda value: value[artifact].update(executable=value[artifact]["executable"].replace("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")), "path or architecture"),
        ("unlisted executable", lambda value: value[artifact].update(filenames=[]), "path or architecture"),
    ):
        changed = copy.deepcopy(messages)
        edit(changed)
        payload = b"".join(json.dumps(message).encode() + b"\n" for message in changed)
        rejected(lambda: compiler_artifact(payload, "x64"), label, expected)
    rejected(lambda: decoded(b'{"status":"passed","status":"failed"}'), "duplicate JSON key", "Duplicate source manifest key")
    rejected(lambda: decoded(b'{"value":NaN}'), "non-finite JSON", "Non-finite backend")


def artifact_controls(directory, evidence):
    for label, edit, expected in (
        ("failed evidence", lambda value: value.update(status="failed"), "incomplete or failed"),
        ("boolean schema version", lambda value: value.update(schemaVersion=True), "incomplete or failed"),
        ("missing architecture", lambda value: value.update(runs=["x64"]), "incomplete or failed"),
        ("stale producer", lambda value: value["producers"].update({"tools/readiness/backend_release.py": "0" * 64}), "producer is stale"),
        ("wrong source set", lambda value: value["sources"]["files"].pop(".cargo/config.toml"), "file set differs"),
        ("wrong aggregate", lambda value: value["summary"]["x64"].update(passed=0), "aggregate summary"),
        ("boolean aggregate count", lambda value: value["summary"]["x64"].update(failed=False), "aggregate summary"),
        ("changed execution binding", lambda value: value["executionSha256"].update(x64="0" * 64), "record changed"),
        ("changed compiler", lambda value: value["tools"]["rustc"].update(sha256="0" * 64), "tool fingerprint"),
    ):
        changed = copy.deepcopy(evidence)
        edit(changed)
        rejected(lambda: verify_record(changed, directory), label, expected)
    architecture = directory / "x64"
    record = read_json(architecture / "execution.json")
    cargo, rustc = evidence["tools"]["cargo"]["path"], evidence["tools"]["rustc"]["path"]
    for label, edit, expected in (
        ("nonzero command status", lambda value: value["steps"][2].update(exitCode=1), "command, exit status"),
        ("boolean command status", lambda value: value["steps"][2].update(exitCode=False), "command, exit status"),
        ("missing include-ignored", lambda value: value["steps"][2]["command"].remove("--include-ignored"), "command, exit status"),
        ("lost native binary", lambda value: value["binaries"].pop("knmon-dynamic-probe.dll"), "binary set"),
        ("wrong binary hash", lambda value: value["binaries"]["backend"].update(sha256="0" * 64), "binary identity"),
        ("boolean result count", lambda value: value["summary"].update(ignored=False), "summary differs"),
    ):
        changed = copy.deepcopy(record)
        edit(changed)
        rejected(lambda: verify_architecture(architecture, changed, "x64", cargo, rustc), label, expected)
    binary = record["binaries"]["backend"]
    rejected(lambda: verify_binary(architecture, binary, Path(binary["source"]), "backend/" + Path(binary["path"]).name, "x86"),
             "actual wrong PE architecture", "binary architecture")
    log = architecture / "tests.log"
    saved = log.read_bytes()
    changed_bytes = saved.replace(str(len(TESTS)).encode() + b" passed", b"0 passed")
    log.write_bytes(changed_bytes)
    changed = copy.deepcopy(record)
    changed["steps"][2].update(logBytes=len(changed_bytes), logSha256=hashlib.sha256(changed_bytes).hexdigest())
    rejected(lambda: verify_architecture(architecture, changed, "x64", cargo, rustc), "rehash false test summary", "summary is incomplete")
    log.write_bytes(saved)
    path = architecture / "environment.json"
    saved = path.read_bytes()
    path.write_bytes(encoded({"KNMON_TEST_NATIVE_HELPER": "C:/foreign/helper.exe", "RUSTC": rustc}))
    changed = copy.deepcopy(record)
    changed["environmentSha256"] = digest_file(path)
    rejected(lambda: verify_architecture(architecture, changed, "x64", cargo, rustc), "rehash wrong helper environment", "environment differs")
    path.write_bytes(saved)
    verify(directory)


def actual_controls(directory, evidence, output):
    for architecture in evidence["runs"]:
        record = read_json(directory / architecture / "execution.json")
        executable = record["binaries"]["backend"]["path"]
        helper = directory / architecture / "native/knmon-native-helper.exe"
        rustc = evidence["tools"]["rustc"]["path"]
        log = output / (architecture + "-ignored.log")
        run([executable, *TEST_ARGUMENTS[1:]], ROOT, log, environment(rustc, helper), timeout=180)
        rejected(lambda: test_results(read_bytes(directory / architecture / "list.log"), read_bytes(log)),
                 architecture + " actual default ignored helper", "missing, duplicated, ignored or failed")
        missing = output / (architecture + "-missing-agent")
        missing.mkdir()
        for name in native_names(architecture):
            if not name.startswith("knmon-agent"):
                shutil.copyfile(directory / architecture / "native" / name, missing / name)
        log = output / (architecture + "-missing-agent.log")
        test_name = "security_tests::actual_helper_stream_finishes_and_retains_launch_identity"
        rejected(lambda: run([executable, *TEST_ARGUMENTS, "--exact", test_name], ROOT, log,
                             environment(rustc, missing / "knmon-native-helper.exe"), timeout=60),
                 architecture + " actual missing agent failure", "Owned command failed (101)")
        text = read_bytes(log)
        require(test_name.encode() + b" ... FAILED" in text and
                ("0 passed; 1 failed; 0 ignored; 0 measured; " + str(len(TESTS) - 1) + " filtered out").encode() in text,
                "Missing-agent negative did not execute the intended real helper test.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    directory = args.evidence.resolve()
    verify(directory)
    output = Path(tempfile.mkdtemp(prefix="backend-negative-", dir=ROOT / "build"))
    print("Backend negative evidence: " + str(output), flush=True)
    parser_controls(directory)
    fixture = output / "retained-fixture"
    evidence = retained_fixture(directory, fixture)
    artifact_controls(fixture, evidence)
    actual_controls(directory, read_json(directory / "evidence.json"), output)
    verify(directory)
    print("Backend Release adversarial validation PASS: " + str(output), flush=True)


if __name__ == "__main__":
    main()
