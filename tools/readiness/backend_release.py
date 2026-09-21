"""Run and replay the complete Release Rust backend tests with real Debug helpers."""
import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_evidence import ROOT, contained, digest_file, read_bytes, read_json, reconstruction_input, require, verify_current_sources
from source_archive import unique_object
from owned_command import run
from desktop_check import machine

ARCHITECTURES = {"x64": ("x86_64-pc-windows-msvc", "native-msvc", 0x8664, "64"),
                 "x86": ("i686-pc-windows-msvc", "native-msvc-x86", 0x14C, "32")}
PRODUCERS = ("tools/readiness/backend_release.py", "tools/readiness/source_evidence.py", "tools/readiness/desktop_check.py",
             "tools/source/owned_command.py", "tools/source/source_archive.py", "tools/source/rebuild_source.py")
TESTS = tuple(sorted([
    "security_tests::actual_helper_failed_target_is_terminal_and_keeps_error",
    "security_tests::actual_helper_stream_finishes_and_retains_launch_identity",
    "security_tests::batch_drain_is_replayable_until_ack_and_byte_bounded",
    "security_tests::bounded_command_output_refuses_invalid_or_incomplete_data",
    "security_tests::cancellation_waits_for_event_creation_without_losing_the_request",
    "security_tests::duplicate_batches_and_future_ack_are_rejected",
    "security_tests::registry_and_global_trace_memory_remain_bounded",
    "security_tests::retained_process_refuses_reused_identity_and_rollback_closes_child",
    "security_tests::startup_failures_are_terminal_and_keep_the_reason",
    "security_tests::stream_framing_has_a_bound_and_requires_a_complete_utf8_line",
    "security_tests::stream_rejects_foreign_identity_and_cannot_revive_after_failure",
    "security_tests::streaming_registration_waits_for_helper_readiness",
    "security_tests::synchronous_reader_cancellation_does_not_require_the_writer_to_exit",
    "tests::argument_observation_survives_host_roundtrip",
    "tests::captured_semantics_preserve_exact_clock_and_error_fields",
    "tests::capture_detail_preserves_policy_and_rejects_contradictory_payloads",
    "tests::stack_observation_preserves_legacy_and_rejects_false_capture",
    "tests::streaming_capture_result_frame_updates_session_cleanup_state",
    "tests::streaming_trace_batch_cursor_returns_only_new_batches",
    "tests::streaming_trace_batch_queue_accounts_host_drops",
    "tests::wait_for_native_session_terminal_returns_updated_terminal_session",
]))
TEST_ARGUMENTS = ["--include-ignored", "--test-threads=1", "--format=pretty", "--color=never"]
SCOPE = "Release Rust backend tests with matching Debug native helpers on x64 and x86"


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()


def decoded(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, "Non-finite backend evidence number."))


def sources():
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, timeout=30)
    files = {}
    for name in sorted(set(names.decode("utf-8").split("\0"))):
        if name and reconstruction_input(name):
            path = contained(ROOT, name)
            files[name] = {"bytes": path.stat().st_size, "sha256": digest_file(path)}
    manifest = {"files": files}
    verify_current_sources(manifest)
    return manifest


def producer_hashes():
    return {name: digest_file(ROOT / name) for name in PRODUCERS}


def environment(rustc=None, helper=None):
    result = {key: value for key, value in os.environ.items()
              if not key.upper().startswith(("CARGO_", "RUST", "LIBTEST_", "KNMON_", "SCCACHE_", "CCACHE_"))}
    if rustc is not None:
        result["RUSTC"] = str(rustc)
    if helper is not None:
        result["KNMON_TEST_NATIVE_HELPER"] = str(helper)
    result["CARGO_TERM_COLOR"] = "never"
    return result


def build_command(cargo, architecture):
    return [str(cargo), "test", "--manifest-path", str(ROOT / "apps/knmon-ui/src-tauri/Cargo.toml"),
            "--package", "knmon-tauri", "--lib", "--no-run", "--release", "--locked", "--target", ARCHITECTURES[architecture][0],
            "--target-dir", str(ROOT / "apps/knmon-ui/src-tauri/target"), "--message-format=json"]


def compiler_artifact(data, architecture):
    require(data.endswith(b"\n"), "Incomplete Cargo log framing.")
    messages = [decoded(line) for line in data.splitlines() if line.lstrip().startswith(b"{")]
    finished = [message for message in messages if message.get("reason") == "build-finished"]
    require(len(finished) == 1 and finished[0].get("success") is True and messages[-1] == finished[0], "Cargo build did not finish successfully.")
    require(not any(message.get("reason") == "compiler-message" and message.get("message", {}).get("level") == "error"
                    for message in messages), "Cargo reported a compiler error.")
    candidates = [message for message in messages if message.get("reason") == "compiler-artifact" and
                  message.get("target", {}).get("name") == "knmon_tauri" and message.get("executable") is not None]
    require(len(candidates) == 1, "Missing or duplicate backend test artifact.")
    artifact = candidates[0]
    target = artifact["target"]
    require(artifact["package_id"] == "path+" + (ROOT / "crates/knmon-tauri").as_uri() + "#0.1.0" and
            Path(artifact["manifest_path"]) == ROOT / "crates/knmon-tauri/Cargo.toml" and
            Path(target["src_path"]) == ROOT / "crates/knmon-tauri/src/lib.rs" and target["kind"] == ["lib"] and
            target["crate_types"] == ["lib"] and target["test"] is True and artifact["features"] == [], "Cargo backend package or test target differs.")
    require(artifact["profile"] == {"opt_level": "3", "debuginfo": 0, "debug_assertions": False, "overflow_checks": False, "test": True} and
            type(artifact["profile"]["test"]) is bool and type(artifact["profile"]["debuginfo"]) is int and
            artifact["profile"]["debug_assertions"] is False and artifact["profile"]["overflow_checks"] is False,
            "Backend artifact is not the expected optimized Release test profile.")
    executable = Path(artifact["executable"])
    expected = ROOT / "apps/knmon-ui/src-tauri/target" / ARCHITECTURES[architecture][0] / "release/deps"
    require(executable.parent == expected and re.fullmatch(r"knmon_tauri-[0-9a-f]+\.exe", executable.name) and
            str(executable) in artifact["filenames"], "Cargo test executable path or architecture differs.")
    return executable


def test_results(listing, output):
    require(listing.endswith(b"\n") and output.endswith(b"\n"), "Incomplete backend test log framing.")
    require(listing.decode("utf-8").splitlines() == [name + ": test" for name in TESTS], "Backend test inventory is incomplete or unexpected.")
    lines = output.decode("utf-8").splitlines()
    expected = [f"running {len(TESTS)} tests", *["test " + name + " ... ok" for name in TESTS]]
    nonempty = [line for line in lines if line]
    require(nonempty[:-1] == expected, "Backend tests were missing, duplicated, ignored or failed.")
    require(re.fullmatch(r"test result: ok\. " + str(len(TESTS)) +
                         r" passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9]+\.[0-9]+s", nonempty[-1]) is not None,
            "Backend test summary is incomplete or failed.")
    return {"passed": len(TESTS), "failed": 0, "ignored": 0, "filtered": 0, "tests": list(TESTS)}


def step(directory, label, command, env, timeout=180):
    arguments = [str(value) for value in command]
    return {"label": label, "command": arguments,
            **run(arguments, ROOT, directory / (label + ".log"), env, timeout=timeout, log_limit=16 * 1024 * 1024)}


def verify_step(directory, record, label, arguments):
    require(record["label"] == label and record["command"] == [str(value) for value in arguments] and
            type(record["exitCode"]) is int and record["exitCode"] == 0 and type(record["elapsedMs"]) is int and record["elapsedMs"] >= 0,
            "Backend command, exit status or accounting differs.")
    data = read_bytes(contained(directory, label + ".log"), 16 * 1024 * 1024)
    require(type(record["logBytes"]) is int and len(data) == record["logBytes"] and hashlib.sha256(data).hexdigest() == record["logSha256"],
            "Backend command log changed.")
    require(read_json(contained(directory, label + ".command.json")) == {"command": record["command"], "cwd": str(ROOT)},
            "Backend owned command request differs.")
    return data


def native_names(architecture):
    return ("knmon-native-helper.exe", "knmon-agent" + ARCHITECTURES[architecture][3] + ".dll", "knmon-sample-fileio.exe", "knmon-dynamic-probe.dll")


def binary_record(source, staged, architecture):
    require(machine(source) == ARCHITECTURES[architecture][2], "Backend binary architecture differs.")
    before = digest_file(source)
    shutil.copyfile(source, staged)
    require(digest_file(source) == before and digest_file(staged) == before, "Backend binary changed while staging.")
    return {"source": str(source), "path": str(staged), "sha256": before}


def verify_binary(directory, record, source, relative, architecture):
    path = contained(directory, relative)
    require(record["path"] == str(directory / relative) and record["source"] == str(source) and
            digest_file(contained(ROOT, source.relative_to(ROOT))) == record["sha256"] and digest_file(path) == record["sha256"],
            "Backend binary identity changed.")
    require(machine(path) == ARCHITECTURES[architecture][2], "Backend binary architecture differs.")
    return path


def execute_architecture(directory, architecture, cargo, rustc):
    directory.mkdir()
    (directory / "native").mkdir()
    (directory / "backend").mkdir()
    binaries = {}
    native = ROOT / "build" / ARCHITECTURES[architecture][1] / "Debug"
    for name in native_names(architecture):
        binaries[name] = binary_record(contained(ROOT, (native / name).relative_to(ROOT)), directory / "native" / name, architecture)
    build = step(directory, "build", build_command(cargo, architecture), environment(rustc), timeout=300)
    executable = compiler_artifact(read_bytes(directory / "build.log", 16 * 1024 * 1024), architecture)
    binaries["backend"] = binary_record(contained(ROOT, executable.relative_to(ROOT)), directory / "backend" / executable.name, architecture)
    staged = directory / "backend" / executable.name
    helper = directory / "native/knmon-native-helper.exe"
    env = environment(rustc, helper)
    request = {"KNMON_TEST_NATIVE_HELPER": str(helper), "RUSTC": str(rustc)}
    (directory / "environment.json").write_bytes(encoded(request))
    listing = step(directory, "list", [staged, "--list", "--format=terse"], env)
    tests = step(directory, "tests", [staged, *TEST_ARGUMENTS], env)
    record = {"architecture": architecture, "target": ARCHITECTURES[architecture][0], "steps": [build, listing, tests], "binaries": binaries,
              "environmentSha256": digest_file(directory / "environment.json"),
              "summary": test_results(read_bytes(directory / "list.log"), read_bytes(directory / "tests.log"))}
    (directory / "execution.json").write_bytes(encoded(record))
    return record


def verify_architecture(directory, record, architecture, cargo, rustc):
    require(record["architecture"] == architecture and record["target"] == ARCHITECTURES[architecture][0], "Backend architecture record differs.")
    require(len(record["steps"]) == 3, "Incomplete backend execution steps.")
    build = verify_step(directory, record["steps"][0], "build", build_command(cargo, architecture))
    executable = compiler_artifact(build, architecture)
    binaries = record["binaries"]
    require(set(binaries) == {*native_names(architecture), "backend"}, "Backend binary set is incomplete.")
    staged = verify_binary(directory, binaries["backend"], executable, "backend/" + executable.name, architecture)
    native = ROOT / "build" / ARCHITECTURES[architecture][1] / "Debug"
    for name in native_names(architecture):
        verify_binary(directory, binaries[name], native / name, "native/" + name, architecture)
    environment_data = read_bytes(contained(directory, "environment.json"))
    require(hashlib.sha256(environment_data).hexdigest() == record["environmentSha256"] and
            decoded(environment_data) == {"KNMON_TEST_NATIVE_HELPER": str(directory / "native/knmon-native-helper.exe"), "RUSTC": str(rustc)},
            "Backend execution environment differs.")
    listing = verify_step(directory, record["steps"][1], "list", [staged, "--list", "--format=terse"])
    tests = verify_step(directory, record["steps"][2], "tests", [staged, *TEST_ARGUMENTS])
    result = test_results(listing, tests)
    require(encoded(record["summary"]) == encoded(result), "Backend summary differs from raw tests.")
    return result


def artifact_hashes(directory):
    names = []
    for label in ("locate-cargo", "locate-rustc", "cargo-version", "rustc-version"):
        names.extend((label + ".log", label + ".command.json"))
    for architecture in ARCHITECTURES:
        names.extend((architecture + "/execution.json", architecture + "/environment.json"))
        for label in ("build", "list", "tests"):
            names.extend((architecture + "/" + label + ".log", architecture + "/" + label + ".command.json"))
        names.extend(architecture + "/native/" + name for name in native_names(architecture))
        with os.scandir(contained(directory, architecture + "/backend")) as entries:
            files = list(itertools.islice(entries, 2))
        require(len(files) == 1 and files[0].is_file(follow_symlinks=False) and
                re.fullmatch(r"knmon_tauri-[0-9a-f]+\.exe", files[0].name), "Unexpected retained backend executable set.")
        names.append(architecture + "/backend/" + files[0].name)
    return {name: digest_file(contained(directory, name)) for name in names}


def verify_record(evidence, directory):
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed" and
            evidence["scope"] == SCOPE and evidence["runs"] == ["x64", "x86"], "Backend proof is incomplete or failed.")
    require(evidence["producers"] == producer_hashes(), "Backend evidence producer is stale.")
    verify_current_sources(evidence["sources"])
    before_artifacts = artifact_hashes(directory)
    tools = evidence["tools"]
    require(set(tools) == {"rustup", "cargo", "rustc", "python"}, "Backend tool inventory is incomplete.")
    for name, record in tools.items():
        require(Path(record["path"]).is_absolute() and digest_file(Path(record["path"])) == record["sha256"], "Backend tool fingerprint changed.")
        if name != "python":
            require(Path(record["path"]).name.lower() == name + ".exe", "Unexpected backend tool executable.")
    require(len(evidence["steps"]) == 4, "Incomplete backend toolchain steps.")
    for index, name in enumerate(("cargo", "rustc")):
        data = verify_step(directory, evidence["steps"][index], "locate-" + name, [tools["rustup"]["path"], "which", name])
        require(data.decode("utf-8").strip() == tools[name]["path"], "Backend toolchain discovery differs.")
    cargo, rustc = tools["cargo"]["path"], tools["rustc"]["path"]
    cargo_version = verify_step(directory, evidence["steps"][2], "cargo-version", [cargo, "--version", "--verbose"]).decode("utf-8")
    rustc_version = verify_step(directory, evidence["steps"][3], "rustc-version", [rustc, "-vV"]).decode("utf-8")
    require(cargo_version.startswith("cargo ") and rustc_version.startswith("rustc ") and
            "host: x86_64-pc-windows-msvc" in rustc_version, "Unexpected backend compiler version output.")
    summary = {}
    for architecture in evidence["runs"]:
        path = contained(directory, architecture + "/execution.json")
        data = read_bytes(path)
        require(hashlib.sha256(data).hexdigest() == evidence["executionSha256"][architecture], "Backend execution record changed.")
        summary[architecture] = verify_architecture(directory / architecture, decoded(data), architecture, cargo, rustc)
    require(encoded(summary) == encoded(evidence["summary"]), "Backend aggregate summary differs.")
    verify_current_sources(evidence["sources"])
    require(evidence["producers"] == producer_hashes() and artifact_hashes(directory) == before_artifacts,
            "Backend producers or artifacts changed during verification.")
    for record in tools.values():
        require(digest_file(Path(record["path"])) == record["sha256"], "Backend tool changed during verification.")
    for architecture in evidence["runs"]:
        record = read_json(contained(directory, architecture + "/execution.json"))
        for binary in record["binaries"].values():
            require(digest_file(contained(ROOT, Path(binary["source"]).relative_to(ROOT))) == binary["sha256"], "Backend source binary changed during verification.")
    return {"scope": SCOPE, "summary": summary, "observedAtUtc": evidence["observedAtUtc"], "windowsVersion": evidence["windowsVersion"],
            "assurance": "Unsigned local consistency; Debug helper integration does not establish the native Release matrix or absence of unknown bugs."}


def verify(directory):
    path = contained(directory, "evidence.json")
    data = read_bytes(path)
    result = verify_record(decoded(data), directory)
    require(digest_file(path) == hashlib.sha256(data).hexdigest(), "Backend evidence changed during verification.")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    if args.check:
        print(json.dumps(verify(args.check.resolve()), indent=2))
        return 0
    (ROOT / "build").mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="backend-release-", dir=ROOT / "build"))
    print("Backend Release evidence: " + str(directory), flush=True)
    evidence = {"schemaVersion": 1, "status": "failed", "scope": SCOPE, "observedAtUtc": datetime.now(timezone.utc).isoformat(),
                "windowsVersion": str(sys.getwindowsversion()), "sources": sources(), "producers": producer_hashes(),
                "steps": [], "runs": [], "summary": {}, "executionSha256": {}, "tools": {}}
    standalone_lock = ROOT / "crates/knmon-tauri/Cargo.lock"
    before_lock = (digest_file(standalone_lock), standalone_lock.stat().st_mtime_ns) if standalone_lock.exists() else None
    try:
        rustup = Path(shutil.which("rustup") or "").resolve(strict=True)
        evidence["tools"]["rustup"] = {"path": str(rustup), "sha256": digest_file(rustup)}
        evidence["tools"]["python"] = {"path": sys.executable, "sha256": digest_file(Path(sys.executable))}
        for name in ("cargo", "rustc"):
            evidence["steps"].append(step(directory, "locate-" + name, [rustup, "which", name], environment(), timeout=30))
            path = Path(read_bytes(directory / ("locate-" + name + ".log")).decode("utf-8").strip()).resolve(strict=True)
            evidence["tools"][name] = {"path": str(path), "sha256": digest_file(path)}
        cargo, rustc = evidence["tools"]["cargo"]["path"], evidence["tools"]["rustc"]["path"]
        evidence["steps"].append(step(directory, "cargo-version", [cargo, "--version", "--verbose"], environment(rustc), timeout=30))
        evidence["steps"].append(step(directory, "rustc-version", [rustc, "-vV"], environment(rustc), timeout=30))
        for architecture in ARCHITECTURES:
            print("Executing backend Release: " + architecture, flush=True)
            record = execute_architecture(directory / architecture, architecture, cargo, rustc)
            evidence["summary"][architecture] = record["summary"]
            evidence["executionSha256"][architecture] = digest_file(directory / architecture / "execution.json")
            evidence["runs"].append(architecture)
        require(before_lock == ((digest_file(standalone_lock), standalone_lock.stat().st_mtime_ns) if standalone_lock.exists() else None),
                "The standalone backend lockfile changed.")
        evidence["status"] = "passed"
        verify_record(evidence, directory)
    except Exception as error:
        evidence["status"] = "failed"
        evidence["failure"] = type(error).__name__ + ": " + str(error)
    (directory / "evidence.json").write_bytes(encoded(evidence))
    print(json.dumps({"status": evidence["status"], "failure": evidence.get("failure"), "directory": str(directory)}), flush=True)
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
