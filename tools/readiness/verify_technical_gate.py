"""Adversarial controls for readiness accounting and retained source artifacts."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_evidence import LABELS, ROOT, contained, expected_commands, read_json, require, verify_current_sources, verify_record, verify_steps
from technical_gate import PENDING, VALIDATED, comparative_cost, outcome, verify_bound_inputs


def rejected(function, label, message):
    try:
        function()
    except ValueError as error:
        require(message in str(error), "Negative control failed at an unintended boundary: " + label + ": " + str(error))
        print("Rejected: " + label, flush=True)
    else:
        raise RuntimeError("Negative readiness control accepted: " + label)


def fixture(directory):
    steps = [{"label": label, "command": ["C:\\fixture\\node.exe", "C:\\fixture\\npm-cli.js"]} for label in LABELS]
    for step, command in zip(steps, expected_commands(directory, steps)):
        data = ("Executed fixture command " + step["label"] + "\n").encode()
        step.update(command=command, exitCode=0, elapsedMs=10, logBytes=len(data), logSha256=hashlib.sha256(data).hexdigest())
        (directory / (step["label"] + ".log")).write_bytes(data)
        (directory / (step["label"] + ".command.json")).write_text(json.dumps({"command": command, "cwd": str(directory / "src")}), encoding="utf-8")
    return steps


def source_input_controls(output):
    root = output / "source-input-fixture"
    (root / "native").mkdir(parents=True)
    payload = {"README.md": b"Source input control.\n", ".gitignore": b"native/hidden.cpp\n", "native/known.cpp": b"int known = 1;\n"}
    manifest = {"files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in payload.items()}}
    for name, data in payload.items():
        (root / name).write_bytes(data)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, timeout=30)
    subprocess.run(["git", "add", "--", *payload], cwd=root, check=True, timeout=30, capture_output=True)
    verify_current_sources(manifest, root)
    (root / "native/hidden.cpp").write_bytes(b"int hidden = 2;\n")
    rejected(lambda: verify_current_sources(manifest, root), "ignored native input", "Unlisted build source hidden")


def junction_control(output):
    source, external = output / "junction-source", output / "external-artifacts"
    source.mkdir()
    external.mkdir()
    (external / "binary.exe").write_bytes(b"Bounded artifact boundary fixture.")
    link = source / "Debug"
    script = "New-Item -ItemType Junction -Path '" + str(link).replace("'", "''") + "' -Target '" + str(external).replace("'", "''") + "' | Out-Null"
    subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], check=True, capture_output=True, timeout=30)
    require(link.is_junction(), "Artifact junction positive control failed.")
    require(contained(link, "binary.exe").resolve() == external / "binary.exe", "Fixture did not reproduce the weak nested-root boundary.")
    rejected(lambda: contained(source, "Debug/binary.exe"), "artifact junction escapes source root", "Artifact escapes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-build", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    (ROOT / "build").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="readiness-negative-", dir=ROOT / "build"))
    print("Readiness negative evidence: " + str(output), flush=True)
    source_input_controls(output)
    junction_control(output)
    bound = output / "bound-input.json"
    bound.write_bytes(b"Original evidence.\n")
    inputs = {"fixture": {"path": str(bound), "sha256": hashlib.sha256(bound.read_bytes()).hexdigest()}}
    verify_bound_inputs(inputs)
    bound.write_bytes(b"Changed after first verification.\n")
    rejected(lambda: verify_bound_inputs(inputs), "evidence changes after first verification", "bound evidence input changed")
    bound.write_bytes(b'{"status":"passed","status":"failed"}')
    rejected(lambda: read_json(bound), "duplicate readiness JSON key", "Duplicate source manifest key")
    bound.write_bytes(b'{"value":NaN}')
    rejected(lambda: read_json(bound), "nonfinite readiness JSON", "Non-finite evidence number")
    steps = fixture(output)
    verify_steps(output, steps)
    for name, edit, error in (
        ("missing command", lambda value: value.pop(), "Incomplete or duplicate"),
        ("duplicate command", lambda value: value.append(value[0]), "Incomplete or duplicate"),
        ("failed command", lambda value: value[0].update(exitCode=7), "command or exit status"),
        ("boolean exit status", lambda value: value[0].update(exitCode=False), "command or exit status"),
        ("wrong build architecture", lambda value: value[6]["command"].remove("-Win32"), "command or exit status"),
        ("false log hash", lambda value: value[0].update(logSha256="0" * 64), "command log changed"),
        ("false log length", lambda value: value[0].update(logBytes=0), "command log changed"),
    ):
        mutated = copy.deepcopy(steps)
        edit(mutated)
        rejected(lambda: verify_steps(output, mutated), name, error)
    path = output / "preflight.command.json"
    saved = path.read_bytes()
    request = read_json(path)
    request["cwd"] = "C:\\unexpected"
    path.write_text(json.dumps(request), encoding="utf-8")
    rejected(lambda: verify_steps(output, steps), "wrong owned command directory", "Owned command request differs")
    path.write_bytes(saved)
    rows = {name: {"status": "passed"} for name in (*VALIDATED, *PENDING)}
    require(outcome(rows) == "passed", "Complete synthetic policy accounting failed.")
    rows["whole_desktop_resources"]["status"] = "not_verified"
    require(outcome(rows) == "incomplete", "Missing scope was counted as passed.")
    partial_profiles = {name: {"status": "passed"} for name in (*VALIDATED, *PENDING)}
    partial_profiles["capture_profile_costs"] = {"status": "not_verified", "nativeStatus": "passed"}
    require(outcome(partial_profiles) == "incomplete", "Native profile evidence incorrectly cleared the complete cost gate.")
    rows["source_reconstruction"]["status"] = "failed"
    require(outcome(rows) == "failed", "Failed evidence was counted as incomplete or passed.")
    missing = copy.deepcopy(rows)
    del missing["whole_desktop_resources"]
    rejected(lambda: outcome(missing), "omitted required gate", "gate set is incomplete")
    overridden = copy.deepcopy(rows)
    overridden["allowIncomplete"] = {"status": "passed"}
    rejected(lambda: outcome(overridden), "unrecognized gate override", "gate set is incomplete")
    rows["source_reconstruction"]["status"] = "skipped"
    rejected(lambda: outcome(rows), "skipped gate state", "Unknown technical gate status")
    report = {"runs": [{"architecture": arch, "mode": mode, "callLatencyUs": {"median": 5 if mode == "knmon" else 4, "p99": 7},
                         "workingSetBytes": 200 if mode == "knmon" else 100}
                        for arch in ("x64", "x86") for mode in ("knmon", "frida", "frida-cmodule")]}
    require(comparative_cost(report)["status"] == "not_verified", "Measured competitor deficit was counted as passed.")
    report["runs"] = [row for row in report["runs"] if row["mode"] != "frida-cmodule"]
    rejected(lambda: comparative_cost(report), "missing competitive mode", "Missing measured competitive mode")
    cli = subprocess.run([sys.executable, "-X", "utf8", ROOT / "tools/readiness/technical_gate.py"], cwd=ROOT, capture_output=True, timeout=120)
    (output / "missing-inputs-cli.log").write_bytes(cli.stdout + cli.stderr)
    require(cli.returncode == 2 and b"Technical readiness incomplete:" in cli.stdout, "Missing evidence did not produce an incomplete nonzero CLI result.")
    invalid_profile = output / "invalid-native-profile"
    invalid_profile.mkdir()
    (invalid_profile / "evidence.json").write_text('{"schemaVersion":1,"status":"passed"}', encoding="utf-8")
    profile_cli = subprocess.run([sys.executable, "-B", "-X", "utf8", ROOT / "tools/readiness/technical_gate.py",
                                  "--native-profiles", invalid_profile], cwd=ROOT, capture_output=True, timeout=120)
    (output / "invalid-native-profile-cli.log").write_bytes(profile_cli.stdout + profile_cli.stderr)
    require(profile_cli.returncode == 1 and b"capture_profile_costs: failed" in profile_cli.stdout,
            "Incomplete supplied native profile evidence did not fail the technical gate.")
    optimized = subprocess.run([sys.executable, "-O", ROOT / "tools/readiness/technical_gate.py"], cwd=ROOT, capture_output=True, timeout=20)
    (output / "optimized-cli.log").write_bytes(optimized.stdout + optimized.stderr)
    require(optimized.returncode != 0 and b"assertions to remain enabled" in optimized.stderr, "Optimized Python disabled evidence checks.")
    if args.source_build is not None:
        require(args.archive is not None, "Real source artifact controls require the archive.")
        directory, archive = args.source_build.resolve(), args.archive.resolve()
        evidence = read_json(directory / "evidence.json")
        verify_record(evidence, directory, archive)
        for name, edit, error in (
            ("declared failure", lambda value: value.update(status="failed"), "did not pass"),
            ("boolean evidence version", lambda value: value.update(schemaVersion=True), "did not pass"),
            ("wrong archive", lambda value: value.update(archiveSha256="0" * 64), "archive changed"),
            ("wrong source manifest", lambda value: value.update(sourceManifestSha256="0" * 64), "manifest provenance differs"),
            ("stale producer", lambda value: value["producer"].update({"owned_command.py": "0" * 64}), "producer is stale"),
            ("wrong toolchain", lambda value: value["toolchain"].update(actualNode="0.0.0"), "toolchain differs"),
            ("unexecuted command", lambda value: value["steps"].pop(), "Incomplete or duplicate"),
            ("missing architecture", lambda value: value["runs"].pop(), "Incomplete source reconstruction architectures"),
            ("wrong CTest hash", lambda value: value["runs"][0].update(ctestSha256="0" * 64), "CTest evidence differs"),
            ("skipped CTest result", lambda value: value["runs"][0]["tests"].pop(), "CTest evidence differs"),
            ("wrong compiler", lambda value: value["runs"][0].update(compilerFileSha256="0" * 64), "Compiler provenance changed"),
            ("missing binary", lambda value: value["runs"][0]["binaries"].pop("knmon-native-helper.exe"), "binaries changed or are incomplete"),
            ("false binary hash", lambda value: value["runs"][0]["binaries"].update({"knmon-native-helper.exe": "0" * 64}), "binaries changed or are incomplete"),
            ("missing frontend", lambda value: value.update(frontendArtifacts={}), "Frontend artifact inventory differs"),
        ):
            mutated = copy.deepcopy(evidence)
            edit(mutated)
            rejected(lambda: verify_record(mutated, directory, archive), name, error)
    print("Readiness adversarial validation PASS: " + str(output))


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Negative controls require Python assertions to remain enabled.")
    main()
