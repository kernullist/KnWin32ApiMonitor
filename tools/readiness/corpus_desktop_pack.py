"""Bind and replay the complete desktop corpus matrix without promoting missing costs."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import stat
import statistics
import sys
import tempfile

sys.dont_write_bytecode = True
from corpus_desktop import PRODUCERS, stage, execute, binaries_for, write_json
from corpus_desktop_check import verify_trial
from desktop_evidence import source_hashes
from desktop_check import machine
from native_profile_costs import MODES, ARCHITECTURES, ITERATIONS, REPETITIONS, pinned_node, same, semantic
from source_evidence import ROOT, digest_file, read_json, require

SCOPE = "Hidden Release desktop with Debug native tools; paced six-API caller, owned Job resources and DOM counter-delivery bounds"
ASSURANCE = "Unsigned local consistency; source and executable identities are recorded, not an authenticated source-to-binary mapping"


def producers():
    return {name: digest_file(ROOT / name) for name in PRODUCERS}


def schedule():
    modes = list(MODES)
    return [(architecture, repeat, modes[(index + repeat) % len(modes)])
            for repeat in range(REPETITIONS) for architecture in ARCHITECTURES for index in range(len(modes))]


def trial_name(architecture, repeat, mode):
    return f"{architecture}-{repeat:02d}-{mode}"


def safe(root, name):
    relative = Path(name)
    require(type(name) is str and name and not relative.is_absolute() and relative.as_posix() == name and
            not any(part in ("", ".", "..") or ":" in part for part in relative.parts), "Noncanonical desktop artifact path.")
    value = root
    for part in ("", *relative.parts):
        value = value / part
        attributes = value.lstat()
        require(not stat.S_ISLNK(attributes.st_mode) and not getattr(attributes, "st_file_attributes", 0) & 0x400,
                "Desktop artifact path contains a reparse point.")
    require(value.resolve(strict=True).is_relative_to(root.resolve(strict=True)), "Desktop artifact escaped its evidence root.")
    return value


def artifacts(root):
    result, seen, total, entries = {}, set(), 0, 0
    trials = {trial_name(*item) for item in schedule()}
    binary_paths = {f"binaries/{arch}/{source.name}" for arch in ARCHITECTURES for source in binaries_for(arch)}

    def visit(directory):
        nonlocal total, entries
        for child in directory.iterdir():
            entries += 1
            require(entries <= 50000, "Desktop artifact inventory exceeds its entry bound.")
            name = child.relative_to(root).as_posix()
            path = safe(root, name)
            require(name.casefold() not in seen, "Desktop artifacts have case-alias paths.")
            seen.add(name.casefold())
            if path.is_dir():
                if len(path.relative_to(root).parts) == 2 and path.parent.name in trials and path.name in ("profile", "tmp"):
                    continue
                visit(path)
            else:
                require(path.is_file(), "Unexpected desktop artifact type.")
                if name == "evidence.json":
                    continue
                size = path.stat().st_size
                total += size
                require(size <= (128 if name in binary_paths else 32) * 1024 * 1024 and total <= 2 * 1024 ** 3,
                        "Desktop artifacts exceed their byte bound.")
                result[name] = digest_file(path)
    visit(root)
    return result


def summarize(runs):
    result = {}
    for architecture in ARCHITECTURES:
        result[architecture] = {}
        for mode in MODES:
            rows = [row["summary"] for row in runs if row["architecture"] == architecture and row["mode"] == mode]
            require(len(rows) == REPETITIONS, "Desktop repetition matrix is incomplete.")
            def med(path):
                values = []
                for row in rows:
                    value = row
                    for key in path:
                        value = value[key]
                    values.append(value)
                return statistics.median(values)
            result[architecture][mode] = {
                "repetitions": len(rows),
                "medianRunCallLatencyUs": {key: med(("caller", "callLatencyUs", key)) for key in ("median", "p95", "p99")},
                "medianWorkloadUs": med(("caller", "workloadUs")),
                "medianCallerCpu100ns": med(("caller", "targetCpu100ns")),
                "medianApplicationCpu100ns": med(("resources", "application", "cpu100ns")),
                "medianApplicationSampledRssSumBytes": med(("resources", "application", "sampledSumMaxima", "rssBytes")),
                "medianApplicationSampledPrivateSumBytes": med(("resources", "application", "sampledSumMaxima", "privateBytes")),
                "medianRunUiDeliveryMs": None if mode == "original" else {
                    side: {key: med(("uiDeliveryMs", side, key)) for key in ("median", "p95", "p99")} for side in ("lower", "upper")}}
    return result


def verify(root, record=None):
    root = root.resolve(strict=True)
    evidence_path = safe(root, "evidence.json")
    initial = digest_file(evidence_path)
    evidence = read_json(evidence_path) if record is None else record
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed" and
            evidence["scope"] == SCOPE and evidence["assurance"] == ASSURANCE and evidence["scopeStatus"] == {
                "desktopCorpus": "passed", "completeCaptureProfileCosts": "not_verified"}, "Desktop evidence scope or status differs.")
    require(type(evidence["iterations"]) is int and evidence["iterations"] == ITERATIONS and
            type(evidence["repetitions"]) is int and evidence["repetitions"] == REPETITIONS and
            evidence["windowsVersion"] == str(sys.getwindowsversion()) and
            type(evidence["cpuCount"]) is int and evidence["cpuCount"] == os.cpu_count(), "Desktop matrix or host scope differs.")
    require(datetime.fromisoformat(evidence["observedAtUtc"]).utcoffset().total_seconds() == 0, "Missing UTC observation time.")
    require(evidence["sources"] == source_hashes() and evidence["producers"] == producers(), "Desktop source or producer inputs changed.")
    require(set(evidence["tools"]) == {"node", "python"}, "Desktop runtime inventory differs.")
    for key, executable in (("node", pinned_node()), ("python", Path(sys.executable).resolve(strict=True))):
        require(evidence["tools"][key] == {"path": str(executable), "sha256": digest_file(executable)}, "Desktop runtime identity changed.")
    require(evidence["artifacts"] == artifacts(root), "Desktop raw artifact set or bytes changed.")
    require(set(evidence["binaries"]) == set(ARCHITECTURES), "Desktop architecture binaries are incomplete.")
    for architecture in ARCHITECTURES:
        binaries = evidence["binaries"][architecture]
        require(set(binaries) == {source.name for source in binaries_for(architecture)}, "Desktop staged binary inventory differs.")
        for source in binaries_for(architecture):
            staged = safe(root, f"binaries/{architecture}/{source.name}")
            require(binaries[source.name] == {"source": str(source), "sha256": digest_file(source)} and
                    digest_file(staged) == binaries[source.name]["sha256"] and machine(staged) == ARCHITECTURES[architecture][2],
                    "Desktop binary fingerprint or architecture changed.")
    runs = evidence["runs"]
    require(type(runs) is list and len(runs) == len(schedule()) and
            same([(row["architecture"], row["repetition"], row["mode"]) for row in runs], schedule()) and
            all(type(row["repetition"]) is int for row in runs), "Desktop matrix or rotated order differs.")
    images, behavior = {}, {}
    for row in runs:
        arch, repeat, mode = row["architecture"], row["repetition"], row["mode"]
        directory = safe(root, trial_name(arch, repeat, mode))
        summary = verify_trial(directory, arch, mode)
        require(same(row["summary"], summary), "Desktop trial summary differs from raw observations.")
        execution = read_json(safe(directory, "execution.json"))
        request = read_json(safe(directory, "request.json"))
        portable, corpus = root / "binaries" / arch, directory / "corpus"
        require(same(execution["commands"], {
            "application": {"argv": [str(portable / "knmon-ui.exe")], "cwd": str(portable)},
            "target": {"argv": [str(portable / "knmon-comparison-target.exe"), str(corpus), str(ITERATIONS), "--coordinated",
                                 execution["controlId"], "30", "30000"], "cwd": str(corpus)},
            "driver": {"argv": [str(pinned_node()), str(ROOT / "tools/readiness/corpus_desktop_driver.mjs"), str(directory / "request.json")],
                       "cwd": str(ROOT)}}), "Desktop execution command differs.")
        require(execution["environment"] == {"TEMP": str(directory / "tmp"), "TMP": str(directory / "tmp"),
            "WEBVIEW2_USER_DATA_FOLDER": str(directory / "profile"),
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--remote-debugging-port=0 --remote-debugging-address=127.0.0.1"},
            "Desktop isolated environment differs.")
        require(request["targetPath"] == execution["targetIdentity"]["image"] == str(portable / "knmon-comparison-target.exe") and
                execution["appIdentity"]["image"] == str(portable / "knmon-ui.exe"), "Desktop root image paths differ.")
        for image, digest in execution["observedImages"].items():
            require(re.fullmatch(r"[a-f0-9]{64}", digest) is not None and (image not in images or images[image] == digest),
                    "Observed image changed during the matrix.")
            images[image] = digest
        behavior.setdefault((arch, repeat), []).append(semantic(read_json(safe(directory, "corpus/oracle.json"))))
    require(all(all(value == values[0] for value in values) for values in behavior.values()), "Desktop capture changed independent caller behavior.")
    require(all(digest_file(Path(path)) == digest for path, digest in images.items()), "An observed process executable changed.")
    require(same(evidence["summary"], summarize(runs)), "Desktop aggregate summary differs from its trials.")
    require(evidence["artifacts"] == artifacts(root) and evidence["sources"] == source_hashes() and evidence["producers"] == producers() and
            digest_file(evidence_path) == initial, "Desktop evidence inputs changed during verification.")
    return evidence


def produce():
    root = Path(tempfile.mkdtemp(prefix="desktop-corpus-", dir=ROOT / "build"))
    print("Desktop corpus matrix: " + str(root), flush=True)
    node = pinned_node()
    evidence = {"schemaVersion": 1, "status": "failed", "scope": SCOPE, "assurance": ASSURANCE,
        "scopeStatus": {"desktopCorpus": "passed", "completeCaptureProfileCosts": "not_verified"},
        "observedAtUtc": datetime.now(timezone.utc).isoformat(), "windowsVersion": str(sys.getwindowsversion()), "cpuCount": os.cpu_count(),
        "iterations": ITERATIONS, "repetitions": REPETITIONS, "sources": source_hashes(), "producers": producers(), "binaries": {}, "runs": [],
        "tools": {key: {"path": str(path), "sha256": digest_file(path)} for key, path in
                  (("node", node), ("python", Path(sys.executable).resolve(strict=True)))}}
    try:
        require(shutil.disk_usage(root).free >= 12 * 1024 ** 3, "Desktop matrix requires at least 12 GiB free space before execution.")
        for architecture in ARCHITECTURES:
            evidence["binaries"][architecture] = stage(root / "binaries" / architecture, architecture)
        for architecture, repeat, mode in schedule():
            name = trial_name(architecture, repeat, mode)
            print("Executing " + name, flush=True)
            require(shutil.disk_usage(root).free >= 3 * 1024 ** 3, "Desktop evidence retention reached the free-space guard.")
            trial = root / name
            execute(trial, architecture, mode, root / "binaries" / architecture, node)
            summary = verify_trial(trial, architecture, mode)
            evidence["runs"].append({"architecture": architecture, "repetition": repeat, "mode": mode, "summary": summary})
        evidence["summary"] = summarize(evidence["runs"])
        evidence["artifacts"] = artifacts(root)
        evidence["status"] = "passed"
        write_json(root / "evidence.json", evidence)
        verify(root)
    except Exception as error:
        evidence.update(status="failed", failure=type(error).__name__ + ": " + str(error))
        evidence["scopeStatus"]["desktopCorpus"] = "failed"
        write_json(root / "evidence.json", evidence)
        raise
    print("Desktop corpus matrix PASS: " + str(root), flush=True)
    return root
