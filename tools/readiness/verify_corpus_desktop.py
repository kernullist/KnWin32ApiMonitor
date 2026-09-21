"""Reject corrupted desktop corpus evidence without changing the retained original."""
import argparse
import copy
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
import corpus_desktop_check as checker
import corpus_desktop_pack as pack
from desktop_evidence import page_endpoint
from corpus_desktop import write_json
from native_profile_costs import ARCHITECTURES, MODES
from source_evidence import ROOT, read_json, require


def controls(directory, trials_only=False):
    output = Path(tempfile.mkdtemp(prefix="desktop-corpus-controls-", dir=ROOT / "build"))
    report = {"schemaVersion": 1, "status": "failed", "scope": "trials-only" if trials_only else "complete-matrix",
              "evidence": str(directory), "producers": pack.producers(), "positiveTrials": [], "rejections": []}

    def rejects(label, action):
        try:
            action()
        except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
            report["rejections"].append({"label": label, "reason": type(error).__name__ + ": " + str(error)})
        else:
            raise AssertionError("Corrupted desktop corpus evidence was accepted: " + label)

    try:
        require(os.name == "nt", "Desktop handoff controls require Windows.")
        exchange = output / "exchange"
        exchange.mkdir()
        first, second = exchange / "query-000001.json", exchange / "query-000002.json"
        write_json(first, {"sequence": 1})
        with first.open("rb") as held:
            rejects("windows-open-file-replacement", lambda: write_json(first, {"sequence": 2}))
            write_json(second, {"sequence": 2})
            require(json.loads(held.read()) == {"sequence": 1} and read_json(second) == {"sequence": 2},
                    "Immutable Windows handoff interfered with the preceding reader.")
        for name in ("../evidence.json", str(directory / "evidence.json"), "binaries\\x64\\knmon-ui.exe"):
            rejects("unsafe-path/" + name, lambda name=name: pack.safe(directory, name))
        junction = output / "junction"
        script = output / "junction.ps1"
        script.write_text("param([string]$Link, [string]$Destination)\n$ErrorActionPreference = 'Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Destination | Out-Null\n", encoding="ascii")
        subprocess.run(["powershell.exe", "-NoProfile", "-File", str(script), str(junction), str(exchange)], check=True, timeout=20,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rejects("windows-junction", lambda: pack.safe(output, "junction/query-000001.json"))
        discovery = output / "discovery/EBWebView"
        discovery.mkdir(parents=True)
        port_file = discovery / "DevToolsActivePort"
        port_file.write_text("12345\n/devtools/browser/12345678", encoding="ascii")
        api = c.WinDLL("kernel32", use_last_error=True)
        api.CreateFileW.restype, api.CreateFileW.argtypes = w.HANDLE, [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        api.CloseHandle.restype, api.CloseHandle.argtypes = w.BOOL, [w.HANDLE]
        handle = api.CreateFileW(str(port_file), 0x80000000, 0, None, 3, 0x80, None)
        require(handle and handle != c.c_void_p(-1).value, "Cannot hold the WebView discovery file exclusively.")
        try:
            require(page_endpoint(discovery.parent, None) is None, "Busy WebView discovery was not deferred within the startup deadline.")
        finally:
            require(api.CloseHandle(handle), "Cannot release the discovery-file control.")
        report["busyDiscovery"] = "deferred"
        evidence = None if trials_only else pack.verify(directory)
        for label, mutate in (() if trials_only else (
            ("failed-status", lambda value: value.update(status="failed")),
            ("bool-schema", lambda value: value.update(schemaVersion=True)),
            ("bool-iterations", lambda value: value.update(iterations=True)),
            ("incomplete-scope", lambda value: value["scopeStatus"].update(completeCaptureProfileCosts="passed")),
            ("missing-producer", lambda value: value["producers"].pop(next(iter(value["producers"])))),
            ("changed-source", lambda value: value["sources"].update({next(iter(value["sources"])): "0" * 64})),
            ("unknown-tool", lambda value: value["tools"].update(extra={})),
            ("changed-node", lambda value: value["tools"]["node"].update(sha256="0" * 64)),
            ("missing-artifact", lambda value: value["artifacts"].pop(next(iter(value["artifacts"])))),
            ("changed-artifact", lambda value: value["artifacts"].update({next(iter(value["artifacts"])): "0" * 64})),
            ("missing-architecture", lambda value: value["binaries"].pop("x86")),
            ("changed-binary", lambda value: value["binaries"]["x64"]["knmon-agent64.dll"].update(sha256="0" * 64)),
            ("missing-run", lambda value: value["runs"].pop()),
            ("wrong-rotation", lambda value: value["runs"].reverse()),
            ("bool-repeat", lambda value: value["runs"][0].update(repetition=False)),
            ("forged-trial", lambda value: value["runs"][0]["summary"]["caller"].update(workloadUs=0)),
            ("forged-summary", lambda value: value["summary"]["x64"]["preview"].update(medianApplicationCpu100ns=0)),
        )):
            changed = copy.deepcopy(evidence)
            mutate(changed)
            rejects(label, lambda changed=changed: pack.verify(directory, changed))

        for architecture in ARCHITECTURES:
            for mode in MODES:
                trial = pack.safe(directory, pack.trial_name(architecture, 0, mode))
                checker.verify_trial(trial, architecture, mode)
                report["positiveTrials"].append(trial.name)
                original = {name: read_json(trial / name) for name in ("execution.json", "driver.json", "request.json", "finish.json", "corpus/oracle.json")}
                original["resources.jsonl"] = checker.json_lines(trial / "resources.jsonl")
                if mode != "original":
                    export = original["driver.json"]["exportFile"]
                    original[export] = checker.json_lines(trial / export)
                cases = [
                    ("failed-execution", "execution.json", lambda value: value.update(status="failed")),
                    ("bool-exit", "execution.json", lambda value: value.update(appExit=False)),
                    ("bool-config", "execution.json", lambda value: value["configuration"].update(stackFrames=False)),
                    ("forced-close", "execution.json", lambda value: value["naturalJobEnd"]["application"].update(activeProcesses=1)),
                    ("target-exited-early", "execution.json", lambda value: value.update(targetAliveAfterDetach=False)),
                    ("foreign-listener", "execution.json", lambda value: value["cdp"]["listener"].update(pid=0)),
                    ("wrong-runtime-image", "execution.json", lambda value: value["cdp"]["listener"].update(image="C:\\fake.exe")),
                    ("unknown-image", "execution.json", lambda value: value["observedImages"].update({"C:\\fake.exe": "0" * 64})),
                    ("early-release", "execution.json", lambda value: value["release"].update(beforeQpc="0")),
                    ("bad-qpc", "execution.json", lambda value: value.update(qpcFrequency="00")),
                    ("renderer-error", "driver.json", lambda value: value["errors"].append("failure")),
                    ("contradictory-state", "driver.json", lambda value: value["terminal"].update(status=value["terminal"]["status"].replace("State: idle", "State: failed"))),
                    ("preexisting-session", "driver.json", lambda value: value.update(initialSessions=[{}])),
                    ("incomplete-drain", "driver.json", lambda value: value["drained"].update(status="State: running\nEvents: 0/1\nDropped: 0\n")),
                    ("changed-policy", "request.json", lambda value: value.update(captureDetail="unknown")),
                    ("missing-api", "request.json", lambda value: value["allowlist"].pop()),
                    ("foreign-completion", "finish.json", lambda value: value.update(controlId="foreign")),
                    ("missing-call", "corpus/oracle.json", lambda value: value["events"].pop()),
                    ("caller-error", "corpus/oracle.json", lambda value: value.update(correct=False)),
                    ("wrong-pacing", "corpus/oracle.json", lambda value: value["coordination"].update(delayMs=0)),
                    ("missing-resources", "resources.jsonl", lambda value: value.clear()),
                    ("backward-resource-clock", "resources.jsonl", lambda value: value[1].update(beforeQpc="0")),
                    ("bool-resource-counter", "resources.jsonl", lambda value: value[0]["application"]["job"].update(user100ns=False)),
                    ("impossible-job", "resources.jsonl", lambda value: value[0]["application"]["job"].update(activeProcesses=10000)),
                    ("unknown-process-status", "resources.jsonl", lambda value: value[0]["application"]["processes"][0].update(status="unverified")),
                    ("missing-idle", "resources.jsonl", lambda value: [row.update(phase="startup") for row in value]),
                    ("missing-ui-observations", "resources.jsonl", lambda value: [row.pop("ui", None) for row in value]),
                    ("bool-ui-sequence", "resources.jsonl", lambda value: next(row["ui"] for row in value if "ui" in row).update(sequence=True)),
                    ("old-ui-clock", "resources.jsonl", lambda value: next(row["ui"] for row in value if "ui" in row).update(receivedQpc="1")),
                ]
                if mode != "original":
                    cases.extend([
                        ("missing-ready", "driver.json", lambda value: value.update(readySessions=[])),
                        ("unready-session", "driver.json", lambda value: value["readySessions"][0].update(sessionState="starting")),
                        ("wrong-helper", "driver.json", lambda value: value["sessions"][0].update(helperProcessId=0)),
                        ("unclean-detach", "driver.json", lambda value: value["sessions"][0].update(agentCleanupSucceeded=False)),
                        ("lost-event", "driver.json", lambda value: value["sessions"][0].update(transportDroppedEvents=1)),
                        ("bool-loss", "driver.json", lambda value: value["sessions"][0].update(hostDroppedBatches=False)),
                        ("false-restoration", "driver.json", lambda value: value["sessions"][0].update(shutdownEvidence='{"messageType":"wrong"}')),
                        ("unknown-row", "driver.json", lambda value: value["filtered"]["rows"][0].__setitem__(0, "0")),
                        ("missing-export", export, lambda value: value.pop()),
                        ("wrong-event-schema", export, lambda value: value[0].update(schemaVersion="9.9.9")),
                        ("reordered-export", export, lambda value: value.reverse()),
                        ("duplicate-call", export, lambda value: value[1].update(callId=value[0]["callId"])),
                        ("wrong-event-policy", export, lambda value: value[0].update(captureDetail="unknown")),
                        ("wrong-return", export, lambda value: value[-1].update(rawReturnValue="0")),
                        ("bool-width", export, lambda value: value[0].update(rawReturnBits=True)),
                        ("wrong-error", export, lambda value: value[-1].update(rawLastErrorCode=0)),
                        ("old-call-clock", export, lambda value: value[0]["timing"].update(endQpc="1")),
                        ("missing-stack-provenance", export, lambda value: value[0].pop("stackSource")),
                    ])
                    if mode.startswith("metadata"):
                        cases.append(("invented-argument", export, lambda value: value[0]["arguments"].append({})))
                    else:
                        cases.append(("missing-argument", export, lambda value: value[0]["arguments"].pop()))
                        cases.append(("wrong-corpus-directory", export, lambda value: [value[0]["arguments"][0].__setitem__(field, "C:\\unexpected\\corpus.bin")
                                                                                       for field in ("rawValue", "decodedValue")]))
                for label, name, mutate in cases:
                    changed = copy.deepcopy(original[name])
                    mutate(changed)
                    target = (trial / name).resolve()
                    def read(path, fallback):
                        return copy.deepcopy(changed) if Path(path).resolve() == target else fallback(path)
                    read_json_original, lines_original = checker.read_json, checker.json_lines
                    with patch.object(checker, "read_json", side_effect=lambda path: read(path, read_json_original)), \
                         patch.object(checker, "json_lines", side_effect=lambda path: read(path, lines_original)):
                        rejects(f"{architecture}/{mode}/{label}", lambda: checker.verify_trial(trial, architecture, mode))
        if not trials_only:
            pack.verify(directory)
        require(report["producers"] == pack.producers(), "Desktop control producers changed during validation.")
        report["status"] = "probe_controls_passed" if trials_only else "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    write_json(output / "evidence.json", report)
    print(json.dumps({"status": report["status"], "rejections": len(report["rejections"]), "directory": str(output),
                      "failure": report.get("failure")}), flush=True)
    require(report["status"] == ("probe_controls_passed" if trials_only else "passed"), report.get("failure", "Desktop corpus controls failed."))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trials-only", action="store_true")
    args = parser.parse_args()
    controls(args.directory.resolve(strict=True), args.trials_only)
