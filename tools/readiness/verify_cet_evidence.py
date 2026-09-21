"""Adversarial controls for actual CET probe and API-capture evidence."""
import argparse
import copy
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from cet_evidence import verify, frames, producers, write_json, artifacts, check_build_config
from cet_check import probe, cleanup_control, capture, target_policy
from cet_process import CetJob
from desktop_processes import check
from source_evidence import ROOT, read_json, require, digest_file


def process_failure_controls(output, executable, report):
    with CetJob() as job:
        for label, arguments in (("nul-argument", ["bad\0argument"]), ("oversized-argument", ["x" * 32768])):
            try:
                job.spawn_policy([executable, *arguments], output, dict(os.environ), False)
            except ValueError:
                require(job.accounting()["totalProcesses"] == 0, "Rejected CET command created a process.")
                report["rejected"].append(label)
            else:
                raise AssertionError("Invalid CET command was accepted.")
        duplicate = w.HANDLE()
        job.api.GetCurrentProcess.argtypes, job.api.GetCurrentProcess.restype = [], w.HANDLE
        job.api.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
        job.api.DuplicateHandle.restype = w.BOOL
        assign = job.api.AssignProcessToJobObject

        def fail_assignment(_job, process):
            current = job.api.GetCurrentProcess()
            check(job.api.DuplicateHandle(current, process, current, c.byref(duplicate), 0, False, 2))
            c.set_last_error(5)
            return False

        job.api.AssignProcessToJobObject = fail_assignment
        try:
            try:
                job.spawn_policy([executable, "--child", "off", "wait"], output, dict(os.environ), False)
            except OSError as error:
                require(error.winerror == 5 and duplicate.value, "CET failed-start control did not reach Job assignment.")
                require(job.api.WaitForSingleObject(duplicate, 0) == 0, "CET failed-start child was left alive.")
                code = w.DWORD()
                check(job.api.GetExitCodeProcess(duplicate, c.byref(code)))
                require(code.value == 99 and job.accounting()["totalProcesses"] == 0,
                        "CET failed-start child was not cleaned through its owned handle.")
                report["positive"].append("actual-suspended-child-assignment-failure-cleanup")
                report["startupFailureExitCode"] = code.value
            else:
                raise AssertionError("Injected CET Job assignment failure did not fail startup.")
        finally:
            job.api.AssignProcessToJobObject = assign
            if duplicate.value:
                job.api.CloseHandle(duplicate)
    try:
        job.spawn_policy([executable], output, dict(os.environ), False)
    except ValueError:
        report["rejected"].append("closed-target-job")
    else:
        raise AssertionError("Closed CET Job accepted a new target.")


def file_controls(output, report):
    root, external = output / "inventory", output / "outside-inventory"
    root.mkdir()
    external.mkdir()
    payload = root / "raw.json"
    payload.write_bytes(b'{"value":1}\n')
    original = artifacts(root)
    payload.write_bytes(b'{"value":2}\n')
    require(artifacts(root) != original, "CET inventory ignored changed raw bytes.")
    report["positive"].append("actual-artifact-byte-change-detected")
    payload.write_bytes(b'{"value":1,"value":2}\n')
    try:
        read_json(payload)
    except ValueError:
        report["rejected"].append("actual-duplicate-json-key")
    else:
        raise AssertionError("CET raw reader accepted duplicate JSON keys.")
    link = root / "probe-build"
    command = "New-Item -ItemType Junction -Path '" + str(link).replace("'", "''") + "' -Target '" + str(external).replace("'", "''") + "' | Out-Null"
    subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], check=True, capture_output=True, timeout=15)
    require(link.is_junction() and link.resolve(strict=True) == external.resolve(strict=True), "CET junction control was not created.")
    try:
        artifacts(root)
    except ValueError as error:
        require("reparse" in str(error), "CET junction failed at the wrong boundary.")
        report["rejected"].append("actual-excluded-build-directory-junction")
    else:
        raise AssertionError("CET inventory accepted a junction in its excluded build path.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    directory = args.evidence.resolve(strict=True)
    evidence = verify(directory)
    require(evidence["status"] == "passed", "Adversarial CET controls require an executed supported-host matrix.")
    output = Path(tempfile.mkdtemp(prefix="cet-negative-", dir=ROOT / "build"))
    report = {"status": "failed", "evidence": str(directory), "evidenceSha256": digest_file(directory / "evidence.json"),
              "producers": producers(), "rejected": [], "positive": []}
    print("CET controls: " + str(output), flush=True)

    def reject(label, base, mutate, check):
        value = copy.deepcopy(base)
        mutate(value)
        try:
            check(value)
        except (ValueError, KeyError, TypeError, IndexError, OverflowError, UnicodeError):
            report["rejected"].append(label)
        else:
            raise AssertionError("Invalid CET evidence accepted: " + label)

    try:
        process_failure_controls(output, directory / "binaries/knmon-cet-probe.exe", report)
        file_controls(output, report)
        raw = read_json(directory / "enforcement.log")
        require(probe(raw)["status"] == "passed", "CET positive enforcement control failed.")
        report["positive"].append("actual-enforcement")
        reject("missing-off-mismatch", raw, lambda value: value["cases"].pop(1), probe)
        reject("missing-strict-mismatch", raw, lambda value: value["cases"].pop(), probe)
        reject("reordered-probes", raw, lambda value: value["cases"].reverse(), probe)
        reject("bool-schema", raw, lambda value: value.update(schemaVersion=True), probe)
        for index in range(4):
            for key, bad in (("requestedPolicy", True), ("processId", 0), ("threadId", 0), ("creationTime100ns", "0"),
                             ("parentPolicyRead", False), ("parentPolicyFlags", True), ("parentPolicyError", True),
                             ("observedExit", False), ("exitCodeRead", False), ("forcedCleanup", True),
                             ("cleanupSucceeded", False), ("jobAssigned", False), ("jobAccountingRead", False),
                             ("jobActiveProcesses", 1), ("debugEvents", True), ("exitCode", True), ("exceptions", []),
                             ("error", True), ("errorStage", "debug"), ("output", "")):
                reject(f"probe-{index}-{key}", raw, lambda value, i=index, k=key, b=bad: value["cases"][i].update({k: b}), probe)
        for key, bad in (("code", 0xC0000005), ("firstChance", 1), ("threadId", 0), ("parameters", [7]), ("parameters", [True])):
            reject("violation-" + key + "-" + str(bad), raw, lambda value, k=key, b=bad: value["cases"][3]["exceptions"][1].update({k: b}), probe)
        reject("violation-returned", raw, lambda value: value["cases"][3].update(output=value["cases"][3]["output"] + '{"phase":"after","returned":73}\n'), probe)
        reject("metadata-only", raw, lambda value: value["cases"][3].update(exitCode=0, debugExitCode=0), probe)
        def change_child_policy(value):
            lines = value["cases"][2]["output"].splitlines()
            before = json.loads(lines[0])
            before["flags"] ^= 1
            value["cases"][2]["output"] = json.dumps(before) + "\n" + lines[1] + "\n"
        reject("child-policy-disagrees", raw, change_child_policy, probe)
        unsupported = copy.deepcopy(raw)
        for row in unsupported["cases"][2:]:
            row.update(parentPolicyFlags=256, exitCode=77, debugExitCode=77, exceptions=row["exceptions"][:1])
            before = json.loads(row["output"].splitlines()[0])
            before["flags"] = 256
            row["output"] = json.dumps(before) + "\n"
        require(probe(unsupported)["status"] == "not_verified", "Unsupported hardware falsely passed.")
        report["positive"].append("unsupported-policy-remains-unverified")
        for name in ("timeout", "output"):
            control = read_json(directory / (name + ".log"))
            check = lambda value, n=name: cleanup_control(value, n)
            check(control)
            report["positive"].append("actual-" + name)
            for key, bad in (("error", 0), ("forcedCleanup", False), ("cleanupSucceeded", False), ("jobActiveProcesses", 1),
                             ("exitCode", 0), ("observedExit", True), ("output", "")):
                reject(name + "-" + key, control, lambda value, k=key, b=bad: value["cases"][0].update({k: b}), check)
        for strict, stop in ((False, "bounded"), (True, "bounded"), (True, "cancel")):
            name = ("strict" if strict else "off") + "-preview-stack32-" + stop
            trial = directory / name
            execution, oracle = (read_json(trial / item) for item in ("execution.json", "oracle.json"))
            oracle.update(cetDirectory=str(trial), cetCreated100ns=execution["policies"]["before"]["created100ns"])
            raw_frames = frames(trial / "helper.log")
            target, agent = (directory / "binaries" / item for item in ("knmon-comparison-target.exe", "knmon-agent64.dll"))
            check = lambda value, o=oracle, s=stop, e=execution: capture(value, o, "preview-stack32", s, e["operationId"], target, agent)
            check(raw_frames)
            report["positive"].append(name)
            for key, bad in (("success", stop == "cancel"), ("cancelObserved", stop != "cancel"), ("architecture", "x86"),
                             ("targetProcessId", 0), ("agentCleanupSucceeded", False), ("hookCleanupOutcome", "released_by_process_exit"),
                             ("transportRecordsProduced", 449), ("transportDroppedEvents", 1), ("transportHighWaterMark", 0),
                             ("capturedEvents", [])):
                reject(name + "-" + key, raw_frames,
                       lambda value, k=key, b=bad: value[-1]["captureResult"].update({k: b}), check)
            for key, bad in (("pid", 0), ("tid", 0), ("api", "WriteFile"), ("callId", "0"), ("recordSequence", "1"),
                             ("rawReturnBits", 32), ("rawLastErrorCode", True), ("arguments", []), ("stack", []), ("captureDetail", "metadata")):
                reject(name + "-event-" + key, raw_frames,
                       lambda value, k=key, b=bad: value[-1]["captureResult"]["capturedEvents"][0].update({k: b}), check)
            reject(name + "-preview", raw_frames,
                   lambda value: value[-1]["captureResult"]["capturedEvents"][1].update(bufferPreview="00"), check)
            reject(name + "-no-readiness", raw_frames,
                   lambda value: value.__setitem__(slice(None), [row for row in value if row["session"]["sessionState"] != "running"]), check)
            reject(name + "-readiness-after-stop", raw_frames, lambda value: value.__setitem__(slice(2, 4), [value[3], value[2]]), check)
            reject(name + "-missing-history-loss-fields", raw_frames,
                   lambda value: [value[-1]["captureResult"]["retainedHistory"].pop(key) for key in list(value[-1]["captureResult"]["retainedHistory"]) if key.startswith("omitted")], check)
            reject(name + "-wrong-api-selection", raw_frames,
                   lambda value: value[-1]["captureResult"].update(apiSelection="kernel32.dll!Sleep"), check)
            reject(name + "-missing-handshake", raw_frames,
                   lambda value: value[-1]["captureResult"]["handshake"].update(received=False), check)
            reject(name + "-agent-event-disagrees", raw_frames,
                   lambda value: next(row for row in value[-1]["captureResult"]["agentMessages"] if row["messageType"] == "api_call").update(rawReturnValue="0"), check)
            for kind in ("agent_hello", "agent_ready", "agent_shutdown"):
                for key, bad in (("operationId", "different"), ("pid", True), ("channelNonce", "0" * 64), ("sequence", True)):
                    reject(name + "-" + kind + "-" + key, raw_frames,
                           lambda value, k=key, b=bad, t=kind: next(row for row in value[-1]["captureResult"]["agentMessages"] if row["messageType"] == t).update({k: b}), check)
            policy = execution["policies"]["before"]
            for key, bad in (("flags", 256 if strict else 277), ("flags", True), ("pid", 0), ("tid", 0), ("created100ns", "0"),
                             ("requestedPolicy", 0), ("queried", False), ("error", True), ("alive", False), ("image", "absent.exe")):
                reject(name + "-policy-" + key + "-" + str(bad), policy,
                       lambda value, k=key, b=bad: value.update({k: b}), lambda value, s=strict, o=oracle: target_policy(value, s, target, o))
        for key, bad in (("scope", "universal"), ("configuration", "Release"), ("producers", {}), ("nativeSourceSha256", "0" * 64),
                         ("artifacts", {}), ("binaries", {}), ("runs", []), ("tools", {}), ("status", "failed")):
            reject("pack-" + key, evidence, lambda value, k=key, b=bad: value.update({k: b}), lambda value: verify(directory, value))
        for name in ("cl", "link", "ml64"):
            reject("configured-tool-" + name, evidence["tools"],
                   lambda value, n=name: value[n].update(path=str(output / (n + ".exe"))), lambda value: check_build_config(directory, value))
        require(report["producers"] == producers() and report["evidenceSha256"] == digest_file(directory / "evidence.json"),
                "CET controls changed their source or positive evidence.")
        report["status"] = "passed"
        print(json.dumps({"status": "passed", "negativeControls": len(report["rejected"]), "positiveControls": len(report["positive"])}), flush=True)
    finally:
        write_json(output / "controls.json", report)


if __name__ == "__main__":
    main()
