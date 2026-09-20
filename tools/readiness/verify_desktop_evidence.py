"""Adversarial controls for desktop ownership, cleanup and raw evidence validation."""
import argparse
import copy
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
import socket
import tempfile
import time

sys.dont_write_bytecode = True
from desktop_check import json_lines, resource_summary, validate_endpoint, verify_architecture, verify_interaction
from desktop_evidence import artifacts
from desktop_processes import Job
from source_evidence import ROOT, read_json, require


def rejected(function, label, expected):
    try:
        function()
    except (ValueError, RuntimeError, OSError) as error:
        require(expected in str(error), "Desktop negative failed at an unintended boundary: " + label + ": " + str(error))
        print("Rejected: " + label, flush=True)
    else:
        raise RuntimeError("Desktop negative control accepted: " + label)


def wait_for(function, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if function():
            return
        time.sleep(0.05)
    raise RuntimeError("Desktop process control deadline exceeded.")


def ownership_controls(output):
    environment = dict(os.environ)
    marker = output / "child-ready.txt"
    child_script = "import pathlib,time; p=pathlib.Path(__import__('sys').argv[1]); p.write_text('ready'); time.sleep(60)"
    parent_script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); time.sleep(60)"
    with Job() as job:
        parent = job.spawn([sys.executable, "-c", parent_script, child_script, str(marker)], output, environment)
        wait_for(marker.is_file)
        require(len(job.pids()) >= 2, "Owned descendant was not assigned to the Job.")
        require(job.sample_process(parent["pid"])["status"] == "sampled", "Owned root was not sampled.")
        rejected(lambda: job.sample_process(os.getpid()), "foreign process identity", "owned Job")
        require(job.close()["activeProcesses"] == 0, "Owned descendant tree did not drain.")
    print("Passed: actual owned descendant cleanup", flush=True)
    with Job() as job, socket.socket() as listener:
        listener.bind(("0.0.0.0", 0))
        listener.listen(1)
        rejected(lambda: job.listener(listener.getsockname()[1]), "wildcard CDP listener", "loopback-only")
    with Job() as job, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        rejected(lambda: job.listener(listener.getsockname()[1]), "foreign CDP listener", "owned Job")
    with Job() as job:
        count = w.DWORD()
        bad_image = output / "invalid.exe"
        bad_image.write_bytes(b"not a PE image")
        rejected(lambda: job.spawn([bad_image], output, environment), "invalid executable warmup", "WinError")
        job.api.GetProcessHandleCount(w.HANDLE(-1), c.byref(count))
        before = count.value
        for _ in range(4):
            rejected(lambda: job.spawn([bad_image], output, environment), "invalid executable", "WinError")
        rejected(lambda: job.spawn([sys.executable, "-c", "pass\0ignored"], output, environment), "embedded command NUL", "command line")
        rejected(lambda: job.spawn([sys.executable], output, {**environment, "BAD": "\0"}), "embedded environment NUL", "environment")
        original = job.api.AssignProcessToJobObject
        def failed_assignment(*_):
            c.set_last_error(5)
            return False
        job.api.AssignProcessToJobObject = failed_assignment
        never_started = output / "must-not-run.txt"
        try:
            for _ in range(4):
                rejected(lambda: job.spawn([sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')", never_started],
                                          output, environment), "failed assignment before resume", "5")
        finally:
            job.api.AssignProcessToJobObject = original
        require(not never_started.exists() and not job.pids(), "A failed startup process executed or escaped cleanup.")
        job.api.GetProcessHandleCount(w.HANDLE(-1), c.byref(count))
        require(count.value <= before, "Failed desktop startups leaked retained handles.")
        child = job.spawn([sys.executable, "-c", "raise SystemExit(7)"], output, environment)
        wait_for(lambda: job.exit_code(child) is not None)
        require(job.exit_code(child) == 7, "Owned nonzero process status was lost.")
    print("Passed: suspended startup, failed assignment, handle stability and nonzero exit", flush=True)


def evidence_controls(directory):
    execution, driver = read_json(directory / "execution.json"), read_json(directory / "driver.json")
    events, samples = json_lines(directory / driver["exportFile"]), json_lines(directory / "resources.jsonl")
    verify_interaction(execution, driver, events)
    resource_summary(samples, execution)
    validate_endpoint(execution["cdp"])
    for endpoint in ("ws://example.invalid:1234/devtools/page/12345678", "ws://127.0.0.1:1234@evil.invalid/devtools/page/12345678"):
        changed = copy.deepcopy(execution["cdp"])
        changed["endpoint"] = endpoint
        rejected(lambda: validate_endpoint(changed), "escaped CDP endpoint", "escaped")
    for label, edit, message in (
        ("missing UI phase", lambda value: value["observations"].pop(2), "phases"),
        ("wrong page", lambda value: value["observations"][2].update(url="https://example.invalid/"), "page identity"),
        ("renderer exception", lambda value: value["errors"].append({"text": "failure"}), "interaction failed"),
        ("ownership poll failure", lambda value: value["observations"][3].update(output=value["observations"][3]["output"] + "\nnative_ownership_poll_failed: list_daemon_sessions; failure"), "polling failure"),
        ("trace drain failure", lambda value: value["observations"][4].update(output=value["observations"][4]["output"] + "\nstream_batch_poll_failed: drain_native_trace_batches; failure"), "polling failure"),
        ("nonempty initial trace", lambda value: value["observations"][0]["rows"].append(["1"]), "preexisting"),
        ("wrong target selection", lambda value: value["observations"][1].update(selectedTarget="wrong"), "owned target"),
        ("dropped native events", lambda value: value["observations"][2].update(status=value["observations"][2]["status"].replace("Dropped: 0", "Dropped: 1")), "event loss"),
        ("wrong filtered row", lambda value: value["observations"][3]["rows"][0].__setitem__(5, "ReadFile"), "filtering"),
        ("failed UI stop", lambda value: value["observations"][4].update(session="running"), "stop"),
        ("wrong rendered TID", lambda value: value["observations"][2]["rows"][0].__setitem__(3, "0"), "differs from the exported"),
    ):
        changed = copy.deepcopy(driver)
        edit(changed)
        rejected(lambda: verify_interaction(execution, changed, events), label, message)
    for label, edit, message in (
        ("lost exported record", lambda value: value.pop(), "counters"),
        ("duplicate exported sequence", lambda value: value[1].update(recordSequence="0"), "sequence"),
        ("wrong exported PID", lambda value: value[0].update(pid=1), "event identity"),
        ("fake capture origin", lambda value: value[0].update(tags=[]), "event identity"),
        ("reversed native timing", lambda value: value[0]["timing"].update(endQpc="0"), "timing"),
        ("failed target call", lambda value: value[0].update(outcome="failure"), "operation failed"),
        ("wrong memory preview", lambda value: next(row for row in value if row["api"] == "WriteFile").update(bufferPreview="00"), "buffer payload"),
    ):
        changed = copy.deepcopy(events)
        edit(changed)
        rejected(lambda: verify_interaction(execution, driver, changed), label, message)
    index = next(index for index, row in enumerate(samples) if row["application"]["processes"] and row["phase"] == "capture")
    for label, edit, message in (
        ("too few resource samples", lambda value: value.__delitem__(slice(40, None)), "sample count"),
        ("resource gap", lambda value: value[1].update(elapsedMs=value[0]["elapsedMs"] + 4000), "gaps"),
        ("visible presentation", lambda value: value[index].update(windows=[{"visible": True}]), "hidden"),
        ("unqueryable live process", lambda value: value[index]["application"]["processes"][0].update(status="unavailable"), "live process"),
        ("duplicate sampled PID", lambda value: value[index]["application"]["processes"].append(value[index]["application"]["processes"][0]), "duplicate PIDs"),
        ("negative resource count", lambda value: value[index]["application"]["processes"][0].update(rssBytes=-1), "resource counters"),
        ("reversed cumulative CPU", lambda value: value[index]["application"]["job"].update(user100ns=0, kernel100ns=0), "backwards"),
        ("missing capture phase", lambda value: [row.update(phase="attach") for row in value if row["phase"] == "capture"], "resource phase"),
    ):
        changed = copy.deepcopy(samples)
        edit(changed)
        rejected(lambda: resource_summary(changed, execution), label, message)
    changed_execution = copy.deepcopy(execution)
    changed_execution["appIdentity"]["created100ns"] = "1"
    rejected(lambda: resource_summary(samples, changed_execution), "wrong retained creation time", "creation identity")
    changed_execution = copy.deepcopy(execution)
    changed_execution["observedImages"][execution["binaries"]["knmon-native-helper.exe"]["path"]] = "0" * 64
    rejected(lambda: resource_summary(samples, changed_execution), "wrong sampled helper image hash", "sampled image fingerprint")
    bound = artifacts(directory.parent, [directory.name])
    bound[directory.name + "/driver.json"] = "0" * 64
    rejected(lambda: verify_architecture(directory, directory.name, bound), "mismatched raw DOM bytes", "artifact bytes differ")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    output = Path(tempfile.mkdtemp(prefix="desktop-negative-", dir=ROOT / "build"))
    print("Desktop negative controls: " + str(output), flush=True)
    ownership_controls(output)
    if args.evidence:
        evidence_controls(args.evidence.resolve())
    print("Desktop adversarial controls passed.", flush=True)


if __name__ == "__main__":
    main()
