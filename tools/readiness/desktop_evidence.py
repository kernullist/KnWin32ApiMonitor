"""Exercise the real desktop attach/filter/stop/export path and retain tree resources."""
import argparse
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from desktop_processes import Job
from source_evidence import ROOT, SOURCE_TREES, contained, digest_file, read_bytes, read_json, reconstruction_input, require
from desktop_check import json_value, machine, verify_architecture

PRODUCERS = ("tools/readiness/desktop_evidence.py", "tools/readiness/desktop_processes.py", "tools/readiness/desktop_driver.mjs",
             "tools/readiness/desktop_check.py", "tools/readiness/source_evidence.py")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def source_hashes():
    files = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, timeout=30).decode("utf-8").split("\0")
    ignored = subprocess.check_output(["git", "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", *SOURCE_TREES], cwd=ROOT, timeout=30)
    hidden = [name for name in ignored.decode("utf-8").split("\0") if name and reconstruction_input(name) and
              not ("__pycache__" in Path(name).parts and Path(name).suffix.lower() in (".pyc", ".pyo"))]
    require(not hidden, "Unlisted build source hidden by Git ignore rules.")
    return {name: digest_file(contained(ROOT, name)) for name in sorted(set(files)) if name and reconstruction_input(name)}


def page_endpoint(profile, job):
    file = profile / "EBWebView/DevToolsActivePort"
    if not file.exists():
        return None
    data = file.read_text(encoding="ascii")
    require(len(data) <= 1024, "Invalid CDP discovery file.")
    lines = data.splitlines()
    require(len(lines) == 2 and lines[0].isdigit() and 0 < int(lines[0]) <= 65535 and lines[1].startswith("/devtools/browser/"),
            "Invalid CDP discovery endpoint.")
    port = int(lines[0])
    owner = job.listener(port)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/json/list", timeout=2) as response:
        payload = response.read(65537)
    require(len(payload) <= 65536, "CDP target list exceeds its bound.")
    targets = [item for item in json.loads(payload) if item.get("type") == "page" and item.get("url") == "http://tauri.localhost/"]
    if not targets:
        return None
    require(len(targets) == 1, "Ambiguous desktop WebView target.")
    endpoint = targets[0]["webSocketDebuggerUrl"]
    parsed = urlsplit(endpoint)
    require(parsed.scheme == "ws" and parsed.hostname == "127.0.0.1" and parsed.port == port and
            parsed.path.startswith("/devtools/page/") and not parsed.query and not parsed.fragment and not parsed.username,
            "CDP page endpoint escaped its owned listener.")
    return {"endpoint": endpoint, "listener": owner, "port": port, "discovery": data}


def execute_architecture(directory, architecture, node):
    directory.mkdir()
    portable, profile, temporary = (directory / name for name in ("portable", "profile", "tmp"))
    for child in (portable, profile, temporary):
        child.mkdir()
    triple, native_dir, agent_name = ("x86_64", "native-msvc", "knmon-agent64.dll") if architecture == "x64" else ("i686", "native-msvc-x86", "knmon-agent32.dll")
    inputs = [ROOT / f"apps/knmon-ui/src-tauri/target/{triple}-pc-windows-msvc/release/knmon-ui.exe",
              *[ROOT / "build" / native_dir / "Debug" / name for name in ("knmon-native-helper.exe", "knmon-collector.exe", agent_name, "knmon-sample-fileio.exe")]]
    binaries = {}
    for source in inputs:
        require(machine(source) == (0x8664 if architecture == "x64" else 0x14C), "Desktop input binary has the wrong architecture.")
        digest = digest_file(source)
        destination = portable / source.name
        shutil.copyfile(source, destination)
        require(digest_file(destination) == digest and digest_file(source) == digest, "Desktop binary changed during staging.")
        binaries[source.name] = {"source": str(source), "path": str(destination), "sha256": digest}
    report = {"schemaVersion": 1, "architecture": architecture, "status": "failed", "binaries": binaries,
              "configuration": {"desktop": "Release", "native": "Debug", "presentation": "hidden", "samplingIntervalMs": 200}}
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith(("WEBVIEW2_", "KNMON_", "TAURI_"))}
    environment.update(TEMP=str(temporary), TMP=str(temporary))
    app_environment = {**environment, "WEBVIEW2_USER_DATA_FOLDER": str(profile),
                       "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--remote-debugging-port=0 --remote-debugging-address=127.0.0.1"}
    started = time.monotonic()
    phase = "startup"
    images = {}
    with Job() as app_job, Job() as target_job, Job() as driver_job:
        app = app_job.spawn([portable / "knmon-ui.exe"], portable, app_environment)
        report["appPid"] = app["pid"]
        report["appIdentity"] = app_job.sample_process(app["pid"])
        target, driver = None, None
        try:
            with (directory / "resources.jsonl").open("x", encoding="utf-8") as stream:
                while time.monotonic() - started < 90:
                    windows = app_job.windows(app)
                    sample = {"elapsedMs": round((time.monotonic() - started) * 1000), "phase": phase,
                              "application": app_job.sample(), "target": target_job.sample(), "windows": windows}
                    for scope in ("application", "target"):
                        for process in sample[scope]["processes"]:
                            if process["status"] == "sampled" and process["image"] not in images:
                                images[process["image"]] = digest_file(Path(process["image"]))
                    stream.write(json.dumps(sample) + "\n")
                    stream.flush()
                    require(app_job.exit_code(app) is None, "Desktop exited during the UI scenario.")
                    if driver is None:
                        endpoint = page_endpoint(profile, app_job)
                        if endpoint is not None:
                            target = target_job.spawn([portable / "knmon-sample-fileio.exe", "--attach-loop", "--iterations", "140", "--delay-ms", "250"], temporary, environment)
                            report["targetPid"], report["targetCommand"] = target["pid"], target["command"]
                            report["targetIdentity"] = target_job.sample_process(target["pid"])
                            report["cdp"] = endpoint
                            request = {"endpoint": endpoint["endpoint"], "targetPid": target["pid"], "targetPath": str(portable / "knmon-sample-fileio.exe")}
                            write_json(directory / "request.json", request)
                            driver_environment = {key: value for key, value in environment.items() if key.upper() not in ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE")}
                            driver = driver_job.spawn([node, ROOT / "tools/readiness/desktop_driver.mjs", directory / "request.json"], directory, driver_environment)
                    else:
                        phase_file = directory / "phase.txt"
                        if phase_file.exists():
                            phase_text = read_bytes(phase_file, 1024).decode("ascii")
                            complete = phase_text.split("\n")[:-1]
                            if complete:
                                phase = complete[-1]
                        driver_exit = driver_job.exit_code(driver)
                        if driver_exit is not None:
                            if "driverExit" not in report and driver_exit == 0:
                                require(target_job.exit_code(target) is None, "Target exited before detached-survival verification.")
                                report["targetAliveAfterDriver"] = True
                            report["driverExit"] = driver_exit
                            require(driver_exit == 0, "Desktop interaction driver failed; inspect driver.json.")
                            phase = "target-completion"
                            if target_job.exit_code(target) is not None:
                                report["targetExit"] = target_job.exit_code(target)
                                require(report["targetExit"] == 0, "Native target oracle failed.")
                                break
                    time.sleep(0.2)
                else:
                    raise ValueError("Desktop scenario exceeded its deadline.")
            report["applicationBeforeClose"] = app_job.accounting()
            report["targetFinal"] = target_job.accounting()
            report["closeWindows"] = app_job.windows(app, close=True)
            deadline = time.monotonic() + 10
            while app_job.exit_code(app) is None and time.monotonic() < deadline:
                time.sleep(0.1)
            report["appExit"] = app_job.exit_code(app)
            require(report["appExit"] == 0, "Desktop did not close normally.")
            report["runtime"] = {"path": report["cdp"]["listener"]["image"], "sha256": digest_file(Path(report["cdp"]["listener"]["image"]))}
            require(all(digest_file(Path(name)) == value for name, value in images.items()), "An executed process image changed during observation.")
            require(all(digest_file(Path(row[key])) == row["sha256"] for row in binaries.values() for key in ("source", "path")), "A desktop input binary changed during execution.")
            report["observedImages"] = images
            report["status"] = "passed"
        except Exception as error:
            report["failure"] = type(error).__name__ + ": " + str(error)
        finally:
            report["cleanup"] = {"application": app_job.close(), "target": target_job.close(), "driver": driver_job.close()}
            write_json(directory / "execution.json", report)
    require(report["status"] == "passed", report.get("failure", "Desktop execution failed."))
    return report


def artifacts(directory, runs):
    result = {}
    for architecture in runs:
        driver = read_json(contained(directory, architecture + "/driver.json"))
        for name in ("execution.json", "driver.json", "resources.jsonl", "capture.png", "request.json", driver["exportFile"]):
            path = contained(directory / architecture, name)
            result[path.relative_to(directory).as_posix()] = digest_file(path)
    return result


def verify(directory):
    evidence_path = contained(directory, "evidence.json")
    data = read_bytes(evidence_path)
    before = hashlib.sha256(data).hexdigest()
    evidence = json_value(data)
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed" and
            evidence["runs"] == ["x64", "x86"], "Desktop proof is incomplete or failed.")
    require(evidence["sources"] == source_hashes(), "Desktop product source fingerprint is stale.")
    require(evidence["producers"] == {name: digest_file(ROOT / name) for name in PRODUCERS}, "Desktop producer fingerprint is stale.")
    require(digest_file(Path(evidence["node"]["path"])) == evidence["node"]["sha256"], "Desktop driver runtime fingerprint is stale.")
    before_artifacts = artifacts(directory, evidence["runs"])
    require(evidence["artifacts"] == before_artifacts, "Desktop raw artifacts changed.")
    summaries = {architecture: verify_architecture(contained(directory, architecture), architecture, before_artifacts) for architecture in evidence["runs"]}
    require(evidence["summary"] == summaries, "Desktop derived summary differs from raw evidence.")
    require(artifacts(directory, evidence["runs"]) == before_artifacts and digest_file(evidence_path) == before and
            evidence["sources"] == source_hashes() and evidence["producers"] == {name: digest_file(ROOT / name) for name in PRODUCERS},
            "Desktop evidence or inputs changed during verification.")
    return {"scope": "Hidden Release desktop with Debug native tools; owned x64/x86 attach/filter/stop/export paths and sampled tree resources.",
            "assurance": "Unsigned local consistency; executable identity is recorded, not an authenticated source-to-binary mapping.",
            "windowsVersion": evidence["windowsVersion"], "observedAtUtc": evidence["observedAtUtc"], "summary": summaries}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=("x64", "x86", "both"), default="both")
    parser.add_argument("--check", type=Path)
    parser.add_argument("--node", type=Path, default=ROOT / "build/deps/node-v24.21.0-win-x64/node.exe")
    args = parser.parse_args()
    if args.check:
        print(json.dumps(verify(args.check.resolve()), indent=2))
        return 0
    directory = Path(tempfile.mkdtemp(prefix="desktop-evidence-", dir=ROOT / "build"))
    print("Desktop evidence: " + str(directory), flush=True)
    sources = source_hashes()
    producers = {name: digest_file(ROOT / name) for name in PRODUCERS}
    report = {"schemaVersion": 1, "status": "failed", "observedAtUtc": datetime.now(timezone.utc).isoformat(),
              "windowsVersion": str(sys.getwindowsversion()), "cpuCount": os.cpu_count(), "sources": sources, "producers": producers,
              "node": {"path": str(args.node.resolve()), "sha256": digest_file(args.node.resolve())}, "runs": [], "summary": {}}
    try:
        for architecture in (("x64", "x86") if args.architecture == "both" else (args.architecture,)):
            execute_architecture(directory / architecture, architecture, args.node.resolve())
            report["summary"][architecture] = verify_architecture(directory / architecture, architecture)
            report["runs"].append(architecture)
        require(source_hashes() == sources, "Desktop product sources changed during execution.")
        require(producers == {name: digest_file(ROOT / name) for name in PRODUCERS}, "Desktop evidence producers changed during execution.")
        require(digest_file(args.node.resolve()) == report["node"]["sha256"], "Desktop driver runtime changed during execution.")
        report["artifacts"] = artifacts(directory, report["runs"])
        require(report["summary"] == {architecture: verify_architecture(directory / architecture, architecture, report["artifacts"]) for architecture in report["runs"]},
                "Desktop raw artifacts changed before publication.")
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    write_json(directory / "evidence.json", report)
    print(json.dumps({"status": report["status"], "failure": report.get("failure"), "directory": str(directory)}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
