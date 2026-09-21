"""Observe a real desktop readiness failure using an isolated hook-free test Agent."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
import desktop_evidence as desktop
from source_evidence import ROOT, digest_file, read_json, require

PRODUCERS = ("tools/readiness/verify_desktop_readiness_failure.py", "tools/readiness/desktop_driver.mjs",
             "tools/readiness/desktop_evidence.py", "tools/readiness/desktop_processes.py", "tools/readiness/desktop_check.py")


def failure_driver():
    template = (ROOT / "tools/readiness/desktop_driver.mjs").read_text(encoding="utf-8")
    start = '  await waitFor(\'document.querySelector(".session-strip strong")?.textContent === "running"\', "active native session", 25000);'
    finish = '\n}\ncatch (error)\n'
    require(template.count(start) == 1 and template.count(finish) == 1, "Desktop driver failure boundary changed.")
    body = '''  await waitFor('document.querySelector(".output-log")?.innerText.includes("native_session_failed:")', "persistent native failure", 25000);
  await delay(1200);
  report.failureOwnership = await evaluate(`(async () =>
  {
    const operations = await window.__TAURI_INTERNALS__.invoke("list_native_operations");
    const sessions = await window.__TAURI_INTERNALS__.invoke("list_native_sessions");
    return { operations, sessions };
  })()`, true);
  await observe("expected-failure");
  report.failureVisible = await evaluate(`(() =>
  {
    const entry = [...document.querySelectorAll(".output-log > div")].find(row => row.innerText.startsWith("native_session_failed:"));
    const bounds = entry?.getBoundingClientRect();
    return Boolean(bounds && bounds.width > 0 && bounds.height > 0 && bounds.top >= 0 && bounds.bottom <= innerHeight);
  })()`);
  requireValue(report.failureVisible, "The native failure is outside the visible Output panel.");
  requireValue(report.errors.length === 0, "Renderer failed while displaying the native failure.");
  const screenshot = await call("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "failure.png"), Buffer.from(screenshot.data, "base64"));
  report.status = "passed";'''
    return template.split(start)[0] + body + finish + template.split(finish)[1]


def main():
    directory = Path(tempfile.mkdtemp(prefix="desktop-readiness-failure-", dir=ROOT / "build"))
    print("Desktop readiness failure controls: " + str(directory), flush=True)
    sources = desktop.source_hashes()
    producers = {name: digest_file(ROOT / name) for name in PRODUCERS}
    node = ROOT / "build/deps/node-v24.21.0-win-x64/node.exe"
    report = {"status": "failed", "scope": "Negative UI controls with hook-free missing-readiness Agent; not production capture evidence",
              "sources": sources, "producers": producers, "runs": [], "artifacts": {},
              "tools": {str(path): digest_file(path) for path in (node, Path(sys.executable))}}
    try:
        fixture = directory / "fixture"
        driver = fixture / "tools/readiness/desktop_driver.mjs"
        driver.parent.mkdir(parents=True)
        driver.write_text(failure_driver(), encoding="utf-8")
        report["generatedDriverSha256"] = digest_file(driver)
        report["inputs"] = {}
        for architecture, triple, native, agent in (("x64", "x86_64", "native-msvc", "knmon-agent64.dll"),
                                                     ("x86", "i686", "native-msvc-x86", "knmon-agent32.dll")):
            ui = Path(f"apps/knmon-ui/src-tauri/target/{triple}-pc-windows-msvc/release/knmon-ui.exe")
            native_root = Path("build") / native / "Debug"
            copies = [(ROOT / ui, fixture / ui)]
            copies += [(ROOT / native_root / name, fixture / native_root / name)
                       for name in ("knmon-native-helper.exe", "knmon-collector.exe", "knmon-sample-fileio.exe")]
            copies.append((ROOT / native_root / "knmon-readiness-probe-agent.dll", fixture / native_root / agent))
            for source, destination in copies:
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = digest_file(source)
                shutil.copyfile(source, destination)
                require(digest_file(source) == digest_file(destination) == digest, "Readiness failure input changed during staging.")
                report["inputs"][str(destination.relative_to(directory))] = {"source": str(source), "sha256": digest}
            # Only the isolated input layout changes; desktop and helper code stay intact.
            with patch.object(desktop, "ROOT", fixture):
                desktop.execute_architecture(directory / architecture, architecture, node, 0, "preview")
            result = read_json(directory / architecture / "driver.json")
            sessions = result["failureOwnership"]["sessions"]
            operations = result["failureOwnership"]["operations"]
            require(result["status"] == "passed" and result["errors"] == [] and result["failureVisible"] is True and
                    len(sessions) == len(operations) == 1,
                    "Readiness failure was not observed through the actual desktop.")
            session = sessions[0]
            require(session["sessionState"] == operations[0]["state"] == "failed" and
                    session["operationId"] == operations[0]["operationId"] and session["targetProcessId"] == result["targetPid"] and
                    "readiness" in session["lastError"].lower() and session["targetAlive"] is True and
                    session["targetExitObserved"] is False and session["sessionProcessAlive"] is False and
                    session["agentCleanupAttempted"] is True and session["agentCleanupSucceeded"] is True and
                    all(type(session[key]) is int and session[key] == 0 for key in ("recordsStreamed", "hostDroppedBatches", "transportDroppedEvents")),
                    "Missing-readiness failure lost its error, target identity or cleanup proof.")
            observed = [row for row in result["observations"] if row["phase"] == "expected-failure"]
            require(len(observed) == 1 and observed[0]["session"] == "" and observed[0]["refreshEnabled"] is True and
                    "Events: 0/0" in observed[0]["status"] and observed[0]["output"].count("native_session_failed:") == 1 and
                    session["lastError"] in observed[0]["output"] and observed[0]["rows"] == [],
                    "The terminal native failure disappeared, repeated, or invented records in the UI.")
            report["runs"].append({"architecture": architecture, "operationId": session["operationId"],
                                   "error": session["lastError"], "driverSha256": digest_file(directory / architecture / "driver.json"),
                                   "executionSha256": digest_file(directory / architecture / "execution.json")})
            for name in ("execution.json", "driver.json", "resources.jsonl", "request.json", "failure.png"):
                relative = architecture + "/" + name
                report["artifacts"][relative] = digest_file(directory / relative)
        require(desktop.source_hashes() == sources and {name: digest_file(ROOT / name) for name in PRODUCERS} == producers,
                "Readiness failure inputs changed during validation.")
        require(all(digest_file(Path(row["source"])) == row["sha256"] and digest_file(directory / name) == row["sha256"]
                    for name, row in report["inputs"].items()), "Readiness failure binaries changed.")
        require(digest_file(driver) == report["generatedDriverSha256"] and
                all(digest_file(Path(path)) == digest for path, digest in report["tools"].items()) and
                all(digest_file(directory / name) == digest for name, digest in report["artifacts"].items()),
                "Readiness failure driver, runtime or retained artifacts changed.")
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    desktop.write_json(directory / "evidence.json", report)
    print(json.dumps({"status": report["status"], "directory": str(directory), "failure": report.get("failure")}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
