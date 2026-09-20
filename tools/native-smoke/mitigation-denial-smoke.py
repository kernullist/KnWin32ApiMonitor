"""Verify real process-local CIG rejects attachment before any remote mutation."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    options = parser.parse_args()
    helper = options.helper.resolve(strict=True)
    evidence = Path(tempfile.mkdtemp(prefix="mitigation-denial-", dir=Path.cwd() / "build"))
    with (evidence / "target.log").open("w", encoding="utf-8") as output:
        target = subprocess.Popen([str(helper.parent / "knmon-mitigation-test.exe"), "--cig-target"],
                                  stdin=subprocess.PIPE, stdout=output, stderr=output,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 5
            while "cig-target-ready" not in (evidence / "target.log").read_text(encoding="utf-8"):
                assert target.poll() is None and time.monotonic() < deadline, "CIG target did not become ready."
                time.sleep(0.02)
            completed = subprocess.run([str(helper), "attach-capture", "--pid", str(target.pid),
                                        "--duration-ms", "100", "--timeout-ms", "2000"],
                                       capture_output=True, text=True, encoding="utf-8", timeout=8,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            result = json.loads(completed.stdout)
            (evidence / "denial.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            # This JSON command returns zero when it successfully reports a failed operation.
            assert completed.returncode == 0 and not result["success"], "CIG denial was not reported correctly."
            assert result["operation"] == "mitigation_policy_conflict", result
            events = {event["eventType"] for event in result["auditEvents"]}
            assert "attach_mitigation_policy_checked" in events, events
            allowed = {"operation_cancellation_ready", "attach_preflight_started", "attach_mitigation_policy_checked",
                       "mitigation_policy_conflict", "attach_preflight_failed", "attach_cleanup_completed"}
            assert events == allowed, f"Unexpected work before preflight denial: {events - allowed}"
            assert result["transportCapacity"] == 0 and not result["handshake"]["received"]
            assert target.poll() is None, "Preflight denial must preserve the running target."
            target.communicate(b"q\n", timeout=5)
            assert target.returncode == 0, "The target could not exit normally after denial."
            print(f"Actual CIG preflight-denial/target-preservation PASS: {evidence}")
        finally:
            if target.poll() is None:
                target.kill()
            target.wait(timeout=5)


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Failure validation must run without Python optimization flags.")
    main()
