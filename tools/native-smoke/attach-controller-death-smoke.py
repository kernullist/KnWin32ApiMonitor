"""Kill an owned attach controller and verify target survival and clean reattach."""
import argparse
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True, type=Path)
    options = parser.parse_args()
    helper = options.helper.resolve(strict=True)
    evidence = Path(tempfile.mkdtemp(prefix="attach-controller-death-", dir=Path.cwd() / "build"))
    sample_log = (evidence / "target.log").open("w", encoding="utf-8")
    error_log = (evidence / "controller-errors.log").open("w", encoding="utf-8")
    target = subprocess.Popen([str(helper.parent / "knmon-sample-fileio.exe"), "--attach-loop",
                               "--iterations", "3000", "--delay-ms", "25"], stdout=sample_log,
                              stderr=sample_log, creationflags=subprocess.CREATE_NO_WINDOW)
    controller = None
    try:
        deadline = time.monotonic() + 10
        while "attach-loop-ready" not in (evidence / "target.log").read_text(encoding="utf-8"):
            assert target.poll() is None and time.monotonic() < deadline, "Target did not become ready."
            time.sleep(0.05)
        controller = subprocess.Popen([str(helper), "attach-session", "--pid", str(target.pid), "--stream-batches",
                                       "--operation-id", "death-" + uuid.uuid4().hex,
                                       "--api-selection", "kernel32.dll!CreateFileW;kernel32.dll!CloseHandle"],
                                      stdout=subprocess.PIPE, stderr=error_log, text=True, encoding="utf-8",
                                      creationflags=subprocess.CREATE_NO_WINDOW)
        frames = queue.Queue()

        def read_frames():
            try:
                with (evidence / "frames.jsonl").open("w", encoding="utf-8") as log:
                    for line in controller.stdout:
                        log.write(line)
                        frames.put(json.loads(line))
            except Exception as error:
                frames.put({"readerError": str(error)})

        reader = threading.Thread(target=read_frames, daemon=True)
        reader.start()
        deadline = time.monotonic() + 20
        captured = False
        while time.monotonic() < deadline:
            try:
                frame = frames.get(timeout=0.2)
            except queue.Empty:
                assert controller.poll() is None, "Controller exited before capture."
                continue
            assert "readerError" not in frame, frame
            if frame.get("frameType") == "trace_batch" and frame.get("events"):
                captured = True
                break
        assert captured, "No actual captured batch before the controller fault."
        controller.kill()
        controller.wait(timeout=5)
        reader.join(timeout=2)
        assert not reader.is_alive()
        assert target.poll() is None, "An attach-controller crash terminated its unowned target."
        deadline = time.monotonic() + 8
        result = None
        while time.monotonic() < deadline:
            completed = subprocess.run([str(helper), "attach-capture", "--pid", str(target.pid),
                                        "--duration-ms", "250", "--timeout-ms", "5000",
                                        "--api-selection", "kernel32.dll!CreateFileW;kernel32.dll!CloseHandle"],
                                       capture_output=True, text=True, encoding="utf-8", timeout=10,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            result = json.loads(completed.stdout)
            (evidence / "reattach.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            if result["success"]:
                assert completed.returncode == 0
                break
            assert result.get("attachState") in ("loaded_active", "loaded_busy"), result.get("message")
            time.sleep(0.05)
        assert result and result["success"], "Agent remained active after controller death."
        assert result["attachStrategy"] == "loaded_agent_reinitialize" and result["agentCleanupSucceeded"]
        assert result["capturedEvents"] and target.poll() is None
        print(f"Attach controller-death/target-survival/reattach PASS: {evidence}")
    finally:
        for process in (controller, target):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
        sample_log.close()
        error_log.close()


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Failure validation must run without Python optimization flags.")
    main()
