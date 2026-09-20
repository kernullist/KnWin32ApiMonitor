import argparse
import json
from pathlib import Path

from run_comparison import MANIFEST, MODES, assert_oracle, compare, digest, knmon_events, oracle_metrics, read_json, semantic, source_hashes


def inside(root, relative):
    if not isinstance(relative, str) or Path(relative).anchor or ".." in Path(relative).parts:
        raise ValueError("Evidence paths must be relative and contained.")
    path = root / relative
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("Evidence path escaped its directory.")
    return resolved


def replay(root, current_sources=True, report_override=None):
    report = read_json(root / "comparison.json") if report_override is None else report_override
    manifest = read_json(MANIFEST)
    assert report["schemaVersion"] == 1 and report["status"] == "passed"
    assert report["corpus"] == manifest["id"]
    assert report["manifestSha256"] == digest(MANIFEST)
    if current_sources:
        assert report["sourceHashes"] == source_hashes(), "Comparison evidence has stale sources."
    assert 1 <= report["repetitions"] <= 100 and 1 <= report["iterations"] <= 10000
    expected = {(arch, mode, repeat) for arch in manifest["architectures"]
                for mode in MODES for repeat in range(report["repetitions"])}
    seen = set()
    groups = {}
    total_bytes = 0
    for run in report["runs"]:
        identity = (run["architecture"], run["mode"], run["repetition"])
        assert identity in expected and identity not in seen
        assert run["targetExitCode"] == 0
        seen.add(identity)
        directory = inside(root, run["directory"])
        assert "oracle.json" in run["artifacts"]
        for relative, sha256 in run["artifacts"].items():
            file = inside(directory, relative)
            size = file.stat().st_size
            total_bytes += size
            assert size <= 128 * 1024 * 1024 and total_bytes <= 1024 * 1024 * 1024, "Evidence read budget exceeded."
            assert digest(file) == sha256, f"Changed evidence: {relative}"
        oracle = read_json(inside(directory, "oracle.json"), run["artifacts"]["oracle.json"])
        assert_oracle(oracle, manifest, report["iterations"])
        assert all(run[key] == value for key, value in oracle_metrics(oracle).items()), "Stored benchmark metrics do not match the oracle."
        start, end = int(run["controllerStartNs"]), int(run["controllerEndNs"])
        assert 0 <= start <= end and run["processWallMs"] == (end - start) / 1e6
        if run["mode"] == "knmon":
            assert "capture.json" in run["artifacts"]
            capture = read_json(inside(directory, "capture.json"), run["artifacts"]["capture.json"])
            assert capture["success"] and capture["targetExitCode"] == 0 and capture["transportDroppedEvents"] == 0
            observed = knmon_events(capture, oracle)
        elif run["mode"] in ("frida", "frida-cmodule"):
            assert "frida-messages.json" in run["artifacts"]
            messages = read_json(inside(directory, "frida-messages.json"), run["artifacts"]["frida-messages.json"])
            assert not any(message["type"] == "error" for message in messages)
            results = [message["payload"] for message in messages if message.get("payload", {}).get("kind") == "corpus"]
            assert len(results) == 1 and results[0]["errors"] == []
            assert results[0]["adapter"] == ("cmodule" if run["mode"] == "frida-cmodule" else "javascript")
            observed = results[0]["events"]
        elif run["mode"] == "etw":
            assert "etw.json" in run["artifacts"] and "corpus.etl" in run["artifacts"]
            trace = read_json(inside(directory, "etw.json"), run["artifacts"]["etw.json"])
            assert trace["source"] == "application_instrumented_private_etw"
            assert oracle["etwStatus"] == oracle["etwWriteFailures"] == oracle["etwEventsLost"] == oracle["etwBuffersLost"] == 0
            observed = trace["events"]
            assert observed == oracle["events"]
        else:
            observed = oracle["events"]
        result = compare(oracle["events"], observed)
        assert result == run["comparison"]
        assert result["missing"] == result["unexpected"] == result["orderMismatches"] == 0
        groups.setdefault((run["architecture"], run["repetition"]), []).append(list(map(semantic, oracle["events"])))
    assert seen == expected, "Incomplete execution matrix."
    assert all(all(events == group[0] for events in group) for group in groups.values())
    return report


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Evidence validation must run without Python optimization flags.")
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    result = replay(arguments.directory)
    print(f"Comparison replay PASS: {len(result['runs'])} executed runs")
