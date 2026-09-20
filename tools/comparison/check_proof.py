import argparse
import json
import math
from pathlib import Path
import re
import statistics

from replay_comparison import replay
from run_comparison import ROOT, MANIFEST, MODES, digest, native_source_hash, read_json, source_hashes


def validate(proof):
    manifest = read_json(MANIFEST)
    assert proof["schemaVersion"] == 1 and proof["status"] == "passed"
    assert proof["fridaVersion"] == manifest["baseline"]["version"] and proof["corpus"] == manifest["id"]
    assert proof["manifestSha256"] == digest(MANIFEST)
    assert proof["sourceHashes"] == source_hashes(), "Comparison source proof is stale."
    assert proof["nativeSourceSha256"] == native_source_hash(), "Native source proof is stale."
    assert 10 <= proof["repetitions"] <= 100 and proof["iterations"] == manifest["defaultIterations"]
    expected = {(arch, mode, repeat) for arch in manifest["architectures"]
                for mode in MODES for repeat in range(proof["repetitions"])}
    seen = set()
    binaries = {}
    for run in proof["runs"]:
        identity = (run["architecture"], run["mode"], run["repetition"])
        assert identity in expected and identity not in seen
        seen.add(identity)
        assert run["configuration"] in ("Debug", "Release") and run["targetExitCode"] == 0
        comparison = run["comparison"]
        assert comparison["expected"] == comparison["observed"] == run["events"] == proof["iterations"] * 7 + 2
        assert comparison["missing"] == comparison["unexpected"] == comparison["orderMismatches"] == 0
        for value in [run["workloadUs"], run["processWallMs"], run["cpu100ns"], run["workingSetBytes"], run["peakWorkingSetBytes"],
                      *run["callLatencyUs"].values()]:
            assert type(value) in (int, float) and math.isfinite(value) and value >= 0
        assert set(run["callLatencyUs"]) == {"median", "p95", "p99"}
        assert 0 < run["workingSetBytes"] <= run["peakWorkingSetBytes"]
        expected_binaries = {"knmon-comparison-target.exe", "knmon-native-helper.exe", "knmon-etw-corpus-reader.exe",
                             f"knmon-agent{'32' if run['architecture'] == 'x86' else '64'}.dll"}
        assert set(run["binaries"]) == expected_binaries and all(re.fullmatch("[0-9a-f]{64}", value) for value in run["binaries"].values())
        encoded = json.dumps(run["binaries"], sort_keys=True)
        assert binaries.setdefault(run["architecture"], encoded) == encoded
    assert seen == expected
    assert len(proof["kernelEtwProbes"]) == 2 and {probe["architecture"] for probe in proof["kernelEtwProbes"]} == {"x86", "x64"}
    for probe in proof["kernelEtwProbes"]:
        assert probe["scope"] == "kernel_etw_session_availability"
        assert type(probe["startStatus"]) is int and 0 <= probe["startStatus"] <= 0xffffffff
        assert type(probe["available"]) is bool
        assert probe["available"] == (probe["startStatus"] == 0 and probe["stopStatus"] == 0)
        if probe["startStatus"] != 0:
            assert probe["stopStatus"] is None and not probe["available"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", type=Path)
    parser.add_argument("--proof", type=Path, default=ROOT / "generated/comparison-proof.json")
    arguments = parser.parse_args()
    proof = replay(arguments.publish) if arguments.publish else read_json(arguments.proof)
    validate(proof)
    if arguments.publish:
        arguments.proof.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    print(f"Comparison proof current: {len(proof['runs'])} executed runs, six APIs, {proof['windowsVersion']}")
    for architecture in ("x64", "x86"):
        for mode in MODES:
            rows = [row for row in proof["runs"] if row["architecture"] == architecture and row["mode"] == mode]
            p50 = statistics.median(row["callLatencyUs"]["median"] for row in rows)
            p99 = statistics.median(row["callLatencyUs"]["p99"] for row in rows)
            rss = statistics.median(row["workingSetBytes"] for row in rows) / (1024 * 1024)
            print(f"{architecture} {mode}: median-call={p50:.2f}us median-run-p99={p99:.2f}us target-RSS={rss:.2f}MiB")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Evidence validation must run without Python optimization flags.")
    main()
