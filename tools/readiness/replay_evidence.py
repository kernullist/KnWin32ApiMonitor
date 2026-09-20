"""Replay competitive artifacts with the declared isolated Frida interpreter."""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from source_evidence import ROOT, digest_file, require
from technical_gate import comparative_cost


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "tools/comparison"))
    import frida
    from check_proof import validate
    from replay_comparison import replay
    directory = args.directory.resolve()
    before = digest_file(directory / "comparison.json")
    proof = replay(directory)
    validate(proof)
    require(frida.__version__ == proof["fridaVersion"], "Comparison verifier requires the recorded Frida baseline.")
    require(digest_file(directory / "comparison.json") == before, "Comparison report changed during replay.")
    probes = proof["kernelEtwProbes"]
    result = {"schemaVersion": 1, "status": "passed", "proofSha256": before, "runs": len(proof["runs"]),
              "windowsVersion": proof["windowsVersion"], "competitiveCost": comparative_cost(proof),
              "kernelEtwAvailability": {"status": "passed" if all(probe["available"] for probe in probes) else "not_verified",
                                        "probes": probes, "scope": "Session availability only; private application ETW is a separate backend."}}
    print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Competitive evidence validation requires Python assertions to remain enabled.")
    main()
