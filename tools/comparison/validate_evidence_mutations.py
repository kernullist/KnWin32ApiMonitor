import argparse
import copy
from pathlib import Path

from replay_comparison import replay


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    root = parser.parse_args().directory
    report = replay(root)
    mutations = [
        ("runs", report["runs"][:-1]),
        ("runs", report["runs"] + [report["runs"][0]]),
        ("status", "failed"),
        ("runs.0.workloadUs", 0),
        ("runs.0.workingSetBytes", 0),
        ("runs.0.callLatencyUs", {"median": 0, "p95": 0, "p99": 0}),
        ("runs.0.targetExitCode", 7),
        ("runs.0.artifacts.oracle.json", "0" * 64),
        ("runs.0.directory", "../outside"),
        ("sourceHashes", {}),
    ]
    for field, replacement in mutations:
        changed = copy.deepcopy(report)
        if field.endswith("oracle.json"):
            changed["runs"][0]["artifacts"]["oracle.json"] = replacement
        else:
            parts = field.split(".")
            target = changed
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            target[parts[-1]] = replacement
        rejected = False
        try:
            replay(root, report_override=changed)
        except (AssertionError, ValueError):
            rejected = True
        assert rejected, f"Evidence mutation accepted: {field}"
    print(f"Evidence mutation rejection PASS: {len(mutations)} cases")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Evidence validation must run without Python optimization flags.")
    main()
