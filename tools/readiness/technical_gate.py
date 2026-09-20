"""Produce an evidence-backed technical readiness report; missing gates fail closed."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_evidence import ROOT, digest_file, read_json, require, verify_current_sources, verify as verify_source
from owned_command import run

PENDING = {
    "native_release_matrix": "Current full x64/x86 Release execution is incomplete; recorded x86 Defender quarantine remains unresolved.",
    "release_backend_runtime": "Separate Release backend execution with both real helpers is not established.",
    "windows_build_matrix": "Only Windows 10.0.26200 has executed evidence; other supported Windows builds need their own runs.",
    "elevated_cross_user_ipc": "Elevated and cross-user IPC contexts lack executed evidence.",
    "hardware_cet_enforcement": "PE compatibility metadata does not establish hardware CET enforcement.",
    "whole_desktop_resources": "Owned x64/x86 desktop interaction and complete sampled WebView Job membership require executed evidence.",
    "capture_profile_costs": "Separate metadata, arguments, preview and stack capture costs are not established.",
    "dependency_maintenance": "Windows-reachable dependency warnings require verified current graph and advisory evidence.",
    "binary_distribution_reconstruction": "Native Debug/frontend source reconstruction does not establish a complete desktop binary distribution rebuild.",
    "competitive_generality": "The six-API Debug corpus does not establish a universal performance or coverage ranking.",
}
VALIDATED = ("source_reconstruction", "dependency_inventory", "typed_abi_source_freshness", "competitive_semantics", "competitive_cost", "kernel_etw_availability", "current_advisory_scan")
PRODUCERS = ("tools/readiness/source_evidence.py", "tools/readiness/technical_gate.py", "tools/readiness/replay_evidence.py", "tools/source/source_archive.py",
             "tools/source/rebuild_source.py", "tools/source/owned_command.py", "tools/security/dependency_inventory.py",
             "tools/security/validate-sbom-schema.mjs", "tools/abi-proof/proof.mjs", "tools/abi-proof/check-proof.mjs",
             "tools/comparison/check_proof.py", "tools/comparison/replay_comparison.py", "tools/comparison/run_comparison.py", "tools/readiness/advisory_audit.py",
             "tools/readiness/desktop_evidence.py", "tools/readiness/desktop_processes.py", "tools/readiness/desktop_driver.mjs", "tools/readiness/desktop_check.py",
             "tools/readiness/backend_release.py", "tools/security/tauri_backport.py")


def outcome(rows):
    require(set(rows) == set(VALIDATED) | set(PENDING), "Technical gate set is incomplete or contains overrides.")
    states = [row["status"] for row in rows.values()]
    require(all(state in ("passed", "failed", "not_verified") for state in states), "Unknown technical gate status.")
    return "failed" if "failed" in states else "incomplete" if "not_verified" in states else "passed"


def comparative_cost(proof):
    values = {}
    passed = True
    for arch in ("x64", "x86"):
        groups = {mode: [row for row in proof["runs"] if row["architecture"] == arch and row["mode"] == mode]
                  for mode in ("knmon", "frida", "frida-cmodule")}
        require(all(groups.values()), "Missing measured competitive mode.")
        values[arch] = {}
        for mode, rows in groups.items():
            values[arch][mode] = {"medianCallUs": statistics.median(row["callLatencyUs"]["median"] for row in rows),
                                  "medianRunP99Us": statistics.median(row["callLatencyUs"]["p99"] for row in rows),
                                  "medianTargetRssBytes": statistics.median(row["workingSetBytes"] for row in rows)}
        for metric, value in values[arch]["knmon"].items():
            passed = passed and value <= min(values[arch][mode][metric] for mode in ("frida", "frida-cmodule"))
    return {"status": "passed" if passed else "not_verified", "measurements": values,
            "scope": "Point estimates on the recorded corpus only; no significance or general ranking claim.",
            "reason": "KNMon meets the recorded competitor point estimates." if passed else "A measured competitor has lower latency or target RSS."}


def verify_bound_inputs(inputs):
    for record in inputs.values():
        require(digest_file(Path(record["path"])) == record["sha256"], "A bound evidence input changed during readiness verification.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-build", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--dependencies", type=Path)
    parser.add_argument("--comparison", type=Path)
    parser.add_argument("--comparison-python", type=Path, default=ROOT / "build/deps/frida-venv/Scripts/python.exe")
    parser.add_argument("--advisory", type=Path)
    parser.add_argument("--desktop", type=Path)
    parser.add_argument("--backend-release", type=Path)
    parser.add_argument("--rustsec-db", type=Path, default=ROOT / "build/deps/rustsec-advisory-db")
    parser.add_argument("--node", type=Path, default=ROOT / "build/deps/node-v24.21.0-win-x64/node.exe")
    args = parser.parse_args()
    (ROOT / "build").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="technical-readiness-", dir=ROOT / "build"))
    rows = {name: {"status": "not_verified", "reason": reason} for name, reason in PENDING.items()}
    rows.update({name: {"status": "not_verified", "reason": "Required evidence was not supplied."} for name in VALIDATED})
    producers = {name: digest_file(ROOT / name) for name in PRODUCERS}
    retained = {}
    report = {"schemaVersion": 1, "observedAtUtc": datetime.now(timezone.utc).isoformat(), "status": "failed", "gates": rows,
              "claim": "Technical scope remains incomplete; no World No.1 or defect-free certification.",
              "assurance": "Unsigned local artifact consistency checks; not builder authentication or SLSA certification.",
              "producer": producers, "inputs": {}}

    def checked(name, function):
        try:
            detail = function()
            rows[name] = {"status": "passed", **detail}
        except Exception as error:
            rows[name] = {"status": "failed", "reason": type(error).__name__ + ": " + str(error)[:1000]}

    def bind(name, path):
        require(path.is_file(), "Required evidence file is missing.")
        before = digest_file(path)
        report["inputs"][name] = {"path": str(path), "sha256": before}
        return before

    def source():
        require(args.archive is not None, "Source reconstruction requires its archive.")
        directory, archive = args.source_build.resolve(), args.archive.resolve()
        before = bind("sourceReconstruction", directory / "evidence.json")
        bind("sourceArchive", archive)
        result = verify_source(directory, archive)
        retained["sourceManifest"] = result.pop("sourceManifest")
        require(digest_file(directory / "evidence.json") == before, "Source reconstruction evidence changed during verification.")
        return result

    def dependencies():
        directory = args.dependencies.resolve()
        before = bind("dependencies", directory / "evidence.json")
        command = [sys.executable, "-X", "utf8", ROOT / "tools/security/dependency_inventory.py", "--check", directory, "--node", args.node.resolve()]
        result = run(command, ROOT, output / "dependencies.log", dict(os.environ), timeout=180)
        require(digest_file(directory / "evidence.json") == before, "Dependency evidence changed during verification.")
        return {"scope": "Current pre-build lock graph, Windows resolution and vendored sources; not a linked-runtime inventory.", "command": result}

    def typed():
        before = bind("typedProof", ROOT / "generated/typed-abi-proof.json")
        result = run([args.node.resolve(), ROOT / "tools/abi-proof/check-proof.mjs"], ROOT, output / "typed-abi.log", dict(os.environ), timeout=90)
        require(digest_file(ROOT / "generated/typed-abi-proof.json") == before, "Typed proof changed during verification.")
        return {"scope": "Source freshness and declared executed six-API proof structure; not a fresh runtime execution.", "command": result}

    def comparison():
        directory = args.comparison.resolve()
        before = bind("comparison", directory / "comparison.json")
        command = [args.comparison_python.resolve(), "-X", "utf8", ROOT / "tools/readiness/replay_evidence.py", directory]
        execution = run(command, ROOT, output / "comparison.log", dict(os.environ), timeout=180)
        result = read_json(output / "comparison.log")
        require(result["schemaVersion"] == 1 and result["status"] == "passed" and result["proofSha256"] == before,
                "Comparison worker result differs from its input.")
        require(digest_file(directory / "comparison.json") == before, "Comparison evidence changed during verification.")
        rows["competitive_cost"] = result["competitiveCost"]
        rows["kernel_etw_availability"] = result["kernelEtwAvailability"]
        return {"runs": result["runs"], "windowsVersion": result["windowsVersion"], "command": execution,
                "scope": "Raw oracle/capture replay, exact matrix and current source fingerprints."}

    def advisory():
        from advisory_audit import verify
        directory = args.advisory.resolve()
        bind("advisory", directory / "evidence.json")
        result = verify(directory, args.rustsec_db.resolve(), output)
        if rows["dependency_inventory"]["status"] == "passed":
            graph_path = args.dependencies.resolve() / "cargo-targets.json"
            bind("advisoryWindowsGraph", graph_path)
            graphs = read_json(graph_path)
            warnings = []
            for warning in result["warnings"]:
                ref = "cargo:" + warning["package"] + "@" + warning["version"]
                targets = sorted(target for target, graph in graphs.items() if any(node["ref"] == ref for node in graph["nodes"]))
                if targets:
                    warnings.append({**warning, "targets": targets})
            rows["dependency_maintenance"] = {"status": "not_verified" if warnings else "passed", "windowsWarnings": warnings,
                                               "scope": "Warnings remain visible; absence from a Windows graph is not an upstream fix."}
        return {**result, "scope": "Known advisory scan, unchanged lockfiles, at most 24 hours old and current RustSec contents; not an absence-of-unknown-defects claim."}

    def desktop():
        from desktop_evidence import verify
        directory = args.desktop.resolve()
        bind("desktop", directory / "evidence.json")
        return verify(directory)

    def backend_release():
        from backend_release import verify
        directory = args.backend_release.resolve()
        bind("backendRelease", directory / "evidence.json")
        return verify(directory)

    try:
        report["checkoutRevision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
        report["trackedDirty"] = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, timeout=30))
        if args.source_build is not None:
            checked("source_reconstruction", source)
        if args.dependencies is not None:
            checked("dependency_inventory", dependencies)
        checked("typed_abi_source_freshness", typed)
        if args.comparison is not None:
            checked("competitive_semantics", comparison)
        if args.advisory is not None:
            checked("current_advisory_scan", advisory)
        if args.desktop is not None:
            checked("whole_desktop_resources", desktop)
        if args.backend_release is not None:
            checked("release_backend_runtime", backend_release)
        if rows["source_reconstruction"]["status"] == "passed":
            verify_current_sources(retained["sourceManifest"])
        verify_bound_inputs(report["inputs"])
        require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip() == report["checkoutRevision"],
                "Checkout revision changed during readiness verification.")
        require(producers == {name: digest_file(ROOT / name) for name in PRODUCERS}, "Readiness producer changed during verification.")
        report["status"] = outcome(rows)
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)[:1000]
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    for name, row in rows.items():
        print(f"{name}: {row['status']}")
    print(f"Technical readiness {report['status']}: {output / 'report.json'}")
    return 0 if report["status"] == "passed" else 2 if report["status"] == "incomplete" else 1


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Readiness validation requires Python assertions to remain enabled.")
    sys.exit(main())
