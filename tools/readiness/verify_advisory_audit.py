"""Reject filtered, stale, altered and source-unbound advisory evidence."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from advisory_audit import ROOT, audit_results, database_files, decoded, read_json, require, validate_cargo_scope, verify_record


def rejected(function, label, message):
    try:
        function()
    except ValueError as error:
        require(message in str(error), "Negative advisory control failed at an unintended boundary: " + str(error))
        print("Rejected: " + label, flush=True)
    else:
        raise RuntimeError("Negative advisory control accepted: " + label)


def database_controls(output):
    root = output / "database-fixture"
    (root / "crates/example").mkdir(parents=True)
    (root / "rust/std").mkdir(parents=True)
    original = b'```toml\n[advisory]\nid = "RUSTSEC-2000-0001"\npackage = "example"\ndate = "2000-01-01"\n[versions]\npatched = []\n```\n# Boundary fixture\n'
    tracked = root / "crates/example/RUSTSEC-2000-0001.md"
    tracked.write_bytes(original)
    (root / "rust/std/CVE-2019-99999.md").write_bytes(original.replace(b"RUSTSEC-2000-0001", b"CVE-2019-99999").replace(b'package = "example"', b'package = "std"'))
    (root / ".gitignore").write_bytes(b"crates/example/RUSTSEC-2000-0002.md\n")

    def git(*args):
        return subprocess.check_output(["git", "-c", "user.name=kernullist", "-c", "user.email=gloryo@naver.com", *args], cwd=root, stderr=subprocess.PIPE, timeout=30)

    git("init", "-q")
    git("add", "--", ".gitignore", "crates", "rust")
    git("commit", "-qm", "Create advisory boundary fixture")
    tree = git("ls-tree", "-rz", "--full-tree", "HEAD")
    snapshot = database_files(root, tree)
    require(snapshot["fileCount"] == 3 and snapshot["advisoryCount"] == 2, "Crate and Rust core advisory positive controls failed.")
    git("update-index", "--assume-unchanged", "crates/example/RUSTSEC-2000-0001.md")
    tracked.write_bytes(original + b"# Hidden change.\n")
    require(git("status", "--porcelain") == b"", "Fixture did not hide its modified tracked file.")
    rejected(lambda: database_files(root, tree), "hidden modified advisory", "differs from its committed blob")
    tracked.write_bytes(original)
    directory_fixture = output / "database-directory-fixture"
    shutil.copytree(root, directory_fixture, ignore=shutil.ignore_patterns(".git"))
    (directory_fixture / "crates/example/unlisted-directory").mkdir()
    rejected(lambda: database_files(directory_fixture, tree), "unlisted advisory directory", "Unlisted advisory directory")
    (root / "crates/example/RUSTSEC-2000-0002.md").write_bytes(original.replace(b"0001", b"0002"))
    require(git("status", "--porcelain") == b"", "Fixture did not hide its extra advisory.")
    rejected(lambda: database_files(root, tree), "ignored extra advisory", "unlisted or missing advisory inputs")
    duplicate = tree + tree.split(b"\0")[0] + b"\0"
    rejected(lambda: database_files(root, duplicate), "duplicate database path", "Unsafe RustSec source path")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--db", type=Path, default=ROOT / "build/deps/rustsec-advisory-db")
    args = parser.parse_args()
    output = Path(tempfile.mkdtemp(prefix="advisory-negative-", dir=ROOT / "build"))
    print("Advisory negative evidence: " + str(output), flush=True)
    database_controls(output)
    directory, db = args.evidence.resolve(), args.db.resolve()
    evidence = read_json(directory / "evidence.json")
    current = evidence["databaseAfter"]
    verify_record(evidence, directory, db, current)
    npm, cargo = read_json(directory / "npm-audit.log"), read_json(directory / "cargo-audit.log")
    result = audit_results(npm, cargo)
    validate_cargo_scope(cargo, current)
    incomplete = copy.deepcopy(cargo)
    incomplete["database"]["advisory-count"] -= 1
    rejected(lambda: validate_cargo_scope(incomplete, current), "incomplete database load", "incomplete database or lockfile scope")
    incomplete = copy.deepcopy(cargo)
    incomplete["lockfile"]["dependency-count"] -= 1
    rejected(lambda: validate_cargo_scope(incomplete, current), "partial lockfile load", "incomplete database or lockfile scope")
    require(len(result["warnings"]) == sum(len(rows) for rows in cargo["warnings"].values()), "Actual Cargo warnings were lost.")
    warning_fixture = copy.deepcopy(cargo)
    warning_fixture["warnings"] = {"unmaintained": [{"package": {"name": "warning-fixture", "version": "1.0.0"}, "advisory": {"id": "RUSTSEC-2000-0001"}}]}
    require(audit_results(npm, warning_fixture)["warnings"][0]["package"] == "warning-fixture", "Cargo warning positive control failed.")
    for label, target, edit, message in (
        ("npm reported vulnerability", "npm", lambda value: value["metadata"]["vulnerabilities"].update(total=1), "npm audit found"),
        ("npm contradictory findings", "npm", lambda value: value.update(vulnerabilities={"fixture": {}}), "npm audit found"),
        ("npm boolean count", "npm", lambda value: value["metadata"]["vulnerabilities"].update(total=False), "npm audit found"),
        ("npm empty scope", "npm", lambda value: value["metadata"]["dependencies"].update(total=0), "no dependency scope"),
        ("Cargo reported vulnerability", "cargo", lambda value: value["vulnerabilities"].update(found=True), "Cargo audit found"),
        ("Cargo contradictory findings", "cargo", lambda value: value["vulnerabilities"].update(list=[{}]), "Cargo audit found"),
        ("Cargo advisory ignore", "cargo", lambda value: value["settings"].update(ignore=["RUSTSEC-2000-0001"]), "filtered its findings"),
        ("Cargo architecture filter", "cargo", lambda value: value["settings"].update(target_arch=["x86_64"]), "filtered its findings"),
        ("Cargo OS filter", "cargo", lambda value: value["settings"].update(target_os=["windows"]), "filtered its findings"),
        ("Cargo severity filter", "cargo", lambda value: value["settings"].update(severity="high"), "filtered its findings"),
        ("Cargo warnings suppressed", "cargo", lambda value: value["settings"].update(informational_warnings=[]), "filtered its findings"),
        ("Cargo empty database", "cargo", lambda value: value["database"].update({"advisory-count": 0}), "no lockfile or advisory scope"),
    ):
        n, c = copy.deepcopy(npm), copy.deepcopy(cargo)
        edit(n if target == "npm" else c)
        rejected(lambda: audit_results(n, c), label, message)
    now = datetime.now(timezone.utc)
    for label, edit, message in (
        ("declared failed audit", lambda value: value.update(status="failed"), "did not pass"),
        ("stale audit", lambda value: value.update(observedAtUtc=(now - timedelta(hours=25)).isoformat()), "stale or future-dated"),
        ("future audit", lambda value: value.update(observedAtUtc=(now + timedelta(hours=1)).isoformat()), "stale or future-dated"),
        ("changed audited lockfile", lambda value: value["sources"].update({"package-lock.json": "0" * 64}), "fingerprints are stale"),
        ("stale audit producer", lambda value: value["producer"].update({"tools/readiness/advisory_audit.py": "0" * 64}), "fingerprints are stale"),
        ("stale RustSec database", lambda value: value["databaseAfter"].update(revision="0" * 40), "database changed"),
        ("missing database query", lambda value: value["databaseArtifacts"].pop("before-db-remote.log"), "query evidence changed or is incomplete"),
        ("changed database query", lambda value: value["databaseArtifacts"].update({"before-db-remote.log": "0" * 64}), "query evidence changed or is incomplete"),
        ("missing audit execution", lambda value: value["steps"].pop(), "command set is incomplete"),
        ("nonzero audit exit", lambda value: value["steps"][3].update(exitCode=1), "command or exit status differs"),
        ("modified audit flags", lambda value: value["steps"][3]["command"].append("--omit=dev"), "command or exit status differs"),
        ("altered audit output", lambda value: value["steps"][3].update(logSha256="0" * 64), "audit log changed"),
        ("altered summary warnings", lambda value: value["result"].update(warnings=[] if result["warnings"] else [{"kind": "fixture"}]), "summary differs from raw reports"),
    ):
        mutated = copy.deepcopy(evidence)
        edit(mutated)
        rejected(lambda: verify_record(mutated, directory, db, current, now), label, message)
    rejected(lambda: decoded(b'{"count":0,"count":1}'), "duplicate audit JSON key", "Duplicate source manifest key")
    rejected(lambda: decoded(b'{"count":NaN}'), "nonfinite audit JSON", "Non-finite advisory evidence number")
    print("Advisory adversarial validation PASS: " + str(output))


if __name__ == "__main__":
    main()
