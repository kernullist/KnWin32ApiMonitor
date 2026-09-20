"""Bind current dependency audits to lockfiles and a verified RustSec worktree."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True
from source_evidence import ROOT, contained, digest_file, read_bytes, read_json, require
from owned_command import run
from source_archive import unique_object

DATABASE_URL = "https://github.com/RustSec/advisory-db.git"
REGISTRY = "https://registry.npmjs.org/"
SOURCES = ("package.json", "package-lock.json", "apps/knmon-ui/package.json", "apps/knmon-ui/src-tauri/Cargo.toml",
           "apps/knmon-ui/src-tauri/Cargo.lock", "crates/knmon-tauri/Cargo.toml", ".cargo/config.toml", "toolchain.json")
PRODUCERS = ("tools/readiness/advisory_audit.py", "tools/readiness/source_evidence.py", "tools/source/owned_command.py", "tools/source/source_archive.py")
LABELS = ("node-version", "npm-version", "cargo-version", "npm-audit", "cargo-audit")
DB_LABELS = tuple(prefix + "-" + suffix for prefix in ("before-db", "after-db") for suffix in ("head", "tree", "remote", "checked-head"))


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()


def decoded(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, "Non-finite advisory evidence number."))


def fingerprints(names):
    return {name: digest_file(ROOT / name) for name in names}


def command(command_line, output, label):
    return run(command_line, ROOT, output / (label + ".log"), dict(os.environ), timeout=180, log_limit=8 * 1024 * 1024)


def database_files(db, tree):
    require(len(tree) <= 4 * 1024 * 1024, "RustSec tree listing exceeds its bound.")
    rows = tree.split(b"\0")
    require(rows[-1] == b"" and 1 < len(rows) <= 10001, "Invalid RustSec tree size.")
    files, total = {}, 0
    for row in rows[:-1]:
        metadata, name = row.decode("utf-8").split("\t", 1)
        mode, kind, object_id = metadata.split()
        require(mode in ("100644", "100755") and kind == "blob" and re.fullmatch("[0-9a-f]{40}", object_id), "Unsupported RustSec tree object.")
        require(name not in files and not Path(name).is_absolute() and "\\" not in name and ":" not in name and
                all(part not in ("", ".", "..", ".git") for part in name.split("/")), "Unsafe RustSec source path.")
        data = read_bytes(contained(db, name))
        total += len(data)
        require(total <= 64 * 1024 * 1024, "RustSec worktree exceeds its aggregate bound.")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(blob == object_id, "RustSec file differs from its committed blob: " + name)
        files[name] = hashlib.sha256(data).hexdigest()
    for collection in ("crates", "rust"):
        expected = {name for name in files if name.startswith(collection + "/")}
        expected_directories = {collection} | {"/".join(name.split("/")[:index]) for name in expected for index in range(1, len(name.split("/")))}
        actual, pending, entries = set(), [db / collection] if (db / collection).exists() else [], 0
        while pending:
            directory = pending.pop()
            require(directory.resolve().is_relative_to(db.resolve()) and not directory.is_symlink() and not directory.is_junction(), "Reparse point in advisory inputs.")
            require(directory.relative_to(db).as_posix() in expected_directories, "Unlisted advisory directory.")
            with os.scandir(directory) as children:
                for child in children:
                    entries += 1
                    require(entries <= 20000 and not child.is_symlink(), "Oversized or linked advisory collection.")
                    if child.is_dir(follow_symlinks=False):
                        pending.append(Path(child.path))
                    else:
                        require(child.is_file(follow_symlinks=False), "Non-file advisory input.")
                        actual.add(Path(child.path).relative_to(db).as_posix())
        require(actual == expected, "RustSec contains unlisted or missing advisory inputs.")
    advisories = sum(1 for name in files if name.startswith(("crates/", "rust/")) and len(Path(name).parts) == 3 and
                     name.endswith(".md") and not Path(name).name.startswith("."))
    return {"sha256": hashlib.sha256(encoded(files)).hexdigest(), "fileCount": len(files), "bytes": total, "advisoryCount": advisories}


def current_database(db, output, prefix):
    command(["git", "-C", db, "rev-parse", "HEAD"], output, prefix + "-head")
    revision = read_bytes(output / (prefix + "-head.log")).decode("ascii").strip()
    require(re.fullmatch("[0-9a-f]{40}", revision), "Invalid RustSec revision.")
    for suffix, arguments in (("tree", ["git", "-C", db, "ls-tree", "-rz", "--full-tree", revision]),
                              ("remote", ["git", "ls-remote", "--exit-code", DATABASE_URL, "refs/heads/main"])):
        command(arguments, output, prefix + "-" + suffix)
    remote = read_bytes(output / (prefix + "-remote.log")).decode("ascii").split()
    require(remote == [revision, "refs/heads/main"], "RustSec checkout is not the current official upstream revision.")
    tree = read_bytes(output / (prefix + "-tree.log"))
    result = {"revision": revision, "upstream": DATABASE_URL, "treeSha256": hashlib.sha256(tree).hexdigest(), **database_files(db, tree)}
    command(["git", "-C", db, "rev-parse", "HEAD"], output, prefix + "-checked-head")
    require(read_bytes(output / (prefix + "-checked-head.log")).decode("ascii").strip() == revision, "RustSec revision changed during verification.")
    return result


def audit_results(npm, cargo):
    require(type(npm.get("auditReportVersion")) is int and npm["auditReportVersion"] == 2 and "error" not in npm,
            "Unsupported or failed npm audit response.")
    counts = npm["metadata"]["vulnerabilities"]
    require(set(counts) == {"info", "low", "moderate", "high", "critical", "total"} and
            all(type(value) is int and value == 0 for value in counts.values()) and npm["vulnerabilities"] == {}, "npm audit found vulnerabilities or inconsistent counts.")
    require(type(npm["metadata"]["dependencies"]["total"]) is int and npm["metadata"]["dependencies"]["total"] > 0, "npm audit has no dependency scope.")
    findings = cargo["vulnerabilities"]
    require(findings["found"] is False and type(findings["count"]) is int and findings["count"] == 0 and findings["list"] == [],
            "Cargo audit found vulnerabilities or inconsistent counts.")
    settings = cargo["settings"]
    require(settings["ignore"] == [] and settings["target_arch"] == [] and settings["target_os"] == [] and settings["severity"] is None and
            set(settings["informational_warnings"]) == {"unmaintained", "unsound", "notice"}, "Cargo audit filtered its findings.")
    require(type(cargo["lockfile"]["dependency-count"]) is int and cargo["lockfile"]["dependency-count"] > 0 and
            type(cargo["database"]["advisory-count"]) is int and cargo["database"]["advisory-count"] > 0, "Cargo audit has no lockfile or advisory scope.")
    warnings = []
    require(isinstance(cargo["warnings"], dict), "Invalid Cargo warnings.")
    for kind, rows in cargo["warnings"].items():
        require(isinstance(rows, list), "Invalid Cargo warning group.")
        for row in rows:
            package = row["package"]
            require(isinstance(package["name"], str) and isinstance(package["version"], str), "Invalid Cargo warning package.")
            warnings.append({"kind": kind, "package": package["name"], "version": package["version"], "advisory": (row.get("advisory") or {}).get("id")})
    return {"npmVulnerabilities": 0, "cargoVulnerabilities": 0, "warnings": warnings,
            "npmDependencies": npm["metadata"]["dependencies"]["total"], "cargoDependencies": cargo["lockfile"]["dependency-count"]}


def commands(tools, db):
    node, npm, audit = tools["node"]["path"], tools["npm"]["path"], tools["cargoAudit"]["path"]
    return [[node, "--version"], [node, npm, "--version"], [audit, "audit", "--version"],
            [node, npm, "audit", "--json", "--package-lock-only", "--include=prod", "--include=dev", "--include=optional", "--include=peer",
             "--workspaces", "--include-workspace-root", "--audit-level=low", "--registry=" + REGISTRY, "--prefer-online"],
            [audit, "audit", "--no-fetch", "--db", str(db), "--file", "apps/knmon-ui/src-tauri/Cargo.lock", "--json"]]


def validate_cargo_scope(cargo, database):
    packages = tomllib.loads(read_bytes(ROOT / "apps/knmon-ui/src-tauri/Cargo.lock").decode("utf-8"))["package"]
    require(cargo["database"]["advisory-count"] == database["advisoryCount"] and
            cargo["lockfile"]["dependency-count"] == len(packages), "Cargo audit loaded an incomplete database or lockfile scope.")


def verify_record(evidence, directory, db, current_db, now=None):
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed", "Advisory audit did not pass.")
    observed = datetime.fromisoformat(evidence["observedAtUtc"])
    now = now or datetime.now(timezone.utc)
    require(observed.tzinfo is not None and -timedelta(minutes=5) <= now - observed <= timedelta(hours=24), "Advisory audit is stale or future-dated.")
    require(evidence["sources"] == fingerprints(SOURCES) and evidence["producer"] == fingerprints(PRODUCERS), "Advisory source or producer fingerprints are stale.")
    require(evidence["databaseBefore"] == evidence["databaseAfter"] == current_db, "Advisory database changed or is no longer current.")
    expected_artifacts = {label + extension for label in DB_LABELS for extension in (".log", ".command.json")}
    require(set(evidence["databaseArtifacts"]) == expected_artifacts, "Advisory database query evidence changed or is incomplete.")
    raw_database = {name: read_bytes(contained(directory, name)) for name in expected_artifacts}
    require(all(hashlib.sha256(data).hexdigest() == evidence["databaseArtifacts"][name] for name, data in raw_database.items()),
            "Advisory database query evidence changed or is incomplete.")
    revision = current_db["revision"]
    for prefix in ("before-db", "after-db"):
        require(raw_database[prefix + "-head.log"].decode("ascii").strip() == revision and
                raw_database[prefix + "-checked-head.log"].decode("ascii").strip() == revision and
                raw_database[prefix + "-remote.log"].decode("ascii").split() == [revision, "refs/heads/main"] and
                hashlib.sha256(raw_database[prefix + "-tree.log"]).hexdigest() == current_db["treeSha256"], "Advisory database query results disagree.")
        for suffix, arguments in (("head", ["git", "-C", str(db), "rev-parse", "HEAD"]),
                                  ("tree", ["git", "-C", str(db), "ls-tree", "-rz", "--full-tree", revision]),
                                  ("remote", ["git", "ls-remote", "--exit-code", DATABASE_URL, "refs/heads/main"]),
                                  ("checked-head", ["git", "-C", str(db), "rev-parse", "HEAD"])):
            require(decoded(raw_database[prefix + "-" + suffix + ".command.json"]) == {"command": arguments, "cwd": str(ROOT)}, "Advisory database query command differs.")
    expected_commands = commands(evidence["tools"], db)
    require(set(evidence["tools"]) == {"node", "npm", "cargoAudit"} and
            all(digest_file(Path(record["path"])) == record["sha256"] for record in evidence["tools"].values()), "Advisory tool identity changed.")
    require([step["label"] for step in evidence["steps"]] == list(LABELS), "Advisory audit command set is incomplete.")
    logs = {}
    for step, arguments in zip(evidence["steps"], expected_commands):
        require(step["command"] == arguments and type(step["exitCode"]) is int and step["exitCode"] == 0, "Advisory command or exit status differs.")
        log = contained(directory, step["label"] + ".log")
        data = read_bytes(log, 8 * 1024 * 1024)
        require(type(step["logBytes"]) is int and len(data) == step["logBytes"] and hashlib.sha256(data).hexdigest() == step["logSha256"], "Advisory audit log changed.")
        logs[step["label"]] = data
        require(read_json(contained(directory, step["label"] + ".command.json")) == {"command": arguments, "cwd": str(ROOT)}, "Advisory owned request differs.")
    require(logs["node-version"].decode().strip() == "v" + read_json(ROOT / "toolchain.json")["node"], "Advisory audit Node baseline differs.")
    require(re.fullmatch(r"cargo-audit(?:-audit)? 0\.22\.2", logs["cargo-version"].decode().strip()), "Unsupported cargo-audit version.")
    cargo = decoded(logs["cargo-audit"])
    result = audit_results(decoded(logs["npm-audit"]), cargo)
    validate_cargo_scope(cargo, current_db)
    require(result == evidence["result"], "Advisory summary differs from raw reports.")
    require(evidence["sources"] == fingerprints(SOURCES) and evidence["producer"] == fingerprints(PRODUCERS), "Advisory inputs changed during verification.")
    return {"observedAtUtc": evidence["observedAtUtc"], "databaseRevision": current_db["revision"], **result}


def verify(directory, db, output):
    evidence = read_json(directory / "evidence.json")
    current = current_database(db, output, "verified-db")
    return verify_record(evidence, directory, db, current)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=ROOT / "build/deps/rustsec-advisory-db")
    parser.add_argument("--node", type=Path, default=ROOT / "build/deps/node-v24.21.0-win-x64/node.exe")
    parser.add_argument("--npm-cli", type=Path, default=Path("C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js"))
    parser.add_argument("--cargo-audit", type=Path, default=ROOT / "build/deps/cargo-audit/bin/cargo-audit.exe")
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    (ROOT / "build").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="advisory-evidence-", dir=ROOT / "build"))
    db = args.db.resolve()
    if args.check:
        result = verify(args.check.resolve(), db, output)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return
    evidence = {"schemaVersion": 1, "status": "failed", "observedAtUtc": datetime.now(timezone.utc).isoformat(), "steps": [],
                "scope": "Known npm and Cargo advisories; dated registry response and current official RustSec worktree; warnings retained.",
                "sources": fingerprints(SOURCES), "producer": fingerprints(PRODUCERS)}
    print("Advisory evidence: " + str(output), flush=True)
    try:
        evidence["tools"] = {name: {"path": str(path.resolve()), "sha256": digest_file(path.resolve())}
                             for name, path in (("node", args.node), ("npm", args.npm_cli), ("cargoAudit", args.cargo_audit))}
        evidence["databaseBefore"] = current_database(db, output, "before-db")
        for label, arguments in zip(LABELS, commands(evidence["tools"], db)):
            print("Advisory audit: " + label, flush=True)
            result = command(arguments, output, label)
            evidence["steps"].append({"label": label, "command": arguments, **result})
        evidence["result"] = audit_results(read_json(output / "npm-audit.log"), read_json(output / "cargo-audit.log"))
        evidence["databaseAfter"] = current_database(db, output, "after-db")
        evidence["databaseArtifacts"] = {label + extension: digest_file(output / (label + extension)) for label in DB_LABELS for extension in (".log", ".command.json")}
        require(evidence["sources"] == fingerprints(SOURCES) and evidence["producer"] == fingerprints(PRODUCERS) and
                evidence["databaseBefore"] == evidence["databaseAfter"], "Advisory inputs changed during execution.")
        candidate = dict(evidence, status="passed")
        verify_record(candidate, output, db, evidence["databaseAfter"])
        evidence["status"] = "passed"
    except BaseException as error:
        evidence["failure"] = type(error).__name__ + ": " + str(error)[:1000]
        raise
    finally:
        (output / "evidence.json").write_bytes(encoded(evidence))
    print("Advisory audit PASS: " + str(output), flush=True)


if __name__ == "__main__":
    main()
