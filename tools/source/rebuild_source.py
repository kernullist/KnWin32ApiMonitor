"""Rebuild a clean source ZIP without Git metadata and retain executed evidence."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from owned_command import run
from source_archive import digest_file, extract_archive, require, verify_tree

ROOT = Path(__file__).resolve().parents[2]
COMMON_TESTS = {"stack-capture", "capture-history", "session-codec", "ipc-security", "bounded-json", "runtime-support", "transport-security",
                "transport-writer", "session-lease", "agent-footprint", "pe-hardening-knmon-native-helper", "pe-hardening-knmon-collector",
                "cfg-enforcement", "lifecycle-process-exit", "lifecycle-stop-reserved", "lifecycle-stop-commit", "sustained-capture",
                "abi-differential", "capture-semantics", "capture-delayed-collector", "capture-stream-retention", "capture-consumer-failure", "module-lifecycle", "corpus-control"}


def validate_tests(path, architecture):
    require(path.stat().st_size <= 16 * 1024 * 1024, "CTest XML exceeds its bound.")
    data = path.read_bytes()
    require(b"<!DOCTYPE" not in data and b"<!ENTITY" not in data, "Unexpected CTest XML declaration.")
    tree = ET.fromstring(data)
    require(tree.tag == "testsuite", "Unexpected CTest report root.")
    cases = tree.findall("testcase")
    expected = COMMON_TESTS | {"pe-hardening-knmon-agent" + ("64" if architecture == "x64" else "32")}
    require(len(cases) == len(expected) and {case.attrib["name"] for case in cases} == expected, "Executed CTest matrix is incomplete.")
    require(all(case.get("status") == "run" and not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in cases),
            "CTest contains failed, skipped or unexecuted cases.")
    require(int(tree.attrib["tests"]) == len(expected) and int(tree.attrib.get("failures", "0")) == 0 and
            int(tree.attrib.get("skipped", "0")) == 0 and int(tree.attrib.get("disabled", "0")) == 0 and
            int(tree.attrib.get("errors", "0")) == 0, "CTest aggregate counts disagree.")
    return sorted(expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--npm-cli", type=Path)
    arguments = parser.parse_args()
    require(os.name == "nt" and arguments.node is not None, "Windows and Node are required.")
    node = Path(arguments.node).resolve()
    npm = (arguments.npm_cli or node.parent / "node_modules/npm/bin/npm-cli.js").resolve()
    require(npm.is_file(), "The installed npm CLI path is required.")
    (ROOT / "build").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="source-rebuild-", dir=ROOT / "build"))
    source = output / "src"
    archive = arguments.archive.resolve()
    evidence = {"schemaVersion": 1, "status": "failed", "scope": "frontend and x86/x64 native Debug source reconstruction",
                "windowsVersion": platform.version(), "steps": [], "runs": []}
    producer_files = (Path(__file__).resolve(), ROOT / "tools/source/source_archive.py", ROOT / "tools/source/owned_command.py")
    evidence["producer"] = {path.name: digest_file(path) for path in producer_files}
    print(f"Source rebuild evidence: {output}", flush=True)
    try:
        evidence["archiveSha256"] = digest_file(archive)
        manifest = extract_archive(archive, source)
        evidence["revision"] = manifest["revision"]
        evidence["sourceManifestSha256"] = digest_file(source / "SOURCE-MANIFEST.json")
        environment = dict(os.environ)
        environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
        environment["GIT_CEILING_DIRECTORIES"] = str(output)
        environment["CMAKE_BUILD_PARALLEL_LEVEL"] = "4"
        environment["MSBUILDDISABLENODEREUSE"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        git = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=source, env=environment, capture_output=True, timeout=10)
        require(git.returncode != 0 and not (source / ".git").exists(), "Source rebuild still resolves Git metadata.")
        toolchain = json.loads((source / "toolchain.json").read_text())
        node_version = subprocess.check_output([node, "--version"], text=True).strip().removeprefix("v")
        require(node_version == toolchain["node"], "Source reproduction requires the pinned Node baseline.")
        cmake_version = subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0].split()[-1]
        require(cmake_version == toolchain["cmake"], "Source reproduction requires the pinned CMake baseline.")
        evidence["toolchain"] = {**toolchain, "actualNode": node_version, "actualCmake": cmake_version,
                                 "python": platform.python_version(), "npm": subprocess.check_output([node, npm, "--version"], text=True).strip()}
        def step(label, command, timeout=900):
            print(f"Source rebuild: {label}", flush=True)
            result = run(command, source, output / f"{label}.log", environment, timeout)
            evidence["steps"].append({"label": label, "command": [str(value) for value in command], **result})
        step("preflight", [node, "tools/source/preflight.mjs"])
        step("npm-ci", [node, npm, "ci", "--no-audit", "--no-fund"])
        step("frontend-build", [node, npm, "run", "build"])
        step("frontend-validation", [node, npm, "run", "ui:validate"])
        for architecture, directory, extra in (("x64", "native", []), ("x86", "native-win32", ["-Win32"])):
            step(architecture + "-native-build", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", source / "Build.ps1", "-SkipUi", *extra])
            binary_dir = source / "build" / directory / "Debug"
            report = output / f"{architecture}-ctest.xml"
            step(architecture + "-ctest", ["ctest", "--test-dir", source / "build" / directory, "-C", "Debug", "--output-on-failure", "--output-junit", report], timeout=300)
            tests = validate_tests(report, architecture)
            names = ("knmon-native-helper.exe", "knmon-collector.exe", "knmon-agent" + ("64" if architecture == "x64" else "32") + ".dll")
            compiler_files = list((source / "build" / directory / "CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
            require(len(compiler_files) == 1, "Missing compiler provenance.")
            compiler = compiler_files[0].read_text()
            require('set(CMAKE_CXX_COMPILER_ID "MSVC")' in compiler, "Unexpected native compiler.")
            evidence["runs"].append({"architecture": architecture, "configuration": "Debug", "tests": tests,
                                     "ctestSha256": digest_file(report), "compilerFileSha256": digest_file(compiler_files[0]),
                                     "compilerVersion": re.search(r'set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)', compiler).group(1),
                                     "binaries": {name: digest_file(binary_dir / name) for name in names}})
        verify_tree(source, manifest)
        require(digest_file(source / "SOURCE-MANIFEST.json") == evidence["sourceManifestSha256"], "Source manifest changed during reconstruction.")
        require(digest_file(archive) == evidence["archiveSha256"], "Source archive changed during reconstruction.")
        evidence["frontendArtifacts"] = {path.relative_to(source).as_posix(): digest_file(path) for path in sorted((source / "apps/knmon-ui/dist").rglob("*")) if path.is_file()}
        require(evidence["frontendArtifacts"], "Frontend build produced no artifacts.")
        require(evidence["producer"] == {path.name: digest_file(path) for path in producer_files}, "Source rebuild producer changed during execution.")
        evidence["status"] = "passed"
    except BaseException as error:
        evidence["failure"] = str(error)
        raise
    finally:
        (output / "evidence.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Source rebuild PASS: {output}", flush=True)


if __name__ == "__main__":
    main()
