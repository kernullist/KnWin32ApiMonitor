"""Recheck retained source reconstruction artifacts without trusting status alone."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/source"))
from rebuild_source import validate_tests
from source_archive import digest_file, inspect_archive, parse_manifest, require, unique_object, validate_container, verify_tree

LABELS = ("preflight", "npm-ci", "frontend-build", "frontend-validation", "x64-native-build", "x64-ctest", "x86-native-build", "x86-ctest")
PRODUCERS = ("rebuild_source.py", "source_archive.py", "owned_command.py")
SOURCE_TREES = ("native", "apps/knmon-ui/src", "apps/knmon-ui/public", "crates/knmon-tauri/src", "tools", "generated", "samples/targets")


def read_bytes(path, limit=4 * 1024 * 1024):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Evidence input exceeds its bound: " + str(path))
    return data


def read_json(path):
    data = read_bytes(path)
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, "Non-finite evidence number."))


def contained(directory, relative):
    path = directory / relative
    require(path.resolve(strict=True).is_relative_to(directory.resolve()) and not path.is_symlink(), "Artifact escapes its evidence directory.")
    return path


def reconstruction_input(name):
    return not (name.startswith("docs/") or name.startswith("tools/readiness/") or
                name == "crates/knmon-tauri/Cargo.lock" or any(part.casefold() == "agents.md" for part in name.split("/")))


def verify_current_sources(manifest, root=ROOT):
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, timeout=30)
    actual = {name for name in names.decode("utf-8").split("\0") if name and reconstruction_input(name)}
    expected = {name for name in manifest["files"] if reconstruction_input(name)}
    require(actual == expected, "Reconstruction input file set differs from the current checkout.")
    ignored = subprocess.check_output(["git", "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", *SOURCE_TREES], cwd=root, timeout=30)
    hidden = [name for name in ignored.decode("utf-8").split("\0") if name and reconstruction_input(name) and
              not ("__pycache__" in Path(name).parts and Path(name).suffix.lower() in (".pyc", ".pyo"))]
    require(not hidden, "Unlisted build source hidden by Git ignore rules: " + ", ".join(hidden[:4]))
    for name in sorted(expected):
        record = manifest["files"][name]
        path = contained(root, name)
        require(path.stat().st_size == record["bytes"] and digest_file(path) == record["sha256"],
                "Reconstruction input changed: " + name)


def expected_commands(directory, steps):
    require(isinstance(steps, list) and [step.get("label") for step in steps] == list(LABELS), "Incomplete or duplicate reconstruction steps.")
    source = directory / "src"
    node, npm = steps[0]["command"][0], steps[1]["command"][1]
    require(isinstance(node, str) and Path(node).name.lower() == "node.exe" and isinstance(npm, str) and Path(npm).name == "npm-cli.js",
            "Unexpected reconstruction command executables.")
    commands = [[node, "tools/source/preflight.mjs"], [node, npm, "ci", "--no-audit", "--no-fund"],
                [node, npm, "run", "build"], [node, npm, "run", "ui:validate"]]
    for arch, build, extra in (("x64", "native", []), ("x86", "native-win32", ["-Win32"])):
        commands.append(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(source / "Build.ps1"), "-SkipUi", *extra])
        commands.append(["ctest", "--test-dir", str(source / "build" / build), "-C", "Debug", "--output-on-failure", "--output-junit", str(directory / f"{arch}-ctest.xml")])
    return commands


def verify_steps(directory, steps):
    commands = expected_commands(directory, steps)
    for step, command in zip(steps, commands):
        require(step["command"] == command and type(step["exitCode"]) is int and step["exitCode"] == 0,
                "Reconstruction command or exit status differs from policy.")
        require(type(step["elapsedMs"]) is int and step["elapsedMs"] >= 0 and type(step["logBytes"]) is int,
                "Invalid reconstruction command accounting.")
        data = read_bytes(contained(directory, step["label"] + ".log"), 32 * 1024 * 1024)
        require(len(data) == step["logBytes"] and hashlib.sha256(data).hexdigest() == step["logSha256"], "Reconstruction command log changed.")
        request = read_json(contained(directory, step["label"] + ".command.json"))
        require(request == {"command": command, "cwd": str(directory / "src")}, "Owned command request differs from its result.")


def verify_record(evidence, directory, archive, current_root=ROOT):
    require(type(evidence["schemaVersion"]) is int and evidence["schemaVersion"] == 1 and evidence["status"] == "passed",
            "Source reconstruction did not pass.")
    require(evidence["scope"] == "frontend and x86/x64 native Debug source reconstruction" and
            re.fullmatch(r"10\.0\.\d+", evidence["windowsVersion"]), "Unexpected source reconstruction scope.")
    validate_container(archive)
    require(digest_file(archive) == evidence["archiveSha256"], "Reconstruction archive changed.")
    with zipfile.ZipFile(archive) as container:
        manifest, _ = inspect_archive(container)
    source = contained(directory, "src")
    manifest_file = contained(source, "SOURCE-MANIFEST.json")
    manifest_data = read_bytes(manifest_file)
    require(hashlib.sha256(manifest_data).hexdigest() == evidence["sourceManifestSha256"] and
            parse_manifest(manifest_data) == manifest and manifest["revision"] == evidence["revision"], "Source manifest provenance differs.")
    verify_tree(source, manifest)
    verify_current_sources(manifest, current_root)
    producer = {name: digest_file(current_root / "tools/source" / name) for name in PRODUCERS}
    require(evidence["producer"] == producer and all(manifest["files"]["tools/source/" + name]["sha256"] == value for name, value in producer.items()),
            "Reconstruction producer is stale or absent from its source archive.")
    tools = evidence["toolchain"]
    pinned = read_json(source / "toolchain.json")
    require(all(tools.get(name) == value for name, value in pinned.items()) and tools["actualNode"] == pinned["node"] and
            tools["actualCmake"] == pinned["cmake"], "Reconstruction toolchain differs from the pinned baseline.")
    verify_steps(directory, evidence["steps"])
    runs = evidence["runs"]
    require(isinstance(runs, list) and len(runs) == 2 and {run["architecture"] for run in runs} == {"x64", "x86"}, "Incomplete source reconstruction architectures.")
    for run in runs:
        arch = run["architecture"]
        report = contained(directory, f"{arch}-ctest.xml")
        require(run["configuration"] == "Debug" and digest_file(report) == run["ctestSha256"] and
                validate_tests(report, arch) == run["tests"], "Reconstruction CTest evidence differs.")
        build = contained(source, "build/" + ("native" if arch == "x64" else "native-win32"))
        compilers = list((build / "CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
        require(len(compilers) == 1, "Compiler provenance changed.")
        compiler_file = contained(source, compilers[0].relative_to(source))
        require(digest_file(compiler_file) == run["compilerFileSha256"], "Compiler provenance changed.")
        compiler = read_bytes(compiler_file).decode("utf-8")
        require('set(CMAKE_CXX_COMPILER_ID "MSVC")' in compiler and
                re.search(r'set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)', compiler).group(1) == run["compilerVersion"], "Compiler identity differs.")
        names = {"knmon-native-helper.exe", "knmon-collector.exe", "knmon-agent" + ("64" if arch == "x64" else "32") + ".dll"}
        require(set(run["binaries"]) == names and all(digest_file(contained(source, (build / "Debug" / name).relative_to(source))) == run["binaries"][name] for name in names),
                "Reconstruction binaries changed or are incomplete.")
    dist = contained(source, "apps/knmon-ui/dist")
    frontend = {path.relative_to(source).as_posix(): digest_file(contained(dist, path.relative_to(dist))) for path in sorted(dist.rglob("*")) if path.is_file()}
    require(frontend and frontend == evidence["frontendArtifacts"], "Frontend artifact inventory differs.")
    return {"revision": evidence["revision"], "archiveSha256": evidence["archiveSha256"], "windowsVersion": evidence["windowsVersion"],
            "nativeTests": {run["architecture"]: len(run["tests"]) for run in runs}, "frontendArtifacts": len(frontend), "sourceManifest": manifest}


def verify(directory, archive):
    return verify_record(read_json(directory / "evidence.json"), directory, archive)
