"""Produce and verify a bounded, source-bound pre-build dependency inventory."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from urllib.parse import quote
from tauri_backport import verify as verify_tauri_backport, LOCAL_VERSION as TAURI_VERSION

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")
MANIFEST = "apps/knmon-ui/src-tauri/Cargo.toml"
LOCK = "apps/knmon-ui/src-tauri/Cargo.lock"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_JSON = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return decode_json(bounded_bytes(path))


def bounded_bytes(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, "Input exceeds size bound.")
    return data


def decode_json(data):
    require(len(data) <= MAX_JSON, "JSON exceeds input size bound.")
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, f"Non-finite JSON: {value}"))


def safe_file(directory, name):
    require(isinstance(name, str) and name and "\\" not in name, "Invalid evidence path.")
    relative = Path(name)
    require(not relative.is_absolute() and ":" not in name and all(part not in (".", "..") for part in name.split("/")),
            "Evidence path escapes its directory.")
    result = directory.joinpath(relative).resolve(strict=True)
    require(result.is_relative_to(directory.resolve()) and result.is_file(), "Evidence file escapes its directory.")
    return result


def native_files(root):
    files = {}
    for name, expected in {
        "native/third-party/nlohmann/json.hpp": "aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63",
        "native/third-party/nlohmann/LICENSE.MIT": "46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603",
    }.items():
        require(digest(bounded_bytes(root / name)) == expected, f"Vendored checksum mismatch: {name}")
        files[name] = expected
    for line in (root / "native/third-party/zstd/SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        require(re.fullmatch("[0-9a-f]{64}", expected), "Invalid vendored checksum.")
        relative = "native/third-party/zstd/" + name
        require(relative not in files, "Duplicate vendored checksum.")
        require(digest(bounded_bytes(safe_file(root / "native/third-party/zstd", name))) == expected,
                f"Vendored checksum mismatch: {name}")
        files[relative] = expected
    zstd_files = {path.relative_to(root).as_posix() for path in (root / "native/third-party/zstd/lib").rglob("*") if path.is_file()}
    zstd_files.update("native/third-party/zstd/" + name for name in ("LICENSE", "COPYING"))
    require(zstd_files == {name for name in files if name.startswith("native/third-party/zstd/")},
            "Vendored manifest does not cover the retained source files.")
    return files


def source_inputs(root=ROOT):
    names = {"package.json", "package-lock.json", "apps/knmon-ui/package.json", MANIFEST, LOCK,
             "crates/knmon-tauri/Cargo.toml", "native/CMakeLists.txt", "native/third-party/zstd/CMakeLists.txt",
             "native/third-party/zstd/SHA256SUMS", "native/third-party/zstd/README.knmon.md",
             "native/third-party/nlohmann/README.md", "VERSION", "toolchain.json", ".cargo/config.toml", ".gitattributes",
             "tools/security/dependency_inventory.py", "tools/security/verify_dependency_inventory.py", "tools/security/validate-sbom-schema.mjs",
             "tools/security/tauri_backport.py", "tools/security/verify_tauri_backport.py", "tools/source/tauri-backport.mjs",
             "tools/source/preflight.mjs", "crates/third-party/README.md"}
    names.update(verify_tauri_backport(root)["inputs"])
    names.update(native_files(root))
    names.update(file.relative_to(root).as_posix() for file in (root / "tools/security/cyclonedx").iterdir() if file.is_file())
    return {name: digest(bounded_bytes(safe_file(root, name))) for name in sorted(names)}


def prop(name, value):
    return {"name": "knmon:" + name, "value": value}


def npm_edges(lock):
    packages = lock["packages"]
    def identity(path):
        entry = packages[path]
        if entry.get("link"):
            path = entry["resolved"]
            entry = packages[path]
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        return "npm:" + name + "@" + entry["version"]
    edges = {}
    for path, entry in packages.items():
        if entry.get("link"):
            continue
        children = set()
        requests = set().union(*(entry.get(kind, {}) for kind in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")))
        for name in requests:
            current, found = path, None
            while True:
                candidate = (current + "/" if current else "") + "node_modules/" + name
                if candidate in packages:
                    found = identity(candidate)
                    break
                if not current:
                    break
                current = current.rsplit("/", 1)[0] if "/" in current else ""
            if found is not None:
                children.add(found)
            else:
                require(name in entry.get("optionalDependencies", {}) or entry.get("peerDependenciesMeta", {}).get(name, {}).get("optional"),
                        f"Required npm dependency is absent: {path}: {name}")
        edges.setdefault(identity(path), set()).update(children)
    for workspace in packages[""].get("workspaces", []):
        require(workspace in packages and not packages[workspace].get("link"), "Unsupported or unresolved npm workspace path.")
        edges[identity("")].add(identity(workspace))
    return {key: sorted(value) for key, value in edges.items()}


def npm_components(bom, lock):
    require(bom["bomFormat"] == "CycloneDX", "Invalid npm inventory format.")
    rows = [bom["metadata"]["component"], *bom["components"]]
    by_ref = {row["bom-ref"]: row for row in rows}
    require(len(by_ref) == len(rows), "Duplicate npm component identity.")
    expected = {}
    for path, entry in lock["packages"].items():
        if entry.get("link"):
            require(entry["resolved"] in lock["packages"], "Unresolved npm workspace link.")
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        key = name + "@" + entry["version"]
        if key in expected:
            require(expected[key].get("integrity") == entry.get("integrity"), "Conflicting npm package identity.")
        expected[key] = entry
    require(set(expected) == set(by_ref), "npm inventory does not match every lockfile package.")
    for key, entry in expected.items():
        row = by_ref[key]
        require(row["version"] == entry["version"], "npm version differs from lockfile.")
        if "integrity" in entry:
            hashes = []
            for integrity in entry["integrity"].split():
                algorithm, value = integrity.split("-", 1)
                require(algorithm in ("sha256", "sha384", "sha512"), "Unsupported npm integrity algorithm.")
                hashes.append({"alg": "SHA-" + algorithm[3:], "content": base64.b64decode(value, validate=True).hex()})
            require(row.get("hashes") == hashes, "npm integrity differs from lockfile.")
            require({"type": "distribution", "url": entry["resolved"]} in row.get("externalReferences", []),
                    "npm distribution differs from lockfile.")
    output = []
    for key, original in sorted(by_ref.items()):
        row = copy.deepcopy(original)
        row["bom-ref"] = "npm:" + key
        row.setdefault("properties", []).append(prop("inventoryScope", "npm lockfile; includes development and optional platforms"))
        output.append(row)
    edges = {"npm:" + row["ref"]: sorted("npm:" + target for target in row["dependsOn"]) for row in bom["dependencies"]}
    require(len(edges) == len(bom["dependencies"]), "Duplicate npm dependency node.")
    require(edges == npm_edges(lock), "npm dependency edges differ from lockfile resolution.")
    return output, edges, "npm:" + bom["metadata"]["component"]["bom-ref"]


def cargo_components(metadata, lock, root):
    locked = {(row["name"], row["version"], row.get("source")): row for row in lock["package"]}
    backport = verify_tauri_backport(root)
    components, edges, graphs, roots = {}, {}, {}, set()
    require(set(metadata) == set(TARGETS), "Both Windows Cargo target graphs are required.")
    for target in TARGETS:
        data = metadata[target]
        require(data["version"] == 1 and data["resolve"] is not None, "Missing Cargo resolution.")
        packages = {row["id"]: row for row in data["packages"]}
        require(len(packages) == len(data["packages"]), "Duplicate Cargo package identity.")
        nodes = {row["id"]: row for row in data["resolve"]["nodes"]}
        require(len(nodes) == len(data["resolve"]["nodes"]), "Duplicate Cargo graph node.")
        require(data["resolve"]["root"] in nodes, "Missing Cargo root.")
        patched = [packages[identity] for identity in nodes if packages[identity]["name"] == "tauri-utils"]
        require(len(patched) == 1 and patched[0]["source"] is None and patched[0]["version"] == TAURI_VERSION and
                Path(patched[0]["manifest_path"]).resolve() == (root / "crates/third-party/tauri-utils/Cargo.toml").resolve(),
                "Cargo did not resolve the pinned Tauri backport.")
        refs = {}
        for identity in nodes:
            package = packages[identity]
            key = (package["name"], package["version"], package["source"])
            require(key in locked and package["source"] in (None, REGISTRY), "Unpinned or unsupported Cargo source.")
            ref = "cargo:" + package["name"] + "@" + package["version"]
            require(ref not in refs.values(), "Conflicting Cargo package identity.")
            refs[identity] = ref
            component = {"bom-ref": ref, "type": "library", "name": package["name"], "version": package["version"],
                         "purl": "pkg:cargo/" + quote(package["name"], safe="") + "@" + quote(package["version"], safe=""),
                         "properties": [prop("inventoryScope", "Windows resolved Cargo graph with tauri/custom-protocol; includes build dependencies")]}
            if package["source"] is None:
                # Cargo package IDs and local paths are opaque, not evidence paths.
                path = Path(package["manifest_path"]).resolve()
                require(path.is_relative_to(root.resolve()), "Local Cargo dependency is outside the source tree.")
                component["properties"].append(prop("manifest", path.relative_to(root.resolve()).as_posix()))
            else:
                checksum = locked[key].get("checksum", "")
                require(re.fullmatch("[0-9a-f]{64}", checksum), "Cargo registry checksum is missing.")
                component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
            if package.get("license"):
                component["licenses"] = [{"expression": package["license"]}]
            if package["name"] == "tauri-utils":
                provenance = backport["manifest"]
                component["properties"].append(prop("sourceTreeSha256", backport["sourceTreeSha256"]))
                component["pedigree"] = {
                    "ancestors": [{"type": "library", "name": "tauri-utils", "version": provenance["package"]["upstreamVersion"],
                                   "purl": "pkg:cargo/tauri-utils@" + provenance["package"]["upstreamVersion"],
                                   "hashes": [{"alg": "SHA-256", "content": provenance["upstream"]["sha256"]}],
                                   "externalReferences": [{"type": "distribution", "url": provenance["upstream"]["url"]}]}],
                    "commits": [{"uid": provenance["backport"]["commit"], "url": provenance["backport"]["url"]}],
                    "notes": "Local backport changes only the URLPattern dependency and package build metadata in the two Cargo manifests. Upstream Rust source is unchanged.",
                }
            require(ref not in components or components[ref] == component, "Cargo target metadata conflict.")
            components[ref] = component
        roots.add(refs[data["resolve"]["root"]])
        graph = []
        for identity, node in sorted(nodes.items(), key=lambda pair: refs[pair[0]]):
            require(set(node["dependencies"]) == {dependency["pkg"] for dependency in node["deps"]}, "Cargo dependency representations disagree.")
            require(all(dependency in refs for dependency in node["dependencies"]), "Cargo edge leaves the target graph.")
            children = sorted(refs[dependency] for dependency in node["dependencies"])
            edges.setdefault(refs[identity], set()).update(children)
            graph.append({"ref": refs[identity], "dependsOn": children, "features": sorted(node["features"]),
                          "dependencyKinds": [{"ref": refs[dependency["pkg"]], "kinds": dependency["dep_kinds"]}
                                              for dependency in sorted(node["deps"], key=lambda row: refs[row["pkg"]])]})
        require("custom-protocol" in nodes[next(key for key in nodes if packages[key]["name"] == "tauri")]["features"],
                "Cargo graph lacks the release protocol feature.")
        graphs[target] = {"root": refs[data["resolve"]["root"]], "nodes": graph}
    for ref, component in components.items():
        targets = [target for target, graph in graphs.items() if any(node["ref"] == ref for node in graph["nodes"])]
        component["properties"].append(prop("targets", ",".join(targets)))
    return list(components.values()), {key: sorted(value) for key, value in edges.items()}, graphs, roots


def build_inventory(npm, cargo, root=ROOT):
    inputs = source_inputs(root)
    npm_rows, edges, npm_root = npm_components(npm, read_json(root / "package-lock.json"))
    cargo_rows, cargo_edges, graphs, cargo_roots = cargo_components(cargo, tomllib.loads((root / LOCK).read_text()), root)
    edges.update(cargo_edges)
    components = npm_rows + cargo_rows
    native = native_files(root)
    for name, version, license_id, prefix in (("nlohmann-json", "3.12.0", "MIT", "native/third-party/nlohmann/"),
                                               ("zstd", "1.5.7", "BSD-3-Clause", "native/third-party/zstd/")):
        ref = "native:" + name + "@" + version
        components.append({"bom-ref": ref, "type": "library", "name": name, "version": version,
                           "licenses": [{"license": {"id": license_id}}],
                           "properties": [prop("inventoryScope", "vendored native source subset; host only")],
                           "components": [{"bom-ref": "file:" + path, "type": "file", "name": path,
                                           "hashes": [{"alg": "SHA-256", "content": checksum}]}
                                          for path, checksum in sorted(native.items()) if path.startswith(prefix)]})
        edges[ref] = []
    platform = "platform:windows"
    components.append({"bom-ref": platform, "type": "operating-system", "name": "Microsoft Windows",
                       "properties": [prop("inventoryScope", "OS-provided APIs including winsqlite3; concrete DLL versions are environment-dependent")]})
    edges[platform] = []
    subject = "knmon:source"
    edges[subject] = sorted([npm_root, *cargo_roots, "native:nlohmann-json@3.12.0", "native:zstd@1.5.7", platform])
    identifiers = {row["bom-ref"] for row in components} | {subject}
    require(len(identifiers) == len(components) + 1, "Duplicate merged component identity.")
    require(set(edges) == identifiers, "Missing dependency graph nodes.")
    require(all(child in identifiers for children in edges.values() for child in children), "Dangling dependency edge.")
    visited, pending = set(), [subject]
    while pending:
        current = pending.pop()
        if current not in visited:
            visited.add(current)
            pending.extend(edges[current])
    require(visited == identifiers, "Unreachable component in dependency inventory.")
    bom = {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
           "metadata": {"lifecycles": [{"phase": "pre-build"}],
                        "component": {"bom-ref": subject, "type": "application", "name": "KnWin32ApiMonitor",
                                      "version": (root / "VERSION").read_text().strip()},
                        "properties": [prop("sourceInputsSha256", digest(encoded(inputs))),
                                       prop("scope", "Source dependency inventory; not a complete linked binary or OS runtime inventory")]},
           "components": sorted(components, key=lambda row: row["bom-ref"]),
           "dependencies": [{"ref": key, "dependsOn": value} for key, value in sorted(edges.items())],
           "compositions": [{"aggregate": "incomplete", "assemblies": [subject]}]}
    return bom, graphs, inputs


def checked_run(command, directory, name, cwd=ROOT):
    output = directory / name
    with output.open("xb") as stream:
        process = subprocess.run([str(part) for part in command], cwd=cwd, stdout=stream, stderr=subprocess.PIPE,
                                 timeout=120, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    require(process.returncode == 0, f"Command failed: {command[0]}: {process.stderr.decode('utf-8', errors='replace')[:2000]}")
    require(output.stat().st_size <= MAX_JSON, "Command output exceeds size bound.")


def resolve_cargo(directory, root=ROOT):
    metadata = {}
    for target, arch in zip(TARGETS, ("x64", "x86")):
        checked_run(["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", MANIFEST,
                     "--filter-platform", target, "--features", "tauri/custom-protocol"], directory, f"cargo-{arch}.json", cwd=root)
        metadata[target] = read_json(directory / f"cargo-{arch}.json")
    return metadata


def verify(directory, root=ROOT, current_cargo=None):
    evidence = read_json(directory / "evidence.json")
    require(evidence["schemaVersion"] == 1 and evidence["status"] == "passed", "Incomplete dependency evidence.")
    require(evidence["sourceInputs"] == source_inputs(root), "Dependency source inputs are stale.")
    expected_artifacts = {"npm.json", "cargo-x64.json", "cargo-x86.json", "bom.cdx.json", "cargo-targets.json", "schema.log", "tools.json"}
    require(set(evidence["artifacts"]) == expected_artifacts, "Dependency artifact set is incomplete.")
    artifacts = {}
    total_bytes = 0
    for name, checksum in evidence["artifacts"].items():
        path = safe_file(directory, name)
        data = bounded_bytes(path)
        total_bytes += len(data)
        require(len(data) <= MAX_JSON and total_bytes <= 64 * 1024 * 1024 and digest(data) == checksum, f"Evidence hash mismatch: {name}")
        artifacts[name] = data
    npm = decode_json(artifacts["npm.json"])
    bom, graphs, _ = build_inventory(npm,
                                    {target: decode_json(artifacts[f"cargo-{arch}.json"]) for target, arch in zip(TARGETS, ("x64", "x86"))}, root)
    require(decode_json(artifacts["bom.cdx.json"]) == bom, "SBOM differs from source and resolved graph evidence.")
    require(decode_json(artifacts["cargo-targets.json"]) == graphs, "Cargo target provenance differs from raw metadata.")
    versions = decode_json(artifacts["tools.json"])
    require(versions["cargoFeatures"] == ["tauri/custom-protocol"] and versions["cargoTargets"] == list(TARGETS) and
            versions["npmLockOnly"] is True and versions["cargoLocked"] is True and versions["cargoOffline"] is True,
            "Dependency tool configuration differs from the required scope.")
    if current_cargo is None:
        with tempfile.TemporaryDirectory(prefix="knmon-cargo-check-") as fresh:
            current_cargo = resolve_cargo(Path(fresh), root)
    current_bom, current_graphs, _ = build_inventory(npm, current_cargo, root)
    require(current_bom == bom and current_graphs == graphs, "Cargo evidence differs from current locked platform resolution.")
    require(evidence["sourceInputs"] == source_inputs(root), "Sources changed during evidence verification.")
    return bom


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", type=Path)
    mode.add_argument("--output", type=Path)
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--npm-cli", type=Path)
    arguments = parser.parse_args()
    require(arguments.node is not None, "Node is required.")
    node = Path(arguments.node).resolve()
    if arguments.check:
        bom = verify(arguments.check.resolve())
        subprocess.run([node, ROOT / "tools/security/validate-sbom-schema.mjs", arguments.check.resolve() / "bom.cdx.json"],
                       cwd=ROOT, check=True, timeout=60)
        print(f"Dependency inventory current: {len(bom['components'])} top-level components.")
        return
    npm_cli = (arguments.npm_cli or node.parent / "node_modules/npm/bin/npm-cli.js").resolve()
    require(npm_cli.is_file(), "Provide the installed npm CLI JavaScript path with --npm-cli.")
    (ROOT / "build").mkdir(exist_ok=True)
    directory = arguments.output.resolve() if arguments.output else Path(tempfile.mkdtemp(prefix="dependency-evidence-", dir=ROOT / "build"))
    if arguments.output:
        directory.mkdir(parents=True, exist_ok=False)
    before = source_inputs()
    checked_run([node, npm_cli, "sbom", "--package-lock-only", "--sbom-format", "cyclonedx"], directory, "npm.json")
    metadata = resolve_cargo(directory)
    bom, graphs, inputs = build_inventory(read_json(directory / "npm.json"), metadata)
    require(before == inputs, "Dependency sources changed during inventory generation.")
    (directory / "bom.cdx.json").write_bytes(encoded(bom))
    (directory / "cargo-targets.json").write_bytes(encoded(graphs))
    checked_run([node, ROOT / "tools/security/validate-sbom-schema.mjs", directory / "bom.cdx.json"], directory, "schema.log")
    versions = {"node": subprocess.check_output([node, "--version"], text=True).strip(),
                "npm": subprocess.check_output([node, npm_cli, "--version"], text=True).strip(),
                "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
                "cargoFeatures": ["tauri/custom-protocol"], "cargoTargets": list(TARGETS),
                "npmLockOnly": True, "cargoLocked": True, "cargoOffline": True}
    (directory / "tools.json").write_bytes(encoded(versions))
    require(inputs == source_inputs(), "Dependency sources changed during verification.")
    evidence = {"schemaVersion": 1, "status": "passed", "sourceInputs": inputs,
                "artifacts": {file.name: digest(file.read_bytes()) for file in sorted(directory.iterdir()) if file.is_file()}}
    (directory / "evidence.json").write_bytes(encoded(evidence))
    verify(directory)
    print(f"Dependency evidence PASS: {directory}; components={len(bom['components'])}")


if __name__ == "__main__":
    main()
