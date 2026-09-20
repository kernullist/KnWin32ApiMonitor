"""Reject corrupted, incomplete, stale and consistently rehashed dependency evidence."""
import argparse
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

sys.dont_write_bytecode = True
import dependency_inventory as inventory


def rejected(function, label, expected=None):
    try:
        function()
    except (ValueError, KeyError, OSError) as error:
        inventory.require(expected is None or expected in str(error), "Negative inventory control rejected at the wrong boundary: " + label)
        print(f"Rejected: {label}")
    else:
        raise RuntimeError(f"Negative evidence accepted: {label}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--node", default=shutil.which("node"))
    arguments = parser.parse_args()
    directory = arguments.evidence.resolve()
    baseline = inventory.verify(directory)
    current = {target: inventory.read_json(directory / f"cargo-{arch}.json")
               for target, arch in zip(inventory.TARGETS, ("x64", "x86"))}
    npm = inventory.read_json(directory / "npm.json")
    lock = inventory.read_json(inventory.ROOT / "package-lock.json")
    cargo_lock = tomllib.loads((inventory.ROOT / inventory.LOCK).read_text(encoding="utf-8"))
    for label in ("registry substitutes backport", "wrong backport version", "wrong backport path", "missing backport graph node"):
        modified = copy.deepcopy(current)
        data = modified[inventory.TARGETS[0]]
        package = next(row for row in data["packages"] if row["name"] == "tauri-utils")
        if label == "registry substitutes backport":
            package["source"] = inventory.REGISTRY
        elif label == "wrong backport version":
            package["version"] = "2.9.2"
        elif label == "wrong backport path":
            package["manifest_path"] = str(inventory.ROOT / "crates/knmon-tauri/Cargo.toml")
        else:
            data["resolve"]["nodes"] = [node for node in data["resolve"]["nodes"] if node["id"] != package["id"]]
        rejected(lambda: inventory.cargo_components(modified, cargo_lock, inventory.ROOT), label, "pinned Tauri backport")
    for label in ("duplicate npm identity", "missing npm component", "wrong npm integrity", "removed npm edge"):
        value = copy.deepcopy(npm)
        if label == "duplicate npm identity":
            value["components"].append(copy.deepcopy(value["components"][0]))
        elif label == "missing npm component":
            value["components"].pop()
        elif label == "wrong npm integrity":
            next(row for row in value["components"] if row.get("hashes"))["hashes"][0]["content"] = "0" * 128
        else:
            next(row for row in value["dependencies"] if row["dependsOn"])["dependsOn"].pop()
        rejected(lambda: inventory.npm_components(value, lock), label)
    with tempfile.TemporaryDirectory(prefix="inventory-negatives-", dir=inventory.ROOT / "build") as temporary:
        temporary = Path(temporary)
        for label in ("artifact hash", "stale source", "missing target", "path escape", "missing graph edge", "wrong feature scope", "forged backport pedigree"):
            case = temporary / label.replace(" ", "-")
            shutil.copytree(directory, case)
            evidence = inventory.read_json(case / "evidence.json")
            if label == "artifact hash":
                evidence["artifacts"]["npm.json"] = "0" * 64
            elif label == "stale source":
                evidence["sourceInputs"][inventory.LOCK] = "0" * 64
            elif label == "missing target":
                del evidence["artifacts"]["cargo-x86.json"]
            elif label == "path escape":
                evidence["artifacts"]["../npm.json"] = evidence["artifacts"].pop("npm.json")
            elif label == "wrong feature scope":
                tools = inventory.read_json(case / "tools.json")
                tools["cargoFeatures"] = []
                (case / "tools.json").write_bytes(inventory.encoded(tools))
                evidence["artifacts"]["tools.json"] = inventory.digest((case / "tools.json").read_bytes())
            elif label == "forged backport pedigree":
                bom = inventory.read_json(case / "bom.cdx.json")
                component = next(row for row in bom["components"] if row["name"] == "tauri-utils")
                component["pedigree"]["ancestors"][0]["hashes"][0]["content"] = "0" * 64
                (case / "bom.cdx.json").write_bytes(inventory.encoded(bom))
                evidence["artifacts"]["bom.cdx.json"] = inventory.digest((case / "bom.cdx.json").read_bytes())
            else:
                modified = copy.deepcopy(current)
                data = modified[inventory.TARGETS[0]]
                node = next(node for node in data["resolve"]["nodes"] if node["id"] == data["resolve"]["root"])
                dependency = next(row["id"] for row in data["packages"] if row["name"] == "serde")
                node["dependencies"].remove(dependency)
                node["deps"] = [row for row in node["deps"] if row["pkg"] != dependency]
                bom, graph, _ = inventory.build_inventory(npm, modified)
                for name, value in (("cargo-x64.json", data), ("bom.cdx.json", bom), ("cargo-targets.json", graph)):
                    (case / name).write_bytes(inventory.encoded(value))
                    evidence["artifacts"][name] = inventory.digest((case / name).read_bytes())
            (case / "evidence.json").write_bytes(inventory.encoded(evidence))
            rejected(lambda: inventory.verify(case, current_cargo=current), label)
        rejected(lambda: inventory.safe_file(directory, "../package-lock.json"), "direct path traversal")
        rejected(lambda: inventory.decode_json(b'{"same":1,"same":2}'), "duplicate JSON keys")
        rejected(lambda: inventory.decode_json(b'{"value":NaN}'), "non-finite JSON")
        rejected(lambda: inventory.decode_json(b" " * (inventory.MAX_JSON + 1)), "oversized JSON")
        invalid = copy.deepcopy(baseline)
        invalid["inventedProperty"] = True
        invalid_path = temporary / "invalid.cdx.json"
        invalid_path.write_bytes(inventory.encoded(invalid))
        result = subprocess.run([arguments.node, inventory.ROOT / "tools/security/validate-sbom-schema.mjs", invalid_path],
                                cwd=inventory.ROOT, capture_output=True, timeout=60)
        inventory.require(result.returncode != 0, "Invalid CycloneDX schema was accepted.")
        print("Rejected: unknown CycloneDX property")
        vendor_root = temporary / "vendor-root"
        shutil.copytree(inventory.ROOT / "native/third-party", vendor_root / "native/third-party")
        with (vendor_root / "native/third-party/nlohmann/json.hpp").open("ab") as output:
            output.write(b"\n ")
        rejected(lambda: inventory.native_files(vendor_root), "modified vendored source")
        shutil.copyfile(inventory.ROOT / "native/third-party/nlohmann/json.hpp", vendor_root / "native/third-party/nlohmann/json.hpp")
        inventory.native_files(vendor_root)
        (vendor_root / "native/third-party/zstd/lib/common/unlisted.c").write_text("/* Unlisted source negative control. */\n", encoding="ascii")
        rejected(lambda: inventory.native_files(vendor_root), "unlisted vendored source")
        (vendor_root / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.24)\nproject(VendorChecksum C)\nadd_subdirectory(native/third-party/zstd)\n', encoding="ascii")
        result = subprocess.run(["cmake", "-S", vendor_root, "-B", vendor_root / "build", "-G", "Visual Studio 17 2022", "-A", "x64"],
                                capture_output=True, timeout=60)
        inventory.require(result.returncode != 0 and b"Pinned zstd manifest does not cover the retained files." in result.stdout + result.stderr,
                          "CMake failed to reject an unlisted vendored source at its checksum boundary.")
        print("Rejected: unlisted CMake input")
    print("Dependency evidence adversarial validation PASS: 23 negative controls.")


if __name__ == "__main__":
    main()
