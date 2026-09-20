"""Exercise both vendor integrity consumers against preserved corrupted fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
from tauri_backport import ARCHIVE, DIRECTORY, MANIFEST, ROOT, encoded, require, verify
sys.path.insert(0, str(ROOT / "tools/source"))
from owned_command import run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", type=Path, default=ROOT / "build/deps/node-v24.21.0-win-x64/node.exe")
    args = parser.parse_args()
    baseline = verify()
    node = args.node.resolve(strict=True)
    directory = Path(tempfile.mkdtemp(prefix="tauri-backport-negative-", dir=ROOT / "build"))
    script = "import { verifyTauriBackport } from " + json.dumps((ROOT / "tools/source/tauri-backport.mjs").as_uri()) + "; verifyTauriBackport(process.argv[1]);"

    def node_check(root, destination):
        return run([node, "--input-type=module", "-e", script, root], ROOT, destination / "node.log", dict(os.environ), timeout=30)

    node_check(ROOT, directory)
    cases = ("changed-source", "changed-manifest", "changed-archive", "rehash-source-and-manifest", "missing-source",
             "extra-source", "extra-directory", "oversized-manifest", "oversized-source", "oversized-archive", "vendor-junction", "ancestor-junction")
    results = []
    for label in cases:
        case = directory / label
        source = case / DIRECTORY
        shutil.copytree(ROOT / DIRECTORY, source)
        file = source / "tauri-utils/src/lib.rs"
        manifest_file = source / MANIFEST
        if label in ("changed-source", "rehash-source-and-manifest"):
            file.write_bytes(file.read_bytes() + b"\n// Corrupted vendor input.\n")
            if label == "rehash-source-and-manifest":
                manifest = json.loads(manifest_file.read_bytes())
                manifest["files"]["tauri-utils/src/lib.rs"].update(bytes=file.stat().st_size, sha256=hashlib.sha256(file.read_bytes()).hexdigest())
                manifest_file.write_bytes(encoded(manifest))
        elif label == "changed-manifest":
            manifest = json.loads(manifest_file.read_bytes())
            manifest["backport"]["commit"] = "0" * 40
            manifest_file.write_bytes(encoded(manifest))
        elif label == "changed-archive":
            archive = source / ARCHIVE
            data = bytearray(archive.read_bytes())
            data[len(data) // 2] ^= 1
            archive.write_bytes(data)
        elif label == "missing-source":
            file.unlink()
        elif label == "extra-source":
            (source / "tauri-utils/src/unlisted.rs").write_bytes(b"// Unlisted vendor input.\n")
        elif label == "extra-directory":
            (source / "tauri-utils/src/unlisted").mkdir()
        elif label == "oversized-manifest":
            manifest_file.write_bytes(b" " * (64 * 1024 + 1))
        elif label == "oversized-source":
            file.write_bytes(b" " * (1024 * 1024 + 1))
        elif label == "oversized-archive":
            (source / ARCHIVE).write_bytes(b" " * (1024 * 1024 + 1))
        else:
            moved = source / "tauri-utils" if label == "vendor-junction" else case / "crates"
            destination = case / "retained-junction-target"
            require(moved.resolve().is_relative_to(case.resolve()) and destination.resolve().is_relative_to(case.resolve()),
                    "Junction fixture move escapes its owned directory.")
            moved.rename(destination)
            command = "New-Item -ItemType Junction -Path '" + str(moved).replace("'", "''") + "' -Target '" + str(destination).replace("'", "''") + "' | Out-Null"
            run(["powershell.exe", "-NoProfile", "-Command", command], ROOT, case / "junction.log", dict(os.environ), timeout=30)
            require(moved.is_junction(), "Junction fixture was not created.")
        try:
            verify(case)
        except (ValueError, OSError) as error:
            python_error = str(error)
        else:
            raise RuntimeError("Python accepted invalid Tauri inputs: " + label)
        try:
            node_check(case, case)
        except RuntimeError as error:
            require("Owned command failed (1)" in str(error), "Node rejected at an unintended execution boundary.")
        else:
            raise RuntimeError("Node accepted invalid Tauri inputs: " + label)
        results.append({"case": label, "python": python_error, "node": "rejected"})
        print("Rejected by Python and Node: " + label, flush=True)
    rebuilt = directory / "reconstructed"
    rebuilt.mkdir()
    run([sys.executable, "-X", "utf8", ROOT / "tools/security/tauri_backport.py", "--output", rebuilt / DIRECTORY],
        ROOT, rebuilt / "reconstruct.log", dict(os.environ), timeout=30)
    require(verify(rebuilt) == baseline, "Offline reconstruction differs from retained provenance.")
    node_check(rebuilt, rebuilt)
    require(verify() == baseline, "Original vendor inputs changed during controls.")
    (directory / "controls.json").write_bytes(encoded({"status": "passed", "sourceTreeSha256": baseline["sourceTreeSha256"], "cases": results}))
    print("Tauri backport adversarial validation PASS: " + str(directory))


if __name__ == "__main__":
    main()
