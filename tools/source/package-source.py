"""Create a source ZIP containing hydrated, hash-verified tracked files."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile
sys.dont_write_bytecode = True
from source_archive import MAX_FILE, MAX_TOTAL, digest_file, parse_manifest, validate_container, validate_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]

    def git(*arguments, data=None):
        return subprocess.check_output(["git", *arguments], cwd=root, input=data)

    initial_status = git("status", "--porcelain", "--untracked-files=no")
    dirty = bool(initial_status)
    if dirty and not args.allow_dirty:
        raise RuntimeError("Release source packaging requires a clean tracked worktree.")
    subprocess.run(["node", "tools/source/preflight.mjs"], cwd=root, check=True)
    revision = git("rev-parse", "HEAD").decode().strip()
    index = git("ls-files", "--stage", "-z")
    files = {}
    for row in index.decode("utf-8").rstrip("\0").split("\0"):
        metadata, name = row.split("\t", 1)
        mode, object_id, stage = metadata.split()
        if mode not in ("100644", "100755") or stage != "0" or name in files:
            raise RuntimeError("Source packaging requires regular, unconflicted tracked files.")
        files[name] = object_id
    payload = {}
    total_bytes = 0
    manifest = {"schemaVersion": 1, "revision": revision,
                "dirtySnapshot": dirty, "files": {}}
    for name, object_id in sorted(files.items()):
        if "do-not-commit" in (part.casefold() for part in Path(name).parts) or Path(name).name.casefold() == "agents.md":
            continue
        validate_name(name)
        source = (root / name).resolve(strict=True)
        if not source.is_relative_to(root) or (root / name).is_symlink():
            raise RuntimeError(f"Unsafe source path: {name}")
        with source.open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        total_bytes += len(data)
        if len(data) > MAX_FILE or total_bytes > MAX_TOTAL:
            raise RuntimeError("Source package exceeds its file or aggregate byte bound.")
        if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise RuntimeError(f"Unhydrated Git LFS pointer: {name}")
        if not dirty and git("hash-object", "--path", name, "--stdin", data=data).decode().strip() != object_id:
            raise RuntimeError(f"Source payload differs from the committed index: {name}")
        payload[name] = data
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    parse_manifest(json.dumps(manifest).encode(), allow_dirty=args.allow_dirty)
    if git("rev-parse", "HEAD").decode().strip() != revision or git("ls-files", "--stage", "-z") != index or \
            git("status", "--porcelain", "--untracked-files=no") != initial_status:
        raise RuntimeError("Git source state changed during packaging.")
    for name, expected in manifest["files"].items():
        if digest_file(root / name) != expected["sha256"]:
            raise RuntimeError(f"Source bytes changed during packaging: {name}")
    payload["SOURCE-MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    destination = Path(args.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compresslevel=9)
    validate_container(destination)
    print(f"Source package: {destination}; files={len(payload)}; sha256={digest_file(destination)}")


if __name__ == "__main__":
    main()
