"""Create a source ZIP containing hydrated, hash-verified tracked files."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]

    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root)

    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    if dirty and not args.allow_dirty:
        raise RuntimeError("Release source packaging requires a clean tracked worktree.")
    subprocess.run(["node", "tools/source/preflight.mjs"], cwd=root, check=True)
    paths = sorted(git("ls-files", "-z", "--cached").decode("utf-8").rstrip("\0").split("\0"))
    payload = {}
    manifest = {"schemaVersion": 1, "revision": git("rev-parse", "HEAD").decode().strip(),
                "dirtySnapshot": dirty, "files": {}}
    for name in paths:
        if "do-not-commit" in Path(name).parts or Path(name).name == "AGENTS.md":
            continue
        source = (root / name).resolve(strict=True)
        if not source.is_relative_to(root) or (root / name).is_symlink():
            raise RuntimeError(f"Unsafe source path: {name}")
        data = source.read_bytes()
        if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise RuntimeError(f"Unhydrated Git LFS pointer: {name}")
        payload[name] = data
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    payload["SOURCE-MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    destination = Path(args.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    print(f"Source package: {destination}; files={len(payload)}; sha256={hashlib.sha256(destination.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
