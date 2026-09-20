"""Reconstruct and verify the narrowly patched stable Tauri utility crate."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = "crates/third-party"
ARCHIVE = "tauri-utils-2.9.2.crate"
MANIFEST = "tauri-utils.provenance.json"
UPSTREAM_SHA256 = "092379df9a707631978e6c56b1bc2401d387f01e2d4a3c123360d167bbb9aa95"
UPSTREAM_REVISION = "499df79be65ef8c0670abc0207cd9e37b55d8491"
BACKPORT_COMMIT = "dd725f4b13c30a86b398ccc59eb498f151f461c5"
LOCAL_VERSION = "2.9.2+knmon.1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def payloads(archive):
    require(len(archive) == 149496 and digest(archive) == UPSTREAM_SHA256, "Tauri upstream archive checksum differs.")
    files, records = {}, {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as container:
        members = container.getmembers()
        require(len(members) == 34 and sum(member.size for member in members) == 615177, "Unexpected Tauri archive inventory.")
        for member in members:
            parts = member.name.split("/")
            require(member.isfile() and parts[0] == "tauri-utils-2.9.2" and len(parts) > 1 and
                    all(part not in ("", ".", "..") and ":" not in part and "\\" not in part for part in parts),
                    "Unsafe Tauri archive entry.")
            name = "/".join(["tauri-utils", *parts[1:]])
            require(name not in files and 0 <= member.size <= 1024 * 1024, "Duplicate or oversized Tauri archive entry.")
            data = container.extractfile(member).read(member.size + 1)
            require(len(data) == member.size, "Truncated Tauri archive entry.")
            original = digest(data)
            if name in ("tauri-utils/Cargo.toml", "tauri-utils/Cargo.toml.orig"):
                replacements = [(b'version = "2.9.2"', ('version = "' + LOCAL_VERSION + '"').encode())]
                if name.endswith(".orig"):
                    replacements.append((b'urlpattern = "0.3"', b'urlpattern = "0.6"'))
                else:
                    replacements.append((b'[dependencies.urlpattern]\nversion = "0.3"', b'[dependencies.urlpattern]\nversion = "0.6"'))
                for before, after in replacements:
                    require(data.count(before) == 1, "Tauri backport context differs.")
                    data = data.replace(before, after, 1)
            files[name] = data
            records[name] = {"bytes": len(data), "sha256": digest(data), "upstreamSha256": original}
    vcs = json.loads(files["tauri-utils/.cargo_vcs_info.json"])
    require(vcs == {"git": {"sha1": UPSTREAM_REVISION}, "path_in_vcs": "crates/tauri-utils"}, "Tauri upstream VCS identity differs.")
    manifest = {
        "schemaVersion": 1,
        "package": {"name": "tauri-utils", "upstreamVersion": "2.9.2", "localVersion": LOCAL_VERSION},
        "upstream": {"archive": ARCHIVE, "sha256": UPSTREAM_SHA256, "revision": UPSTREAM_REVISION,
                     "url": "https://static.crates.io/crates/tauri-utils/" + ARCHIVE},
        "backport": {"commit": BACKPORT_COMMIT, "url": "https://github.com/tauri-apps/tauri/commit/" + BACKPORT_COMMIT,
                     "changes": ["urlpattern 0.3 to 0.6", "local package version build metadata"],
                     "modifiedFiles": ["tauri-utils/Cargo.toml", "tauri-utils/Cargo.toml.orig"]},
        "files": records,
    }
    return files, manifest


def regular_file(root, name, limit):
    parts = name.split("/")
    require(parts and all(part not in ("", ".", "..") and ":" not in part and "\\" not in part for part in parts), "Unsafe Tauri source path.")
    path = root
    for part in parts:
        path /= part
        require(not path.is_symlink() and not path.is_junction(), "Reparse point in Tauri source inputs.")
    require(path.resolve(strict=True).is_relative_to(root.resolve()) and path.is_file(), "Tauri source escapes its root.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Tauri source input exceeds its bound.")
    return data


def verify(root=ROOT):
    root = root.resolve()
    archive = regular_file(root, DIRECTORY + "/" + ARCHIVE, 1024 * 1024)
    files, manifest = payloads(archive)
    expected_manifest = encoded(manifest)
    retained = regular_file(root, DIRECTORY + "/" + MANIFEST, 64 * 1024)
    require(retained == expected_manifest, "Tauri provenance differs from the pinned upstream backport.")
    expected_names = set(files)
    expected_dirs = {"/".join(name.split("/")[:index]) for name in files for index in range(1, len(name.split("/")))}
    base = root / DIRECTORY
    actual, pending, entries = set(), [base / "tauri-utils"], 0
    while pending:
        directory = pending.pop()
        require(not directory.is_symlink() and not directory.is_junction() and directory.resolve().is_relative_to(base.resolve()),
                "Reparse point in Tauri vendor tree.")
        require(directory.relative_to(base).as_posix() in expected_dirs, "Unlisted Tauri source directory.")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                require(entries <= 128 and not child.is_symlink(), "Oversized or linked Tauri vendor tree.")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    require(child.is_file(follow_symlinks=False), "Non-file Tauri source entry.")
                    actual.add(Path(child.path).relative_to(base).as_posix())
    require(actual == expected_names, "Unlisted or missing Tauri vendor source.")
    inputs = {DIRECTORY + "/" + ARCHIVE: digest(archive), DIRECTORY + "/" + MANIFEST: digest(retained)}
    for name, expected in files.items():
        data = regular_file(root, DIRECTORY + "/" + name, 1024 * 1024)
        require(data == expected, "Tauri vendor payload differs: " + name)
        inputs[DIRECTORY + "/" + name] = digest(data)
    return {"inputs": inputs, "manifest": manifest, "sourceTreeSha256": digest(encoded(manifest["files"]))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.check:
        require(args.archive is None and args.output is None, "Check does not accept reconstruction arguments.")
        result = verify()
        print("Tauri stable backport integrity PASS: " + result["sourceTreeSha256"])
    else:
        with (args.archive or ROOT / DIRECTORY / ARCHIVE).open("rb") as stream:
            archive = stream.read(1024 * 1024 + 1)
        files, manifest = payloads(archive)
        output = args.output or Path(tempfile.mkdtemp(prefix="tauri-backport-", dir=ROOT / "build")) / "vendor"
        output.mkdir(parents=True, exist_ok=False)
        for name, data in files.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        (output / ARCHIVE).write_bytes(archive)
        (output / MANIFEST).write_bytes(encoded(manifest))
        print("Tauri stable backport reconstructed: " + str(output.resolve()))
        print("Provenance SHA256: " + digest(encoded(manifest)))


if __name__ == "__main__":
    main()
