"""Validate and extract the exact bounded source archive format."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 10000
MAX_COMPRESSED = 512 * 1024 * 1024
BUILD_OUTPUTS = {"build", "node_modules", "apps/knmon-ui/node_modules", "apps/knmon-ui/dist",
                 "apps/knmon-ui/src-tauri/target", "crates/knmon-tauri/target"}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest_file(path):
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            count += len(block)
            require(count <= MAX_TOTAL, "Hash input exceeds its byte bound.")
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "Duplicate source manifest key.")
        result[name] = value
    return result


def parse_manifest(data, allow_dirty=False):
    require(len(data) <= MAX_MANIFEST, "Source manifest exceeds its bound.")
    result = json.loads(data, object_pairs_hook=unique_object,
                        parse_constant=lambda value: require(False, "Non-finite source manifest number."))
    require(type(result.get("schemaVersion")) is int and result["schemaVersion"] == 1 and
            re.fullmatch("[0-9a-f]{40}", result.get("revision", "")), "Invalid source provenance.")
    require(type(result.get("dirtySnapshot")) is bool and (allow_dirty or not result["dirtySnapshot"]), "Dirty source snapshot is not release evidence.")
    files = result.get("files")
    require(isinstance(files, dict) and 1 <= len(files) <= MAX_FILES, "Invalid source file count.")
    total, identities = 0, set()
    for name, entry in files.items():
        validate_name(name)
        require(name != "SOURCE-MANIFEST.json" and name.casefold() not in identities, "Duplicate source path identity.")
        identities.add(name.casefold())
        require(isinstance(entry, dict) and type(entry.get("bytes")) is int and 0 <= entry["bytes"] <= MAX_FILE and
                re.fullmatch("[0-9a-f]{64}", entry.get("sha256", "")), "Invalid source file length or hash.")
        total += entry["bytes"]
    require(total <= MAX_TOTAL, "Source archive exceeds its aggregate bound.")
    for name in identities:
        parts = name.split("/")
        require(all("/".join(parts[:index]) not in identities for index in range(1, len(parts))), "Source file/directory identity collision.")
    return result


def validate_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 240 and "\\" not in name, "Invalid source path.")
    parts = name.split("/")
    for part in parts:
        require(part and part not in (".", "..") and not part.endswith((".", " ")) and
                not any(ord(character) < 32 or character in '<>:"|?*~' for character in part), "Unsafe Windows source path.")
        require(not re.fullmatch(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?", part, re.IGNORECASE),
                "Reserved Windows source path.")
        require(part.casefold() not in (".git", "agents.md", "do-not-commit"), "Excluded source path.")
    require(name.casefold() != "crates/knmon-tauri/cargo.lock", "Local backend lockfile is excluded.")


def inspect_archive(archive, allow_dirty=False):
    infos = archive.infolist()
    require(2 <= len(infos) <= MAX_FILES + 1, "Invalid archive entry count.")
    entries = {}
    folded = set()
    total = 0
    for info in infos:
        require(info.orig_filename == info.filename, "NUL-truncated ZIP filename.")
        validate_name(info.filename)
        require(info.filename.casefold() not in folded and not info.is_dir(), "Duplicate or directory ZIP entry.")
        folded.add(info.filename.casefold())
        require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG) and not (info.flag_bits & 1), "Link or encrypted source entry.")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and 0 <= info.file_size <= MAX_FILE,
                "Unsupported or oversized source entry.")
        total += info.file_size
        entries[info.filename] = info
    require(total <= MAX_TOTAL + MAX_MANIFEST, "ZIP uncompressed total exceeds its bound.")
    require("SOURCE-MANIFEST.json" in entries and entries["SOURCE-MANIFEST.json"].file_size <= MAX_MANIFEST, "Missing or oversized source manifest.")
    manifest = parse_manifest(archive.read(entries["SOURCE-MANIFEST.json"]), allow_dirty)
    require(set(entries) == set(manifest["files"]) | {"SOURCE-MANIFEST.json"}, "Source archive membership differs from its manifest.")
    require(all(entries[name].file_size == record["bytes"] for name, record in manifest["files"].items()), "Source ZIP and manifest lengths disagree.")
    return manifest, entries


def validate_container(path):
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        require(22 <= size <= MAX_COMPRESSED, "Compressed source archive exceeds its bound.")
        stream.seek(-22, 2)
        signature, disk, directory_disk, disk_count, total_count, directory_size, directory_offset, comment = struct.unpack("<4s4H2LH", stream.read(22))
    require(signature == b"PK\x05\x06" and disk == directory_disk == comment == 0 and disk_count == total_count and
            2 <= total_count <= MAX_FILES + 1 and directory_size <= MAX_MANIFEST and directory_offset + directory_size == size - 22,
            "Invalid, oversized or unsupported ZIP central directory.")


def extract_archive(path, destination, allow_dirty=False):
    validate_container(path)
    with zipfile.ZipFile(path) as archive:
        manifest, entries = inspect_archive(archive, allow_dirty)
        destination.mkdir(parents=True, exist_ok=False)
        root = destination.resolve()
        for name, info in entries.items():
            output = root.joinpath(*name.split("/"))
            output.parent.mkdir(parents=True, exist_ok=True)
            require(output.parent.resolve().is_relative_to(root), "Source extraction escapes its directory.")
            checksum, length = hashlib.sha256(), 0
            with archive.open(info) as source, output.open("xb") as target:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    length += len(block)
                    require(length <= info.file_size, "Source entry exceeds its advertised length.")
                    target.write(block)
                    checksum.update(block)
            require(length == info.file_size, "Truncated source entry.")
            if name in manifest["files"]:
                require(checksum.hexdigest() == manifest["files"][name]["sha256"], "Source payload hash mismatch.")
    verify_tree(destination, manifest)
    return manifest


def verify_tree(directory, manifest):
    root = directory.resolve()
    for name, expected in manifest["files"].items():
        path = root.joinpath(*name.split("/"))
        require(path.resolve(strict=True).is_relative_to(root) and not path.is_symlink(), "Source file escapes its tree.")
        require(path.stat().st_size == expected["bytes"] and digest_file(path) == expected["sha256"], "Source tree differs from archive manifest: " + name)
    for parent, children, files in os.walk(root):
        retained = []
        for child in children:
            path = Path(parent) / child
            if path.relative_to(root).as_posix() not in BUILD_OUTPUTS:
                require(path.resolve().is_relative_to(root) and not path.is_symlink() and not path.is_junction(),
                        "Reparse point in source directory tree.")
                retained.append(child)
        children[:] = retained
        for name in files:
            relative = (Path(parent) / name).relative_to(root).as_posix()
            require(relative in manifest["files"] or relative == "SOURCE-MANIFEST.json", "Unexpected source file outside build outputs: " + relative)
