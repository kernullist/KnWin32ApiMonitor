"""Verify clean-index provenance, deterministic packaging and explicit dirty snapshots."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_archive import digest_file, extract_archive, require

ROOT = Path(__file__).resolve().parents[2]


def main():
    (ROOT / "build").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="source-package-negative-", dir=ROOT / "build"))
    fixture = output / "repository"
    directory = fixture / "tools/source"
    directory.mkdir(parents=True)
    for name in ("package-source.py", "source_archive.py"):
        shutil.copyfile(ROOT / "tools/source" / name, directory / name)
    (directory / "preflight.mjs").write_text('console.log("Controlled packaging fixture preflight.");\n', encoding="ascii")
    (fixture / "payload.txt").write_bytes(b"Original fixture payload.\n")

    def git(*args):
        return subprocess.run(["git", "-c", "user.name=kernullist", "-c", "user.email=gloryo@naver.com", *args],
                              cwd=fixture, check=True, capture_output=True, timeout=15)

    def package(name, dirty=False):
        archive = output / (name + ".zip")
        result = subprocess.run([sys.executable, "-X", "utf8", directory / "package-source.py", "--output", archive,
                                 *(["--allow-dirty"] if dirty else [])], cwd=fixture, capture_output=True, timeout=60)
        (output / (name + ".log")).write_bytes(result.stdout + result.stderr)
        return result, archive

    git("init", "-b", "main")
    git("add", "--all")
    git("commit", "-m", "Create isolated source packaging fixture")
    first, first_zip = package("clean1")
    second, second_zip = package("clean2")
    require(first.returncode == second.returncode == 0 and digest_file(first_zip) == digest_file(second_zip), "Clean packaging is not deterministic.")
    record = extract_archive(first_zip, output / "clean-tree")
    require(record["dirtySnapshot"] is False, "Clean archive has incorrect provenance.")
    git("update-index", "--assume-unchanged", "--", "payload.txt")
    (fixture / "payload.txt").write_bytes(b"Hidden modified payload.\n")
    require(not git("status", "--porcelain", "--untracked-files=no").stdout, "Hidden-change positive control failed.")
    hidden, hidden_zip = package("hidden-index-change")
    require(hidden.returncode != 0 and b"differs from the committed index" in hidden.stderr and not hidden_zip.exists(),
            "Index-hidden source change was accepted as a clean release.")
    git("update-index", "--no-assume-unchanged", "--", "payload.txt")
    dirty, dirty_zip = package("dirty-rejected")
    require(dirty.returncode != 0 and not dirty_zip.exists(), "Dirty tracked source was accepted without opt-in.")
    candidate, candidate_zip = package("dirty-candidate", dirty=True)
    require(candidate.returncode == 0, "Explicit dirty snapshot failed.")
    try:
        extract_archive(candidate_zip, output / "invalid-release")
    except ValueError:
        pass
    else:
        raise RuntimeError("Dirty candidate was accepted as release provenance.")
    candidate_record = extract_archive(candidate_zip, output / "candidate-tree", allow_dirty=True)
    require(candidate_record["dirtySnapshot"] is True, "Candidate provenance was silently promoted.")
    (output / "evidence.json").write_text(json.dumps({"status": "passed", "cleanArchiveSha256": digest_file(first_zip),
                                                     "controls": ["repeatable_clean_archive", "hidden_index_change_rejected", "dirty_rejected", "explicit_candidate_not_release"]}, indent=2), encoding="ascii")
    print(f"Source package provenance adversarial validation PASS: {output}")


if __name__ == "__main__":
    main()
