import struct
import subprocess
import tempfile

from run_comparison import ROOT, MANIFEST, checked_run, read_json, assert_oracle, frida_run


def main():
    from pathlib import Path
    root = Path(tempfile.mkdtemp(prefix="corpus-negative-", dir=ROOT / "build"))
    manifest = read_json(MANIFEST)
    for architecture, build in (("x64", "native-msvc"), ("x86", "native-msvc-x86")):
        directory = ROOT / "build" / build / "Debug"
        target = directory / "knmon-comparison-target.exe"
        trial = root / architecture
        trial.mkdir()
        checked_run([target, trial, "2", "--etw-private"])
        oracle = read_json(trial / "oracle.json")
        assert_oracle(oracle, manifest, 2)
        checked_run([directory / "knmon-etw-corpus-reader.exe", trial / "corpus.etl"])
        event = oracle["events"][0]
        payload = struct.pack("<QQIIIIII16s", int(event["startQpc"]), int(event["endQpc"]), event["sequence"],
                              manifest["apis"].index(event["api"]), int(event["success"]), event["error"], event["byteCount"],
                              len(event["preview"]) // 2, bytes.fromhex(event["preview"]).ljust(16, b"\0"))
        data = (trial / "corpus.etl").read_bytes()
        assert data.count(payload) == 1
        offset = data.index(payload)
        for name, field, value, encoding in (("api", 20, 6, "<I"), ("preview", 36, 17, "<I"),
                                              ("sequence", 16, 1, "<I"), ("clock", 0, int(event["endQpc"]) + 1, "<Q")):
            changed = bytearray(data)
            struct.pack_into(encoding, changed, offset + field, value)
            file = trial / f"invalid-{name}.etl"
            file.write_bytes(changed)
            result = subprocess.run([str(directory / "knmon-etw-corpus-reader.exe"), str(file)], capture_output=True, timeout=30)
            assert result.returncode != 0 and b"invalid=1" in result.stderr, name
        failure = root / f"{architecture}-nonzero-frida"
        failure.mkdir()
        rejected = False
        try:
            frida_run(target, failure, 2, ["--nonzero-exit"])
        except AssertionError as error:
            rejected = "exit code: 7" in str(error)
        assert rejected, "A valid report followed by nonzero target exit must not pass."
        print(f"Native corpus negatives PASS: {architecture}, malformed ETL and observed nonzero process exit")
    print(f"Native corpus evidence: {root}")


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("Evidence validation must run without Python optimization flags.")
    main()
