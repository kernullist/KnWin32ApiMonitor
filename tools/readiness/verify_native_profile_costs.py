"""Adversarial controls against retained real native capture-profile evidence."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
import native_profile_costs as profile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    directory = args.evidence.resolve(strict=True)
    output = Path(tempfile.mkdtemp(prefix="native-profile-controls-", dir=profile.ROOT / "build"))
    print("Native profile controls: " + str(output), flush=True)
    record = {"status": "failed", "evidence": str(directory), "evidenceSha256": profile.digest_file(directory / "evidence.json"),
              "producers": profile.sources(), "rejections": []}

    def rejects(label, action):
        try:
            action()
        except (AssertionError, RuntimeError, ValueError, KeyError, TypeError, OSError):
            record["rejections"].append(label)
            print("Rejected: " + label, flush=True)
        else:
            raise RuntimeError("Negative control was accepted: " + label)

    def modified(value, action):
        changed = copy.deepcopy(value)
        action(changed)
        return changed

    try:
        evidence = profile.verify(directory)
        top_level = [
            ("failed-status", lambda v: v.update(status="failed")),
            ("bool-iterations", lambda v: v.update(iterations=True)),
            ("wrong-configuration", lambda v: v.update(configuration="Release")),
            ("missing-producer", lambda v: v["producers"].pop(next(iter(v["producers"])))),
            ("changed-source", lambda v: v.update(nativeSourceSha256="0" * 64)),
            ("untrusted-tool-path", lambda v: v["tools"]["node"].update(path="C:\\untrusted\\node.exe")),
            ("missing-tool", lambda v: v["tools"].pop("python")),
            ("missing-artifact", lambda v: v["artifacts"].pop(next(iter(v["artifacts"])))),
            ("missing-architecture", lambda v: v["binaries"].pop("x86")),
            ("changed-binary", lambda v: v["binaries"]["x64"]["knmon-native-helper.exe"].update(sha256="0" * 64)),
            ("missing-run", lambda v: v["runs"].pop()),
            ("wrong-rotation", lambda v: v["runs"].reverse()),
            ("bool-repetition", lambda v: v["runs"][0].update(repetition=False)),
            ("changed-command", lambda v: v["runs"][0]["steps"][0]["command"].append("--nonzero-exit")),
            ("negative-duration", lambda v: v["runs"][0]["steps"][0].update(elapsedMs=-1)),
            ("forged-metric", lambda v: v["runs"][0]["metrics"].update(workloadUs=0.0)),
            ("bool-cpu", lambda v: v["runs"][0]["metrics"].update(targetCpu100ns=False)),
            ("forged-summary", lambda v: v["summary"]["x64"]["original"].update(workloadUs=0.0)),
        ]
        for label, mutate in top_level:
            rejects(label, lambda mutate=mutate: profile.verify(directory, modified(evidence, mutate)))
        for architecture in profile.ARCHITECTURES:
            for mode in profile.MODES:
                trial = directory / f"{architecture}-00-{mode}"
                oracle = profile.read_json(trial / "oracle.json")
                for label, mutate in (
                    ("missing-call", lambda v: v["events"].pop()),
                    ("bool-sequence", lambda v: v["events"][0].update(sequence=False)),
                    ("wrong-data", lambda v: v["events"][1].update(preview="00")),
                    ("invalid-clock", lambda v: v["events"][0].update(endQpc="0")),
                    ("noncanonical-counter", lambda v: v.update(kernelCpu100ns="00")),
                    ("invalid-rss", lambda v: v.update(workingSetBytes=0)),
                ):
                    rejects(f"{architecture}/{mode}/{label}", lambda mutate=mutate: profile.oracle_metrics(modified(oracle, mutate)))
                if mode == "original":
                    continue
                capture = profile.read_json(trial / "execute.log")
                replay = profile.read_json(trial / "replay.log")
                mutations = [
                    ("wrong-policy", lambda v: v["capturedEvents"][0].update(captureDetail="unknown")),
                    ("missing-call", lambda v: v["capturedEvents"].pop()),
                    ("reordered-call", lambda v: v["capturedEvents"].reverse()),
                    ("dropped-event", lambda v: v.update(transportDroppedEvents=1)),
                    ("undrained-tail", lambda v: v.update(transportRecordsConsumed=449)),
                    ("bool-drop", lambda v: v.update(droppedEvents=False)),
                    ("impossible-high-water", lambda v: v.update(transportHighWaterMark=1024)),
                    ("duplicate-call-id", lambda v: v["capturedEvents"][1].update(callId=v["capturedEvents"][0]["callId"])),
                    ("forged-return-width", lambda v: v["capturedEvents"][0].update(rawReturnBits=16)),
                    ("changed-error", lambda v: v["capturedEvents"][-1].update(rawLastErrorCode=0)),
                    ("out-of-interval-clock", lambda v: v["capturedEvents"][0]["timing"].update(endQpc="18446744073709551615")),
                ]
                if mode.startswith("metadata"):
                    mutations.append(("invented-argument", lambda v: v["capturedEvents"][0].update(arguments=[{}])))
                else:
                    mutations.extend([
                        ("missing-create-arguments", lambda v: v["capturedEvents"][0].update(arguments=[])),
                        ("wrong-allocation-input", lambda v: v["capturedEvents"][5]["arguments"][1].update(rawValue="4097")),
                        ("bool-argument-index", lambda v: v["capturedEvents"][0]["arguments"][0].update(index=False)),
                        ("wrong-handle-chain", lambda v: v["capturedEvents"][4]["arguments"][0].update(rawValue="0x" + "0" * (16 if architecture == "x64" else 8))),
                    ])
                if mode.startswith("preview"):
                    mutations.append(("wrong-preview", lambda v: v["capturedEvents"][1].update(bufferPreview="00")))
                else:
                    mutations.append(("disabled-preview", lambda v: v["capturedEvents"][1].update(bufferPreview="20")))
                if mode == "arguments":
                    mutations.append(("disabled-read", lambda v: v["capturedEvents"][1]["arguments"][1]["capture"].update(capturedBytes=16)))
                if "stack32" in mode:
                    mutations.extend([
                        ("missing-stack", lambda v: v["capturedEvents"][0].update(stack=[])),
                        ("forged-stack-limit", lambda v: v["capturedEvents"][0]["stackCapture"].update(requestedFrames=16)),
                        ("zero-address", lambda v: v["capturedEvents"][0]["stack"].__setitem__(0, "0x" + "0" * (16 if architecture == "x64" else 8))),
                    ])
                else:
                    mutations.append(("invented-stack", lambda v: v["capturedEvents"][0].update(stack=["0x12345678"])))
                for label, mutate in mutations:
                    rejects(f"{architecture}/{mode}/{label}", lambda mutate=mutate: profile.check_capture(modified(capture, mutate), oracle, mode, architecture))
                rejects(f"{architecture}/{mode}/changed-replay", lambda: profile.check_replay(
                    modified(replay, lambda v: v["traceEvents"][0].update(rawReturnValue="0")), capture))
                rejects(f"{architecture}/{mode}/bool-replay-event", lambda: profile.check_replay(
                    modified(replay, lambda v: v["traceEvents"][0].update(eventId=True)), capture))

        # Rehashing changed raw streams must not bypass semantic comparisons.
        trial = directory / "x64-00-preview"
        target = output / "rehashed-session"
        shutil.copytree(trial / "session", target / "session")
        capture = profile.read_json(trial / "execute.log")
        replay = profile.read_json(trial / "replay.log")
        path = target / "session/trace-events.jsonl"
        data = path.read_bytes()
        rows = [json.loads(line) for line in data.splitlines()]
        rows[0]["rawReturnValue"] = "0"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        record["changedArtifactSha256"] = profile.digest_file(path)
        rejects("rehashed-raw-session", lambda: profile.check_session(target, capture, replay))
        path.write_bytes(data)
        profile.check_session(target, capture, replay)
        excess = output / "excess-artifacts"
        excess.mkdir()
        for index in range(2001):
            (excess / str(index)).touch()
        rejects("excess-artifact-count", lambda: profile.artifact_hashes(excess))
        oversized = output / "oversized-artifact"
        oversized.mkdir()
        with (oversized / "oversized.log").open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        rejects("oversized-nonbinary-artifact", lambda: profile.artifact_hashes(oversized))
        profile.verify(directory)
        profile.require(record["evidenceSha256"] == profile.digest_file(directory / "evidence.json") and
                        record["producers"] == profile.sources(), "Profile controls changed inputs.")
        record["status"] = "passed"
    except BaseException as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        profile.write_json(output / "evidence.json", record)
    print(f"Native profile controls PASS: {len(record['rejections'])} rejections", flush=True)


if __name__ == "__main__":
    main()
