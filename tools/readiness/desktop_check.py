"""Recompute desktop evidence from retained UI exports and owned-process samples."""
import json
import hashlib
from pathlib import Path
import re
import struct
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from source_evidence import contained, digest_file, read_bytes, read_json, require, unique_object


def json_value(payload):
    return json.loads(payload, object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, "Non-finite desktop evidence."))


def json_lines_data(payload):
    return [json.loads(line, object_pairs_hook=unique_object,
                       parse_constant=lambda _: require(False, "Non-finite desktop evidence."))
            for line in payload.decode("utf-8").splitlines() if line.strip()]


def json_lines(path):
    return json_lines_data(read_bytes(path, 32 * 1024 * 1024))


def machine(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:2] == b"MZ", "Desktop input is not a PE image.")
        offset = struct.unpack_from("<I", header, 0x3C)[0]
        require(64 <= offset <= 1024 * 1024, "Invalid desktop PE header offset.")
        stream.seek(offset)
        data = stream.read(6)
    require(len(data) == 6 and data[:4] == b"PE\0\0", "Invalid desktop PE signature.")
    return struct.unpack_from("<H", data, 4)[0]


def event_count(observation):
    result = re.search(r"(?:^|\n)Events: (\d+)/(\d+)(?:\n|$)", observation["status"])
    require(result is not None and result[1] == result[2], "Desktop trace counters are missing or trimmed.")
    require("\nDropped: 0\n" in observation["status"], "Desktop reported event loss.")
    return int(result[1])


def verify_interaction(execution, driver, events):
    pid = execution["targetPid"]
    require(type(driver["schemaVersion"]) is int and driver["schemaVersion"] == 1 and driver["status"] == "passed" and
            driver["errors"] == [] and driver["targetPid"] == pid, "Desktop interaction failed or target identity differs.")
    observations = driver["observations"]
    names = ("idle", "selected", "capture", "filtered", "stopped", "settled")
    require([item["phase"] for item in observations] == list(names), "Desktop interaction phases are incomplete or reordered.")
    require(all(item["url"] == "http://tauri.localhost/" and item["readyState"] == "complete" for item in observations), "Desktop page identity differs.")
    require(all("native_ownership_poll_failed:" not in item["output"] and "stream_batch_poll_failed:" not in item["output"]
                for item in observations), "Healthy desktop probe contains a polling failure.")
    by_name = dict(zip(names, observations))
    require(event_count(by_name["idle"]) == 0 and not by_name["idle"]["rows"], "Desktop started with preexisting events.")
    require(execution["binaries"]["knmon-sample-fileio.exe"]["path"].lower() in by_name["selected"]["selectedTarget"].lower() and
            str(pid) in by_name["selected"]["selectedTarget"].splitlines(), "The UI did not select the owned target.")
    for name in ("capture", "filtered"):
        row = by_name[name]
        require(event_count(row) > 40 and row["rows"] and f"target {pid} alive" in row["session"] and
                "\nrunning\n" in row["session"] and "\n0 drop\n0 ui-drop\n" in row["session"], "The UI did not observe a lossless active native capture.")
    for name in ("stopped", "settled"):
        row = by_name[name]
        require(row["status"].startswith("State: idle\n") and row["session"] == "" and
                "session_stop_requested: stop_native_session; win32=0;" in row["output"], "Native stop was not observed in the UI.")
    require(event_count(by_name["stopped"]) == event_count(by_name["settled"]) == len(events) and 40 < len(events) <= 5000,
            "UI counters and settled JSONL export differ.")
    require(all(row["filter"] == "WriteFile" and row["rows"] and all(cells[5] == "WriteFile" for cells in row["rows"])
                for row in (by_name["filtered"], by_name["stopped"], by_name["settled"])), "UI event filtering did not match its input.")
    require([event["eventId"] for event in events] == list(range(1, len(events) + 1)) and
            [event["recordSequence"] for event in events] == [str(value) for value in range(len(events))], "Exported event sequence is missing, duplicated or reordered.")
    required = {"CreateFileW", "WriteFile", "ReadFile", "CloseHandle", "NtCreateFile", "CreateFileA"}
    require(required <= {event["api"] for event in events}, "Native file workload coverage is incomplete.")
    session_tags = set()
    for event in events:
        require(event["schemaVersion"] == "0.1.0" and event["pid"] == pid and event["process"] == "knmon-sample-fileio.exe" and
                event["tid"] > 0 and {"native-capture", "shared-memory", "ui-stream"} <= set(event["tags"]), "Exported native event identity differs.")
        require(event["timeSource"] == "qpc" and int(event["timing"]["qpcFrequency"]) > 0 and
                int(event["timing"]["endQpc"]) >= int(event["timing"]["startQpc"]) > 0, "Exported native timing is invalid.")
        require(event["outcome"] == "success" and event["error"] is None, "Native target operation failed.")
        tags = [tag for tag in event["tags"] if tag.startswith("session:")]
        require(len(tags) == 1, "Native event session identity is missing or ambiguous.")
        session_tags.update(tags)
        if event["api"] in ("WriteFile", "ReadFile"):
            arguments = {argument["name"]: argument for argument in event["arguments"]}
            require(event["bufferPreview"] == "4b 4e 4d 6f 6e 20 61 74 74 61 63 68 20 46 69 6c" and
                    arguments["lpBuffer"]["capture"]["capturedBytes"] == 16 and event["rawReturnValue"] == "1", "Native buffer payload differs from the target fixture.")
    require(len(session_tags) == 1, "Desktop export mixes native sessions.")
    lookup = {str(event["eventId"]): event for event in events}
    for row in observations[2:]:
        require(re.search(r"(?:^|\n)DOM (\d+)(?:\n|$)", row["stats"])[1] == str(len(row["rows"])), "Rendered row accounting differs.")
        for cells in row["rows"]:
            require(len(cells) == 11 and cells[0] in lookup, "Rendered trace row is absent from the export.")
            event = lookup[cells[0]]
            require(cells[2:6] == [str(pid), str(event["tid"]), event["module"], event["api"]] and cells[7] == event["returnValue"],
                    "Rendered trace row differs from the exported event.")
    return {"exportedEvents": len(events), "renderedRows": {name: len(row["rows"]) for name, row in by_name.items()}, "apis": sorted({event["api"] for event in events})}


def natural(value):
    return type(value) is int and value >= 0


def validate_endpoint(cdp):
    port = cdp["port"]
    require(type(port) is int and 0 < port <= 65535, "Invalid owned CDP port.")
    endpoint = urlsplit(cdp["endpoint"])
    require(endpoint.scheme == "ws" and endpoint.netloc == f"127.0.0.1:{port}" and
            re.fullmatch(r"/devtools/page/[A-Fa-f0-9-]{8,128}", endpoint.path) is not None and
            not endpoint.query and not endpoint.fragment, "CDP page endpoint escaped its owned listener.")
    discovery = cdp["discovery"].splitlines()
    require(len(discovery) == 2 and discovery[0] == str(port) and
            re.fullmatch(r"/devtools/browser/[A-Fa-f0-9-]{8,128}", discovery[1]) is not None, "CDP discovery identity differs.")
    require(cdp["listener"]["status"] == "sampled" and Path(cdp["listener"]["image"]).name.lower() == "msedgewebview2.exe",
            "CDP listener is not an observed WebView runtime.")


def resource_summary(samples, execution):
    require(50 <= len(samples) <= 600, "Desktop resource sample count is outside its bound.")
    require(all(natural(row["elapsedMs"]) for row in samples) and samples[0]["elapsedMs"] < 3000 and samples[-1]["elapsedMs"] <= 95000,
            "Desktop resource time coverage is invalid.")
    gaps = [right["elapsedMs"] - left["elapsedMs"] for left, right in zip(samples, samples[1:])]
    require(all(0 < gap <= 3500 for gap in gaps), "Desktop resource samples are reordered or have excessive gaps.")
    identities, groups, phase_rows = {}, {}, {}
    unresolved = 0
    previous_cpu = {"application": 0, "target": 0}
    phase_order = ("startup", "idle", "attach", "capture", "stop", "settled", "finished", "target-completion")
    previous_phase = 0
    for sample in samples:
        require(sample["phase"] in phase_order and phase_order.index(sample["phase"]) >= previous_phase, "Desktop resource phase order differs.")
        previous_phase = phase_order.index(sample["phase"])
        require(all(window["visible"] is False for window in sample["windows"]), "Desktop presentation was not hidden.")
        phase_rows.setdefault(sample["phase"], []).append(sample)
        for scope in ("application", "target"):
            owned = sample[scope]
            account = owned["job"]
            require(all(natural(account[key]) for key in ("user100ns", "kernel100ns", "totalProcesses", "activeProcesses", "terminatedProcesses")) and
                    account["totalProcesses"] >= account["activeProcesses"] and len(owned["processes"]) <= 128, "Invalid owned Job accounting.")
            cpu = account["user100ns"] + account["kernel100ns"]
            require(cpu >= previous_cpu[scope], "Cumulative Job CPU moved backwards.")
            previous_cpu[scope] = cpu
            require(len({item["pid"] for item in owned["processes"]}) == len(owned["processes"]), "Resource sample contains duplicate PIDs.")
            totals = {key: 0 for key in ("rssBytes", "privateBytes", "handles")}
            for item in owned["processes"]:
                require(item["status"] in ("sampled", "exited", "exited-before-open"), "Resource sampler could not query a live process.")
                if item["status"] != "sampled":
                    unresolved += 1
                    continue
                require(all(natural(item[key]) for key in (*totals, "pid", "user100ns", "kernel100ns")) and item["pid"] > 0 and
                        str(int(item["created100ns"])) == item["created100ns"] and int(item["created100ns"]) > 0, "Invalid process resource counters or identity.")
                identity = f'{item["pid"]}:{item["created100ns"]}'
                require(identity not in identities or identities[identity] == item["image"], "Process image identity changed during sampling.")
                identities[identity] = item["image"]
                for key in totals:
                    totals[key] += item[key]
            group = groups.setdefault(scope, {key: 0 for key in totals})
            for key in totals:
                group[key] = max(group[key], totals[key])
    for phase, minimum in (("idle", 8), ("capture", 20), ("settled", 5)):
        require(len(phase_rows.get(phase, [])) >= minimum, "Missing desktop resource phase: " + phase)
    app_paths = {item["image"].lower() for sample in samples for item in sample["application"]["processes"] if item["status"] == "sampled"}
    require(execution["binaries"]["knmon-ui.exe"]["path"].lower() in app_paths and
            execution["binaries"]["knmon-native-helper.exe"]["path"].lower() in app_paths and
            execution["runtime"]["path"].lower() in app_paths, "Whole desktop samples lack the app, helper or WebView runtime.")
    target_rows = [item for sample in samples for item in sample["target"]["processes"] if item["status"] == "sampled" and item["pid"] == execution["targetPid"]]
    require(target_rows and {item["image"].lower() for item in target_rows} == {execution["binaries"]["knmon-sample-fileio.exe"]["path"].lower()}, "Owned target resource identity differs.")
    for scope, identity_name, pid_name, image_name in (("application", "appIdentity", "appPid", "knmon-ui.exe"),
                                                      ("target", "targetIdentity", "targetPid", "knmon-sample-fileio.exe")):
        identity = execution[identity_name]
        roots = [item for sample in samples for item in sample[scope]["processes"] if item["status"] == "sampled" and
                 item["image"].lower() == execution["binaries"][image_name]["path"].lower()]
        require(identity["status"] == "sampled" and identity["pid"] == execution[pid_name] and roots and
                all(item["pid"] == identity["pid"] and item["created100ns"] == identity["created100ns"] for item in roots),
                "Owned root PID or process creation identity differs.")
    require(set(identities.values()) == set(execution["observedImages"]) and
            all(re.fullmatch(r"[0-9a-f]{64}", value) for value in execution["observedImages"].values()), "Observed process image fingerprints are incomplete.")
    require(execution["observedImages"][execution["runtime"]["path"]] == execution["runtime"]["sha256"], "WebView runtime identity differs from its sampled image.")
    observed = {name.casefold(): value for name, value in execution["observedImages"].items()}
    require(len(observed) == len(execution["observedImages"]), "Duplicate sampled image paths.")
    for binary in execution["binaries"].values():
        if binary["path"].casefold() in observed:
            require(observed[binary["path"].casefold()] == binary["sha256"], "Staged binary and sampled image fingerprint differ.")
    listener = execution["cdp"]["listener"]
    require(identities.get(f'{listener["pid"]}:{listener["created100ns"]}') == execution["runtime"]["path"], "CDP listener creation identity was not sampled.")
    phases = {}
    for phase, rows in phase_rows.items():
        phases[phase] = {"samples": len(rows), "elapsedMs": rows[-1]["elapsedMs"] - rows[0]["elapsedMs"]}
        for scope in ("application", "target"):
            phases[phase][scope + "Cpu100ns"] = sum(rows[-1][scope]["job"][key] - rows[0][scope]["job"][key] for key in ("user100ns", "kernel100ns"))
    return {"samples": len(samples), "maxSamplingGapMs": max(gaps), "sampledSumMaxima": groups, "phases": phases,
            "observedProcessIdentities": len(identities), "processesExitingDuringSample": unresolved,
            "imagePaths": sorted(set(identities.values()))}


def verify_architecture(directory, architecture, expected_artifacts=None):
    def payload(name, limit=4 * 1024 * 1024):
        file = contained(directory, name)
        data = read_bytes(file, limit)
        if expected_artifacts is not None:
            key = architecture + "/" + Path(name).as_posix()
            require(expected_artifacts.get(key) == hashlib.sha256(data).hexdigest(), "Desktop artifact bytes differ from their bound fingerprint.")
        return data
    execution, driver = json_value(payload("execution.json")), json_value(payload("driver.json"))
    require(type(execution["schemaVersion"]) is int and execution["schemaVersion"] == 1 and execution["status"] == "passed" and
            execution["architecture"] == architecture and execution["configuration"] ==
            {"desktop": "Release", "native": "Debug", "presentation": "hidden", "samplingIntervalMs": 200}, "Desktop execution scope or status differs.")
    require(all(type(execution[key]) is int and execution[key] == 0 for key in ("appExit", "targetExit", "driverExit")), "Desktop scenario did not exit normally.")
    require(execution["targetAliveAfterDriver"] is True, "Target did not survive native stop and UI export.")
    require(execution["closeWindows"] == [{"postedClose": True}] and set(execution["cleanup"]) == {"application", "target", "driver"} and
            all(type(row["activeProcesses"]) is int and row["activeProcesses"] == 0 for row in execution["cleanup"].values()), "Owned desktop trees did not drain.")
    expected = {"knmon-ui.exe", "knmon-native-helper.exe", "knmon-collector.exe", "knmon-sample-fileio.exe", "knmon-agent" + ("64" if architecture == "x64" else "32") + ".dll"}
    require(set(execution["binaries"]) == expected, "Desktop binary set is incomplete.")
    for name, binary in execution["binaries"].items():
        file = contained(directory, "portable/" + name)
        require(Path(binary["path"]) == file and file.stat().st_size <= 256 * 1024 * 1024 and digest_file(file) == binary["sha256"] and
                machine(file) == (0x8664 if architecture == "x64" else 0x14C), "Desktop binary hash, path or architecture differs.")
    request = json_value(payload("request.json"))
    validate_endpoint(execution["cdp"])
    require(request == {"endpoint": execution["cdp"]["endpoint"], "targetPid": execution["targetPid"],
                        "targetPath": execution["binaries"]["knmon-sample-fileio.exe"]["path"]}, "Desktop driver request identity differs.")
    require(re.fullmatch(r"downloads/knmon-session-[0-9TZ-]+\.jsonl", Path(driver["exportFile"]).as_posix()) is not None, "Unexpected desktop export filename.")
    events = json_lines_data(payload(driver["exportFile"], 32 * 1024 * 1024))
    interaction = verify_interaction(execution, driver, events)
    resources = resource_summary(json_lines_data(payload("resources.jsonl", 32 * 1024 * 1024)), execution)
    png = payload("capture.png", 8 * 1024 * 1024)
    require(png.startswith(b"\x89PNG\r\n\x1a\n") and len(png) > 1024, "Desktop screenshot is absent or invalid.")
    return {"architecture": architecture, "interaction": interaction, "resources": resources,
            "runtime": execution["runtime"], "configuration": execution["configuration"]}
