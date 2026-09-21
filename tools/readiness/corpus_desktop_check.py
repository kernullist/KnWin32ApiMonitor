"""Recompute coordinated desktop metrics from raw caller, UI and process data."""
from pathlib import Path
import os
import re
import sys

sys.dont_write_bytecode = True
from source_evidence import ROOT, contained, read_json, read_bytes, require
from desktop_check import json_lines, json_value, validate_endpoint
from native_profile_costs import MODES, ITERATIONS, MANIFEST, natural, decimal, quantiles, oracle_metrics, check_arguments, check_stack, same

EXPECTED = ITERATIONS * 7 + 2


def counters(snapshot):
    status = snapshot["status"]
    require(snapshot["sessionState"] in (None, "running") and
            re.findall(r"(?:^|\n)State: ([^\n]+)(?=\n|$)", status) == [snapshot["sessionState"] or "idle"],
            "Desktop status bar contradicts the observed session state.")
    matches = re.findall(r"(?:^|\n)Events: (0|[1-9][0-9]*)/(0|[1-9][0-9]*)(?=\n|$)", status)
    require(len(matches) == 1 and "\nTrimmed:" not in status and re.findall(r"(?:^|\n)Dropped: (\d+)(?=\n|$)", status) == ["0"],
            "Desktop corpus counters are missing, trimmed or lossy.")
    retained, total = map(int, matches[0])
    gaps = re.findall(r"(?:^|\n)Not ingested: (\d+)(?=\n|$)", status)
    require(0 <= retained <= total <= EXPECTED and gaps == ([str(total - retained)] if total > retained else []),
            "Desktop corpus ingestion gap is inconsistent.")
    output = snapshot["output"]
    require("native_ownership_poll_failed:" not in output and "stream_batch_poll_failed:" not in output,
            "Desktop corpus contains a polling failure.")
    return retained, total


def exported_events(directory, execution, driver, oracle, mode, architecture):
    detail, frames = MODES[mode]
    if mode == "original":
        require("exportFile" not in driver and "sessions" not in driver and driver["readySessions"] == [],
                "Original caller has a capture session or export.")
        return []
    events = json_lines(contained(directory, driver["exportFile"]))
    require(len(events) == EXPECTED, "Desktop corpus export has missing or extra events.")
    sessions = driver["sessions"]
    require(type(sessions) is list and len(sessions) == 1, "Desktop corpus session identity is ambiguous.")
    session = sessions[0]
    ready = driver["readySessions"]
    require(type(ready) is list and len(ready) == 1 and ready[0]["sessionState"] == "running" and
            all(same(ready[0][key], session[key]) for key in ("sessionId", "operationId", "sessionKind", "ownerProcessId", "helperProcessId",
                                                           "targetProcessId", "targetProcessCreationTime")) and
            ready[0]["recordsStreamed"] == 0 and type(ready[0]["recordsStreamed"]) is int and
            ready[0]["stopRequested"] is False and ready[0]["lastError"] == "", "Desktop ready session was absent or changed identity.")
    require(session["targetProcessId"] == oracle["pid"] and session["ownerProcessId"] == execution["appPid"] and
            session["targetProcessCreationTime"] in ("0", execution["targetIdentity"]["created100ns"]) and
            session["sessionKind"] == "attach_capture_stream" and session["targetAlive"] is True and session["targetExitObserved"] is False and
            session["sessionState"] == "stopped" and session["agentCleanupAttempted"] is True and
            session["agentCleanupSucceeded"] is True and session["stopRequested"] is True and
            session["lastError"] == "" and session["stoppedUtc"] and session["shutdownEvidence"],
            "Desktop corpus session did not prove clean detach.")
    shutdown = json_value(session["shutdownEvidence"].encode("utf-8"))
    require(shutdown["messageType"] == "agent_shutdown" and shutdown["operationId"] == session["operationId"] and
            type(shutdown["pid"]) is int and shutdown["pid"] == oracle["pid"] and shutdown["lifecycleState"] == "disabled" and
            shutdown["reason"] == "self_disable" and type(shutdown["installedHooks"]) is int and shutdown["installedHooks"] > 0 and
            type(shutdown["restoredHooks"]) is int and shutdown["restoredHooks"] == shutdown["installedHooks"] and
            all(type(shutdown[key]) is int and shutdown[key] == 0 for key in ("failedHooks", "droppedCount")),
            "Desktop shutdown does not prove complete hook restoration.")
    require(all(type(session[key]) is int and session[key] == EXPECTED for key in ("recordsStreamed", "lastTransportSequence")) and
            all(type(session[key]) is int and session[key] == 0 for key in ("transportDroppedEvents", "hostDroppedBatches")),
            "Desktop corpus native counters differ from the complete oracle.")
    for index, (event, expected) in enumerate(zip(events, oracle["events"])):
        require(event["schemaVersion"] == "0.1.0" and type(event["eventId"]) is int and event["eventId"] == index + 1 and decimal(event["recordSequence"]) == index and
                decimal(event["callId"]) == index + 1 and decimal(event["parentCallId"]) == 0 and
                type(event["callDepth"]) is int and event["callDepth"] == 0 and event["api"] == expected["api"] and
                event["module"].lower() == "kernel32.dll" and event["process"] == "knmon-comparison-target.exe" and
                type(event["pid"]) is int and event["pid"] == oracle["pid"] and type(event["tid"]) is int and event["tid"] == oracle["tid"],
                "Desktop export call identity or order differs.")
        tags = [tag for tag in event["tags"] if tag.startswith("session:")]
        require(tags == ["session:" + session["sessionId"]] and
                event["captureDetail"] == detail and type(event["arguments"]) is list and
                type(event["bufferPreview"]) is str and (detail != "metadata" or event["arguments"] == []) and
                (detail == "preview" or event["bufferPreview"] == ""), "Desktop corpus policy or session tags differ.")
        timing = event["timing"]
        require(event["timeSource"] == "qpc" and decimal(timing["qpcFrequency"]) == decimal(oracle["qpcFrequency"]) and
                decimal(expected["startQpc"]) <= decimal(timing["startQpc"]) <= decimal(timing["endQpc"]) <= decimal(expected["endQpc"]),
                "Desktop export clock exceeds its independent caller interval.")
        bits = 64 if architecture == "x64" and event["api"] in ("CreateFileW", "VirtualAlloc") else 32
        require(type(event["rawReturnBits"]) is int and event["rawReturnBits"] == bits and
                decimal(event["rawReturnValue"]) < 1 << bits, "Desktop return width differs.")
        raw = decimal(event["rawReturnValue"])
        success = raw != (1 << bits) - 1 if event["api"] == "CreateFileW" else raw != 0
        require(success == expected["success"] and type(event["rawLastErrorCode"]) is int and
                event["rawLastErrorCode"] == expected["error"] and event["outcome"] == ("success" if success else "failure"),
                "Desktop export caller result or error differs.")
        require(event["hookContext"]["agent"] == ("knmon-agent64.dll" if architecture == "x64" else "knmon-agent32.dll"),
                "Desktop Agent provenance differs.")
        check_stack(event, frames, architecture)
        if detail != "metadata":
            check_arguments(events, index, architecture)
            if event["api"] == "CreateFileW":
                file_name = "missing-file.bin" if index == EXPECTED - 1 else "corpus.bin"
                require(Path(event["arguments"][0]["rawValue"]) == (directory / "corpus" / file_name).resolve(strict=False),
                        "Desktop captured file path differs from its independent caller command.")
        if detail != "metadata" and event["api"] in ("ReadFile", "WriteFile"):
            buffer, count = event["arguments"][1], event["arguments"][3]
            require((count["decodeStatus"] == "decoded" and count["decodedValue"] == str(expected["byteCount"])) if success else
                    count["decodeStatus"] == "not_captured", "Desktop I/O transfer count differs.")
            if detail == "arguments":
                capture = buffer["capture"]
                require(buffer["decodeStatus"] == "not_captured" and capture["phase"] == "none" and
                        capture["readStatus"] == "not_captured" and type(capture["capturedBytes"]) is int and
                        capture["capturedBytes"] == 0 and capture["truncationReason"] == "capture_detail",
                        "Disabled desktop preview was captured.")
            else:
                require(event["bufferPreview"].replace(" ", "") == expected["preview"], "Desktop preview bytes differ.")
    return events


def process_samples(samples, execution, oracle):
    before, after = decimal(oracle["startQpc"]), decimal(oracle["endQpc"])
    frequency = decimal(oracle["qpcFrequency"])
    previous = 0
    last_counters = {}
    identities = {}
    for sample in samples:
        first, last = decimal(sample["beforeQpc"]), decimal(sample["afterQpc"])
        require(previous < first <= last, "Desktop resource clocks are reversed or duplicated.")
        previous = last
        for scope in ("application", "target"):
            resource = sample[scope]
            job = resource["job"]
            require(set(job) == {"user100ns", "kernel100ns", "totalProcesses", "activeProcesses", "terminatedProcesses"} and
                    all(natural(value) for value in job.values()) and job["activeProcesses"] <= job["totalProcesses"] and
                    job["terminatedProcesses"] <= job["totalProcesses"], "Invalid Job accounting.")
            io = resource["io"]
            require(set(io) == {"readOperations", "writeOperations", "otherOperations", "readBytes", "writeBytes", "otherBytes"} and
                    all(natural(value) for value in io.values()), "Invalid Job I/O counters.")
            monotonic = {**io, **{key: job[key] for key in ("user100ns", "kernel100ns", "totalProcesses", "terminatedProcesses")}}
            require(all(value >= last_counters.get(scope, {}).get(key, 0) for key, value in monotonic.items()), "Job counters decreased.")
            last_counters[scope] = monotonic
            pids = set()
            for process in resource["processes"]:
                require(natural(process["pid"], 0xFFFFFFFF) and process["pid"] > 0 and process["pid"] not in pids,
                        "Invalid or duplicated sampled PID.")
                pids.add(process["pid"])
                require(process["status"] in ("sampled", "exited", "exited-before-open"), "Unknown process-sample outcome.")
                if process["status"] == "sampled":
                    require(decimal(process["created100ns"]) > 0 and process["image"] in execution["observedImages"] and
                            all(natural(process[key]) for key in ("rssBytes", "privateBytes", "handles", "user100ns", "kernel100ns")),
                            "Invalid sampled process resources or provenance.")
                    identity = (process["pid"], process["created100ns"])
                    require(identity not in identities or identities[identity] == (scope, process["image"]), "Sampled process identity changed scope or image.")
                    identities[identity] = (scope, process["image"])
    require(set(execution["observedImages"]) == {image for scope, image in identities.values()}, "Sampled image inventory differs.")
    for label, scope in (("appIdentity", "application"), ("targetIdentity", "target")):
        identity = execution[label]
        require(identity["status"] == "sampled" and identities.get((identity["pid"], identity["created100ns"])) == (scope, identity["image"]),
                "Root process identity is absent from owned samples.")
    listener = execution["cdp"]["listener"]
    require(identities.get((listener["pid"], listener["created100ns"])) == ("application", listener["image"]),
            "CDP listener is absent from owned application samples.")
    require(len(samples) <= 900, "Desktop sampling exceeds its lifetime bound.")
    portable = Path(execution["appIdentity"]["image"]).parent
    for (pid, created), (scope, image) in identities.items():
        path = Path(image)
        allowed = ({str(portable / "knmon-ui.exe"), str(portable / "knmon-native-helper.exe"), listener["image"]}
                   if scope == "application" else {str(portable / "knmon-comparison-target.exe")})
        require(image in allowed or path.name.lower() == "conhost.exe" and path.parent == Path(os.environ["SystemRoot"]) / "System32",
                "Unexpected executable in the owned desktop scenario.")
    helper_ids = {pid for (pid, created), (scope, image) in identities.items()
                  if scope == "application" and image == str(portable / "knmon-native-helper.exe")}
    require(helper_ids, "Native desktop enumeration helper was never observed.")
    preceding = [index for index, sample in enumerate(samples) if decimal(sample["afterQpc"]) <= before]
    following = [index for index, sample in enumerate(samples) if decimal(sample["beforeQpc"]) >= after]
    require(preceding and following, "Resource samples do not bracket the caller workload.")
    first, last = preceding[-1], following[0]
    active = samples[first:last + 1]
    require(len(active) >= 10 and all(decimal(right["beforeQpc"]) - decimal(left["afterQpc"]) <= frequency // 2
                                    for left, right in zip(active, active[1:])), "Desktop active sampling is sparse or interrupted.")
    result = {"samples": len(active), "windowMs": (decimal(active[-1]["afterQpc"]) - decimal(active[0]["beforeQpc"])) * 1000 / frequency}
    for scope in ("application", "target"):
        start, finish = active[0][scope], active[-1][scope]
        result[scope] = {"cpu100ns": sum(finish["job"][key] - start["job"][key] for key in ("kernel100ns", "user100ns")),
                         "io": {key: finish["io"][key] - start["io"][key] for key in start["io"]},
                         "sampledSumMaxima": {key: max(sum(process[key] for process in row[scope]["processes"] if process["status"] == "sampled")
                                                       for row in active) for key in ("rssBytes", "privateBytes", "handles")}}
    idle = [row for row in samples if row["phase"] == "idle"]
    require(len(idle) >= 10 and decimal(idle[-1]["beforeQpc"]) - decimal(idle[0]["afterQpc"]) >= frequency and
            decimal(idle[-1]["afterQpc"]) < decimal(execution["start"]["beforeQpc"]), "Desktop idle resource window is incomplete.")
    result["idle"] = {"samples": len(idle), "windowMs": (decimal(idle[-1]["afterQpc"]) - decimal(idle[0]["beforeQpc"])) * 1000 / frequency,
                      "applicationCpu100ns": sum(idle[-1]["application"]["job"][key] - idle[0]["application"]["job"][key]
                                                 for key in ("user100ns", "kernel100ns"))}
    return result


def verify_trial(directory, architecture, mode):
    execution, driver, request = (read_json(contained(directory, name)) for name in ("execution.json", "driver.json", "request.json"))
    require(type(execution["schemaVersion"]) is int and execution["schemaVersion"] == 1 and
            type(driver["schemaVersion"]) is int and driver["schemaVersion"] == 1 and
            execution["status"] == "executed" and execution["architecture"] == architecture and execution["mode"] == mode and
            driver["status"] == "passed" and driver["errors"] == [], "Desktop corpus execution or driver failed.")
    detail, frames = MODES[mode]
    require(same(execution["configuration"], {"iterations": ITERATIONS, "delayMs": 30, "waitMs": 30000,
                                           "captureDetail": detail, "stackFrames": frames, "desktop": "Release", "native": "Debug",
                                           "samplingIntervalMs": 100, "presentation": "hidden"}), "Desktop corpus configuration differs.")
    validate_endpoint(execution["cdp"])
    require(request["endpoint"] == execution["cdp"]["endpoint"] and driver["initialSessions"] == [], "Unexpected initial session or CDP endpoint.")
    expected_phases = ["idle", "workload-ready", "finished"] if mode == "original" else ["idle", "attach", "workload-ready", "stop", "finished"]
    require(read_bytes(contained(directory, "phase.txt"), 1024).decode("ascii").splitlines() == expected_phases and
            same(read_json(contained(directory, "finish.json")), {"controlId": execution["controlId"]}), "Desktop control phases or completion identity differ.")
    expected_keys = sorted("kernel32.dll!" + api for api in read_json(ROOT / MANIFEST)["apis"])
    require(request["allowlist"] == driver["allowlist"] == expected_keys and request["mode"] == mode and
            request["captureDetail"] == (detail or "preview") and request["stackFrames"] == frames and
            type(request["stackFrames"]) is int, "Desktop requested allowlist or capture policy differs.")
    require(all(type(execution[key]) is int and execution[key] == 0 for key in ("appExit", "targetExit", "driverExit")) and
            execution["targetAliveAfterDetach"] is True and set(execution["cleanup"]) == set(execution["naturalJobEnd"]) == {"application", "target", "driver"} and
            all(type(row[key]) is int and row[key] == 0 for name in ("cleanup", "naturalJobEnd")
                for row in execution[name].values() for key in ("activeProcesses", "terminatedProcesses")),
            "Desktop corpus process lifetime was incomplete or force-terminated.")
    oracle = read_json(contained(directory, "corpus/oracle.json"))
    metrics = oracle_metrics(oracle)
    require(oracle["pid"] == execution["targetPid"] == request["targetPid"] == driver["targetPid"] == execution["targetIdentity"]["pid"] and
            execution["appIdentity"]["pid"] == execution["appPid"], "Desktop caller identity differs.")
    require(read_bytes(contained(directory, "corpus/corpus.bin"), 64) == bytes(range(32, 96)), "Desktop corpus output bytes differ.")
    coordination = oracle["coordination"]
    require(re.fullmatch(r"[a-f0-9]{32}", execution["controlId"]) is not None and
            coordination["id"] == request["controlId"] == execution["controlId"] and
            type(coordination["delayMs"]) is int and coordination["delayMs"] == 30 and
            type(coordination["waitTimeoutMs"]) is int and coordination["waitTimeoutMs"] == 30000 and
            decimal(execution["qpcFrequency"]) == decimal(oracle["qpcFrequency"]), "Desktop corpus coordination differs.")
    require(0 < decimal(coordination["readyQpc"]) <= decimal(execution["targetReadyObservedQpc"]) <= decimal(execution["start"]["beforeQpc"]) <=
            decimal(execution["start"]["afterQpc"]) and decimal(execution["start"]["beforeQpc"]) <= decimal(coordination["startGateQpc"]) <=
            decimal(oracle["startQpc"]) <= decimal(oracle["endQpc"]) <= decimal(execution["doneObservedQpc"]) <=
            decimal(execution["drainedObservedQpc"]) <= decimal(execution["release"]["beforeQpc"]) <= decimal(execution["release"]["afterQpc"]),
            "Desktop corpus lifecycle or timing order differs.")
    require(metrics["workloadUs"] >= ITERATIONS * 30 * 800, "Desktop workload did not retain configured pacing.")
    expected = 0 if mode == "original" else EXPECTED
    for name in ("ready", "drained", "terminal"):
        snapshot = driver[name]
        wanted = 0 if name == "ready" else expected
        require(counters(snapshot) == (wanted, wanted) and snapshot["captureDetail"] == (detail or "preview") and
                snapshot["stackFrames"] == str(frames) and snapshot["sessionState"] == ("running" if mode != "original" and name != "terminal" else None) and
                snapshot["controlsLocked"] is (mode != "original" and name != "terminal"), "Desktop phase counters or controls differ.")
    events = exported_events(directory, execution, driver, oracle, mode, architecture)
    samples = json_lines(contained(directory, "resources.jsonl"))
    resource_metrics = process_samples(samples, execution, oracle)
    if events:
        require(any(process["status"] == "sampled" and process["pid"] == driver["sessions"][0]["helperProcessId"] and
                    process["image"] == str(Path(execution["appIdentity"]["image"]).parent / "knmon-native-helper.exe")
                    for sample in samples for process in sample["application"]["processes"]), "Capture helper identity was never sampled.")
    previous_count, previous_total, previous_request, previous_received, queries = 0, 0, decimal(execution["start"]["beforeQpc"]), 0, 0
    lower, upper = [], []
    frequency = decimal(oracle["qpcFrequency"])
    for sample in samples:
        if "ui" not in sample:
            continue
        ui = sample["ui"]
        queries += 1
        require(queries <= 150 and same(read_json(contained(directory, f"query-{queries:06d}.json")), {"sequence": queries}) and
                same(read_json(contained(directory, f"reply-{queries:06d}.json")), ui["reply"]), "UI observation exchange differs from immutable files.")
        require(type(ui["sequence"]) is int and type(ui["reply"]["sequence"]) is int and
                ui["sequence"] == queries == ui["reply"]["sequence"], "UI query sequence differs.")
        first, last = decimal(ui["requestedQpc"]), decimal(ui["receivedQpc"])
        require(previous_received < first <= last and last - first <= frequency // 2 and
                decimal(execution["start"]["beforeQpc"]) <= first <= decimal(sample["beforeQpc"]) <= decimal(sample["afterQpc"]) <= last and
                last <= decimal(execution["drainedObservedQpc"]), "UI observation bracket is invalid or too wide.")
        count, total = counters(ui["reply"]["snapshot"])
        require(ui["reply"]["snapshot"]["sessionState"] == (None if mode == "original" else "running") and
                ui["reply"]["snapshot"]["captureDetail"] == (detail or "preview") and ui["reply"]["snapshot"]["stackFrames"] == str(frames),
                "Desktop capture policy or state changed during the workload.")
        require(previous_count <= count <= total <= expected and previous_total <= total,
                "UI counter moved backward or exceeded the independent workload.")
        for index in range(previous_count, count):
            end = decimal(events[index]["timing"]["endQpc"])
            require(end <= last, "UI observation predates the captured original call.")
            lower.append(max(0, previous_request - end) * 1000 / frequency)
            upper.append((last - end) * 1000 / frequency)
        previous_count, previous_total, previous_request, previous_received = count, total, first, last
    require(queries >= 10 and previous_count == expected, "UI observation coverage is incomplete.")
    if events:
        require(len(lower) == len(upper) == EXPECTED and all(a <= b for a, b in zip(lower, upper)), "UI delivery intervals are incomplete.")
        lookup = {str(event["eventId"]): event for event in events}
        rows = driver["filtered"]["rows"]
        require(rows and all(len(cells) == 11 and cells[0] in lookup and cells[5] == "WriteFile" and
                            cells[2:6] == [str(oracle["pid"]), str(oracle["tid"]), lookup[cells[0]]["module"], lookup[cells[0]]["api"]]
                            for cells in rows), "Filtered desktop rows differ from the complete export.")
    return {"caller": metrics, "delivered": len(events), "resources": resource_metrics, "uiQueries": queries,
            "uiDeliveryMs": {"lower": quantiles(lower), "upper": quantiles(upper),
                             "maxBracketWidth": max(b - a for a, b in zip(lower, upper))} if events else None}
