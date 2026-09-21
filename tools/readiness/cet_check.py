"""Recompute local CET enforcement and capture compatibility from raw observations."""
from pathlib import Path
import re

from desktop_check import json_value
from native_profile_costs import MODES, ITERATIONS, MANIFEST, natural, decimal, same, oracle_metrics, check_arguments, check_stack
from source_evidence import ROOT, require, read_json

EXPECTED_CALLS = ITERATIONS * 7 + 2
SCOPE = "Local Windows x64 hardware shadow-stack enforcement and Debug native six-API attach compatibility"
ASSURANCE = "No x86, other-host, other-Windows-build, native Release, general API coverage or performance claim; unsigned local consistency, not builder authentication"


def schedule():
    return [(strict, mode, "bounded") for mode in MODES for strict in (False, True)] + [(True, "preview-stack32", "cancel")]


def trial_name(strict, mode, stop):
    return ("strict" if strict else "off") + "-" + mode + "-" + stop


def policy_flags(flags, strict):
    require(natural(flags, 0xFFFFFFFF) and flags & 0x13 == (0x11 if strict else 0),
            "Actual CET policy does not match the requested non-audit mode.")


def before_record(case, strict, mismatch):
    require(type(case["output"]) is str and 0 < len(case["output"]) <= 65536 and "\n" in case["output"],
            "CET child did not publish a bounded policy observation.")
    before = json_value(case["output"].split("\n", 1)[0].encode("ascii"))
    expected = {"phase": "before", "processId": case["processId"], "threadId": case["threadId"],
                "queried": True, "flags": case["parentPolicyFlags"], "error": 0, "strict": strict, "mismatch": mismatch}
    require(same(before, expected), "CET child and parent policy or execution identities differ.")
    return before


def observed_child(case, forced):
    require(natural(case["processId"], 0xFFFFFFFF) and case["processId"] > 0 and
            natural(case["threadId"], 0xFFFFFFFF) and case["threadId"] > 0 and decimal(case["creationTime100ns"]) > 0,
            "CET child identity is invalid.")
    require(case["parentPolicyRead"] is True and natural(case["parentPolicyFlags"], 0xFFFFFFFF) and
            type(case["parentPolicyError"]) is int and case["parentPolicyError"] == 0 and
            case["exitCodeRead"] is True and case["cleanupSucceeded"] is True and case["jobAssigned"] is True and
            case["jobAccountingRead"] is True and case["forcedCleanup"] is forced and
            type(case["jobActiveProcesses"]) is int and case["jobActiveProcesses"] == 0,
            "CET policy query, process ownership or cleanup is incomplete.")
    require(natural(case["debugEvents"], 4096) and case["debugEvents"] > 1 and
            natural(case["exitCode"], 0xFFFFFFFF) and natural(case["debugExitCode"], 0xFFFFFFFF),
            "CET exit or debugger accounting is invalid.")
    exceptions = case["exceptions"]
    require(type(exceptions) is list and 0 < len(exceptions) <= 32, "CET exception sequence is absent or oversized.")
    for row in exceptions:
        require(set(row) == {"code", "firstChance", "threadId", "parameters"} and
                natural(row["code"], 0xFFFFFFFF) and natural(row["firstChance"], 1) and
                type(row["threadId"]) is int and row["threadId"] == case["threadId"] and
                type(row["parameters"]) is list and len(row["parameters"]) <= 15 and all(natural(value) for value in row["parameters"]),
                "CET exception shape or thread identity differs.")
    require(same(exceptions[0], {"code": 0x80000003, "firstChance": 1, "threadId": case["threadId"], "parameters": [0]}),
            "CET initial debugger breakpoint was not observed.")


def probe(document):
    require(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1 and
            document["architecture"] == "x64" and document["kind"] == "observed", "Unexpected CET probe scope.")
    cases = document["cases"]
    require(type(cases) is list and [case["name"] for case in cases] == ["off-valid", "off-mismatch", "strict-valid", "strict-mismatch"],
            "CET differential matrix is incomplete or reordered.")
    unsupported = []
    for index, case in enumerate(cases):
        strict, mismatch = index >= 2, index % 2 != 0
        require(type(case["requestedPolicy"]) is int and case["requestedPolicy"] == (3 if strict else 2) << 28,
                "CET creation policy differs.")
        if strict and case["errorStage"] in ("attributes", "create") and type(case["error"]) is int and case["error"] in (50, 87, 1150):
            require(case["processId"] == 0 and case["cleanupSucceeded"] is True and case["observedExit"] is False and
                    case["forcedCleanup"] is False and case["output"] == "" and case["exceptions"] == [],
                    "Unsupported CET creation left a live or partly executed target.")
            unsupported.append(case["name"])
            continue
        observed_child(case, False)
        require(type(case["error"]) is int and case["error"] == 0 and case["errorStage"] == "none" and
                case["observedExit"] is True and case["exitCode"] == case["debugExitCode"], "CET probe did not exit naturally.")
        before_record(case, strict, mismatch)
        if strict and case["exitCode"] == 77:
            require(case["parentPolicyFlags"] & 0x13 != 0x11 and len(case["exceptions"]) == 1 and
                    len(case["output"].splitlines()) == 1, "CET unsupported outcome contradicts its observations.")
            unsupported.append(case["name"])
            continue
        policy_flags(case["parentPolicyFlags"], strict)
        if strict and mismatch:
            require(case["exitCode"] == 0xC0000409 and len(case["exceptions"]) == 2 and
                    len(case["output"].splitlines()) == 1, "Strict CET mismatch returned or lacked the expected termination.")
            failure = case["exceptions"][1]
            require(failure["code"] == 0xC0000409 and failure["firstChance"] == 0 and
                    len(failure["parameters"]) >= 1 and failure["parameters"][0] == 57,
                    "Termination does not prove an invalid-return-address shadow-stack failure.")
        else:
            lines = case["output"].splitlines()
            require(case["exitCode"] == 0 and len(case["exceptions"]) == 1 and len(lines) == 2 and
                    same(json_value(lines[1].encode("ascii")), {"phase": "after", "returned": 73}),
                    "CET positive or policy-off mismatched-return control failed.")
    require(not unsupported or unsupported == ["strict-valid", "strict-mismatch"], "Inconsistent CET availability observations.")
    identities = [(row["processId"], row["creationTime100ns"]) for row in cases if row["processId"]]
    require(len(identities) == len(set(identities)), "CET probe reused a child identity.")
    return {"status": "not_verified" if unsupported else "passed", "controls": 4, "unsupported": unsupported}


def cleanup_control(document, name):
    require(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1 and document["kind"] == "cleanup-control" and
            document["architecture"] == "x64" and type(document["cases"]) is list and len(document["cases"]) == 1,
            "Invalid CET cleanup-control report.")
    case = document["cases"][0]
    observed_child(case, True)
    policy_flags(case["parentPolicyFlags"], False)
    before_record(case, False, False)
    require(case["name"] == name + "-control" and type(case["requestedPolicy"]) is int and case["requestedPolicy"] == 2 << 28 and
            type(case["error"]) is int and case["error"] == (1460 if name == "timeout" else 111) and case["errorStage"] == "debug" and
            case["observedExit"] is False and case["exitCode"] == 99 and case["debugExitCode"] == 0 and len(case["exceptions"]) == 1,
            "CET cleanup control did not reproduce its expected failure.")
    tail = case["output"].split("\n", 1)[1]
    require((tail == "") if name == "timeout" else (len(case["output"]) == 65536 and tail and set(tail) == {"x"}),
            "CET output bound or preserved failure prefix differs.")


def target_policy(row, strict, target, oracle):
    require(row["queried"] is True and row["alive"] is True and type(row["error"]) is int and row["error"] == 0 and
            type(row["requestedPolicy"]) is int and row["requestedPolicy"] == (3 if strict else 2) << 28 and
            type(row["pid"]) is int and row["pid"] == oracle["pid"] and type(row["tid"]) is int and row["tid"] == oracle["tid"] and
            decimal(row["created100ns"]) > 0 and Path(row["image"]) == target,
            "CET target policy query or image/process identity differs.")
    policy_flags(row["flags"], strict)


def capture(frames, oracle, mode, stop, operation, target, agent):
    require(type(frames) is list and 4 <= len(frames) <= 32 and frames[0]["frameType"] == "session_started" and
            all(row["schemaVersion"] == "0.1.0" for row in frames), "CET capture frame sequence is invalid.")
    require([row["frameType"] for row in frames] == ["session_started", "session_state", "session_state", "session_stopping", "session_stopped", "capture_result"] and
            [row["session"]["sessionState"] for row in frames] == ["starting", "starting", "running", "stopping_agent", "stopped", "stopped"],
            "CET capture readiness and shutdown frame order differs.")
    for row in frames:
        session = row["session"]
        require(session["operationId"] == session["sessionId"] == operation and type(session["targetProcessId"]) is int and
                session["targetProcessId"] == oracle["pid"], "CET capture frame changed operation or target identity.")
    result, session = frames[-1]["captureResult"], frames[-1]["session"]
    cancelled = stop == "cancel"
    require(result["success"] is (not cancelled) and result["cancelRequested"] is cancelled and result["cancelObserved"] is cancelled and
            type(result["win32ErrorCode"]) is int and result["win32ErrorCode"] == (1223 if cancelled else 0) and
            (not cancelled or result["operation"] == "operation_cancelled") and result["sessionState"] == "stopped" and
            result["operationId"] == result["sessionId"] == operation and result["architecture"] == "x64" and
            result["captureMode"] == "bounded-native-attach" and result["sessionKind"] == "attach_capture" and
            result["apiSelection"] == ";".join("kernel32.dll!" + name for name in read_json(ROOT / MANIFEST)["apis"]) and
            type(result["targetProcessId"]) is int and result["targetProcessId"] == oracle["pid"] and
            type(result["targetThreadId"]) is int and result["targetThreadId"] == 0 and
            Path(result["targetPath"]) == target and Path(result["agentPath"]) == agent and result["hookCleanupOutcome"] == "restored_by_agent" and
            result["agentCleanupAttempted"] is True and result["agentCleanupSucceeded"] is True,
            "CET attach/cancel/cleanup outcome differs from the requested lifecycle.")
    require(session["sessionState"] == "stopped" and session["targetAlive"] is True and session["targetExitObserved"] is False and
            session["agentCleanupAttempted"] is True and session["agentCleanupSucceeded"] is True and session["lastError"] == "" and
            session["stopRequested"] is cancelled and session["sessionKind"] == "attach_capture" and
            session["targetProcessCreationTime"] in ("0", oracle["cetCreated100ns"]) and
            same(frames[-2]["session"], session), "CET target did not survive a clean detach.")
    shutdown = json_value(session["shutdownEvidence"].encode("utf-8"))
    require(session["shutdownEvidence"] == result["sessionShutdownEvidence"] and shutdown["messageType"] == "agent_shutdown" and
            shutdown["operationId"] == operation and type(shutdown["pid"]) is int and shutdown["pid"] == oracle["pid"] and
            shutdown["lifecycleState"] == "disabled" and shutdown["reason"] == "self_disable" and
            type(shutdown["installedHooks"]) is int and shutdown["installedHooks"] > 0 and
            type(shutdown["restoredHooks"]) is int and shutdown["restoredHooks"] == shutdown["installedHooks"] and
            all(type(shutdown[key]) is int and shutdown[key] == 0 for key in ("failedHooks", "droppedCount")),
            "CET detach lacks complete hook restoration evidence.")
    handshake = result["handshake"]
    hello = json_value(handshake["rawPayload"].encode("utf-8"))
    require(handshake["received"] is True and handshake["schemaVersion"] == "0.1.0" and handshake["architecture"] == "x64" and
            handshake["operationId"] == operation and type(handshake["processId"]) is int and handshake["processId"] == oracle["pid"] and
            natural(handshake["threadId"], 0xFFFFFFFF) and handshake["threadId"] > 0 and hello["messageType"] == "agent_hello" and
            hello["architecture"] == "x64" and type(hello["tid"]) is int and hello["tid"] == handshake["threadId"] and
            hello["agentVersion"] == handshake["agentVersion"], "CET capture lacks its actual Agent HELLO.")
    messages = result["agentMessages"]
    require(type(messages) is list and EXPECTED_CALLS < len(messages) <= EXPECTED_CALLS + 128,
            "CET Agent protocol observations are absent or oversized.")
    lifecycle = [message for message in messages if message["messageType"] in ("agent_hello", "agent_ready", "agent_shutdown")]
    require([message["messageType"] for message in lifecycle] == ["agent_hello", "agent_ready", "agent_shutdown"] and
            same(lifecycle[0], hello) and same(lifecycle[-1], shutdown), "CET Agent readiness and shutdown observations differ.")
    nonce = hello["channelNonce"]
    require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None,
            "CET Agent channel identity is invalid.")
    for message in lifecycle:
        require(message["schemaVersion"] == "0.1.0" and message["operationId"] == operation and message["channelNonce"] == nonce and
                type(message["pid"]) is int and message["pid"] == oracle["pid"] and natural(message["sequence"]) and message["sequence"] > 0,
                "CET Agent lifecycle changed target or authenticated channel identity.")
    require(hello["sequence"] < lifecycle[1]["sequence"] < shutdown["sequence"] and
            lifecycle[1]["captureDetail"] == MODES[mode][0] and type(lifecycle[1]["stackFrames"]) is int and lifecycle[1]["stackFrames"] == MODES[mode][1],
            "CET Agent readiness policy or protocol sequence differs.")
    cleanup = result["cleanupState"]
    require(cleanup["source"] == "controller_query" and cleanup["operationId"] == operation and cleanup["lifecycle"] == "disabled" and
            cleanup["active"] is False and cleanup["busy"] is False and
            all(type(cleanup[key]) is int and cleanup[key] == 0 for key in ("hooksEnabled", "failedHooks", "droppedEvents")) and
            type(cleanup["installedHooks"]) is int and type(cleanup["restoredHooks"]) is int and
            cleanup["installedHooks"] == cleanup["restoredHooks"] == shutdown["installedHooks"], "CET controller cleanup query disagrees.")
    require(all(type(result[key]) is int and result[key] == EXPECTED_CALLS for key in
                ("transportRecordsProduced", "transportRecordsConsumed", "recordsStreamed", "lastTransportSequence")) and
            all(type(result[key]) is int and result[key] == 0 for key in ("transportAbortedRecords", "transportDroppedEvents", "droppedEvents")) and
            type(result["transportCapacity"]) is int and result["transportCapacity"] == 1024 and
            natural(result["transportHighWaterMark"], min(1024, EXPECTED_CALLS)) and result["transportHighWaterMark"] > 0,
            "CET transport omitted, lost or failed to drain records.")
    for key in ("recordsStreamed", "lastTransportSequence"):
        require(type(session[key]) is int and session[key] == EXPECTED_CALLS, "CET session record accounting differs.")
    for key in ("transportDroppedEvents", "transportAbortedRecords", "hostDroppedBatches"):
        require(type(session[key]) is int and session[key] == 0, "CET session reports lost records.")
    history = result["retainedHistory"]
    omitted = ("omittedCapturedEvents", "omittedAgentMessages", "omittedResolverPointerCandidates", "omittedResolverPointerUnsupported", "omittedAuditEvents")
    require(set(history) == {"bounded", "capturedEventsTotal", *omitted} and history["bounded"] is False and
            type(history["capturedEventsTotal"]) is int and history["capturedEventsTotal"] == EXPECTED_CALLS and
            all(type(history[key]) is int and history[key] == 0 for key in omitted),
            "CET retained history is incomplete.")
    events = result["capturedEvents"]
    require(type(events) is list and len(events) == len(oracle["events"]) == EXPECTED_CALLS, "CET observed event count differs.")
    require(same([message for message in messages if message["messageType"] == "api_call"], events),
            "CET Agent messages and captured events disagree.")
    detail, count = MODES[mode]
    for index, (event, expected) in enumerate(zip(events, oracle["events"])):
        require(event["api"] == expected["api"] and event["module"].lower() == "kernel32.dll" and
                type(event["pid"]) is int and event["pid"] == oracle["pid"] and type(event["tid"]) is int and event["tid"] == oracle["tid"] and
                event["operationId"] == operation and decimal(event["recordSequence"]) == index and decimal(event["callId"]) == index + 1 and
                decimal(event["parentCallId"]) == 0 and type(event["callDepth"]) is int and event["callDepth"] == 0,
                "CET API identity, ordering or call sequence differs.")
        timing = event["timing"]
        require(event["timeSource"] == "qpc" and decimal(timing["qpcFrequency"]) == decimal(oracle["qpcFrequency"]) and
                decimal(expected["startQpc"]) <= decimal(timing["startQpc"]) <= decimal(timing["endQpc"]) <= decimal(expected["endQpc"]),
                "CET hook clock is outside the independent caller interval.")
        bits = 64 if event["api"] in ("CreateFileW", "VirtualAlloc") else 32
        raw = decimal(event["rawReturnValue"])
        success = raw != (1 << bits) - 1 if event["api"] == "CreateFileW" else raw != 0
        require(type(event["rawReturnBits"]) is int and event["rawReturnBits"] == bits and raw < 1 << bits and
                success == expected["success"] and type(event["rawLastErrorCode"]) is int and event["rawLastErrorCode"] == expected["error"],
                "CET caller return or error behavior changed.")
        require(event["captureDetail"] == detail and type(event["arguments"]) is list and type(event["bufferPreview"]) is str and
                (detail != "metadata" or event["arguments"] == []) and (detail == "preview" or event["bufferPreview"] == ""),
                "CET capture policy differs.")
        check_stack(event, count, "x64")
        if detail != "metadata":
            check_arguments(events, index, "x64")
            if event["api"] == "CreateFileW":
                expected_path = Path(oracle["cetDirectory"]) / ("missing-file.bin" if index == EXPECTED_CALLS - 1 else "corpus.bin")
                require(Path(event["arguments"][0]["rawValue"]) == expected_path, "CET captured file path differs.")
            if event["api"] in ("ReadFile", "WriteFile"):
                buffer, transferred = event["arguments"][1], event["arguments"][3]
                require((transferred["decodeStatus"] == "decoded" and transferred["decodedValue"] == str(expected["byteCount"])) if success else
                        transferred["decodeStatus"] == "not_captured", "CET I/O output count changed.")
                if detail == "arguments":
                    observed = buffer["capture"]
                    require(buffer["decodeStatus"] == "not_captured" and observed["phase"] == "none" and observed["readStatus"] == "not_captured" and
                            type(observed["capturedBytes"]) is int and observed["capturedBytes"] == 0 and observed["truncationReason"] == "capture_detail",
                            "CET arguments-only policy captured a disabled buffer.")
                else:
                    require(event["bufferPreview"].replace(" ", "") == expected["preview"], "CET preview changed caller bytes.")
    return {"observed": len(events), "dropped": 0, "restoredHooks": shutdown["restoredHooks"], "cancelled": cancelled}
