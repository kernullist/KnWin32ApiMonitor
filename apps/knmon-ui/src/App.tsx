import {
  Activity,
  Braces,
  ChevronRight,
  CircleDot,
  Cpu,
  Database,
  Download,
  FileText,
  Filter,
  FolderOpen,
  GitBranch,
  HardDrive,
  Layers,
  Play,
  RefreshCcw,
  Rocket,
  Search,
  Server,
  Square,
  Trash2
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  attachTargetProcessCapture,
  captureSampleFileIoEvents,
  captureSampleFileIoSession,
  launchSampleEarlyBirdCapture,
  listNativeTargetProcesses,
  listTargetProcesses,
  replayLastSampleSession,
  startBackendSession,
  stopBackendSession,
  superviseProcessTree
} from "./backend";
import { apiTree, captureProfiles, createMockFileIoEvent, initialTraceEvents } from "./mockData";
import { downloadJsonl, estimateSessionBytes } from "./session";
import type { AgentApiCallEvent, ApiNode, AuditEvent, BackendMode, CaptureResult, InspectorTab, LaunchResult, ProcessTreeResult, SessionInfo, TargetProcess, TraceEvent } from "./types";

type LeftTab = "targets" | "apis" | "profiles";
type TraceMode = "flat" | "call-tree";
type TargetSource = "mock" | "native";
type ChildPolicy = ProcessTreeResult["childPolicy"];

const inspectorTabs: Array<{ id: InspectorTab; label: string }> = [
  { id: "parameters", label: "Parameters" },
  { id: "buffer", label: "Buffer" },
  { id: "stack", label: "Call Stack" },
  { id: "return", label: "Return/Error" },
  { id: "output", label: "Output" }
];

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / 1024 / 1024).toFixed(2)} MB`;
}

function renderApiTree(nodes: ApiNode[], depth = 0): JSX.Element {
  return (
    <div className="tree-group">
      {nodes.map((node) => (
        <div key={node.id}>
          <div className="tree-row" style={{ paddingLeft: 8 + depth * 16 }}>
            {node.children ? <ChevronRight size={13} className="tree-caret" /> : <span className="tree-leaf" />}
            <input type="checkbox" checked={node.checked} readOnly />
            <FileText size={14} className={node.checked ? "tree-icon enabled" : "tree-icon"} />
            <span>{node.label}</span>
          </div>
          {node.children ? renderApiTree(node.children, depth + 1) : null}
        </div>
      ))}
    </div>
  );
}

function compactArgs(event: TraceEvent): string {
  return event.arguments
    .slice(0, 3)
    .map((argument) => `${argument.name}=${argument.decodedValue}`)
    .join(", ");
}

function makeAuditEvent(eventType: string, operation: string, message: string, win32ErrorCode = 0): AuditEvent {
  return {
    schemaVersion: "0.1.0",
    operationId: "ui",
    eventType,
    timestampUtc: new Date().toISOString(),
    subsystem: "ui",
    operation,
    win32ErrorCode,
    ntStatus: "0x00000000",
    message
  };
}

function fileNameFromPath(value: string): string {
  const parts = value.split(/[\\/]/u);
  return parts[parts.length - 1] || value;
}

function createAgentLoadedEvent(result: LaunchResult, eventId: number): TraceEvent {
  return {
    schemaVersion: result.schemaVersion,
    eventId,
    relativeTimeMs: eventId * 137,
    pid: result.targetProcessId,
    tid: result.targetThreadId,
    process: "knmon-sample-fileio.exe",
    module: fileNameFromPath(result.agentPath),
    api: result.handshake.received ? "agent_loaded" : "capture_backend_status",
    arguments: [
      {
        index: 0,
        type: "LPCWSTR",
        name: "AgentPath",
        direction: "in",
        preCallValue: result.agentPath,
        postCallValue: result.agentPath,
        rawValue: result.agentPath,
        decodedValue: result.agentPath,
        decodeStatus: "decoded"
      },
      {
        index: 1,
        type: "LPCWSTR",
        name: "InjectionMethod",
        direction: "in",
        preCallValue: result.injectionMethod,
        postCallValue: result.injectionMethod,
        rawValue: result.injectionMethod,
        decodedValue: result.injectionMethod,
        decodeStatus: "decoded"
      },
      {
        index: 2,
        type: "BOOL",
        name: "HandshakeReceived",
        direction: "out",
        preCallValue: "FALSE",
        postCallValue: result.handshake.received ? "TRUE" : "FALSE",
        rawValue: result.handshake.received ? "1" : "0",
        decodedValue: result.handshake.message,
        decodeStatus: "decoded"
      }
    ],
    returnValue: result.success ? "TRUE" : "FALSE",
    error: result.success
      ? null
      : {
          kind: "win32",
          code: `0x${result.win32ErrorCode.toString(16).padStart(8, "0")}`,
          message: result.message
        },
    durationUs: 0,
    tags: ["native-capture", "early-bird", result.handshake.received ? "agent-hello" : "status"],
    stack: [
      "knmon-native-helper.exe!LaunchWithEarlyBirdApc",
      "kernel32.dll!QueueUserAPC",
      "kernel32.dll!ResumeThread"
    ],
    bufferPreview: result.handshake.rawPayload
  };
}

function createTraceEventFromAgentApiCall(event: AgentApiCallEvent, eventId: number): TraceEvent {
  return {
    schemaVersion: event.schemaVersion,
    eventId,
    relativeTimeMs: event.sequence * 10,
    pid: event.pid,
    tid: event.tid,
    process: event.process,
    module: event.module,
    api: event.api,
    arguments: event.arguments,
    returnValue: event.returnValue,
    error: event.lastErrorCode === 0
      ? null
      : {
          kind: "win32",
          code: `0x${event.lastErrorCode.toString(16).padStart(8, "0")}`,
          message: event.lastErrorMessage
        },
    durationUs: event.durationUs,
    tags: event.tags,
    stack: event.stack,
    bufferPreview: event.bufferPreview || undefined
  };
}

function clampDurationMs(value: string | number, fallback: number): number {
  const parsed = typeof value === "number" ? value : Number.parseInt(value, 10);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.min(30000, Math.max(250, Math.trunc(parsed)));
}

function getRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  return null;
}

function readNumberField(record: Record<string, unknown>, name: string): number | null {
  const value = record[name];

  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  return null;
}

function hookRestoreSummary(result: CaptureResult | null): string {
  if (!result) {
    return "not available";
  }

  const shutdown = result.agentMessages
    .map((message) => getRecord(message))
    .find((message) => message?.messageType === "agent_shutdown");

  if (!shutdown) {
    return "agent_shutdown not observed";
  }

  const restoredHooks = readNumberField(shutdown, "restoredHooks");
  const installedHooks = readNumberField(shutdown, "installedHooks");
  const failedHooks = readNumberField(shutdown, "failedHooks");
  const reason = typeof shutdown.reason === "string" ? shutdown.reason : "self_disable";

  if (restoredHooks === null || installedHooks === null || failedHooks === null) {
    return `agent_shutdown reason=${reason}`;
  }

  return `agent_shutdown reason=${reason}; restored=${restoredHooks}/${installedHooks}; failed=${failedHooks}`;
}

function targetEligibilityReason(target: TargetProcess | null, source: TargetSource): string | null {
  if (!target) {
    return "Select a target row.";
  }

  if (source !== "native") {
    return "Switch target source to Native.";
  }

  if (target.status !== "available") {
    return `Target status is ${target.status}.`;
  }

  if (target.architecture !== "x64" && target.architecture !== "x86") {
    return `Architecture ${target.architecture} is unsupported.`;
  }

  return null;
}

function summarizeProcessTree(result: ProcessTreeResult | null) {
  const empty = {
    childCount: 0,
    eligibleCount: 0,
    mutationAttemptedCount: 0,
    attachSuccessCount: 0,
    attachFailureCount: 0,
    capturedEventCount: 0
  };

  if (!result) {
    return empty;
  }

  return {
    childCount: result.processNodes.filter((node) => !node.isRoot).length,
    eligibleCount: result.policyDecisions.filter((decision) => decision.eligibilityStatus === "eligible").length,
    mutationAttemptedCount: result.policyDecisions.filter((decision) => decision.mutationAttempted).length,
    attachSuccessCount: result.childAttachResults.filter((capture) => capture.success).length,
    attachFailureCount: result.childAttachResults.filter((capture) => !capture.success).length,
    capturedEventCount: result.childAttachResults.reduce((total, capture) => total + capture.capturedEvents.length, 0)
  };
}

function App() {
  const [leftTab, setLeftTab] = useState<LeftTab>("targets");
  const [targetSource, setTargetSource] = useState<TargetSource>("mock");
  const [targets, setTargets] = useState<TargetProcess[]>([]);
  const [selectedTargetPid, setSelectedTargetPid] = useState<number | null>(null);
  const [backendMode, setBackendMode] = useState<BackendMode>("mock");
  const [events, setEvents] = useState<TraceEvent[]>(initialTraceEvents);
  const [selectedEventId, setSelectedEventId] = useState<number>(initialTraceEvents[0]?.eventId ?? 0);
  const [filter, setFilter] = useState("");
  const [running, setRunning] = useState(false);
  const [droppedCount, setDroppedCount] = useState(0);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("parameters");
  const [traceMode, setTraceMode] = useState<TraceMode>("flat");
  const [nativeBusy, setNativeBusy] = useState(false);
  const [attachDurationMs, setAttachDurationMs] = useState(3000);
  const [treeDurationMs, setTreeDurationMs] = useState(3000);
  const [childPolicy, setChildPolicy] = useState<ChildPolicy>("observe");
  const [launchResult, setLaunchResult] = useState<LaunchResult | null>(null);
  const [captureResult, setCaptureResult] = useState<CaptureResult | null>(null);
  const [attachResult, setAttachResult] = useState<CaptureResult | null>(null);
  const [processTreeResult, setProcessTreeResult] = useState<ProcessTreeResult | null>(null);
  const [lastSession, setLastSession] = useState<SessionInfo | null>(null);
  const [outputEvents, setOutputEvents] = useState<AuditEvent[]>([
    makeAuditEvent("backend_ready", "mock_init", "Mock File I/O backend initialized.")
  ]);
  const nextEventId = useRef(initialTraceEvents.length + 1);

  useEffect(() => {
    let active = true;

    listTargetProcesses().then((result) => {
      if (active) {
        setTargets(result.targets);
        setBackendMode(result.mode);
        setSelectedTargetPid(null);
      }
    });

    return () => {
      active = false;
    };
  }, []);

  function appendOutput(eventsToAppend: AuditEvent[]) {
    setOutputEvents((current) => [...eventsToAppend, ...current].slice(0, 80));
  }

  function replaceTargets(nextTargets: TargetProcess[], nextSource: TargetSource, nextMode: BackendMode) {
    setTargetSource(nextSource);
    setTargets(nextTargets);
    setBackendMode(nextMode);
    setSelectedTargetPid((current) => {
      if (current !== null && nextTargets.some((target) => target.pid === current)) {
        return current;
      }

      return null;
    });
  }

  function appendCapturedEvents(capturedEvents: AgentApiCallEvent[], contextTags: string[]) {
    if (capturedEvents.length === 0) {
      return;
    }

    const traceEvents = capturedEvents.map((event, index) => {
      const traceEvent = createTraceEventFromAgentApiCall(event, nextEventId.current + index);

      return {
        ...traceEvent,
        tags: Array.from(new Set([...traceEvent.tags, ...contextTags]))
      };
    });

    nextEventId.current += traceEvents.length;
    setEvents((current) => [...current, ...traceEvents].slice(-400));
    setSelectedEventId(traceEvents[traceEvents.length - 1].eventId);
  }

  async function handleLoadMockTargets() {
    const result = await listTargetProcesses();
    replaceTargets(result.targets, "mock", result.mode);
    appendOutput([makeAuditEvent("target_source_changed", "load_mock_targets", "Loaded mock target rows.")]);
  }

  async function handleLoadNativeTargets() {
    setNativeBusy(true);

    try {
      const result = await listNativeTargetProcesses();
      replaceTargets(result.targets, "native", result.mode);
      appendOutput([makeAuditEvent("native_enum_completed", "list_native_target_processes", `Loaded ${result.targets.length} native target rows.`)]);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      replaceTargets([], "native", "mock");
      appendOutput([makeAuditEvent("native_enum_blocked", "list_native_target_processes", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  useEffect(() => {
    if (!running) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      const next = createMockFileIoEvent(nextEventId.current);
      nextEventId.current += 1;
      setEvents((current) => [...current, next].slice(-400));
      setSelectedEventId(next.eventId);
    }, 900);

    return () => {
      window.clearInterval(timer);
    };
  }, [running]);

  const filteredEvents = useMemo(() => {
    const normalized = filter.trim().toLowerCase();

    if (!normalized) {
      return events;
    }

    return events.filter((event) => {
      const haystack = [
        event.api,
        event.module,
        event.process,
        event.returnValue,
        event.error?.message ?? "",
        event.tags.join(" "),
        compactArgs(event)
      ].join(" ").toLowerCase();

      return haystack.includes(normalized);
    });
  }, [events, filter]);

  const selectedEvent = events.find((event) => event.eventId === selectedEventId) ?? filteredEvents[0] ?? events[0];
  const selectedTarget = selectedTargetPid === null ? null : targets.find((target) => target.pid === selectedTargetPid) ?? null;
  const targetBlockReason = targetEligibilityReason(selectedTarget, targetSource);
  const canRunTargetAction = targetBlockReason === null && !nativeBusy;
  const processTreeSummary = summarizeProcessTree(processTreeResult);
  const sessionBytes = estimateSessionBytes(events);

  async function handleStartCapture() {
    await startBackendSession();
    setRunning(true);
  }

  async function handleStopCapture() {
    await stopBackendSession();
    setRunning(false);
  }

  function handleClear() {
    setRunning(false);
    setEvents([]);
    setSelectedEventId(0);
    nextEventId.current = 1;
  }

  async function handleLaunchSample() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("launch_requested", "launch_sample_early_bird_capture", "Controlled sample launch requested from UI.")]);
      const result = await launchSampleEarlyBirdCapture();
      setLaunchResult(result);
      setBackendMode(result.success ? "native-capture" : "native-enum");
      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("launch_result", result.operation, result.message, result.win32ErrorCode)]);

      const traceEvent = createAgentLoadedEvent(result, nextEventId.current);
      nextEventId.current += 1;
      setEvents((current) => [...current, traceEvent]);
      setSelectedEventId(traceEvent.eventId);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("launch_blocked", "launch_sample_early_bird_capture", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleCaptureSampleFileIo() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("capture_requested", "capture_sample_fileio_events", "Controlled native File I/O capture requested from UI.")]);
      const result = await captureSampleFileIoEvents();
      setCaptureResult(result);
      setBackendMode(result.success ? "native-capture" : "native-enum");
      setDroppedCount(result.droppedEvents);
      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("capture_result", result.operation, result.message, result.win32ErrorCode)]);

      if (result.capturedEvents.length > 0) {
        appendCapturedEvents(result.capturedEvents, ["sample-capture", `target:${result.targetProcessId}`]);
      }

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("capture_blocked", "capture_sample_fileio_events", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleCaptureAndSaveSession() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_capture_requested", "capture_sample_fileio_session_events", "Controlled native capture and session write requested from UI.")]);
      const result = await captureSampleFileIoSession();
      setCaptureResult(result);
      setBackendMode(result.success ? "native-capture" : "native-enum");
      setDroppedCount(result.droppedEvents);

      if (result.session) {
        setLastSession(result.session);
        appendOutput([
          makeAuditEvent(
            result.session.success ? "session_written" : "session_write_failed",
            "capture_sample_fileio_session_events",
            `${result.session.sessionPath}; traceEvents=${result.session.traceEventCount}; dropped=${result.session.droppedEvents}`,
            result.session.win32ErrorCode
          )
        ]);
      }

      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("capture_result", result.operation, result.message, result.win32ErrorCode)]);

      if (result.capturedEvents.length > 0) {
        appendCapturedEvents(result.capturedEvents, ["sample-session", `target:${result.targetProcessId}`]);
      }

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_capture_blocked", "capture_sample_fileio_session_events", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleReplayLastSession() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_replay_requested", "replay_last_sample_session", "Replay last saved sample session requested from UI.")]);
      const result = await replayLastSampleSession();
      setBackendMode(result.backendMode);
      setLastSession(result.session);
      setDroppedCount(result.session.droppedEvents);
      appendOutput([
        makeAuditEvent(
          result.success ? "session_replayed" : "session_replay_failed",
          "replay_last_sample_session",
          `${result.message}; path=${result.session.sessionPath}; traceEvents=${result.traceEvents.length}; dropped=${result.session.droppedEvents}`,
          result.session.win32ErrorCode
        )
      ]);

      if (result.traceEvents.length > 0) {
        setEvents(result.traceEvents);
        nextEventId.current = result.traceEvents.length + 1;
        setSelectedEventId(result.traceEvents[result.traceEvents.length - 1].eventId);
      }

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_replay_blocked", "replay_last_sample_session", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleAttachSelectedTarget() {
    if (!selectedTarget || targetBlockReason) {
      appendOutput([makeAuditEvent("attach_blocked", "attach_target_process_capture", targetBlockReason ?? "No target selected.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setAttachResult(null);

    try {
      appendOutput([makeAuditEvent("attach_requested", "attach_target_process_capture", `Bounded attach requested for PID ${selectedTarget.pid}.`)]);
      const result = await attachTargetProcessCapture(selectedTarget.pid, attachDurationMs);
      setAttachResult(result);
      setCaptureResult(result);
      setBackendMode(result.backendMode);
      setDroppedCount(result.droppedEvents);
      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("attach_result", result.operation, result.message, result.win32ErrorCode)]);
      appendCapturedEvents(result.capturedEvents, ["ui-attach", `target:${result.targetProcessId}`]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("attach_blocked", "attach_target_process_capture", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleSuperviseSelectedTree() {
    if (!selectedTarget || targetBlockReason) {
      appendOutput([makeAuditEvent("process_tree_blocked", "supervise_process_tree", targetBlockReason ?? "No target selected.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setProcessTreeResult(null);

    try {
      appendOutput([makeAuditEvent("process_tree_requested", "supervise_process_tree", `Supervision requested for PID ${selectedTarget.pid}; policy=${childPolicy}.`)]);
      const result = await superviseProcessTree(selectedTarget.pid, treeDurationMs, childPolicy);
      const childAuditEvents = result.childAttachResults.flatMap((capture) => capture.auditEvents);
      const childDroppedEvents = result.childAttachResults.reduce((total, capture) => total + capture.droppedEvents, 0);

      setProcessTreeResult(result);
      setBackendMode(result.backendMode);
      setDroppedCount(childDroppedEvents);
      appendOutput(
        result.auditEvents.length + childAuditEvents.length > 0
          ? [...result.auditEvents, ...childAuditEvents]
          : [makeAuditEvent("process_tree_result", result.operation, result.message, result.win32ErrorCode)]
      );

      result.childAttachResults.forEach((capture) => {
        appendCapturedEvents(capture.capturedEvents, ["process-tree", `child:${capture.targetProcessId}`]);
      });

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("process_tree_blocked", "supervise_process_tree", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <CircleDot size={16} />
          <span>KN Win32 API Monitor</span>
        </div>
        <div className="toolbar" aria-label="Capture toolbar">
          <button className="tool-button" type="button" title="Open session">
            <FolderOpen size={15} />
          </button>
          <button className="tool-button" type="button" title="Export JSONL" onClick={() => downloadJsonl(events)}>
            <Download size={15} />
          </button>
          <span className="toolbar-separator" />
          <button className="tool-button primary" type="button" title="Start capture" onClick={handleStartCapture} disabled={running}>
            <Play size={15} />
            <span>Start</span>
          </button>
          <button className="tool-button" type="button" title="Stop capture" onClick={handleStopCapture} disabled={!running}>
            <Square size={14} />
            <span>Stop</span>
          </button>
          <button className="tool-button danger" type="button" title="Clear session" onClick={handleClear}>
            <Trash2 size={15} />
          </button>
        </div>
        <div className="topbar-status">
          <span className={running ? "pulse running" : "pulse"} />
          <span>{running ? "capturing" : "stopped"}</span>
        </div>
      </header>

      <main className="workspace">
        <aside className="left-rail">
          <div className="segmented">
            <button type="button" className={leftTab === "targets" ? "active" : ""} onClick={() => setLeftTab("targets")}>Targets</button>
            <button type="button" className={leftTab === "apis" ? "active" : ""} onClick={() => setLeftTab("apis")}>API Library</button>
            <button type="button" className={leftTab === "profiles" ? "active" : ""} onClick={() => setLeftTab("profiles")}>Profiles</button>
          </div>

          {leftTab === "targets" ? (
            <section className="rail-section">
              <div className="source-panel">
                <div className="source-title">
                  <Cpu size={14} />
                  <span>Target Source</span>
                </div>
                <div className="source-toggle">
                  <button type="button" className={targetSource === "mock" ? "active" : ""} onClick={handleLoadMockTargets} disabled={nativeBusy}>
                    Mock
                  </button>
                  <button type="button" className={targetSource === "native" ? "active" : ""} onClick={handleLoadNativeTargets} disabled={nativeBusy}>
                    Native
                  </button>
                  <button type="button" title="Refresh current target source" onClick={targetSource === "native" ? handleLoadNativeTargets : handleLoadMockTargets} disabled={nativeBusy}>
                    <RefreshCcw size={13} />
                  </button>
                </div>
              </div>
              <div className="section-title">
                <Server size={14} />
                <span>Running Processes</span>
              </div>
              <div className="process-list">
                {targets.map((target) => (
                  <button
                    type="button"
                    className={`process-row ${target.status === "unsupported" ? "muted" : ""} ${selectedTargetPid === target.pid ? "selected" : ""}`}
                    key={`${target.pid}-${target.imageName}`}
                    aria-pressed={selectedTargetPid === target.pid}
                    onClick={() => setSelectedTargetPid(target.pid)}
                  >
                    <span className="process-icon">{target.imageName.slice(0, 1).toUpperCase()}</span>
                    <span className="process-main">
                      <strong>{target.imageName}</strong>
                      <small>{target.imagePath ?? "path unavailable"}</small>
                    </span>
                    <span className="process-meta">
                      <span>{target.pid}</span>
                      <span>{target.architecture}</span>
                    </span>
                  </button>
                ))}
              </div>
              <div className="target-actions-panel">
                <div className="section-title">
                  <GitBranch size={14} />
                  <span>Selected Target</span>
                </div>
                <div className="target-action-grid">
                  <label>PID</label>
                  <span>{selectedTarget?.pid ?? "none"}</span>
                  <label>Image</label>
                  <span>{selectedTarget?.imageName ?? "select a row"}</span>
                  <label>Architecture</label>
                  <span>{selectedTarget?.architecture ?? "unknown"}</span>
                  <label>Status</label>
                  <span>{selectedTarget?.status ?? "not selected"}</span>
                  <label>Eligibility</label>
                  <span className={targetBlockReason ? "eligibility-badge blocked" : "eligibility-badge ready"}>
                    {targetBlockReason ?? "same-bitness helper gate"}
                  </span>
                </div>

                <div className="action-subpanel">
                  <div className="action-subtitle">
                    <Activity size={13} />
                    <span>Bounded Attach</span>
                  </div>
                  <div className="action-controls">
                    <label htmlFor="attach-duration">Duration</label>
                    <input
                      id="attach-duration"
                      type="number"
                      min={250}
                      max={30000}
                      step={250}
                      value={attachDurationMs}
                      onChange={(event) => setAttachDurationMs(clampDurationMs(event.target.value, attachDurationMs))}
                    />
                    <button type="button" className="tool-button primary" onClick={handleAttachSelectedTarget} disabled={!canRunTargetAction}>
                      <Play size={13} />
                      <span>Attach Capture</span>
                    </button>
                  </div>
                  {attachResult ? (
                    <div className={attachResult.success ? "result-block success" : "result-block failure"}>
                      <div>PID {attachResult.targetProcessId}; attachPid={attachResult.attachProcessId ?? 0}</div>
                      <div>{attachResult.captureMode}; {attachResult.injectionMethod}; {attachResult.detachPolicy || "self-disable-no-unload"}</div>
                      <div>events={attachResult.capturedEvents.length}; dropped={attachResult.droppedEvents}; transport={attachResult.transportRecordsConsumed}/{attachResult.transportRecordsProduced}</div>
                      <div>{hookRestoreSummary(attachResult)}</div>
                      <div>{attachResult.operation}; subsystem={attachResult.subsystem}; win32={attachResult.win32ErrorCode}; {attachResult.message}</div>
                    </div>
                  ) : null}
                </div>

                <div className="action-subpanel">
                  <div className="action-subtitle">
                    <GitBranch size={13} />
                    <span>Process Tree</span>
                  </div>
                  <div className="action-controls tree-controls">
                    <label htmlFor="tree-duration">Duration</label>
                    <input
                      id="tree-duration"
                      type="number"
                      min={250}
                      max={30000}
                      step={250}
                      value={treeDurationMs}
                      onChange={(event) => setTreeDurationMs(clampDurationMs(event.target.value, treeDurationMs))}
                    />
                    <div className="policy-toggle" aria-label="Child attach policy">
                      <button type="button" className={childPolicy === "observe" ? "active" : ""} onClick={() => setChildPolicy("observe")} disabled={nativeBusy}>
                        Observe
                      </button>
                      <button type="button" className={childPolicy === "attach-supported" ? "active" : ""} onClick={() => setChildPolicy("attach-supported")} disabled={nativeBusy}>
                        Attach supported
                      </button>
                    </div>
                    <button type="button" className="tool-button primary" onClick={handleSuperviseSelectedTree} disabled={!canRunTargetAction}>
                      <Play size={13} />
                      <span>Supervise</span>
                    </button>
                  </div>
                  {processTreeResult ? (
                    <div className={processTreeResult.success ? "result-block success" : "result-block failure"}>
                      <div>root={processTreeResult.rootProcessId}; policy={processTreeResult.childPolicy}; duration={processTreeResult.durationMs}ms</div>
                      <div>children={processTreeSummary.childCount}; eligible={processTreeSummary.eligibleCount}; mutations={processTreeSummary.mutationAttemptedCount}</div>
                      <div>childAttach ok={processTreeSummary.attachSuccessCount}; fail={processTreeSummary.attachFailureCount}; events={processTreeSummary.capturedEventCount}; dropped={droppedCount}</div>
                      <div>{processTreeResult.operation}; subsystem={processTreeResult.subsystem}; win32={processTreeResult.win32ErrorCode}; {processTreeResult.message}</div>
                    </div>
                  ) : null}
                  {processTreeResult ? (
                    <div className="process-tree-table" aria-label="Process tree nodes">
                      <div className="process-tree-row header">
                        <span>PID</span>
                        <span>Image</span>
                        <span>Arch</span>
                        <span>Decision</span>
                      </div>
                      {processTreeResult.processNodes.map((node) => (
                        <div className="process-tree-row" key={`${node.processId}-${node.parentProcessId}`}>
                          <span>{node.processId}</span>
                          <span title={node.imagePath || node.imageName}>{node.imageName}</span>
                          <span>{node.architecture}</span>
                          <span title={`${node.eligibilityStatus}: ${node.message}`}>{node.policyDecision}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {processTreeResult && processTreeResult.policyDecisions.length > 0 ? (
                    <div className="policy-decision-list" aria-label="Child policy decisions">
                      {processTreeResult.policyDecisions.map((decision) => (
                        <div className="policy-decision-row" key={`${decision.processId}-${decision.decision}`}>
                          <span>{decision.processId}</span>
                          <strong>{decision.decision}</strong>
                          <small>{decision.mutationAttempted ? "mutation attempted" : "no mutation"}; {decision.reason}</small>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {processTreeResult && processTreeResult.childAttachResults.length > 0 ? (
                    <div className="child-attach-list" aria-label="Child attach summaries">
                      {processTreeResult.childAttachResults.map((capture) => (
                        <div className="child-attach-row" key={`${capture.operationId}-${capture.targetProcessId}`}>
                          <span>PID {capture.targetProcessId}</span>
                          <strong>{capture.success ? "attach ok" : "attach failed"}</strong>
                          <small>events={capture.capturedEvents.length}; dropped={capture.droppedEvents}; {hookRestoreSummary(capture)}</small>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
              <div className="controlled-launch">
                <div className="section-title">
                  <Rocket size={14} />
                  <span>Controlled Launch</span>
                </div>
                <div className="launch-grid">
                  <label>Sample target</label>
                  <span>knmon-sample-fileio.exe</span>
                  <label>Agent</label>
                  <span>{fileNameFromPath(captureResult?.agentPath ?? launchResult?.agentPath ?? "knmon-agent64.dll")}</span>
                  <label>Architecture</label>
                  <span>{captureResult?.architecture ?? launchResult?.architecture ?? "x64"} exact match</span>
                  <label>Injection</label>
                  <span>early-bird APC</span>
                  <label>Handshake</label>
                  <span>{captureResult ? (captureResult.handshake.received ? "HELLO received" : "not received") : launchResult ? (launchResult.handshake.received ? "HELLO received" : "not received") : "not launched"}</span>
                  <label>Captured rows</label>
                  <span>{captureResult ? captureResult.capturedEvents.length : 0}</span>
                  <label>Dropped</label>
                  <span>{captureResult ? captureResult.droppedEvents : droppedCount}</span>
                  <label>Transport</label>
                  <span>{captureResult ? captureResult.transportMode : "not active"}</span>
                  <label>Transport rows</label>
                  <span>{captureResult ? `${captureResult.transportRecordsConsumed}/${captureResult.transportRecordsProduced}` : "0/0"}</span>
                  <label>Hook avg</label>
                  <span>{captureResult ? `${captureResult.hookOverheadAvgUs} us avg` : "not measured"}</span>
                  <label>Session</label>
                  <span>{lastSession ? lastSession.sessionId || "latest-sample-fileio" : "not saved"}</span>
                </div>
                <div className="launch-actions">
                  <button type="button" className="tool-button primary" onClick={handleLaunchSample} disabled={nativeBusy}>
                    <Play size={14} />
                    <span>Launch Sample</span>
                  </button>
                  <button type="button" className="tool-button primary" onClick={handleCaptureSampleFileIo} disabled={nativeBusy}>
                    <Activity size={14} />
                    <span>Capture File I/O</span>
                  </button>
                  <button type="button" className="tool-button" onClick={handleCaptureAndSaveSession} disabled={nativeBusy}>
                    <Database size={14} />
                    <span>Capture And Save</span>
                  </button>
                  <button type="button" className="tool-button" onClick={handleReplayLastSession} disabled={nativeBusy}>
                    <FolderOpen size={14} />
                    <span>Replay Last</span>
                  </button>
                  <button type="button" className="tool-button" disabled title="Bounded sample capture owns target lifetime for this milestone; persistent terminate control is not implemented yet.">
                    <Square size={13} />
                    <span>Terminate</span>
                  </button>
                </div>
                {launchResult ? (
                  <div className={launchResult.success ? "launch-result success" : "launch-result failure"}>
                    PID {launchResult.targetProcessId} / {launchResult.injectionMethod} / {launchResult.message}
                  </div>
                ) : null}
                {captureResult ? (
                  <div className={captureResult.success ? "launch-result success" : "launch-result failure"}>
                    PID {captureResult.targetProcessId} / {captureResult.captureMode} / events={captureResult.capturedEvents.length} / {captureResult.message}
                  </div>
                ) : null}
                {lastSession ? (
                  <div className={lastSession.success ? "launch-result success" : "launch-result failure"}>
                    session {lastSession.sessionId || "latest-sample-fileio"} / events={lastSession.traceEventCount} / {lastSession.message}
                  </div>
                ) : null}
              </div>
            </section>
          ) : null}

          {leftTab === "apis" ? (
            <section className="rail-section">
              <div className="section-title">
                <Layers size={14} />
                <span>Capture Filter</span>
              </div>
              {renderApiTree(apiTree)}
            </section>
          ) : null}

          {leftTab === "profiles" ? (
            <section className="rail-section">
              <div className="section-title">
                <Database size={14} />
                <span>Capture Profiles</span>
              </div>
              <div className="profile-list">
                {captureProfiles.map((profile) => (
                  <button type="button" className="profile-row" key={profile.id}>
                    <strong>{profile.name}</strong>
                    <span>{profile.description}</span>
                    <small>{profile.enabledApis.length} APIs enabled</small>
                  </button>
                ))}
              </div>
            </section>
          ) : null}
        </aside>

        <section className="main-panel">
          <div className="trace-control">
            <div className="filter-box">
              <Search size={14} />
              <input
                type="search"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="Display filter: api/module/path/error/tag"
              />
            </div>
            <div className="mode-toggle">
              <button type="button" className={traceMode === "flat" ? "active" : ""} onClick={() => setTraceMode("flat")}>
                <Activity size={14} />
                <span>Flat</span>
              </button>
              <button type="button" className={traceMode === "call-tree" ? "active" : ""} onClick={() => setTraceMode("call-tree")}>
                <GitBranch size={14} />
                <span>Call Tree</span>
              </button>
            </div>
          </div>

          <div className="trace-table-wrap">
            <table className="trace-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>PID</th>
                  <th>TID</th>
                  <th>Module</th>
                  <th>API</th>
                  <th>Arguments</th>
                  <th>Return</th>
                  <th>Error</th>
                  <th>Duration</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((event) => (
                  <tr
                    key={event.eventId}
                    className={selectedEvent?.eventId === event.eventId ? "selected" : ""}
                    onClick={() => setSelectedEventId(event.eventId)}
                  >
                    <td>{event.eventId}</td>
                    <td>{(event.relativeTimeMs / 1000).toFixed(3)}s</td>
                    <td>{event.pid}</td>
                    <td>{event.tid}</td>
                    <td>{event.module}</td>
                    <td className="api-cell">{event.api}</td>
                    <td className="args-cell">{compactArgs(event)}</td>
                    <td>{event.returnValue}</td>
                    <td className={event.error ? "error-cell" : ""}>{event.error ? `${event.error.code} = ${event.error.message}` : ""}</td>
                    <td>{event.durationUs} us</td>
                    <td>
                      <div className="tag-list">
                        {event.tags.map((tag) => (
                          <span key={tag}>{tag}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="inspector">
            <div className="inspector-tabs">
              {inspectorTabs.map((tab) => (
                <button
                  type="button"
                  key={tab.id}
                  className={inspectorTab === tab.id ? "active" : ""}
                  onClick={() => setInspectorTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="inspector-body">
              {selectedEvent || inspectorTab === "output" ? (
                <>
                  {selectedEvent && inspectorTab === "parameters" ? (
                    <table className="detail-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Type</th>
                          <th>Name</th>
                          <th>Pre-call</th>
                          <th>Post-call</th>
                          <th>Decoded</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedEvent.arguments.map((argument) => (
                          <tr key={`${selectedEvent.eventId}-${argument.index}`}>
                            <td>{argument.index}</td>
                            <td>{argument.type}</td>
                            <td>{argument.name}</td>
                            <td>{argument.preCallValue}</td>
                            <td>{argument.postCallValue}</td>
                            <td>{argument.decodedValue}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : null}

                  {selectedEvent && inspectorTab === "buffer" ? (
                    <div className="buffer-view">
                      <div className="buffer-toolbar">
                        <HardDrive size={14} />
                        <span>{selectedEvent.bufferPreview ? "Hex Buffer 16 bytes" : "No buffer snapshot for this call"}</span>
                      </div>
                      <pre>{selectedEvent.bufferPreview ?? "buffer snapshot unavailable"}</pre>
                    </div>
                  ) : null}

                  {selectedEvent && inspectorTab === "stack" ? (
                    <div className="stack-list">
                      {selectedEvent.stack.map((frame, index) => (
                        <div className="stack-row" key={frame}>
                          <span>{index}</span>
                          <code>{frame}</code>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {selectedEvent && inspectorTab === "return" ? (
                    <div className="return-grid">
                      <label>Return Value</label>
                      <code>{selectedEvent.returnValue}</code>
                      <label>Error Source</label>
                      <code>{selectedEvent.error?.kind ?? "none"}</code>
                      <label>Error Code</label>
                      <code>{selectedEvent.error?.code ?? "0"}</code>
                      <label>Message</label>
                      <code>{selectedEvent.error?.message ?? "success"}</code>
                    </div>
                  ) : null}

                  {inspectorTab === "output" ? (
                    <div className="output-log">
                      <div><Braces size={14} /> schemaVersion={selectedEvent?.schemaVersion ?? "0.1.0"}</div>
                      <div><Filter size={14} /> backend={backendMode}; filter="{filter || "*"}"; mode={traceMode}</div>
                      <div><Database size={14} /> sessionBytes={formatBytes(sessionBytes)}; droppedEvents={droppedCount}</div>
                      {outputEvents.map((event) => (
                        <div key={`${event.timestampUtc}-${event.eventType}-${event.message}`}>
                          <Activity size={14} />
                          {event.eventType}: {event.operation}; win32={event.win32ErrorCode}; {event.message}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="empty-state">No event selected.</div>
              )}
            </div>
          </div>
        </section>
      </main>

      <footer className="statusbar">
        <span>State: {running ? "running" : "stopped"}</span>
        <span>Events: {events.length}</span>
        <span>Dropped: {droppedCount}</span>
        <span>Session: {formatBytes(sessionBytes)}</span>
        <span>Backend: {backendMode}</span>
        <span>Protocol: 0.1.0</span>
      </footer>
    </div>
  );
}

export default App;
