import {
  Activity,
  Braces,
  ChevronRight,
  CircleDot,
  Clock3,
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
  Plus,
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
  cancelNativeOperation,
  catalogNativeSessions,
  captureSampleFileIoEvents,
  captureSampleFileIoSession,
  drainNativeTraceBatches,
  launchSampleEarlyBirdCapture,
  listDaemonSessions,
  listNativeSessions,
  listNativeTargetProcesses,
  listNativeOperations,
  listTargetProcesses,
  queryNativeSessionCatalog,
  removeMissingNativeSessionCatalogEntries,
  replayLastSampleSession,
  replaySessionPath,
  startBackendSession,
  startDaemonSupervisedSession,
  startStreamingAttachSession,
  stopBackendSession,
  stopDaemonSession,
  stopNativeSession,
  superviseProcessTree
} from "./backend";
import { apiTree, captureProfiles, createMockFileIoEvent, initialTraceEvents } from "./mockData";
import { downloadJsonl, estimateSessionBytes } from "./session";
import type { AgentApiCallEvent, ApiNode, AuditEvent, BackendMode, CaptureResult, InspectorTab, LaunchResult, NativeOperation, NativeSession, NativeSessionCatalog, NativeSessionCatalogRow, NativeTraceBatch, ProcessTreeResult, SessionInfo, TargetProcess, TraceEvent } from "./types";
import {
  buildTraceIssueGroups,
  compileTraceQuery,
  matchesFreeTextFilter,
  operatorNeedsValue,
  traceQueryFieldOptions,
  traceQueryOperatorOptions
} from "./traceQuery";
import type { TraceIssueGroup, TraceQueryClause, TraceQueryField, TraceQueryMatchMode, TraceQueryOperator } from "./traceQuery";
import { buildTraceThreadGroups, buildTraceTimeline } from "./traceViews";
import type { TraceThreadGroup, TraceTimelineBucket } from "./traceViews";
import { computeVirtualTraceWindow } from "./virtualTrace";

type LeftTab = "targets" | "apis" | "profiles";
type TraceMode = "flat" | "call-tree" | "errors" | "threads" | "timeline";
type TargetSource = "mock" | "native";
type ChildPolicy = ProcessTreeResult["childPolicy"];

const inspectorTabs: Array<{ id: InspectorTab; label: string }> = [
  { id: "parameters", label: "Parameters" },
  { id: "buffer", label: "Buffer" },
  { id: "stack", label: "Call Stack" },
  { id: "return", label: "Return/Error" },
  { id: "output", label: "Output" }
];

const traceRowHeight = 27;
const traceOverscanRows = 6;

type ReplaySource =
  | { kind: "sample"; label: string; path: string; validationStatus: string }
  | { kind: "catalog"; label: string; path: string; validationStatus: string };

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

function isNativeOperationActive(operation: NativeOperation): boolean {
  return ["queued", "running", "cancel_requested", "stopping_agent", "draining"].includes(operation.state);
}

function isNativeSessionActive(session: NativeSession): boolean {
  return ["created", "starting", "running", "stop_requested", "stopping_agent", "draining"].includes(session.sessionState);
}

function isDaemonSession(session: NativeSession): boolean {
  return session.sessionKind.startsWith("daemon_") || session.daemonProcessId > 0;
}

function formatElapsedMs(value: number): string {
  return `${(value / 1000).toFixed(1)}s`;
}

function nextTraceEventId(events: TraceEvent[]): number {
  return events.reduce((maximum, event) => Math.max(maximum, event.eventId), 0) + 1;
}

function catalogRowLabel(row: NativeSessionCatalogRow): string {
  return row.targetImage || row.sessionId || fileNameFromPath(row.path);
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
  const [traceQueryMatchMode, setTraceQueryMatchMode] = useState<TraceQueryMatchMode>("all");
  const [traceQueryClauses, setTraceQueryClauses] = useState<TraceQueryClause[]>([]);
  const [durationThresholdUs, setDurationThresholdUs] = useState(100);
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
  const [nativeOperations, setNativeOperations] = useState<NativeOperation[]>([]);
  const [nativeSessions, setNativeSessions] = useState<NativeSession[]>([]);
  const [sessionCatalog, setSessionCatalog] = useState<NativeSessionCatalog | null>(null);
  const [catalogStateFilter, setCatalogStateFilter] = useState("all");
  const [catalogTargetFilter, setCatalogTargetFilter] = useState("");
  const [catalogLimit, setCatalogLimit] = useState(50);
  const [selectedCatalogPath, setSelectedCatalogPath] = useState("");
  const [replaySource, setReplaySource] = useState<ReplaySource | null>(null);
  const [traceScrollTop, setTraceScrollTop] = useState(0);
  const [traceViewportHeight, setTraceViewportHeight] = useState(0);
  const [outputEvents, setOutputEvents] = useState<AuditEvent[]>([
    makeAuditEvent("backend_ready", "mock_init", "Mock File I/O backend initialized.")
  ]);
  const nextEventId = useRef(initialTraceEvents.length + 1);
  const nextQueryClauseId = useRef(1);
  const streamBatchCursors = useRef<Record<string, number>>({});
  const traceScrollRef = useRef<HTMLDivElement | null>(null);

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

  useEffect(() => {
    const element = traceScrollRef.current;
    if (!element) {
      return undefined;
    }

    const updateViewportHeight = () => {
      setTraceViewportHeight(element.clientHeight);
    };

    updateViewportHeight();
    const observer = new ResizeObserver(updateViewportHeight);
    observer.observe(element);

    return () => {
      observer.disconnect();
    };
  }, []);

  function appendOutput(eventsToAppend: AuditEvent[]) {
    setOutputEvents((current) => [...eventsToAppend, ...current].slice(0, 80));
  }

  function createTraceQueryClause(template?: Partial<Omit<TraceQueryClause, "id">>): TraceQueryClause {
    const id = `q-${nextQueryClauseId.current}`;
    nextQueryClauseId.current += 1;

    return {
      id,
      field: template?.field ?? "api",
      operator: template?.operator ?? "contains",
      value: template?.value ?? ""
    };
  }

  function handleAddTraceQueryClause() {
    setTraceQueryClauses((current) => [...current, createTraceQueryClause()]);
  }

  function handleUpdateTraceQueryClause(id: string, patch: Partial<Omit<TraceQueryClause, "id">>) {
    setTraceQueryClauses((current) => current.map((clause) => {
      if (clause.id !== id) {
        return clause;
      }

      return {
        ...clause,
        ...patch
      };
    }));
  }

  function handleRemoveTraceQueryClause(id: string) {
    setTraceQueryClauses((current) => current.filter((clause) => clause.id !== id));
  }

  function handleClearTraceQuery() {
    setTraceQueryClauses([]);
    setFilter("");
    appendOutput([makeAuditEvent("trace_query_cleared", "trace_query", "Trace query and display filter cleared.")]);
  }

  function handleApplyIssueGroup(group: TraceIssueGroup) {
    const nextClauses = group.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    setSelectedEventId(group.eventIds[0] ?? 0);
    setInspectorTab(group.kind === "error" || group.kind === "module_api" ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_issue_filter_applied", "trace_issue_view", `${group.kind}; ${group.label}; events=${group.count}`)]);
  }

  function handleApplyThreadGroup(group: TraceThreadGroup) {
    const nextClauses = group.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    setSelectedEventId(group.eventIds[0] ?? 0);
    setInspectorTab(group.errorCount > 0 ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_thread_filter_applied", "trace_thread_view", `${group.threadLabel}; events=${group.eventCount}; spanMs=${group.spanMs}`)]);
  }

  function handleApplyTimelineBucket(bucket: TraceTimelineBucket) {
    const nextClauses = bucket.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    setSelectedEventId(bucket.eventIds[0] ?? 0);
    setInspectorTab(bucket.errorCount > 0 ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_timeline_filter_applied", "trace_timeline_view", `${formatElapsedMs(bucket.startRelativeTimeMs)}-${formatElapsedMs(bucket.endRelativeTimeMs)}; events=${bucket.eventCount}`)]);
  }

  function applySessionCatalog(catalog: NativeSessionCatalog) {
    setSessionCatalog(catalog);
    setSelectedCatalogPath((current) => {
      if (current && catalog.sessions.some((row) => row.path === current)) {
        return current;
      }

      return catalog.sessions[0]?.path ?? "";
    });
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

  function appendTraceBatches(batches: NativeTraceBatch[]) {
    if (batches.length === 0) {
      return;
    }

    batches.forEach((batch) => {
      appendCapturedEvents(batch.events, ["ui-stream", `batch:${batch.batchSequence}`]);
    });

    const latest = batches[batches.length - 1];
    setDroppedCount(latest.droppedEvents);
    streamBatchCursors.current[latest.sessionId] = latest.batchSequence;
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

  useEffect(() => {
    if (
      !nativeBusy &&
      nativeOperations.every((operation) => !isNativeOperationActive(operation)) &&
      nativeSessions.every((session) => !isNativeSessionActive(session))
    ) {
      return undefined;
    }

    let active = true;

    const refreshNativeOwnership = async () => {
      try {
        const [operations, sessions, daemonSessions] = await Promise.all([
          listNativeOperations(),
          listNativeSessions(),
          listDaemonSessions()
        ]);
        if (active) {
          setNativeOperations(operations);
          const daemonIds = new Set(daemonSessions.map((session) => session.sessionId));
          setNativeSessions([...daemonSessions, ...sessions.filter((session) => !daemonIds.has(session.sessionId))]);
        }
      } catch (error) {
        if (active) {
          const message = error instanceof Error ? error.message : String(error);
          appendOutput([makeAuditEvent("native_ownership_poll_failed", "list_native_sessions", message)]);
        }
      }
    };

    void refreshNativeOwnership();
    const timer = window.setInterval(() => {
      void refreshNativeOwnership();
    }, 500);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [nativeBusy, nativeOperations, nativeSessions]);

  const compiledTraceQuery = useMemo(
    () => compileTraceQuery(traceQueryClauses, traceQueryMatchMode),
    [traceQueryClauses, traceQueryMatchMode]
  );
  const invalidTraceQueryClauseIds = useMemo(
    () => new Set(compiledTraceQuery.invalidClauses.map((clause) => clause.id)),
    [compiledTraceQuery]
  );
  const issueGroups = useMemo(
    () => buildTraceIssueGroups(events, durationThresholdUs),
    [events, durationThresholdUs]
  );
  const visibleIssueGroups = useMemo(
    () => issueGroups.slice(0, 12),
    [issueGroups]
  );
  const threadGroups = useMemo(
    () => buildTraceThreadGroups(events, durationThresholdUs),
    [events, durationThresholdUs]
  );
  const visibleThreadGroups = useMemo(
    () => threadGroups.slice(0, 16),
    [threadGroups]
  );
  const timelineView = useMemo(
    () => buildTraceTimeline(events, durationThresholdUs),
    [events, durationThresholdUs]
  );
  const visibleTimelineBuckets = useMemo(
    () => timelineView.buckets.slice(0, 48),
    [timelineView]
  );
  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      return matchesFreeTextFilter(event, filter) && compiledTraceQuery.matches(event);
    });
  }, [events, filter, compiledTraceQuery]);

  const selectedTraceIndex = useMemo(
    () => filteredEvents.findIndex((event) => event.eventId === selectedEventId),
    [filteredEvents, selectedEventId]
  );
  const selectedEvent = selectedTraceIndex >= 0
    ? filteredEvents[selectedTraceIndex]
    : filteredEvents[0] ?? events.find((event) => event.eventId === selectedEventId) ?? events[0];
  const selectedTarget = selectedTargetPid === null ? null : targets.find((target) => target.pid === selectedTargetPid) ?? null;
  const targetBlockReason = targetEligibilityReason(selectedTarget, targetSource);
  const activeNativeOperation = nativeOperations.find(isNativeOperationActive) ?? null;
  const activeNativeSession = nativeSessions.find(isNativeSessionActive) ?? null;
  const canRunTargetAction = targetBlockReason === null && !nativeBusy && activeNativeOperation === null && activeNativeSession === null;
  const processTreeSummary = summarizeProcessTree(processTreeResult);
  const sessionBytes = useMemo(() => estimateSessionBytes(events), [events]);
  const selectedCatalogRow = sessionCatalog?.sessions.find((row) => row.path === selectedCatalogPath) ?? null;
  const virtualTraceWindow = useMemo(() => {
    return computeVirtualTraceWindow({
      itemCount: filteredEvents.length,
      rowHeight: traceRowHeight,
      viewportHeight: Math.max(0, traceViewportHeight - traceRowHeight),
      scrollTop: Math.max(0, traceScrollTop - traceRowHeight),
      overscan: traceOverscanRows
    });
  }, [filteredEvents.length, traceScrollTop, traceViewportHeight]);
  const visibleTraceEvents = useMemo(
    () => filteredEvents.slice(virtualTraceWindow.startIndex, virtualTraceWindow.endIndex),
    [filteredEvents, virtualTraceWindow.startIndex, virtualTraceWindow.endIndex]
  );

  useEffect(() => {
    const element = traceScrollRef.current;
    if (element) {
      element.scrollTop = 0;
    }

    setTraceScrollTop(0);
  }, [filter, traceMode, compiledTraceQuery]);

  useEffect(() => {
    const element = traceScrollRef.current;
    if (!element || selectedTraceIndex < 0) {
      return;
    }

    const selectedTop = traceRowHeight + selectedTraceIndex * traceRowHeight;
    const selectedBottom = selectedTop + traceRowHeight;
    if (selectedTop < element.scrollTop) {
      element.scrollTop = selectedTop;
      setTraceScrollTop(selectedTop);
    }
    else if (selectedBottom > element.scrollTop + element.clientHeight) {
      const nextScrollTop = Math.max(0, selectedBottom - element.clientHeight);
      element.scrollTop = nextScrollTop;
      setTraceScrollTop(nextScrollTop);
    }
  }, [selectedTraceIndex, filteredEvents.length]);

  useEffect(() => {
    if (!activeNativeSession) {
      return undefined;
    }

    if (isDaemonSession(activeNativeSession)) {
      return undefined;
    }

    let active = true;
    const sessionId = activeNativeSession.sessionId;

    const refreshTraceBatches = async () => {
      const cursor = streamBatchCursors.current[sessionId] ?? 0;
      try {
        const batches = await drainNativeTraceBatches(sessionId, cursor);
        if (active && batches.length > 0) {
          appendTraceBatches(batches);
        }
      } catch (error) {
        if (active) {
          const message = error instanceof Error ? error.message : String(error);
          appendOutput([makeAuditEvent("stream_batch_poll_failed", "drain_native_trace_batches", message)]);
        }
      }
    };

    void refreshTraceBatches();
    const timer = window.setInterval(() => {
      void refreshTraceBatches();
    }, 350);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [activeNativeSession?.sessionId]);

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
    setReplaySource(null);
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

      setEvents(result.traceEvents);
      nextEventId.current = nextTraceEventId(result.traceEvents);
      setSelectedEventId(result.traceEvents[result.traceEvents.length - 1]?.eventId ?? 0);
      setReplaySource({
        kind: "sample",
        label: result.session.sessionId || "latest-sample-fileio",
        path: result.session.sessionPath,
        validationStatus: result.session.success ? "valid" : "invalid"
      });

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setEvents([]);
      setSelectedEventId(0);
      nextEventId.current = 1;
      setReplaySource(null);
      appendOutput([makeAuditEvent("session_replay_blocked", "replay_last_sample_session", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleRefreshSessionCatalog() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_catalog_requested", "catalog_native_sessions", "Session catalog refresh requested from UI.")]);
      const catalog = await catalogNativeSessions();
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_refreshed" : "session_catalog_failed",
          "catalog_native_sessions",
          `${catalog.message}; sessions=${catalog.sessionCount}; valid=${catalog.validSessionCount}; invalid=${catalog.invalidSessionCount}; stored=${formatBytes(catalog.storedBytes)}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_blocked", "catalog_native_sessions", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleQuerySessionCatalog() {
    setNativeBusy(true);

    try {
      const queryState = catalogStateFilter === "all" ? "" : catalogStateFilter;
      appendOutput([makeAuditEvent("session_catalog_query_requested", "query_native_session_catalog", `state=${catalogStateFilter}; target=${catalogTargetFilter || "*"}; limit=${catalogLimit}`)]);
      const catalog = await queryNativeSessionCatalog(catalogLimit, queryState, catalogTargetFilter.trim());
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_queried" : "session_catalog_query_failed",
          "query_native_session_catalog",
          `${catalog.message}; sessions=${catalog.sessionCount}; valid=${catalog.validSessionCount}; invalid=${catalog.invalidSessionCount}; stored=${formatBytes(catalog.storedBytes)}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_query_blocked", "query_native_session_catalog", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleRemoveMissingCatalogEntries(dryRun: boolean) {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_catalog_prune_requested", "remove_missing_native_session_catalog_entries", dryRun ? "Dry-run missing-row prune requested from UI." : "Missing-row prune requested from UI.")]);
      const catalog = await removeMissingNativeSessionCatalogEntries(dryRun);
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_pruned" : "session_catalog_prune_failed",
          "remove_missing_native_session_catalog_entries",
          `${catalog.message}; dryRun=${catalog.dryRun}; mutation=${catalog.mutationAttempted}; missing=${catalog.missingSessionPaths.length}; sessions=${catalog.sessionCount}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_prune_blocked", "remove_missing_native_session_catalog_entries", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleReplayCatalogRow(row: NativeSessionCatalogRow) {
    setNativeBusy(true);
    setSelectedCatalogPath(row.path);

    try {
      appendOutput([makeAuditEvent("session_catalog_replay_requested", "replay_session_path", `Catalog replay requested for ${row.path}.`)]);
      const result = await replaySessionPath(row.path);
      setBackendMode(result.backendMode);
      setLastSession(result.session);
      setDroppedCount(result.session.droppedEvents);
      setEvents(result.traceEvents);
      nextEventId.current = nextTraceEventId(result.traceEvents);
      setSelectedEventId(result.traceEvents[result.traceEvents.length - 1]?.eventId ?? 0);
      setReplaySource({
        kind: "catalog",
        label: catalogRowLabel(row),
        path: row.path,
        validationStatus: row.validationStatus
      });
      appendOutput([
        makeAuditEvent(
          result.success ? "session_catalog_replayed" : "session_catalog_replay_failed",
          "replay_session_path",
          `${result.message}; path=${row.path}; traceEvents=${result.traceEvents.length}; dropped=${result.session.droppedEvents}; validation=${row.validationStatus}`,
          result.session.win32ErrorCode
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setEvents([]);
      setSelectedEventId(0);
      nextEventId.current = 1;
      setReplaySource({
        kind: "catalog",
        label: catalogRowLabel(row),
        path: row.path,
        validationStatus: row.validationStatus
      });
      appendOutput([makeAuditEvent("session_catalog_replay_blocked", "replay_session_path", message)]);
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

  async function handleStartStreamingAttach() {
    if (!selectedTarget || targetBlockReason) {
      appendOutput([makeAuditEvent("stream_attach_blocked", "start_streaming_attach_session", targetBlockReason ?? "No target selected.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("stream_attach_requested", "start_streaming_attach_session", `Streaming attach requested for PID ${selectedTarget.pid}.`)]);
      const session = await startStreamingAttachSession(selectedTarget.pid, attachDurationMs);
      streamBatchCursors.current[session.sessionId] = 0;
      setNativeSessions((current) => {
        const remaining = current.filter((item) => item.sessionId !== session.sessionId);
        return [session, ...remaining];
      });
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("stream_attach_blocked", "start_streaming_attach_session", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleStartDaemonSession() {
    if (!selectedTarget || targetBlockReason) {
      appendOutput([makeAuditEvent("daemon_session_blocked", "start_daemon_supervised_session", targetBlockReason ?? "No target selected.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("daemon_session_requested", "start_daemon_supervised_session", `Daemon-supervised attach requested for PID ${selectedTarget.pid}.`)]);
      const session = await startDaemonSupervisedSession(selectedTarget.pid, attachDurationMs);
      setNativeSessions((current) => {
        const remaining = current.filter((item) => item.sessionId !== session.sessionId);
        return [session, ...remaining];
      });
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("daemon_session_blocked", "start_daemon_supervised_session", message)]);
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

  async function handleCancelNativeOperation() {
    if (!activeNativeOperation) {
      return;
    }

    try {
      appendOutput([makeAuditEvent("operation_cancel_requested", "cancel_native_operation", activeNativeOperation.operationId)]);
      const operation = await cancelNativeOperation(activeNativeOperation.operationId);
      setNativeOperations((current) => {
        const remaining = current.filter((item) => item.operationId !== operation.operationId);
        return [operation, ...remaining];
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("operation_cancel_failed", "cancel_native_operation", message)]);
    } finally {
      setInspectorTab("output");
    }
  }

  async function handleStopNativeSession() {
    if (!activeNativeSession) {
      return;
    }

    try {
      appendOutput([makeAuditEvent("session_stop_requested", "stop_native_session", activeNativeSession.sessionId)]);
      const session = isDaemonSession(activeNativeSession)
        ? await stopDaemonSession(activeNativeSession.sessionId)
        : await stopNativeSession(activeNativeSession.sessionId);
      setNativeSessions((current) => {
        const remaining = current.filter((item) => item.sessionId !== session.sessionId);
        return [session, ...remaining];
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_stop_failed", "stop_native_session", message)]);
    } finally {
      setInspectorTab("output");
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
                {activeNativeOperation ? (
                  <div className="operation-strip">
                    <span>{activeNativeOperation.operationKind}</span>
                    <strong>{activeNativeOperation.state}</strong>
                    <span>{formatElapsedMs(activeNativeOperation.elapsedMs)} / {formatElapsedMs(activeNativeOperation.durationMs)}</span>
                    <button
                      type="button"
                      className="tool-button"
                      onClick={handleCancelNativeOperation}
                      disabled={activeNativeOperation.cancelRequested}
                      title="Cancel native operation"
                    >
                      <Square size={13} />
                      <span>Cancel</span>
                    </button>
                  </div>
                ) : null}
                {activeNativeSession ? (
                  <div className="session-strip">
                    <span>{activeNativeSession.sessionKind}</span>
                    <strong>{activeNativeSession.sessionState}</strong>
                    <span>{activeNativeSession.recordsStreamed} rec</span>
                    <span>{activeNativeSession.transportDroppedEvents} drop</span>
                    <span>{activeNativeSession.hostDroppedBatches} ui-drop</span>
                    <button
                      type="button"
                      className="tool-button"
                      onClick={handleStopNativeSession}
                      disabled={activeNativeSession.stopRequested}
                      title={activeNativeSession.recoveryAction || "Stop native session"}
                    >
                      <Square size={13} />
                      <span>Stop</span>
                    </button>
                    {activeNativeSession.helperProcessId ? <small>helper {activeNativeSession.helperProcessId}</small> : null}
                    {activeNativeSession.daemonProcessId ? <small>daemon {activeNativeSession.daemonProcessId}</small> : null}
                    {activeNativeSession.recoveryState ? <small>{activeNativeSession.recoveryState}/{activeNativeSession.recoveryReason || "n/a"}</small> : null}
                    {activeNativeSession.pruneEligible ? <small>prune {activeNativeSession.pruneReason || "eligible"}</small> : null}
                    {activeNativeSession.daemonProcessId ? <small>alive d={activeNativeSession.daemonAlive ? "yes" : "no"} w={activeNativeSession.sessionProcessAlive ? "yes" : "no"} t={activeNativeSession.targetAlive ? "yes" : "no"}</small> : null}
                    {activeNativeSession.knapmPath ? <small title={activeNativeSession.knapmPath}>{activeNativeSession.knapmPath}</small> : null}
                    {activeNativeSession.staleReason ? <small>{activeNativeSession.staleReason}</small> : null}
                    {activeNativeSession.lastError ? <small>{activeNativeSession.lastError}</small> : null}
                  </div>
                ) : null}

                <div className="action-subpanel">
                  <div className="action-subtitle">
                    <Activity size={13} />
                    <span>Bounded Attach</span>
                  </div>
                  <div className="action-controls attach-controls">
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
                    <button type="button" className="tool-button" onClick={handleStartStreamingAttach} disabled={!canRunTargetAction}>
                      <Activity size={13} />
                      <span>Start Stream</span>
                    </button>
                    <button type="button" className="tool-button" onClick={handleStartDaemonSession} disabled={!canRunTargetAction}>
                      <HardDrive size={13} />
                      <span>Daemon</span>
                    </button>
                  </div>
                  {attachResult ? (
                    <div className={attachResult.success ? "result-block success" : "result-block failure"}>
                      <div>PID {attachResult.targetProcessId}; attachPid={attachResult.attachProcessId ?? 0}</div>
                      <div>{attachResult.captureMode}; {attachResult.injectionMethod}; {attachResult.detachPolicy || "self-disable-no-unload"}</div>
                      <div>state={attachResult.attachState || "not_loaded"}; strategy={attachResult.attachStrategy || "load_library_initialize"}; loaded={attachResult.loadedAgentDetected ? "yes" : "no"}</div>
                      <div>op={attachResult.operationState || (attachResult.success ? "completed" : "failed")}; cancel={attachResult.cancelObserved ? attachResult.cancelStage || "observed" : "no"}; cleanup={attachResult.agentCleanupAttempted ? (attachResult.agentCleanupSucceeded ? "ok" : "failed") : "n/a"}</div>
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
                      <div>op={processTreeResult.operationState || (processTreeResult.success ? "completed" : "failed")}; cancel={processTreeResult.cancelObserved ? processTreeResult.cancelStage || "observed" : "no"}</div>
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
                  <button type="button" className="tool-button" onClick={handleRefreshSessionCatalog} disabled={nativeBusy}>
                    <RefreshCcw size={14} />
                    <span>Build Catalog</span>
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
                <div className="catalog-browser">
                  <div className="catalog-summary">
                    <Database size={14} />
                    <strong>{sessionCatalog ? `${sessionCatalog.sessionCount} sessions` : "Catalog"}</strong>
                    <span>{sessionCatalog ? `${sessionCatalog.validSessionCount} valid` : "not loaded"}</span>
                    <span>{sessionCatalog ? `${sessionCatalog.invalidSessionCount} invalid` : "0 invalid"}</span>
                    <span>{sessionCatalog ? `${formatBytes(sessionCatalog.storedBytes)} stored` : "0 B stored"}</span>
                  </div>
                  <div className="catalog-controls">
                    <label htmlFor="catalog-state">State</label>
                    <select
                      id="catalog-state"
                      value={catalogStateFilter}
                      onChange={(event) => setCatalogStateFilter(event.target.value)}
                    >
                      <option value="all">All</option>
                      <option value="valid">Valid</option>
                      <option value="invalid">Invalid</option>
                      <option value="finalized">Finalized</option>
                      <option value="partial">Partial</option>
                      <option value="failed">Failed</option>
                      <option value="stale">Stale</option>
                      <option value="recovery_required">Recovery</option>
                      <option value="malformed">Malformed</option>
                    </select>
                    <label htmlFor="catalog-target">Target</label>
                    <input
                      id="catalog-target"
                      type="search"
                      value={catalogTargetFilter}
                      onChange={(event) => setCatalogTargetFilter(event.target.value)}
                      placeholder="pid or image"
                    />
                    <label htmlFor="catalog-limit">Limit</label>
                    <input
                      id="catalog-limit"
                      type="number"
                      min={1}
                      max={5000}
                      value={catalogLimit}
                      onChange={(event) => setCatalogLimit(Math.min(5000, Math.max(1, Number.parseInt(event.target.value, 10) || 1)))}
                    />
                    <button type="button" className="tool-button" onClick={handleRefreshSessionCatalog} disabled={nativeBusy}>
                      <RefreshCcw size={13} />
                      <span>Rebuild</span>
                    </button>
                    <button type="button" className="tool-button" onClick={handleQuerySessionCatalog} disabled={nativeBusy}>
                      <Search size={13} />
                      <span>Query</span>
                    </button>
                    <button type="button" className="tool-button" onClick={() => handleRemoveMissingCatalogEntries(true)} disabled={nativeBusy}>
                      <Trash2 size={13} />
                      <span>Dry</span>
                    </button>
                    <button type="button" className="tool-button danger" onClick={() => handleRemoveMissingCatalogEntries(false)} disabled={nativeBusy}>
                      <Trash2 size={13} />
                      <span>Prune</span>
                    </button>
                  </div>
                  {sessionCatalog && sessionCatalog.sessions.length > 0 ? (
                    <div className="catalog-row-list" aria-label="Replay catalog rows">
                      {sessionCatalog.sessions.map((row) => (
                        <div className={selectedCatalogPath === row.path ? "catalog-browser-row selected" : "catalog-browser-row"} key={row.contentIdentity || row.path}>
                          <button type="button" className="catalog-row-main" title={row.path} onClick={() => setSelectedCatalogPath(row.path)}>
                            <strong>{catalogRowLabel(row)}</strong>
                            <span>PID {row.targetProcessId || "n/a"} / {row.targetArchitecture || "unknown"}</span>
                            <span>{row.sessionId || "session n/a"}</span>
                            <span>{row.validationStatus}</span>
                            <span>{row.recoveryState || row.writerState || "n/a"}</span>
                            <span>{row.compression || "none"}</span>
                            <span>{row.traceEventCount} ev</span>
                            <span>{formatBytes(row.storedBytes)} / {formatBytes(row.uncompressedBytes)}</span>
                            <span>{row.lastValidatedUtc || "not validated"}</span>
                            <small>{row.path}</small>
                          </button>
                          <button type="button" className="tool-button" onClick={() => handleReplayCatalogRow(row)} disabled={nativeBusy}>
                            <FolderOpen size={13} />
                            <span>Replay</span>
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="catalog-empty">No catalog rows loaded.</div>
                  )}
                  {selectedCatalogRow ? (
                    <div className="catalog-selected" title={selectedCatalogRow.path}>
                      selected {catalogRowLabel(selectedCatalogRow)} / {selectedCatalogRow.validationStatus} / {selectedCatalogRow.recoveryState || selectedCatalogRow.writerState || "n/a"}
                    </div>
                  ) : null}
                </div>
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
              <button type="button" className={traceMode === "errors" ? "active" : ""} onClick={() => setTraceMode("errors")}>
                <Filter size={14} />
                <span>Errors</span>
              </button>
              <button type="button" className={traceMode === "threads" ? "active" : ""} onClick={() => setTraceMode("threads")}>
                <GitBranch size={14} />
                <span>Threads</span>
              </button>
              <button type="button" className={traceMode === "timeline" ? "active" : ""} onClick={() => setTraceMode("timeline")}>
                <Clock3 size={14} />
                <span>Timeline</span>
              </button>
            </div>
            <div className="trace-stats">
              <span>{filteredEvents.length}/{events.length} rows</span>
              <span>DOM {visibleTraceEvents.length}</span>
              {compiledTraceQuery.activeClauseCount > 0 ? <span>{compiledTraceQuery.activeClauseCount} query</span> : null}
              {compiledTraceQuery.invalidClauses.length > 0 ? <span>{compiledTraceQuery.invalidClauses.length} invalid</span> : null}
              {replaySource ? <span title={replaySource.path}>Replay {replaySource.label} / {replaySource.validationStatus}</span> : null}
            </div>
          </div>

          <div className="query-panel">
            <div className="query-header">
              <div className="query-title">
                <Filter size={14} />
                <strong>Trace Query</strong>
                <span>{traceQueryMatchMode}; {compiledTraceQuery.activeClauseCount} active; {compiledTraceQuery.invalidClauses.length} invalid</span>
              </div>
              <div className="query-actions">
                <div className="mini-segmented" aria-label="Trace query match mode">
                  <button type="button" className={traceQueryMatchMode === "all" ? "active" : ""} onClick={() => setTraceQueryMatchMode("all")}>All</button>
                  <button type="button" className={traceQueryMatchMode === "any" ? "active" : ""} onClick={() => setTraceQueryMatchMode("any")}>Any</button>
                </div>
                <button type="button" className="tool-button" onClick={handleAddTraceQueryClause}>
                  <Plus size={13} />
                  <span>Add</span>
                </button>
                <button type="button" className="tool-button" onClick={handleClearTraceQuery}>
                  <Trash2 size={13} />
                  <span>Clear</span>
                </button>
              </div>
            </div>
            {traceQueryClauses.length > 0 ? (
              <div className="query-clause-list">
                {traceQueryClauses.map((clause, index) => {
                  const invalidReason = compiledTraceQuery.invalidClauses.find((invalidClause) => invalidClause.id === clause.id)?.reason ?? "";
                  const needsValue = operatorNeedsValue(clause.operator);

                  return (
                    <div className={invalidTraceQueryClauseIds.has(clause.id) ? "query-clause-row invalid" : "query-clause-row"} key={clause.id}>
                      <span>{index + 1}</span>
                      <select
                        value={clause.field}
                        onChange={(event) => handleUpdateTraceQueryClause(clause.id, { field: event.target.value as TraceQueryField })}
                      >
                        {traceQueryFieldOptions.map((option) => (
                          <option value={option.id} key={option.id}>{option.label}</option>
                        ))}
                      </select>
                      <select
                        value={clause.operator}
                        onChange={(event) => handleUpdateTraceQueryClause(clause.id, { operator: event.target.value as TraceQueryOperator })}
                      >
                        {traceQueryOperatorOptions.map((option) => (
                          <option value={option.id} key={option.id}>{option.label}</option>
                        ))}
                      </select>
                      <input
                        type={clause.field === "pid" || clause.field === "tid" || clause.field === "relativeTimeMs" || clause.field === "durationUs" ? "number" : "text"}
                        value={clause.value}
                        disabled={!needsValue}
                        onChange={(event) => handleUpdateTraceQueryClause(clause.id, { value: event.target.value })}
                        placeholder={needsValue ? "value" : ""}
                      />
                      <small>{invalidReason ? `${invalidReason}; ignored` : "active"}</small>
                      <button type="button" className="tool-button danger" onClick={() => handleRemoveTraceQueryClause(clause.id)}>
                        <Trash2 size={13} />
                      </button>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="query-empty">No structured clauses.</div>
            )}
            {traceMode === "errors" ? (
              <div className="issue-panel">
                <div className="issue-toolbar">
                  <div className="query-title">
                    <Activity size={14} />
                    <strong>Issue Groups</strong>
                    <span>{issueGroups.length} groups</span>
                  </div>
                  <label htmlFor="duration-threshold">Slow us</label>
                  <input
                    id="duration-threshold"
                    type="number"
                    min={1}
                    max={60000000}
                    value={durationThresholdUs}
                    onChange={(event) => setDurationThresholdUs(Math.min(60000000, Math.max(1, Number.parseInt(event.target.value, 10) || 1)))}
                  />
                </div>
                {visibleIssueGroups.length > 0 ? (
                  <div className="issue-group-list">
                    {visibleIssueGroups.map((group) => (
                      <button type="button" className={`issue-group ${group.kind}`} key={group.id} onClick={() => handleApplyIssueGroup(group)}>
                        <span>{group.kind}</span>
                        <strong>{group.label}</strong>
                        <em>{group.count}</em>
                        <small>{group.detail}</small>
                        <small>{group.samples.map((sample) => `#${sample.eventId} ${sample.module}!${sample.api}`).join("; ")}</small>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="query-empty">No error, decode, or slow-call groups.</div>
                )}
              </div>
            ) : null}
            {traceMode === "threads" ? (
              <div className="analysis-panel">
                <div className="issue-toolbar">
                  <div className="query-title">
                    <GitBranch size={14} />
                    <strong>Thread Groups</strong>
                    <span>{threadGroups.length} groups; top {visibleThreadGroups.length}</span>
                  </div>
                  <label htmlFor="thread-duration-threshold">Slow us</label>
                  <input
                    id="thread-duration-threshold"
                    type="number"
                    min={1}
                    max={60000000}
                    value={durationThresholdUs}
                    onChange={(event) => setDurationThresholdUs(Math.min(60000000, Math.max(1, Number.parseInt(event.target.value, 10) || 1)))}
                  />
                </div>
                {visibleThreadGroups.length > 0 ? (
                  <div className="thread-group-list">
                    {visibleThreadGroups.map((group) => (
                      <button
                        type="button"
                        className={[
                          "analysis-group",
                          "thread",
                          group.errorCount > 0 ? "has-error" : "",
                          group.decodeFailureCount > 0 ? "has-decode" : "",
                          group.slowCallCount > 0 ? "has-slow" : ""
                        ].filter(Boolean).join(" ")}
                        key={group.id}
                        onClick={() => handleApplyThreadGroup(group)}
                      >
                        <span>PID {group.pid}</span>
                        <strong>{group.threadLabel}</strong>
                        <em>{group.eventCount}</em>
                        <small>{formatElapsedMs(group.firstRelativeTimeMs)}-{formatElapsedMs(group.lastRelativeTimeMs)} / span {formatElapsedMs(group.spanMs)}</small>
                        <small>err={group.errorCount}; decode={group.decodeFailureCount}; slow={group.slowCallCount}</small>
                        <small>api={group.topApis.map((item) => `${item.value}:${item.count}`).join(", ") || "n/a"}</small>
                        <small>mod={group.topModules.map((item) => `${item.value}:${item.count}`).join(", ") || "n/a"}</small>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="query-empty">No thread groups.</div>
                )}
              </div>
            ) : null}
            {traceMode === "timeline" ? (
              <div className="analysis-panel">
                <div className="issue-toolbar">
                  <div className="query-title">
                    <Clock3 size={14} />
                    <strong>Timeline Buckets</strong>
                    <span>{timelineView.buckets.length} buckets; size {formatElapsedMs(timelineView.bucketSizeMs)}</span>
                  </div>
                  <label htmlFor="timeline-duration-threshold">Slow us</label>
                  <input
                    id="timeline-duration-threshold"
                    type="number"
                    min={1}
                    max={60000000}
                    value={durationThresholdUs}
                    onChange={(event) => setDurationThresholdUs(Math.min(60000000, Math.max(1, Number.parseInt(event.target.value, 10) || 1)))}
                  />
                </div>
                {visibleTimelineBuckets.length > 0 ? (
                  <div className="timeline-bucket-list">
                    {visibleTimelineBuckets.map((bucket) => (
                      <button
                        type="button"
                        className={[
                          "analysis-group",
                          "timeline",
                          bucket.errorCount > 0 ? "has-error" : "",
                          bucket.decodeFailureCount > 0 ? "has-decode" : "",
                          bucket.slowCallCount > 0 ? "has-slow" : ""
                        ].filter(Boolean).join(" ")}
                        key={bucket.id}
                        onClick={() => handleApplyTimelineBucket(bucket)}
                      >
                        <span>{formatElapsedMs(bucket.startRelativeTimeMs)}</span>
                        <strong>{formatElapsedMs(bucket.startRelativeTimeMs)}-{formatElapsedMs(bucket.endRelativeTimeMs)}</strong>
                        <em>{bucket.eventCount}</em>
                        <small>err={bucket.errorCount}; decode={bucket.decodeFailureCount}; slow={bucket.slowCallCount}</small>
                        <small>api={bucket.dominantApi || "n/a"}; mod={bucket.dominantModule || "n/a"}</small>
                        <small>{bucket.samples.map((sample) => `#${sample.eventId} ${sample.module}!${sample.api}`).join("; ")}</small>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="query-empty">No timeline buckets.</div>
                )}
              </div>
            ) : null}
          </div>

          <div
            className="trace-table-wrap"
            ref={traceScrollRef}
            onScroll={(event) => setTraceScrollTop(event.currentTarget.scrollTop)}
          >
            <table className="trace-table trace-table-head">
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
            </table>
            <div className="trace-virtual-body" style={{ height: virtualTraceWindow.totalHeight }}>
              <div className="trace-virtual-window" style={{ transform: `translateY(${virtualTraceWindow.offsetTop}px)` }}>
                {visibleTraceEvents.map((event, index) => (
                  <button
                    type="button"
                    key={event.eventId}
                    className={[
                      "trace-virtual-row",
                      selectedEvent?.eventId === event.eventId ? "selected" : "",
                      (virtualTraceWindow.startIndex + index) % 2 === 1 ? "alt" : ""
                    ].filter(Boolean).join(" ")}
                    style={{ height: traceRowHeight }}
                    onClick={() => setSelectedEventId(event.eventId)}
                  >
                    <span>{event.eventId}</span>
                    <span>{(event.relativeTimeMs / 1000).toFixed(3)}s</span>
                    <span>{event.pid}</span>
                    <span>{event.tid}</span>
                    <span>{event.module}</span>
                    <span className="api-cell">{event.api}</span>
                    <span className="args-cell">{compactArgs(event)}</span>
                    <span>{event.returnValue}</span>
                    <span className={event.error ? "error-cell" : ""}>{event.error ? `${event.error.code} = ${event.error.message}` : ""}</span>
                    <span>{event.durationUs} us</span>
                    <span className="tag-list">
                      {event.tags.map((tag) => (
                        <span key={tag}>{tag}</span>
                      ))}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            {filteredEvents.length === 0 ? <div className="trace-empty">No trace events match the current filter or query.</div> : null}
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
                      <div><Filter size={14} /> queryMode={traceQueryMatchMode}; activeClauses={compiledTraceQuery.activeClauseCount}; invalidClauses={compiledTraceQuery.invalidClauses.length}; filteredRows={filteredEvents.length}</div>
                      <div><Database size={14} /> sessionBytes={formatBytes(sessionBytes)}; droppedEvents={droppedCount}</div>
                      {replaySource ? <div><FolderOpen size={14} /> replay={replaySource.kind}; status={replaySource.validationStatus}; path={replaySource.path}</div> : null}
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
