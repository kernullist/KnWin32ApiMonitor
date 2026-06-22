import {
  Activity,
  AlertTriangle,
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
  RefreshCcw,
  Rocket,
  Search,
  Server,
  Square,
  Trash2
} from "lucide-react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, PointerEvent as ReactPointerEvent } from "react";
import {
  attachTargetProcessCapture,
  buildNativeSessionCatalogIndex,
  buildNativeTraceIndex,
  cancelNativeOperation,
  catalogNativeSessions,
  drainNativeTraceBatches,
  getNativeHelperArchitecture,
  listDaemonSessions,
  listNativeSessions,
  listNativeTargetProcesses,
  listNativeOperations,
  queryTargetBinaryArchitecture,
  queryNativeSessionCatalog,
  queryNativeSessionCatalogIndex,
  queryNativeTraceIndex,
  removeMissingNativeSessionCatalogIndexEntries,
  removeMissingNativeSessionCatalogEntries,
  removeMissingNativeTraceIndexEntries,
  replaySessionPath,
  startDaemonSupervisedSession,
  startLaunchMonitorSession,
  startStreamingAttachSession,
  stopDaemonSession,
  stopNativeSession,
  superviseProcessTree
} from "./backend";
import { apiCatalogEntries, apiTree, captureProfiles } from "./catalogData";
import { downloadJsonl, estimateSessionBytes } from "./session";
import type { AgentApiCallEvent, ApiNode, AuditEvent, BackendMode, CaptureResult, InspectorTab, NativeOperation, NativeSession, NativeSessionCatalog, NativeSessionCatalogRow, NativeTraceBatch, NativeTraceIndex, NativeTraceIndexEvent, ProcessTreeResult, SessionInfo, TargetProcess, TraceEvent } from "./types";
import {
  buildTraceIssueGroups,
  compileTraceQuery,
  matchesFreeTextFilter,
} from "./traceQuery";
import type { TraceIssueGroup, TraceQueryClause, TraceQueryMatchMode } from "./traceQuery";
import { buildTraceHighlightState } from "./traceHighlights";
import type { TraceHighlightSummary } from "./traceHighlights";
import { traceDisplayEventLimit } from "./traceIngestConfig";
import { buildTraceThreadGroups, buildTraceTimeline } from "./traceViews";
import type { TraceThreadGroup, TraceTimelineBucket } from "./traceViews";
import { computeVirtualTraceWindow } from "./virtualTrace";

type LeftTab = "targets" | "apis" | "profiles";
type TraceMode = "flat" | "call-tree" | "errors" | "threads" | "timeline";
type ChildPolicy = ProcessTreeResult["childPolicy"];
type NativeArchitecture = "x64" | "x86" | "unknown";

const inspectorTabs: Array<{ id: InspectorTab; label: string }> = [
  { id: "parameters", label: "Parameters" },
  { id: "buffer", label: "Buffer" },
  { id: "stack", label: "Call Stack" },
  { id: "return", label: "Return/Error" },
  { id: "output", label: "Output" }
];

const traceRowHeight = 27;
const traceOverscanRows = 6;
const boundedCaptureMaxDurationMs = 30000;
const minInspectorHeight = 170;
const maxInspectorHeight = 620;

type ColumnConfig = {
  id: string;
  label: string;
  width: number;
  minWidth: number;
};

const traceColumns: ColumnConfig[] = [
  { id: "event", label: "#", width: 52, minWidth: 42 },
  { id: "time", label: "Time", width: 72, minWidth: 58 },
  { id: "pid", label: "PID", width: 70, minWidth: 52 },
  { id: "tid", label: "TID", width: 70, minWidth: 52 },
  { id: "module", label: "Module", width: 116, minWidth: 84 },
  { id: "api", label: "API", width: 126, minWidth: 96 },
  { id: "arguments", label: "Arguments", width: 300, minWidth: 170 },
  { id: "return", label: "Return", width: 142, minWidth: 96 },
  { id: "error", label: "Error", width: 185, minWidth: 120 },
  { id: "duration", label: "Duration", width: 82, minWidth: 72 },
  { id: "tags", label: "Tags", width: 150, minWidth: 92 }
];

const detailColumns: ColumnConfig[] = [
  { id: "index", label: "#", width: 44, minWidth: 36 },
  { id: "type", label: "Type", width: 150, minWidth: 90 },
  { id: "name", label: "Name", width: 190, minWidth: 110 },
  { id: "pre", label: "Pre-call", width: 230, minWidth: 140 },
  { id: "post", label: "Post-call", width: 230, minWidth: 140 },
  { id: "decoded", label: "Decoded", width: 260, minWidth: 150 }
];

type ReplaySource =
  | { kind: "catalog"; label: string; path: string; validationStatus: string };

type CapturedEventChunk = {
  events: AgentApiCallEvent[];
  contextTags: string[];
};

type TraceIngestCommand =
  | { type: "reset" }
  | { type: "replace"; events: TraceEvent[]; selectedEventId?: number }
  | { type: "enqueue-events"; chunks: CapturedEventChunk[] }
  | { type: "enqueue-batches"; batches: NativeTraceBatch[] };

type TraceIngestSnapshot = {
  type: "snapshot";
  events: TraceEvent[];
  totalCapturedEvents: number;
  selectedEventId: number;
  processedEvents: number;
};

type ProcessExitNotice = {
  sessionId: string;
  sessionKind: string;
  targetProcessId: number;
  sessionState: string;
  observedUtc: string;
  message: string;
};

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / 1024 / 1024).toFixed(2)} MB`;
}

type ApiNodeCheckState = "checked" | "unchecked" | "mixed";

type ApiTreeCheckboxProps = {
  state: ApiNodeCheckState;
  onChange: () => void;
  label: string;
  disabled?: boolean;
};

function collectApiLeafKeys(nodes: ApiNode[]): string[] {
  const keys: string[] = [];

  for (const node of nodes) {
    if (node.children && node.children.length > 0) {
      keys.push(...collectApiLeafKeys(node.children));
    }
    else if (node.selectionKey) {
      keys.push(node.selectionKey);
    }
  }

  return keys;
}

function getApiNodeCheckState(node: ApiNode, selectedKeys: Set<string>): ApiNodeCheckState {
  const leafKeys = collectApiLeafKeys([node]);
  if (leafKeys.length === 0) {
    return "unchecked";
  }

  const selectedCount = leafKeys.filter((key) => selectedKeys.has(key)).length;
  if (selectedCount === 0) {
    return "unchecked";
  }

  return selectedCount === leafKeys.length ? "checked" : "mixed";
}

function countSelectedApiLeafKeys(nodes: ApiNode[], selectedKeys: Set<string>): number {
  return collectApiLeafKeys(nodes).filter((key) => selectedKeys.has(key)).length;
}

function ApiTreeCheckbox({ state, onChange, label, disabled = false }: ApiTreeCheckboxProps): JSX.Element {
  const checkboxRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (checkboxRef.current) {
      checkboxRef.current.indeterminate = state === "mixed";
    }
  }, [state]);

  return (
    <input
      ref={checkboxRef}
      type="checkbox"
      checked={state === "checked"}
      aria-checked={state === "mixed" ? "mixed" : state === "checked"}
      aria-label={label}
      disabled={disabled}
      onChange={onChange}
    />
  );
}

function renderApiTree(
  nodes: ApiNode[],
  selectedKeys: Set<string>,
  expandedNodes: Set<string>,
  onToggleNode: (node: ApiNode) => void,
  onToggleExpanded: (nodeId: string) => void,
  disabled: boolean,
  depth = 0
): JSX.Element {
  return (
    <div className="tree-group">
      {nodes.map((node) => {
        const checkState = getApiNodeCheckState(node, selectedKeys);
        const expanded = expandedNodes.has(node.id);
        const selectedCount = node.children ? countSelectedApiLeafKeys([node], selectedKeys) : checkState === "checked" ? 1 : 0;
        const totalCount = node.children ? collectApiLeafKeys([node]).length : 1;

        return (
          <div key={node.id}>
            <div className="tree-row" style={{ paddingLeft: 8 + depth * 16 }}>
              {node.children ? (
                <button
                  type="button"
                  className={expanded ? "tree-caret expanded" : "tree-caret"}
                  aria-label={expanded ? `Collapse ${node.label}` : `Expand ${node.label}`}
                  onClick={() => onToggleExpanded(node.id)}
                >
                  <ChevronRight size={13} />
                </button>
              ) : (
                <span className="tree-leaf" />
              )}
              <ApiTreeCheckbox
                state={checkState}
                label={`Monitor ${node.label}`}
                disabled={disabled}
                onChange={() => onToggleNode(node)}
              />
              <FileText size={14} className={checkState !== "unchecked" ? "tree-icon enabled" : "tree-icon"} />
              <span title={node.selectionKey ?? node.label}>{node.label}</span>
              <small>{node.children ? `${selectedCount}/${totalCount}` : node.module}</small>
            </div>
            {node.children && expanded ? renderApiTree(
              node.children,
              selectedKeys,
              expandedNodes,
              onToggleNode,
              onToggleExpanded,
              disabled,
              depth + 1
            ) : null}
          </div>
        );
      })}
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

function clampDurationMs(value: string | number, fallback: number, maximum = boundedCaptureMaxDurationMs): number {
  const parsed = typeof value === "number" ? value : Number.parseInt(value, 10);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.min(maximum, Math.max(250, Math.trunc(parsed)));
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

function readStringField(record: Record<string, unknown>, name: string): string {
  const value = record[name];
  return typeof value === "string" ? value : "";
}

function readBooleanField(record: Record<string, unknown>, name: string): boolean {
  return record[name] === true;
}

function resolverPointerOutputEvents(result: CaptureResult): AuditEvent[] {
  return result.agentMessages
    .map((message) => getRecord(message))
    .filter((message): message is Record<string, unknown> =>
      message?.messageType === "resolver_pointer_instrumented" ||
      message?.messageType === "resolver_pointer_candidate" ||
      message?.messageType === "resolver_pointer_unsupported"
    )
    .map((message) => {
      const messageType = readStringField(message, "messageType");
      const classification = readStringField(message, "classification")
        || (messageType === "resolver_pointer_instrumented" ? "instrumented" : (messageType === "resolver_pointer_candidate" ? "candidate" : "unsupported"));
      const resolverApi = readStringField(message, "resolverApi") || "resolver";
      const requestedModule = readStringField(message, "requestedModule");
      const requestedName = readStringField(message, "requestedName");
      const lookupKind = readStringField(message, "lookupKind");
      const requestedOrdinal = readNumberField(message, "requestedOrdinal");
      const requestedSymbol = lookupKind === "ordinal"
        ? `ordinal:${requestedOrdinal ?? 0}`
        : (requestedName || "<unnamed>");
      const targetModule = readStringField(message, "targetModule");
      const targetRvaHex = readStringField(message, "targetRvaHex");
      const definitionName = readStringField(message, "definitionName");
      const definitionApiId = readNumberField(message, "definitionApiId");
      const reason = readStringField(message, "reason");
      const instrumented = readBooleanField(message, "instrumented");
      const replacementPointer = readStringField(message, "replacementPointer");
      const instrumentationReason = readStringField(message, "instrumentationReason");
      const mapped = definitionName ? `; apiId=${definitionApiId ?? 0} ${definitionName}` : "";
      const target = targetModule ? ` -> ${targetModule}${targetRvaHex ? `+${targetRvaHex}` : ""}` : "";
      const replacement = instrumented && replacementPointer ? `; replacement=${replacementPointer}` : "";
      const instrumentation = instrumentationReason ? `; instrumentationReason=${instrumentationReason}` : "";
      const source = `${requestedModule ? `${requestedModule}!` : ""}${requestedSymbol}`;
      const messageText = `${classification} via ${resolverApi}: ${source}${target}${mapped}; reason=${reason || "none"}${replacement}${instrumentation}; instrumented=${instrumented ? "true" : "false"}`;

      return makeAuditEvent(messageType, "resolver_pointer_classification", messageText);
    });
}

function captureResultOutputEvents(result: CaptureResult, fallbackType: string): AuditEvent[] {
  const resolverEvents = resolverPointerOutputEvents(result);
  if (result.auditEvents.length > 0 || resolverEvents.length > 0) {
    return [...resolverEvents, ...result.auditEvents];
  }

  return [makeAuditEvent(fallbackType, result.operation, result.message, result.win32ErrorCode)];
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

function resolverPointerCountSummary(result: CaptureResult | null): string {
  if (!result) {
    return "resolver=0/0";
  }

  return `resolver=${result.resolverPointerCandidates ?? 0}/${result.resolverPointerUnsupported ?? 0}`;
}

function includesNormalized(value: string | number | undefined | null, normalizedNeedle: string): boolean {
  if (value === undefined || value === null) {
    return false;
  }

  return String(value).toLowerCase().includes(normalizedNeedle);
}

function argumentMatchesQuickFilter(event: TraceEvent, normalizedNeedle: string): boolean {
  return event.arguments.some((argument) => {
    return [
      argument.type,
      argument.name,
      argument.preCallValue,
      argument.postCallValue,
      argument.rawValue,
      argument.decodedValue,
      argument.decodeStatus
    ].some((value) => includesNormalized(value, normalizedNeedle));
  });
}

function matchesQuickTraceFilters(event: TraceEvent, apiFilter: string, moduleFilter: string, parameterFilter: string): boolean {
  const normalizedApi = apiFilter.trim().toLowerCase();
  const normalizedModule = moduleFilter.trim().toLowerCase();
  const normalizedParameter = parameterFilter.trim().toLowerCase();

  if (normalizedApi && !includesNormalized(event.api, normalizedApi)) {
    return false;
  }

  if (normalizedModule && !includesNormalized(event.module, normalizedModule)) {
    return false;
  }

  if (normalizedParameter && !argumentMatchesQuickFilter(event, normalizedParameter)) {
    return false;
  }

  return true;
}

function normalizeNativeArchitecture(value: string): NativeArchitecture {
  return value === "x64" || value === "x86" ? value : "unknown";
}

function toolLabelForArchitecture(architecture: NativeArchitecture): string {
  if (architecture === "x86") {
    return "Win32/x86 KN Win32 API Monitor";
  }

  if (architecture === "x64") {
    return "x64 KN Win32 API Monitor";
  }

  return "matching-bitness KN Win32 API Monitor";
}

function architectureMismatchMessage(targetArchitecture: NativeArchitecture, helperArchitecture: NativeArchitecture): string {
  return `Target architecture ${targetArchitecture} does not match this ${helperArchitecture} build. Run the ${toolLabelForArchitecture(targetArchitecture)} tool to monitor this target.`;
}

function targetEligibilityReason(target: TargetProcess | null, helperArchitecture: NativeArchitecture): string | null {
  if (!target) {
    return "Select a target row.";
  }

  if (target.status !== "available") {
    return `Target status is ${target.status}.`;
  }

  if (target.architecture !== "x64" && target.architecture !== "x86") {
    return `Architecture ${target.architecture} is unsupported.`;
  }

  if (helperArchitecture !== "unknown" && target.architecture !== helperArchitecture) {
    const targetArchitecture = normalizeNativeArchitecture(target.architecture);
    return architectureMismatchMessage(targetArchitecture, helperArchitecture);
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

function isNativeSessionTerminal(session: NativeSession): boolean {
  return ["stopped", "failed", "stale", "recovery_required"].includes(session.sessionState);
}

function isDaemonSession(session: NativeSession): boolean {
  return session.sessionKind.startsWith("daemon_") || session.daemonProcessId > 0;
}

function targetExitNoticeMessage(session: NativeSession): string {
  return `Target process ${session.targetProcessId} exited while ${session.sessionKind} was being monitored.`;
}

function formatElapsedMs(value: number): string {
  return `${(value / 1000).toFixed(1)}s`;
}

function catalogRowLabel(row: NativeSessionCatalogRow): string {
  return row.targetImage || row.sessionId || fileNameFromPath(row.path);
}

function traceIndexEventKey(event: NativeTraceIndexEvent): string {
  return `${event.sessionPath}:${event.eventId}:${event.recordSequence}`;
}

function traceIndexEventLabel(event: NativeTraceIndexEvent): string {
  return `${event.api || "api"} / ${event.module || "module"}`;
}

function directoryNameFromPath(path: string): string {
  const lastBackslash = path.lastIndexOf("\\");
  const lastSlash = path.lastIndexOf("/");
  const separatorIndex = Math.max(lastBackslash, lastSlash);

  if (separatorIndex <= 0) {
    return "";
  }

  return path.slice(0, separatorIndex);
}

function clampNumber(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function sumColumnWidths(widths: number[]): number {
  return widths.reduce((total, width) => total + width, 0);
}

function App() {
  const [leftTab, setLeftTab] = useState<LeftTab>("targets");
  const [targets, setTargets] = useState<TargetProcess[]>([]);
  const [selectedTargetPid, setSelectedTargetPid] = useState<number | null>(null);
  const [backendMode, setBackendMode] = useState<BackendMode>("native-enum");
  const [nativeHelperArchitecture, setNativeHelperArchitecture] = useState<NativeArchitecture>("unknown");
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [selectedEventId, setSelectedEventId] = useState<number>(0);
  const [filter, setFilter] = useState("");
  const [quickApiFilter, setQuickApiFilter] = useState("");
  const [quickModuleFilter, setQuickModuleFilter] = useState("");
  const [quickParameterFilter, setQuickParameterFilter] = useState("");
  const [traceQueryMatchMode, setTraceQueryMatchMode] = useState<TraceQueryMatchMode>("all");
  const [traceQueryClauses, setTraceQueryClauses] = useState<TraceQueryClause[]>([]);
  const [durationThresholdUs, setDurationThresholdUs] = useState(100);
  const [highlightingEnabled, setHighlightingEnabled] = useState(true);
  const [droppedCount, setDroppedCount] = useState(0);
  const [totalCapturedEvents, setTotalCapturedEvents] = useState(0);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("parameters");
  const [traceMode, setTraceMode] = useState<TraceMode>("flat");
  const [nativeBusy, setNativeBusy] = useState(false);
  const [launchTargetPath, setLaunchTargetPath] = useState("");
  const [launchWorkingDirectory, setLaunchWorkingDirectory] = useState("");
  const [launchArguments, setLaunchArguments] = useState("");
  const [launchDialogOpen, setLaunchDialogOpen] = useState(false);
  const [attachDurationMs, setAttachDurationMs] = useState(3000);
  const [treeDurationMs, setTreeDurationMs] = useState(3000);
  const [childPolicy, setChildPolicy] = useState<ChildPolicy>("observe");
  const [launchSession, setLaunchSession] = useState<NativeSession | null>(null);
  const [captureResult, setCaptureResult] = useState<CaptureResult | null>(null);
  const [attachResult, setAttachResult] = useState<CaptureResult | null>(null);
  const [processTreeResult, setProcessTreeResult] = useState<ProcessTreeResult | null>(null);
  const [lastSession, setLastSession] = useState<SessionInfo | null>(null);
  const [nativeOperations, setNativeOperations] = useState<NativeOperation[]>([]);
  const [nativeSessions, setNativeSessions] = useState<NativeSession[]>([]);
  const [processExitNotice, setProcessExitNotice] = useState<ProcessExitNotice | null>(null);
  const [sessionCatalog, setSessionCatalog] = useState<NativeSessionCatalog | null>(null);
  const [catalogStateFilter, setCatalogStateFilter] = useState("all");
  const [catalogTargetFilter, setCatalogTargetFilter] = useState("");
  const [catalogLimit, setCatalogLimit] = useState(50);
  const [selectedCatalogPath, setSelectedCatalogPath] = useState("");
  const [traceIndex, setTraceIndex] = useState<NativeTraceIndex | null>(null);
  const [traceIndexText, setTraceIndexText] = useState("");
  const [traceIndexApi, setTraceIndexApi] = useState("");
  const [traceIndexModule, setTraceIndexModule] = useState("");
  const [traceIndexLimit, setTraceIndexLimit] = useState(50);
  const [selectedTraceIndexEventKey, setSelectedTraceIndexEventKey] = useState("");
  const [replaySource, setReplaySource] = useState<ReplaySource | null>(null);
  const [traceScrollTop, setTraceScrollTop] = useState(0);
  const [traceViewportHeight, setTraceViewportHeight] = useState(0);
  const [traceAutoScroll, setTraceAutoScroll] = useState(true);
  const [inspectorHeight, setInspectorHeight] = useState(260);
  const [traceColumnWidths, setTraceColumnWidths] = useState(() => traceColumns.map((column) => column.width));
  const [detailColumnWidths, setDetailColumnWidths] = useState(() => detailColumns.map((column) => column.width));
  const [selectedApiKeys, setSelectedApiKeys] = useState<Set<string>>(() => new Set(collectApiLeafKeys(apiTree)));
  const [expandedApiNodes, setExpandedApiNodes] = useState<Set<string>>(() => new Set(apiTree.map((node) => node.id)));
  const [outputEvents, setOutputEvents] = useState<AuditEvent[]>([
    makeAuditEvent("backend_ready", "native_init", "Native desktop backend ready. Launch a target or attach to a running process.")
  ]);
  const nextQueryClauseId = useRef(1);
  const streamBatchCursors = useRef<Record<string, number>>({});
  const terminalDrainCompleted = useRef<Set<string>>(new Set());
  const lastSessionTargetAlive = useRef<Record<string, boolean>>({});
  const notifiedExitedSessions = useRef<Set<string>>(new Set());
  const traceScrollRef = useRef<HTMLDivElement | null>(null);
  const traceIngestWorker = useRef<Worker | null>(null);
  const pendingTraceIngestCommands = useRef<TraceIngestCommand[]>([]);
  const traceAutoScrollRef = useRef(traceAutoScroll);
  const selectedEventIdRef = useRef(selectedEventId);

  useEffect(() => {
    traceAutoScrollRef.current = traceAutoScroll;
  }, [traceAutoScroll]);

  useEffect(() => {
    let active = true;

    getNativeHelperArchitecture()
      .then((architecture) => {
        if (!active) {
          return;
        }

        setNativeHelperArchitecture(normalizeNativeArchitecture(architecture));
      })
      .catch((error) => {
        if (!active) {
          return;
        }

        const message = error instanceof Error ? error.message : String(error);
        setNativeHelperArchitecture("unknown");
        appendOutput([makeAuditEvent("native_architecture_unknown", "get_native_helper_architecture", message)]);
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    selectedEventIdRef.current = selectedEventId;
  }, [selectedEventId]);

  useEffect(() => {
    const worker = new Worker(new URL("./traceIngest.worker.ts", import.meta.url), { type: "module" });

    worker.onmessage = (event: MessageEvent<TraceIngestSnapshot>) => {
      if (event.data.type !== "snapshot") {
        return;
      }

      setEvents(event.data.events);
      setTotalCapturedEvents(event.data.totalCapturedEvents);
      if (traceAutoScrollRef.current || selectedEventIdRef.current === 0) {
        selectedEventIdRef.current = event.data.selectedEventId;
        setSelectedEventId(event.data.selectedEventId);
      }
    };

    worker.onerror = (event) => {
      setOutputEvents((current) => [
        makeAuditEvent("trace_ingest_worker_failed", "trace_ingest_worker", event.message || "Trace ingest worker failed."),
        ...current
      ].slice(0, 80));
    };

    traceIngestWorker.current = worker;
    const pendingCommands = pendingTraceIngestCommands.current.splice(0);
    pendingCommands.forEach((command) => {
      worker.postMessage(command);
    });

    return () => {
      traceIngestWorker.current = null;
      pendingTraceIngestCommands.current = [];
      worker.terminate();
    };
  }, []);

  useEffect(() => {
    let active = true;
    setNativeBusy(true);

    listNativeTargetProcesses()
      .then((result) => {
        if (!active) {
          return;
        }

        setTargets(result.targets);
        setBackendMode(result.mode);
        setSelectedTargetPid(null);
        appendOutput([makeAuditEvent("native_enum_completed", "list_native_target_processes", `Loaded ${result.targets.length} native target rows.`)]);
      })
      .catch((error) => {
        if (!active) {
          return;
        }

        const message = error instanceof Error ? error.message : String(error);
        setTargets([]);
        setBackendMode("native-enum");
        setSelectedTargetPid(null);
        appendOutput([makeAuditEvent("native_enum_blocked", "list_native_target_processes", message)]);
        setInspectorTab("output");
      })
      .finally(() => {
        if (active) {
          setNativeBusy(false);
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

  function postTraceIngest(command: TraceIngestCommand) {
    if (!traceIngestWorker.current) {
      pendingTraceIngestCommands.current.push(command);
      return;
    }

    traceIngestWorker.current.postMessage(command);
  }

  function observeTargetExitTransitions(sessions: NativeSession[]) {
    const exitEvents: AuditEvent[] = [];

    sessions.forEach((session) => {
      if (session.targetProcessId === 0) {
        return;
      }

      const previousAlive = lastSessionTargetAlive.current[session.sessionId];
      const exitReason = [session.staleReason, session.recoveryReason, session.lastError]
        .some((value) => value.toLowerCase().includes("target_exited"));
      const observedExit = session.targetExitObserved || exitReason;
      const firstTerminalExit = previousAlive === undefined && !session.targetAlive && observedExit;
      const transitionedToExited = previousAlive === true && !session.targetAlive;
      const rememberedExit = session.targetExitObserved && !session.targetAlive;

      lastSessionTargetAlive.current[session.sessionId] = session.targetAlive;

      if (!transitionedToExited && !firstTerminalExit && !rememberedExit) {
        return;
      }

      if (notifiedExitedSessions.current.has(session.sessionId)) {
        return;
      }

      notifiedExitedSessions.current.add(session.sessionId);

      const observedUtc = new Date().toISOString();
      const message = targetExitNoticeMessage(session);
      setProcessExitNotice({
        sessionId: session.sessionId,
        sessionKind: session.sessionKind,
        targetProcessId: session.targetProcessId,
        sessionState: session.sessionState,
        observedUtc,
        message
      });
      exitEvents.push(makeAuditEvent("target_process_exited", "list_native_sessions", message));
    });

    if (exitEvents.length > 0) {
      appendOutput(exitEvents);
      setInspectorTab("output");
    }
  }

  function observeTargetExitFromCaptureResult(result: CaptureResult) {
    if (result.targetProcessId === 0) {
      return;
    }

    const exited = result.auditEvents.some((event) => {
      const eventType = event.eventType.toLowerCase();
      const message = event.message.toLowerCase();
      return eventType.includes("target_exited") || message.includes("target exited");
    });

    if (!exited) {
      return;
    }

    const sessionId = result.sessionId || result.operationId;
    if (notifiedExitedSessions.current.has(sessionId)) {
      return;
    }

    notifiedExitedSessions.current.add(sessionId);
    const sessionKind = result.sessionKind || result.captureMode;
    const message = `Target process ${result.targetProcessId} exited while ${sessionKind} was being monitored.`;
    setProcessExitNotice({
      sessionId,
      sessionKind,
      targetProcessId: result.targetProcessId,
      sessionState: result.sessionState || result.operationState || "stopped",
      observedUtc: new Date().toISOString(),
      message
    });
    appendOutput([makeAuditEvent("target_process_exited", result.operation, message, result.win32ErrorCode)]);
    setInspectorTab("output");
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

  function clearQuickTraceFilters() {
    setQuickApiFilter("");
    setQuickModuleFilter("");
    setQuickParameterFilter("");
  }

  function handleClearTraceFilters() {
    setTraceQueryClauses([]);
    setFilter("");
    clearQuickTraceFilters();
    appendOutput([makeAuditEvent("trace_filters_cleared", "trace_filter", "Current trace filters cleared.")]);
  }

  function handleApplyIssueGroup(group: TraceIssueGroup) {
    const nextClauses = group.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    clearQuickTraceFilters();
    setSelectedEventId(group.eventIds[0] ?? 0);
    setInspectorTab(group.kind === "error" || group.kind === "module_api" ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_issue_filter_applied", "trace_issue_view", `${group.kind}; ${group.label}; events=${group.count}`)]);
  }

  function handleApplyThreadGroup(group: TraceThreadGroup) {
    const nextClauses = group.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    clearQuickTraceFilters();
    setSelectedEventId(group.eventIds[0] ?? 0);
    setInspectorTab(group.errorCount > 0 ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_thread_filter_applied", "trace_thread_view", `${group.threadLabel}; events=${group.eventCount}; spanMs=${group.spanMs}`)]);
  }

  function handleApplyTimelineBucket(bucket: TraceTimelineBucket) {
    const nextClauses = bucket.clauses.map((clause) => createTraceQueryClause(clause));
    setTraceQueryMatchMode("all");
    setTraceQueryClauses(nextClauses);
    setFilter("");
    clearQuickTraceFilters();
    setSelectedEventId(bucket.eventIds[0] ?? 0);
    setInspectorTab(bucket.errorCount > 0 ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_timeline_filter_applied", "trace_timeline_view", `${formatElapsedMs(bucket.startRelativeTimeMs)}-${formatElapsedMs(bucket.endRelativeTimeMs)}; events=${bucket.eventCount}`)]);
  }

  function handleApplyHighlightSummary(summary: TraceHighlightSummary) {
    if (summary.count === 0) {
      return;
    }

    if (summary.clauses.length > 0) {
      const nextClauses = summary.clauses.map((clause) => createTraceQueryClause(clause));
      setTraceQueryMatchMode(summary.matchMode);
      setTraceQueryClauses(nextClauses);
      setFilter("");
      clearQuickTraceFilters();
    }

    setSelectedEventId(summary.eventIds[0] ?? 0);
    setInspectorTab(summary.severity === "critical" ? "return" : "parameters");
    appendOutput([makeAuditEvent("trace_highlight_filter_applied", "trace_highlight_rules", `${summary.label}; severity=${summary.severity}; events=${summary.count}; clauses=${summary.clauses.length}`)]);
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

  function applyTraceIndexResult(result: NativeTraceIndex) {
    setTraceIndex(result);
    setSelectedTraceIndexEventKey((current) => {
      if (current && result.events.some((event) => traceIndexEventKey(event) === current)) {
        return current;
      }

      return result.events[0] ? traceIndexEventKey(result.events[0]) : "";
    });
  }

  function replaceTargets(nextTargets: TargetProcess[], nextMode: BackendMode) {
    setTargets(nextTargets);
    setBackendMode(nextMode);
    setSelectedTargetPid((current) => {
      if (current !== null && nextTargets.some((target) => target.pid === current)) {
        return current;
      }

      return null;
    });
  }

  function appendCapturedEventChunks(chunks: CapturedEventChunk[]) {
    const incomingCount = chunks.reduce((count, chunk) => count + chunk.events.length, 0);
    if (incomingCount === 0) {
      return;
    }

    postTraceIngest({ type: "enqueue-events", chunks });
  }

  function appendCapturedEvents(capturedEvents: AgentApiCallEvent[], contextTags: string[]) {
    appendCapturedEventChunks([{ events: capturedEvents, contextTags }]);
  }

  function appendTraceBatches(batches: NativeTraceBatch[]) {
    if (batches.length === 0) {
      return;
    }

    postTraceIngest({ type: "enqueue-batches", batches });

    const latest = batches[batches.length - 1];
    setDroppedCount(latest.droppedEvents);
    streamBatchCursors.current[latest.sessionId] = latest.batchSequence;
  }

  function replaceTraceEvents(nextEvents: TraceEvent[], selectedId?: number) {
    postTraceIngest({ type: "replace", events: nextEvents, selectedEventId: selectedId });
  }

  async function handleLoadNativeTargets() {
    setNativeBusy(true);

    try {
      const result = await listNativeTargetProcesses();
      replaceTargets(result.targets, result.mode);
      appendOutput([makeAuditEvent("native_enum_completed", "list_native_target_processes", `Loaded ${result.targets.length} native target rows.`)]);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      replaceTargets([], "native-enum");
      appendOutput([makeAuditEvent("native_enum_blocked", "list_native_target_processes", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  const nativePollingEnabled =
    nativeBusy ||
    nativeOperations.some((operation) => isNativeOperationActive(operation)) ||
    nativeSessions.some((session) => isNativeSessionActive(session));

  useEffect(() => {
    if (!nativePollingEnabled) {
      return undefined;
    }

    let active = true;
    let pollInFlight = false;

    const refreshNativeOwnership = async () => {
      if (pollInFlight) {
        return;
      }

      pollInFlight = true;
      try {
        const [operations, sessions, daemonSessions] = await Promise.all([
          listNativeOperations(),
          listNativeSessions(),
          listDaemonSessions()
        ]);
        if (active) {
          setNativeOperations(operations);
          const daemonIds = new Set(daemonSessions.map((session) => session.sessionId));
          const nextSessions = [...daemonSessions, ...sessions.filter((session) => !daemonIds.has(session.sessionId))];
          observeTargetExitTransitions(nextSessions);
          setNativeSessions(nextSessions);
        }
      } catch (error) {
        if (active) {
          const message = error instanceof Error ? error.message : String(error);
          appendOutput([makeAuditEvent("native_ownership_poll_failed", "list_native_sessions", message)]);
        }
      }
      finally {
        pollInFlight = false;
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
  }, [nativePollingEnabled]);

  const compiledTraceQuery = useMemo(
    () => compileTraceQuery(traceQueryClauses, traceQueryMatchMode),
    [traceQueryClauses, traceQueryMatchMode]
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
  const traceHighlightState = useMemo(
    () => buildTraceHighlightState(events, durationThresholdUs),
    [events, durationThresholdUs]
  );
  const visibleHighlightSummaries = useMemo(
    () => traceHighlightState.summaries.slice(0, 8),
    [traceHighlightState]
  );
  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      return matchesFreeTextFilter(event, filter)
        && matchesQuickTraceFilters(event, quickApiFilter, quickModuleFilter, quickParameterFilter)
        && compiledTraceQuery.matches(event);
    });
  }, [events, filter, quickApiFilter, quickModuleFilter, quickParameterFilter, compiledTraceQuery]);

  const selectedTraceIndex = useMemo(
    () => filteredEvents.findIndex((event) => event.eventId === selectedEventId),
    [filteredEvents, selectedEventId]
  );
  const selectedEvent = selectedTraceIndex >= 0
    ? filteredEvents[selectedTraceIndex]
    : filteredEvents[0] ?? events.find((event) => event.eventId === selectedEventId) ?? events[0];
  const selectedEventHighlight = selectedEvent
    ? traceHighlightState.eventHighlightsById.get(selectedEvent.eventId) ?? null
    : null;
  const selectedTarget = selectedTargetPid === null ? null : targets.find((target) => target.pid === selectedTargetPid) ?? null;
  const apiLeafKeys = useMemo(() => collectApiLeafKeys(apiTree), []);
  const selectedApiList = useMemo(
    () => apiLeafKeys.filter((key) => selectedApiKeys.has(key)),
    [apiLeafKeys, selectedApiKeys]
  );
  const selectedApiModules = useMemo(() => {
    const modules = new Set<string>();
    for (const entry of apiCatalogEntries) {
      if (selectedApiKeys.has(entry.selectionKey)) {
        modules.add(entry.module);
      }
    }

    return modules.size;
  }, [selectedApiKeys]);
  const apiSelectionRequest = selectedApiList.length === apiLeafKeys.length ? [] : selectedApiList;
  const apiSelectionSummary = selectedApiList.length === apiLeafKeys.length
    ? "all current hooks"
    : `${selectedApiList.length}/${apiLeafKeys.length} APIs`;
  const apiSelectionBlocked = selectedApiList.length === 0;
  const activeCurrentLogFilterCount = [filter, quickApiFilter, quickModuleFilter, quickParameterFilter]
    .filter((value) => value.trim().length > 0)
    .length;
  const targetBlockReason = targetEligibilityReason(selectedTarget, nativeHelperArchitecture);
  const activeNativeOperation = nativeOperations.find(isNativeOperationActive) ?? null;
  const activeNativeSession = nativeSessions.find(isNativeSessionActive) ?? null;
  const currentLaunchSession = launchSession
    ? nativeSessions.find((session) => session.sessionId === launchSession.sessionId) ?? launchSession
    : null;
  const displayNativeSession = activeNativeSession ?? currentLaunchSession;
  const canStopNativeSession = activeNativeSession !== null && !activeNativeSession.stopRequested;
  const launchMonitorActive = activeNativeSession?.sessionKind === "launch_capture_stream";
  const launchButtonLabel = launchDialogOpen ? "Choose Target" : launchMonitorActive ? "Monitoring" : nativeBusy ? "Working" : "Launch & Monitor";
  const topbarPulseClass = processExitNotice
    ? "pulse stopped"
    : activeNativeSession || nativeBusy
      ? "pulse running"
      : displayNativeSession && isNativeSessionTerminal(displayNativeSession)
        ? "pulse stopped"
        : "pulse";
  const topbarStatusLabel = processExitNotice
    ? "target exited"
    : activeNativeSession
      ? activeNativeSession.sessionState
      : nativeBusy
        ? "working"
        : displayNativeSession
          ? displayNativeSession.sessionState
          : "idle";
  const canLaunchMonitor = !apiSelectionBlocked && !launchDialogOpen && !nativeBusy && activeNativeOperation === null && activeNativeSession === null;
  const canRunTargetAction = !apiSelectionBlocked && targetBlockReason === null && !nativeBusy && activeNativeOperation === null && activeNativeSession === null;
  const drainNativeSession = activeNativeSession && !isDaemonSession(activeNativeSession)
    ? activeNativeSession
    : currentLaunchSession && !isDaemonSession(currentLaunchSession) && !terminalDrainCompleted.current.has(currentLaunchSession.sessionId)
      ? currentLaunchSession
      : null;
  const processTreeSummary = summarizeProcessTree(processTreeResult);
  const sessionBytes = useMemo(() => estimateSessionBytes(events), [events]);
  const totalTraceEventCount = Math.max(totalCapturedEvents, displayNativeSession?.recordsStreamed ?? 0);
  const trimmedTraceEventCount = Math.max(0, totalTraceEventCount - events.length);
  const selectedCatalogRow = sessionCatalog?.sessions.find((row) => row.path === selectedCatalogPath) ?? null;
  const selectedTraceIndexEvent = traceIndex?.events.find((event) => traceIndexEventKey(event) === selectedTraceIndexEventKey) ?? null;
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
  const traceGridTemplate = useMemo(() => traceColumnWidths.map((width) => `${width}px`).join(" "), [traceColumnWidths]);
  const traceTableWidth = useMemo(() => sumColumnWidths(traceColumnWidths), [traceColumnWidths]);
  const detailTableWidth = useMemo(() => sumColumnWidths(detailColumnWidths), [detailColumnWidths]);
  const mainPanelStyle = {
    "--inspector-height": `${inspectorHeight}px`
  } as CSSProperties;

  function handleTraceAutoScrollChange(checked: boolean) {
    setTraceAutoScroll(checked);
    traceAutoScrollRef.current = checked;

    if (!checked) {
      return;
    }

    const latestEvent = filteredEvents[filteredEvents.length - 1] ?? events[events.length - 1];
    if (!latestEvent) {
      return;
    }

    selectedEventIdRef.current = latestEvent.eventId;
    setSelectedEventId(latestEvent.eventId);
  }

  function startColumnResize(
    columns: ColumnConfig[],
    widths: number[],
    setWidths: (updater: (current: number[]) => number[]) => void,
    index: number,
    event: ReactPointerEvent<HTMLButtonElement>
  ) {
    event.preventDefault();
    event.stopPropagation();

    const startX = event.clientX;
    const startWidth = widths[index] ?? columns[index].width;
    const minWidth = columns[index].minWidth;

    document.body.classList.add("column-resizing");

    const handlePointerMove = (moveEvent: PointerEvent) => {
      const nextWidth = Math.round(Math.max(minWidth, startWidth + moveEvent.clientX - startX));
      setWidths((current) => current.map((width, currentIndex) => currentIndex === index ? nextWidth : width));
    };

    const handlePointerUp = () => {
      document.body.classList.remove("column-resizing");
      window.removeEventListener("pointermove", handlePointerMove);
    };

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", handlePointerUp, { once: true });
  }

  function resetColumnWidth(
    columns: ColumnConfig[],
    setWidths: (updater: (current: number[]) => number[]) => void,
    index: number
  ) {
    setWidths((current) => current.map((width, currentIndex) => currentIndex === index ? columns[index].width : width));
  }

  function handleInspectorResizeStart(event: ReactPointerEvent<HTMLDivElement>) {
    event.preventDefault();
    const startY = event.clientY;
    const startHeight = inspectorHeight;

    document.body.classList.add("panel-resizing");

    const handlePointerMove = (moveEvent: PointerEvent) => {
      const nextHeight = clampNumber(Math.round(startHeight + startY - moveEvent.clientY), minInspectorHeight, maxInspectorHeight);
      setInspectorHeight(nextHeight);
    };

    const handlePointerUp = () => {
      document.body.classList.remove("panel-resizing");
      window.removeEventListener("pointermove", handlePointerMove);
    };

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", handlePointerUp, { once: true });
  }

  function handleToggleApiNode(node: ApiNode) {
    const nodeLeafKeys = collectApiLeafKeys([node]);
    if (nodeLeafKeys.length === 0) {
      return;
    }

    setSelectedApiKeys((current) => {
      const next = new Set(current);
      const allSelected = nodeLeafKeys.every((key) => next.has(key));

      for (const key of nodeLeafKeys) {
        if (allSelected) {
          next.delete(key);
        }
        else {
          next.add(key);
        }
      }

      return next;
    });
  }

  function handleToggleApiExpanded(nodeId: string) {
    setExpandedApiNodes((current) => {
      const next = new Set(current);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      }
      else {
        next.add(nodeId);
      }

      return next;
    });
  }

  function handleSelectAllApis() {
    setSelectedApiKeys(new Set(apiLeafKeys));
  }

  function handleClearApiSelection() {
    setSelectedApiKeys(new Set());
  }

  function handleApplyCaptureProfile(profileId: string) {
    const profile = captureProfiles.find((item) => item.id === profileId);
    if (!profile) {
      return;
    }

    const validKeys = new Set(apiLeafKeys);
    const profileKeys = profile.enabledApis.filter((key) => validKeys.has(key));
    setSelectedApiKeys(new Set(profileKeys));
    appendOutput([makeAuditEvent("api_profile_applied", "api_selection", `${profile.name}; selected=${profileKeys.length}/${apiLeafKeys.length}`)]);
  }

  useEffect(() => {
    const element = traceScrollRef.current;
    if (element) {
      element.scrollTop = 0;
    }

    setTraceScrollTop(0);
  }, [filter, quickApiFilter, quickModuleFilter, quickParameterFilter, traceMode, compiledTraceQuery]);

  useEffect(() => {
    const element = traceScrollRef.current;
    if (!traceAutoScroll || !element || selectedTraceIndex < 0) {
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
  }, [traceAutoScroll, selectedTraceIndex, filteredEvents.length]);

  useEffect(() => {
    if (!drainNativeSession) {
      return undefined;
    }

    if (isDaemonSession(drainNativeSession)) {
      return undefined;
    }

    let active = true;
    let timer: number | undefined;
    let pollInFlight = false;
    const sessionSnapshot = drainNativeSession;
    const sessionId = sessionSnapshot.sessionId;

    const refreshTraceBatches = async () => {
      if (pollInFlight) {
        return;
      }

      pollInFlight = true;
      const cursor = streamBatchCursors.current[sessionId] ?? 0;
      try {
        const batches = await drainNativeTraceBatches(sessionId, cursor);
        if (active && batches.length > 0) {
          appendTraceBatches(batches);
        }

        if (active && isNativeSessionTerminal(sessionSnapshot)) {
          terminalDrainCompleted.current.add(sessionId);
          active = false;

          if (timer !== undefined) {
            window.clearInterval(timer);
          }
        }
      } catch (error) {
        if (active) {
          const message = error instanceof Error ? error.message : String(error);
          appendOutput([makeAuditEvent("stream_batch_poll_failed", "drain_native_trace_batches", message)]);
        }
      }
      finally {
        pollInFlight = false;
      }
    };

    void refreshTraceBatches();
    if (!isNativeSessionTerminal(sessionSnapshot)) {
      timer = window.setInterval(() => {
        void refreshTraceBatches();
      }, 350);
    }

    return () => {
      active = false;
      if (timer !== undefined) {
        window.clearInterval(timer);
      }
    };
  }, [drainNativeSession?.sessionId, drainNativeSession?.sessionState]);

  function handleClear() {
    postTraceIngest({ type: "reset" });
    setReplaySource(null);
    setProcessExitNotice(null);
    terminalDrainCompleted.current.clear();
  }

  async function startLaunchMonitorForTarget(targetPath: string, workingDirectory: string) {
    if (apiSelectionBlocked) {
      appendOutput([makeAuditEvent("launch_blocked", "api_selection", "Select at least one API before starting launch monitoring.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setLaunchSession(null);
    setProcessExitNotice(null);

    try {
      const targetArchitectureValue = await queryTargetBinaryArchitecture(targetPath);
      const targetArchitecture = normalizeNativeArchitecture(targetArchitectureValue);
      if (nativeHelperArchitecture !== "unknown" && targetArchitecture !== "unknown" && targetArchitecture !== nativeHelperArchitecture) {
        const message = architectureMismatchMessage(targetArchitecture, nativeHelperArchitecture);
        appendOutput([makeAuditEvent("launch_blocked", "query_target_binary_architecture", message)]);
        setInspectorTab("output");
        return;
      }

      if (targetArchitecture === "unknown" && targetArchitectureValue !== "unknown") {
        const message = `Target architecture ${targetArchitectureValue} is unsupported. Run a KN Win32 API Monitor build that matches a supported x86 or x64 target.`;
        appendOutput([makeAuditEvent("launch_blocked", "query_target_binary_architecture", message)]);
        setInspectorTab("output");
        return;
      }

      appendOutput([makeAuditEvent("launch_requested", "start_launch_monitor_session", `Early-bird launch monitor requested for ${targetPath}; scope=${apiSelectionSummary}.`)]);
      const session = await startLaunchMonitorSession(targetPath, workingDirectory, launchArguments.trim(), apiSelectionRequest);
      terminalDrainCompleted.current.delete(session.sessionId);
      streamBatchCursors.current[session.sessionId] = 0;
      setLaunchSession(session);
      setBackendMode("native-capture");
      setNativeSessions((current) => {
        const remaining = current.filter((item) => item.sessionId !== session.sessionId);
        return [session, ...remaining];
      });
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("launch_blocked", "start_launch_monitor_session", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleStartLaunchMonitor() {
    setLeftTab("targets");
    setLaunchDialogOpen(true);

    let selectedPath = "";
    try {
      const selection = await openDialog({
        title: "Select target executable",
        multiple: false,
        directory: false,
        defaultPath: launchTargetPath.trim() || launchWorkingDirectory.trim() || undefined,
        filters: [
          {
            name: "Windows executables",
            extensions: ["exe"]
          }
        ]
      });

      if (typeof selection === "string") {
        selectedPath = selection;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("launch_dialog_failed", "dialog.open", message)]);
      setInspectorTab("output");
      setLaunchDialogOpen(false);
      return;
    }

    setLaunchDialogOpen(false);

    if (!selectedPath) {
      appendOutput([makeAuditEvent("launch_cancelled", "dialog.open", "Launch target selection was cancelled.")]);
      setInspectorTab("output");
      return;
    }

    const selectedWorkingDirectory = launchWorkingDirectory.trim() || directoryNameFromPath(selectedPath);
    setLaunchTargetPath(selectedPath);

    if (!launchWorkingDirectory.trim() && selectedWorkingDirectory) {
      setLaunchWorkingDirectory(selectedWorkingDirectory);
    }

    await startLaunchMonitorForTarget(selectedPath, selectedWorkingDirectory);
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

  async function handleBuildSessionCatalogIndex(rebuild: boolean) {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_catalog_index_requested", "build_native_session_catalog_index", rebuild ? "Catalog DB index rebuild requested from UI." : "Catalog DB index build requested from UI.")]);
      const catalog = await buildNativeSessionCatalogIndex(rebuild);
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_index_built" : "session_catalog_index_failed",
          "build_native_session_catalog_index",
          `${catalog.message}; db=${catalog.databasePath || "n/a"}; backend=${catalog.indexBackend || "n/a"}; schema=${catalog.indexSchemaVersion ?? 0}; sessions=${catalog.sessionCount}; stale=${catalog.staleIdentityCount ?? 0}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_index_blocked", "build_native_session_catalog_index", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleQuerySessionCatalogIndex() {
    setNativeBusy(true);

    try {
      const queryState = catalogStateFilter === "all" ? "" : catalogStateFilter;
      appendOutput([makeAuditEvent("session_catalog_index_query_requested", "query_native_session_catalog_index", `state=${catalogStateFilter}; target=${catalogTargetFilter || "*"}; limit=${catalogLimit}`)]);
      const catalog = await queryNativeSessionCatalogIndex(catalogLimit, queryState, catalogTargetFilter.trim());
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_index_queried" : "session_catalog_index_query_failed",
          "query_native_session_catalog_index",
          `${catalog.message}; db=${catalog.databasePath || "n/a"}; sessions=${catalog.sessionCount}; valid=${catalog.validSessionCount}; invalid=${catalog.invalidSessionCount}; stale=${catalog.staleIdentityCount ?? 0}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_index_query_blocked", "query_native_session_catalog_index", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleRemoveMissingCatalogIndexEntries(dryRun: boolean) {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("session_catalog_index_prune_requested", "remove_missing_native_session_catalog_index_entries", dryRun ? "Dry-run DB missing-row prune requested from UI." : "DB missing-row prune requested from UI.")]);
      const catalog = await removeMissingNativeSessionCatalogIndexEntries(dryRun);
      applySessionCatalog(catalog);
      appendOutput([
        makeAuditEvent(
          catalog.success ? "session_catalog_index_pruned" : "session_catalog_index_prune_failed",
          "remove_missing_native_session_catalog_index_entries",
          `${catalog.message}; dryRun=${catalog.dryRun}; mutation=${catalog.mutationAttempted}; missing=${catalog.missingSessionPaths.length}; sessions=${catalog.sessionCount}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("session_catalog_index_prune_blocked", "remove_missing_native_session_catalog_index_entries", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleBuildTraceIndex(rebuild: boolean) {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("trace_index_requested", "build_native_trace_index", rebuild ? "Trace DB index rebuild requested from UI." : "Trace DB index build requested from UI.")]);
      const result = await buildNativeTraceIndex(rebuild);
      applyTraceIndexResult(result);
      appendOutput([
        makeAuditEvent(
          result.success ? "trace_index_built" : "trace_index_failed",
          "build_native_trace_index",
          `${result.message}; db=${result.databasePath || "n/a"}; backend=${result.indexBackend}; sessions=${result.indexedSessionCount}/${result.sessionCount}; events=${result.eventCount}; invalid=${result.invalidSessionCount}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("trace_index_blocked", "build_native_trace_index", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleQueryTraceIndex() {
    setNativeBusy(true);

    try {
      appendOutput([
        makeAuditEvent(
          "trace_index_query_requested",
          "query_native_trace_index",
          `text=${traceIndexText || "*"}; api=${traceIndexApi || "*"}; module=${traceIndexModule || "*"}; limit=${traceIndexLimit}`
        )
      ]);
      const result = await queryNativeTraceIndex(
        traceIndexLimit,
        traceIndexText.trim(),
        traceIndexApi.trim(),
        traceIndexModule.trim(),
        "",
        ""
      );
      applyTraceIndexResult(result);
      appendOutput([
        makeAuditEvent(
          result.success ? "trace_index_queried" : "trace_index_query_failed",
          "query_native_trace_index",
          `${result.message}; matches=${result.matchedEventCount}; indexedEvents=${result.eventCount}; sessions=${result.indexedSessionCount}/${result.sessionCount}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("trace_index_query_blocked", "query_native_trace_index", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleRemoveMissingTraceIndexEntries(dryRun: boolean) {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("trace_index_prune_requested", "remove_missing_native_trace_index_entries", dryRun ? "Dry-run trace DB missing-row prune requested from UI." : "Trace DB missing-row prune requested from UI.")]);
      const result = await removeMissingNativeTraceIndexEntries(dryRun);
      applyTraceIndexResult(result);
      appendOutput([
        makeAuditEvent(
          result.success ? "trace_index_pruned" : "trace_index_prune_failed",
          "remove_missing_native_trace_index_entries",
          `${result.message}; dryRun=${result.dryRun}; mutation=${result.mutationAttempted}; missing=${result.missingSessionPaths.length}; sessions=${result.indexedSessionCount}`
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("trace_index_prune_blocked", "remove_missing_native_trace_index_entries", message)]);
      setInspectorTab("output");
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleReplayTraceIndexEvent(event: NativeTraceIndexEvent) {
    setNativeBusy(true);
    setSelectedTraceIndexEventKey(traceIndexEventKey(event));

    try {
      appendOutput([makeAuditEvent("trace_index_replay_requested", "replay_session_path", `Trace hit replay requested for ${event.api} event ${event.eventId} from ${event.sessionPath}.`)]);
      const result = await replaySessionPath(event.sessionPath);
      setBackendMode(result.backendMode);
      setLastSession(result.session);
      setDroppedCount(result.session.droppedEvents);
      replaceTraceEvents(result.traceEvents, event.eventId);
      setReplaySource({
        kind: "catalog",
        label: traceIndexEventLabel(event),
        path: event.sessionPath,
        validationStatus: result.session.success ? "valid" : "invalid"
      });
      appendOutput([
        makeAuditEvent(
          result.success ? "trace_index_replayed" : "trace_index_replay_failed",
          "replay_session_path",
          `${result.message}; path=${event.sessionPath}; hit=${event.api}#${event.eventId}; traceEvents=${result.traceEvents.length}`,
          result.session.win32ErrorCode
        )
      ]);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("trace_index_replay_blocked", "replay_session_path", message)]);
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
      replaceTraceEvents(result.traceEvents);
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
      postTraceIngest({ type: "reset" });
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

    if (apiSelectionBlocked) {
      appendOutput([makeAuditEvent("attach_blocked", "api_selection", "Select at least one API before attaching to a process.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setAttachResult(null);
    setProcessExitNotice(null);

    try {
      appendOutput([makeAuditEvent("attach_requested", "attach_target_process_capture", `Bounded attach requested for PID ${selectedTarget.pid}; scope=${apiSelectionSummary}.`)]);
      const result = await attachTargetProcessCapture(selectedTarget.pid, attachDurationMs, apiSelectionRequest);
      setAttachResult(result);
      setCaptureResult(result);
      setBackendMode(result.backendMode);
      setDroppedCount(result.droppedEvents);
      appendOutput(captureResultOutputEvents(result, "attach_result"));
      appendCapturedEvents(result.capturedEvents, ["ui-attach", `target:${result.targetProcessId}`]);
      observeTargetExitFromCaptureResult(result);
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

    if (apiSelectionBlocked) {
      appendOutput([makeAuditEvent("stream_attach_blocked", "api_selection", "Select at least one API before starting attach monitoring.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setProcessExitNotice(null);

    try {
      appendOutput([makeAuditEvent("stream_attach_requested", "start_streaming_attach_session", `Streaming attach requested for PID ${selectedTarget.pid}; scope=${apiSelectionSummary}.`)]);
      const session = await startStreamingAttachSession(selectedTarget.pid, apiSelectionRequest);
      terminalDrainCompleted.current.delete(session.sessionId);
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

    if (apiSelectionBlocked) {
      appendOutput([makeAuditEvent("daemon_session_blocked", "api_selection", "Select at least one API before starting daemon attach monitoring.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setProcessExitNotice(null);

    try {
      appendOutput([makeAuditEvent("daemon_session_requested", "start_daemon_supervised_session", `Daemon-supervised attach requested for PID ${selectedTarget.pid}; scope=${apiSelectionSummary}.`)]);
      const session = await startDaemonSupervisedSession(selectedTarget.pid, apiSelectionRequest);
      terminalDrainCompleted.current.delete(session.sessionId);
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

    if (apiSelectionBlocked) {
      appendOutput([makeAuditEvent("process_tree_blocked", "api_selection", "Select at least one API before starting process-tree supervision.")]);
      setInspectorTab("output");
      return;
    }

    setNativeBusy(true);
    setProcessTreeResult(null);
    setProcessExitNotice(null);

    try {
      appendOutput([makeAuditEvent("process_tree_requested", "supervise_process_tree", `Supervision requested for PID ${selectedTarget.pid}; policy=${childPolicy}; scope=${apiSelectionSummary}.`)]);
      const result = await superviseProcessTree(selectedTarget.pid, treeDurationMs, childPolicy, apiSelectionRequest);
      const childAuditEvents = result.childAttachResults.flatMap((capture) => capture.auditEvents);
      const childResolverEvents = result.childAttachResults.flatMap((capture) => resolverPointerOutputEvents(capture));
      const childDroppedEvents = result.childAttachResults.reduce((total, capture) => total + capture.droppedEvents, 0);

      setProcessTreeResult(result);
      setBackendMode(result.backendMode);
      setDroppedCount(childDroppedEvents);
      appendOutput(
        result.auditEvents.length + childAuditEvents.length + childResolverEvents.length > 0
          ? [...childResolverEvents, ...result.auditEvents, ...childAuditEvents]
          : [makeAuditEvent("process_tree_result", result.operation, result.message, result.win32ErrorCode)]
      );

      result.childAttachResults.forEach((capture) => {
        appendCapturedEvents(capture.capturedEvents, ["process-tree", `child:${capture.targetProcessId}`]);
        observeTargetExitFromCaptureResult(capture);
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
        <div className="toolbar primary-toolbar" aria-label="Monitoring actions">
          <button
            className="tool-button primary command-button"
            type="button"
            title="Choose an executable and start monitoring"
            onClick={handleStartLaunchMonitor}
            disabled={!canLaunchMonitor}
          >
            <Rocket size={15} />
            <span>{launchButtonLabel}</span>
          </button>
          <button
            className="tool-button command-button"
            type="button"
            title={targetBlockReason ?? "Attach to the selected running process"}
            onClick={handleStartStreamingAttach}
            disabled={!canRunTargetAction}
          >
            <Activity size={15} />
            <span>Attach Selected</span>
          </button>
          <button
            className="tool-button command-button"
            type="button"
            title={activeNativeSession?.recoveryAction || "Stop native session"}
            onClick={handleStopNativeSession}
            disabled={!canStopNativeSession}
          >
            <Square size={14} />
            <span>Stop</span>
          </button>
        </div>
        <div className="toolbar utility-toolbar" aria-label="Session toolbar">
          <button className="tool-button" type="button" title="Open session">
            <FolderOpen size={15} />
          </button>
          <button className="tool-button" type="button" title="Export JSONL" onClick={() => downloadJsonl(events)}>
            <Download size={15} />
          </button>
          <button className="tool-button" type="button" title="Refresh process list" onClick={handleLoadNativeTargets} disabled={nativeBusy}>
            <RefreshCcw size={15} />
          </button>
          <button className="tool-button danger" type="button" title="Clear session" onClick={handleClear}>
            <Trash2 size={15} />
          </button>
        </div>
        <div className="topbar-status">
          <span className={topbarPulseClass} />
          <span>{topbarStatusLabel}</span>
        </div>
      </header>

      <main className={processExitNotice ? "workspace has-process-exit" : "workspace"}>
        {processExitNotice ? (
          <div className="process-exit-banner" role="status" aria-live="polite">
            <AlertTriangle size={17} />
            <strong>Target exited</strong>
            <span>{processExitNotice.message}</span>
            <small>{processExitNotice.sessionState} / {processExitNotice.observedUtc}</small>
            <button type="button" className="tool-button" onClick={() => setProcessExitNotice(null)}>
              <span>Dismiss</span>
            </button>
          </div>
        ) : null}
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
                  <span>Running Process Attach</span>
                </div>
                <div className="source-toggle">
                  <button type="button" className="active" onClick={handleLoadNativeTargets} disabled={nativeBusy}>
                    Desktop
                  </button>
                  <button type="button" title="Refresh native target list" onClick={handleLoadNativeTargets} disabled={nativeBusy}>
                    <RefreshCcw size={13} />
                  </button>
                </div>
              </div>
              <div className={apiSelectionBlocked ? "api-scope-panel blocked" : "api-scope-panel"}>
                <div className="api-scope-header">
                  <div>
                    <strong>Monitoring Scope</strong>
                    <span>{apiSelectionSummary}; {selectedApiModules} modules</span>
                  </div>
                  <button type="button" className="tool-button" onClick={() => setLeftTab("apis")} disabled={nativeBusy}>
                    <Layers size={13} />
                    <span>Edit</span>
                  </button>
                </div>
                <div className="api-scope-actions">
                  <button type="button" onClick={handleSelectAllApis} disabled={nativeBusy}>All</button>
                  <button type="button" onClick={handleClearApiSelection} disabled={nativeBusy}>None</button>
                  <select
                    aria-label="Apply API profile"
                    value=""
                    onChange={(event) => handleApplyCaptureProfile(event.target.value)}
                    disabled={nativeBusy}
                  >
                    <option value="" disabled>Profile</option>
                    {captureProfiles.map((profile) => (
                      <option value={profile.id} key={profile.id}>{profile.name}</option>
                    ))}
                  </select>
                </div>
                <div className="api-scope-tree compact" aria-label="Monitoring API selection">
                  {renderApiTree(
                    apiTree,
                    selectedApiKeys,
                    expandedApiNodes,
                    handleToggleApiNode,
                    handleToggleApiExpanded,
                    nativeBusy || activeNativeSession !== null
                  )}
                </div>
                {apiSelectionBlocked ? <div className="scope-warning">Select at least one API before launch or attach.</div> : null}
              </div>
              <div className="section-title">
                <Server size={14} />
                <span>Pick Running Process</span>
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
                  <span>Selected Process</span>
                </div>
                <div className="target-action-grid">
                  <label>PID</label>
                  <span>{selectedTarget?.pid ?? "none"}</span>
                  <label>Image</label>
                  <span>{selectedTarget?.imageName ?? "select a row"}</span>
                  <label>Architecture</label>
                  <span>{selectedTarget?.architecture ?? "unknown"}</span>
                  <label>Tool arch</label>
                  <span>{nativeHelperArchitecture}</span>
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
                    <span>
                      {formatElapsedMs(activeNativeOperation.elapsedMs)} /{" "}
                      {activeNativeOperation.durationMs === 0 ? "manual stop" : formatElapsedMs(activeNativeOperation.durationMs)}
                    </span>
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
                    {activeNativeSession.targetProcessId ? (
                      <small className={activeNativeSession.targetAlive ? "alive-pill" : "alive-pill exited"}>
                        target {activeNativeSession.targetProcessId} {activeNativeSession.targetAlive ? "alive" : "exited"}
                      </small>
                    ) : null}
                    <button
                      type="button"
                      className="tool-button"
                      onClick={handleStopNativeSession}
                      disabled={!canStopNativeSession}
                      title={activeNativeSession.recoveryAction || "Stop native session"}
                    >
                      <Square size={13} />
                      <span>Stop</span>
                    </button>
                    {activeNativeSession.helperProcessId ? <small>helper {activeNativeSession.helperProcessId}</small> : null}
                    {activeNativeSession.daemonProcessId ? <small>daemon {activeNativeSession.daemonProcessId}</small> : null}
                    {activeNativeSession.recoveryState ? <small>{activeNativeSession.recoveryState}/{activeNativeSession.recoveryReason || "n/a"}</small> : null}
                    {activeNativeSession.pruneEligible ? <small>prune {activeNativeSession.pruneReason || "eligible"}</small> : null}
                    {activeNativeSession.daemonProcessId ? <small>alive d={activeNativeSession.daemonAlive ? "yes" : "no"} w={activeNativeSession.sessionProcessAlive ? "yes" : "no"}</small> : null}
                    {activeNativeSession.knapmPath ? <small title={activeNativeSession.knapmPath}>{activeNativeSession.knapmPath}</small> : null}
                    {activeNativeSession.staleReason ? <small>{activeNativeSession.staleReason}</small> : null}
                    {activeNativeSession.lastError ? <small>{activeNativeSession.lastError}</small> : null}
                  </div>
                ) : null}

                <div className="action-subpanel">
                  <div className="action-subtitle">
                    <Activity size={13} />
                    <span>Attach Monitor</span>
                  </div>
                  <div className="action-controls attach-controls">
                    <label htmlFor="attach-duration">Capture ms</label>
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
                      <span>Capture Window</span>
                    </button>
                    <button type="button" className="tool-button" onClick={handleStartStreamingAttach} disabled={!canRunTargetAction}>
                      <Activity size={13} />
                      <span>Attach &amp; Monitor</span>
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
                      <div>events={attachResult.capturedEvents.length}; {resolverPointerCountSummary(attachResult)}; dropped={attachResult.droppedEvents}; transport={attachResult.transportRecordsConsumed}/{attachResult.transportRecordsProduced}</div>
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
                  <span>Start New Process</span>
                </div>
                <div className="launch-grid">
                  <label>Executable</label>
                  <div className={launchTargetPath ? "launch-selected-path" : "launch-selected-path empty"} title={launchTargetPath || "Choose an executable with Launch & Monitor"}>
                    {launchTargetPath || "Choose with Launch & Monitor"}
                  </div>
                  <label htmlFor="launch-working-directory">Working dir</label>
                  <input
                    id="launch-working-directory"
                    type="text"
                    value={launchWorkingDirectory}
                    onChange={(event) => setLaunchWorkingDirectory(event.target.value)}
                    placeholder="defaults to executable folder"
                  />
                  <label htmlFor="launch-arguments">Arguments</label>
                  <input
                    id="launch-arguments"
                    type="text"
                    value={launchArguments}
                    onChange={(event) => setLaunchArguments(event.target.value)}
                    placeholder="optional command-line parameters"
                  />
                  <label>Lifetime</label>
                  <span className="launch-selected-path">until stopped</span>
                </div>
                <div className="launch-mode-strip">
                  <span>early-bird APC</span>
                  <span>same-bitness</span>
                  <span>agent64</span>
                  <span>manual stop</span>
                </div>
                <div className="launch-actions">
                  <button type="button" className="tool-button primary launch-primary-button" onClick={handleStartLaunchMonitor} disabled={!canLaunchMonitor}>
                    <Play size={14} />
                    <span>{launchButtonLabel}</span>
                  </button>
                  <button type="button" className="tool-button" onClick={handleRefreshSessionCatalog} disabled={nativeBusy}>
                    <RefreshCcw size={14} />
                    <span>Refresh Catalog</span>
                  </button>
                  <button type="button" className="tool-button" onClick={handleStopNativeSession} disabled={!canStopNativeSession}>
                    <Square size={13} />
                    <span>Stop Session</span>
                  </button>
                </div>
                {currentLaunchSession ? (
                  <div className={currentLaunchSession.sessionState === "failed" || currentLaunchSession.sessionState === "recovery_required" ? "launch-result failure" : "launch-result success"}>
                    {currentLaunchSession.sessionKind} / PID {currentLaunchSession.targetProcessId || "pending"} / {currentLaunchSession.recordsStreamed} records / {currentLaunchSession.sessionState}
                  </div>
                ) : null}
                {captureResult ? (
                  <div className={captureResult.success ? "launch-result success" : "launch-result failure"}>
                    PID {captureResult.targetProcessId} / {captureResult.captureMode} / events={captureResult.capturedEvents.length} / {resolverPointerCountSummary(captureResult)} / {captureResult.message}
                  </div>
                ) : null}
                {lastSession ? (
                  <div className={lastSession.success ? "launch-result success" : "launch-result failure"}>
                    session {lastSession.sessionId || "replayed-session"} / events={lastSession.traceEventCount} / {lastSession.message}
                  </div>
                ) : null}
              </div>
              <div className="catalog-browser session-catalog-panel">
                  <div className="catalog-summary">
                    <Database size={14} />
                    <strong>{sessionCatalog ? `${sessionCatalog.sessionCount} sessions` : "Catalog"}</strong>
                    <span>{sessionCatalog ? `${sessionCatalog.validSessionCount} valid` : "not loaded"}</span>
                    <span>{sessionCatalog ? `${sessionCatalog.invalidSessionCount} invalid` : "0 invalid"}</span>
                    <span>{sessionCatalog ? `${formatBytes(sessionCatalog.storedBytes)} stored` : "0 B stored"}</span>
                    <span>{sessionCatalog?.databasePath ? `DB ${sessionCatalog.indexBackend || "index"}` : "JSON catalog"}</span>
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
                  <div className="catalog-index-controls">
                    <span>Index</span>
                    <button type="button" className="tool-button" onClick={() => handleBuildSessionCatalogIndex(false)} disabled={nativeBusy}>
                      <Database size={13} />
                      <span>Build DB</span>
                    </button>
                    <button type="button" className="tool-button" onClick={() => handleBuildSessionCatalogIndex(true)} disabled={nativeBusy}>
                      <RefreshCcw size={13} />
                      <span>Rebuild DB</span>
                    </button>
                    <button type="button" className="tool-button" onClick={handleQuerySessionCatalogIndex} disabled={nativeBusy}>
                      <Search size={13} />
                      <span>Query DB</span>
                    </button>
                    <button type="button" className="tool-button" onClick={() => handleRemoveMissingCatalogIndexEntries(true)} disabled={nativeBusy}>
                      <Trash2 size={13} />
                      <span>Dry DB</span>
                    </button>
                    <button type="button" className="tool-button danger" onClick={() => handleRemoveMissingCatalogIndexEntries(false)} disabled={nativeBusy}>
                      <Trash2 size={13} />
                      <span>Prune DB</span>
                    </button>
                  </div>
                  {sessionCatalog?.databasePath ? (
                    <div className="catalog-selected" title={sessionCatalog.databasePath}>
                      index {sessionCatalog.indexSchemaVersion ?? 0} / stale identity {sessionCatalog.staleIdentityCount ?? 0} / {sessionCatalog.databasePath}
                    </div>
                  ) : null}
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
                  <div className="trace-index-panel">
                    <div className="trace-index-summary">
                      <Search size={14} />
                      <strong>{traceIndex ? `${traceIndex.matchedEventCount} hits` : "Trace Search"}</strong>
                      <span>{traceIndex ? `${traceIndex.eventCount} indexed` : "0 indexed"}</span>
                      <span>{traceIndex ? `${traceIndex.indexedSessionCount}/${traceIndex.sessionCount} sessions` : "0 sessions"}</span>
                    </div>
                    <div className="trace-index-controls">
                      <label htmlFor="trace-index-text">Text</label>
                      <input
                        id="trace-index-text"
                        type="search"
                        value={traceIndexText}
                        onChange={(event) => setTraceIndexText(event.target.value)}
                        placeholder="api arg tag"
                      />
                      <label htmlFor="trace-index-api">API</label>
                      <input
                        id="trace-index-api"
                        type="search"
                        value={traceIndexApi}
                        onChange={(event) => setTraceIndexApi(event.target.value)}
                        placeholder="CreateFileW"
                      />
                      <label htmlFor="trace-index-module">Module</label>
                      <input
                        id="trace-index-module"
                        type="search"
                        value={traceIndexModule}
                        onChange={(event) => setTraceIndexModule(event.target.value)}
                        placeholder="kernel32.dll"
                      />
                      <label htmlFor="trace-index-limit">Limit</label>
                      <input
                        id="trace-index-limit"
                        type="number"
                        min={1}
                        max={1000}
                        value={traceIndexLimit}
                        onChange={(event) => setTraceIndexLimit(Math.min(1000, Math.max(1, Number.parseInt(event.target.value, 10) || 1)))}
                      />
                    </div>
                    <div className="trace-index-actions">
                      <button type="button" className="tool-button" onClick={() => handleBuildTraceIndex(false)} disabled={nativeBusy}>
                        <Database size={13} />
                        <span>Build Trace DB</span>
                      </button>
                      <button type="button" className="tool-button" onClick={() => handleBuildTraceIndex(true)} disabled={nativeBusy}>
                        <RefreshCcw size={13} />
                        <span>Rebuild Trace DB</span>
                      </button>
                      <button type="button" className="tool-button" onClick={handleQueryTraceIndex} disabled={nativeBusy}>
                        <Search size={13} />
                        <span>Search Trace</span>
                      </button>
                      <button type="button" className="tool-button" onClick={() => handleRemoveMissingTraceIndexEntries(true)} disabled={nativeBusy}>
                        <Trash2 size={13} />
                        <span>Dry Trace</span>
                      </button>
                      <button type="button" className="tool-button danger" onClick={() => handleRemoveMissingTraceIndexEntries(false)} disabled={nativeBusy}>
                        <Trash2 size={13} />
                        <span>Prune Trace</span>
                      </button>
                    </div>
                    {traceIndex?.databasePath ? (
                      <div className="catalog-selected" title={traceIndex.databasePath}>
                        trace index {traceIndex.indexSchemaVersion} / {traceIndex.indexBackend} / {traceIndex.databasePath}
                      </div>
                    ) : null}
                    {traceIndex && traceIndex.events.length > 0 ? (
                      <div className="trace-index-row-list" aria-label="Trace index search results">
                        {traceIndex.events.map((event) => {
                          const key = traceIndexEventKey(event);
                          return (
                            <div className={selectedTraceIndexEventKey === key ? "trace-index-row selected" : "trace-index-row"} key={key}>
                              <button type="button" className="trace-index-row-main" title={event.excerpt} onClick={() => setSelectedTraceIndexEventKey(key)}>
                                <strong>{traceIndexEventLabel(event)}</strong>
                                <span>PID {event.pid || event.targetProcessId || "n/a"} / TID {event.tid || "n/a"}</span>
                                <span>{event.sessionId || "session n/a"}</span>
                                <span>event {event.eventId}</span>
                                <span>{event.durationUs} us</span>
                                <small>{event.excerpt}</small>
                              </button>
                              <button type="button" className="tool-button" onClick={() => handleReplayTraceIndexEvent(event)} disabled={nativeBusy}>
                                <FolderOpen size={13} />
                                <span>Replay</span>
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="catalog-empty">No trace index hits loaded.</div>
                    )}
                    {selectedTraceIndexEvent ? (
                      <div className="catalog-selected" title={selectedTraceIndexEvent.sessionPath}>
                        selected {traceIndexEventLabel(selectedTraceIndexEvent)} / event {selectedTraceIndexEvent.eventId} / {fileNameFromPath(selectedTraceIndexEvent.sessionPath)}
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
                <span>Monitoring APIs</span>
              </div>
              <div className={apiSelectionBlocked ? "api-scope-panel full blocked" : "api-scope-panel full"}>
                <div className="api-scope-header">
                  <div>
                    <strong>{selectedApiList.length}/{apiLeafKeys.length} APIs</strong>
                    <span>{selectedApiModules} selected modules; partial selection is sent as an agent allowlist</span>
                  </div>
                </div>
                <div className="api-scope-actions">
                  <button type="button" onClick={handleSelectAllApis} disabled={nativeBusy || activeNativeSession !== null}>All</button>
                  <button type="button" onClick={handleClearApiSelection} disabled={nativeBusy || activeNativeSession !== null}>None</button>
                  <select
                    aria-label="Apply API profile"
                    value=""
                    onChange={(event) => handleApplyCaptureProfile(event.target.value)}
                    disabled={nativeBusy || activeNativeSession !== null}
                  >
                    <option value="" disabled>Profile</option>
                    {captureProfiles.map((profile) => (
                      <option value={profile.id} key={profile.id}>{profile.name}</option>
                    ))}
                  </select>
                </div>
                <div className="api-scope-tree" aria-label="Monitoring API checkbox tree">
                  {renderApiTree(
                    apiTree,
                    selectedApiKeys,
                    expandedApiNodes,
                    handleToggleApiNode,
                    handleToggleApiExpanded,
                    nativeBusy || activeNativeSession !== null
                  )}
                </div>
                {apiSelectionBlocked ? <div className="scope-warning">No API selected. Launch and attach are disabled.</div> : null}
              </div>
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
                  <button
                    type="button"
                    className="profile-row"
                    key={profile.id}
                    onClick={() => handleApplyCaptureProfile(profile.id)}
                    disabled={nativeBusy || activeNativeSession !== null}
                  >
                    <strong>{profile.name}</strong>
                    <span>{profile.description}</span>
                    <small>{profile.enabledApis.length} APIs</small>
                  </button>
                ))}
              </div>
            </section>
          ) : null}
        </aside>

        <section className="main-panel" style={mainPanelStyle}>
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
              <label className="auto-scroll-toggle" title="Follow the latest trace row while events stream">
                <input
                  type="checkbox"
                  checked={traceAutoScroll}
                  onChange={(event) => handleTraceAutoScrollChange(event.target.checked)}
                />
                <span>Auto-scroll</span>
              </label>
              <span>{filteredEvents.length}/{events.length} rows</span>
              <span>{totalTraceEventCount} total</span>
              {trimmedTraceEventCount > 0 ? <span>last {events.length} shown</span> : null}
              <span>DOM {visibleTraceEvents.length}</span>
              {activeCurrentLogFilterCount > 0 ? <span>{activeCurrentLogFilterCount} filters</span> : null}
              {compiledTraceQuery.activeClauseCount > 0 ? <span>{compiledTraceQuery.activeClauseCount} view rules</span> : null}
              {compiledTraceQuery.invalidClauses.length > 0 ? <span>{compiledTraceQuery.invalidClauses.length} invalid rules</span> : null}
              {traceHighlightState.eventHighlights.length > 0 ? <span>{traceHighlightState.eventHighlights.length} highlighted</span> : null}
              {replaySource ? <span title={replaySource.path}>Replay {replaySource.label} / {replaySource.validationStatus}</span> : null}
            </div>
          </div>

          <div className="query-panel current-filter-panel">
            <div className="query-header">
              <div className="query-title">
                <Filter size={14} />
                <strong>Current Log Filters</strong>
                <span>{activeCurrentLogFilterCount} filters; {filteredEvents.length}/{events.length} rows</span>
              </div>
              <div className="query-actions">
                <button type="button" className="tool-button" onClick={handleClearTraceFilters}>
                  <Trash2 size={13} />
                  <span>Clear</span>
                </button>
              </div>
            </div>
            <div className="quick-filter-grid">
              <label htmlFor="quick-api-filter">API</label>
              <input
                id="quick-api-filter"
                type="search"
                value={quickApiFilter}
                onChange={(event) => setQuickApiFilter(event.target.value)}
                placeholder="CreateFileW"
              />
              <label htmlFor="quick-module-filter">DLL</label>
              <input
                id="quick-module-filter"
                type="search"
                value={quickModuleFilter}
                onChange={(event) => setQuickModuleFilter(event.target.value)}
                placeholder="kernel32.dll"
              />
              <label htmlFor="quick-parameter-filter">Parameter</label>
              <input
                id="quick-parameter-filter"
                type="search"
                value={quickParameterFilter}
                onChange={(event) => setQuickParameterFilter(event.target.value)}
                placeholder="lpFileName or C:\\Temp"
              />
            </div>
            {compiledTraceQuery.activeClauseCount > 0 || compiledTraceQuery.invalidClauses.length > 0 ? (
              <div className="view-rule-strip">
                <Filter size={13} />
                <span>{traceQueryMatchMode}; {compiledTraceQuery.activeClauseCount} view rules; {compiledTraceQuery.invalidClauses.length} invalid</span>
              </div>
            ) : null}
            <div className="highlight-panel">
              <div className="highlight-toolbar">
                <div className="query-title">
                  <CircleDot size={14} />
                  <strong>Highlight Rules</strong>
                  <span>{traceHighlightState.eventHighlights.length} events; {visibleHighlightSummaries.length} rules</span>
                </div>
                <label className="highlight-toggle">
                  <input
                    type="checkbox"
                    checked={highlightingEnabled}
                    onChange={(event) => setHighlightingEnabled(event.target.checked)}
                  />
                  <span>Enabled</span>
                </label>
              </div>
              <div className="highlight-summary-list">
                {visibleHighlightSummaries.map((summary) => (
                  <button
                    type="button"
                    className={`highlight-rule-card ${summary.severity}`}
                    key={summary.id}
                    disabled={summary.count === 0}
                    onClick={() => handleApplyHighlightSummary(summary)}
                  >
                    <span>{summary.severity}</span>
                    <strong>{summary.label}</strong>
                    <em>{summary.count}</em>
                    <small>{summary.detail}</small>
                    <small>{summary.samples.length > 0 ? summary.samples.map((sample) => `#${sample.eventId} ${sample.module || "n/a"}!${sample.api || "n/a"} ${sample.reason}`).join("; ") : "no matches"}</small>
                  </button>
                ))}
              </div>
            </div>
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
            <table className="trace-table trace-table-head" style={{ minWidth: traceTableWidth, width: traceTableWidth }}>
              <colgroup>
                {traceColumns.map((column, index) => (
                  <col key={column.id} style={{ width: traceColumnWidths[index] }} />
                ))}
              </colgroup>
              <thead>
                <tr>
                  {traceColumns.map((column, index) => (
                    <th className="resizable-column" key={column.id} style={{ width: traceColumnWidths[index] }}>
                      <span>{column.label}</span>
                      <button
                        type="button"
                        className="column-resize-handle"
                        aria-label={`Resize ${column.label} column`}
                        title="Drag to resize; double-click to reset"
                        onPointerDown={(event) => startColumnResize(traceColumns, traceColumnWidths, setTraceColumnWidths, index, event)}
                        onDoubleClick={(event) => {
                          event.preventDefault();
                          resetColumnWidth(traceColumns, setTraceColumnWidths, index);
                        }}
                      />
                    </th>
                  ))}
                </tr>
              </thead>
            </table>
            <div className="trace-virtual-body" style={{ height: virtualTraceWindow.totalHeight, minWidth: traceTableWidth, width: traceTableWidth }}>
              <div className="trace-virtual-window" style={{ transform: `translateY(${virtualTraceWindow.offsetTop}px)` }}>
                {visibleTraceEvents.map((event, index) => {
                  const eventHighlight = traceHighlightState.eventHighlightsById.get(event.eventId) ?? null;

                  return (
                    <button
                      type="button"
                      key={event.eventId}
                      className={[
                        "trace-virtual-row",
                        selectedEvent?.eventId === event.eventId ? "selected" : "",
                        (virtualTraceWindow.startIndex + index) % 2 === 1 ? "alt" : "",
                        highlightingEnabled && eventHighlight ? `highlight-${eventHighlight.highestSeverity}` : ""
                      ].filter(Boolean).join(" ")}
                      style={{ height: traceRowHeight, gridTemplateColumns: traceGridTemplate, minWidth: traceTableWidth, width: traceTableWidth }}
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
                        {highlightingEnabled && eventHighlight ? eventHighlight.matches.slice(0, 2).map((match) => (
                          <span className={`highlight-badge ${match.severity}`} key={`${event.eventId}-${match.ruleId}`}>{match.label}</span>
                        )) : null}
                        {event.tags.map((tag) => (
                          <span key={tag}>{tag}</span>
                        ))}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
            {filteredEvents.length === 0 ? <div className="trace-empty">No trace events match the current filters.</div> : null}
          </div>

          <div
            className="trace-panel-resizer"
            role="separator"
            aria-orientation="horizontal"
            aria-label="Resize trace details"
            title="Drag to resize trace rows and details"
            onPointerDown={handleInspectorResizeStart}
          />

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
                  {selectedEvent && selectedEventHighlight ? (
                    <div className="highlight-inspector">
                      <div className="highlight-inspector-title">
                        <CircleDot size={14} />
                        <strong>Matched Rules</strong>
                        <span>{selectedEventHighlight.matches.length}</span>
                      </div>
                      <div className="highlight-inspector-list">
                        {selectedEventHighlight.matches.map((match) => (
                          <div className={`highlight-inspector-rule ${match.severity}`} key={`${selectedEvent.eventId}-${match.ruleId}`}>
                            <span>{match.severity}</span>
                            <strong>{match.label}</strong>
                            <small>{match.reason}</small>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {selectedEvent && inspectorTab === "parameters" ? (
                    <table className="detail-table" style={{ minWidth: detailTableWidth, width: detailTableWidth }}>
                      <colgroup>
                        {detailColumns.map((column, index) => (
                          <col key={column.id} style={{ width: detailColumnWidths[index] }} />
                        ))}
                      </colgroup>
                      <thead>
                        <tr>
                          {detailColumns.map((column, index) => (
                            <th className="resizable-column" key={column.id} style={{ width: detailColumnWidths[index] }}>
                              <span>{column.label}</span>
                              <button
                                type="button"
                                className="column-resize-handle"
                                aria-label={`Resize ${column.label} column`}
                                title="Drag to resize; double-click to reset"
                                onPointerDown={(event) => startColumnResize(detailColumns, detailColumnWidths, setDetailColumnWidths, index, event)}
                                onDoubleClick={(event) => {
                                  event.preventDefault();
                                  resetColumnWidth(detailColumns, setDetailColumnWidths, index);
                                }}
                              />
                            </th>
                          ))}
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
                      <div><Filter size={14} /> api="{quickApiFilter || "*"}"; dll="{quickModuleFilter || "*"}"; parameter="{quickParameterFilter || "*"}"; filteredRows={filteredEvents.length}</div>
                      <div><Filter size={14} /> viewRules={traceQueryMatchMode}; active={compiledTraceQuery.activeClauseCount}; invalid={compiledTraceQuery.invalidClauses.length}</div>
                      <div><Activity size={14} /> totalCaptured={totalTraceEventCount}; displayedRows={events.length}; trimmedRows={trimmedTraceEventCount}; displayLimit={traceDisplayEventLimit}</div>
                      <div><CircleDot size={14} /> highlighting={highlightingEnabled ? "enabled" : "disabled"}; highlightedRows={traceHighlightState.eventHighlights.length}</div>
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
        <span>State: {displayNativeSession ? displayNativeSession.sessionState : "idle"}</span>
        {processExitNotice ? <span>Target exited: {processExitNotice.targetProcessId}</span> : null}
        <span>Events: {events.length}/{totalTraceEventCount}</span>
        {trimmedTraceEventCount > 0 ? <span>Trimmed: {trimmedTraceEventCount}</span> : null}
        <span>Dropped: {droppedCount}</span>
        <span>Session: {formatBytes(sessionBytes)}</span>
        <span>Backend: {backendMode}</span>
        <span>Protocol: 0.1.0</span>
      </footer>
    </div>
  );
}

export default App;
