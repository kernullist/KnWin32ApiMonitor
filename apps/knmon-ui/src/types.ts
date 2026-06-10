export type BackendMode = "mock" | "native-enum" | "native-capture";

export type SessionStateName = "stopped" | "running";

export type InspectorTab =
  | "parameters"
  | "buffer"
  | "stack"
  | "return"
  | "output";

export interface TargetProcess {
  pid: number;
  parentPid?: number | null;
  imageName: string;
  imagePath?: string | null;
  architecture: string;
  status: string;
}

export interface CaptureSessionState {
  state: SessionStateName;
  backendMode: BackendMode;
  eventCount: number;
  droppedEvents: number;
}

export interface NativeOperation {
  operationId: string;
  operationKind: "capture_sample" | "attach_capture" | "process_tree_supervision" | "agent_cleanup" | string;
  targetProcessId: number;
  state: "queued" | "running" | "cancel_requested" | "stopping_agent" | "draining" | "completed" | "failed" | "cancelled" | "cleanup_failed" | string;
  cancelRequested: boolean;
  elapsedMs: number;
  durationMs: number;
}

export interface NativeSession {
  schemaVersion: string;
  sessionId: string;
  operationId: string;
  sessionKind: string;
  ownerProcessId: number;
  helperProcessId: number;
  targetProcessId: number;
  sessionState: "created" | "starting" | "running" | "stop_requested" | "stopping_agent" | "draining" | "stopped" | "failed" | "stale" | "recovery_required" | string;
  startedUtc: string;
  updatedUtc: string;
  stoppedUtc: string;
  cancellationEventName: string;
  lastTransportSequence: number;
  recordsStreamed: number;
  transportDroppedEvents: number;
  hostDroppedBatches: number;
  staleReason: string;
  recoveryAction: string;
  shutdownEvidence: string;
  stopRequested: boolean;
  agentCleanupAttempted: boolean;
  agentCleanupSucceeded: boolean;
  lastError: string;
  elapsedMs: number;
  durationMs: number;
}

export interface AuditEvent {
  schemaVersion: string;
  operationId: string;
  eventType: string;
  timestampUtc: string;
  subsystem: string;
  operation: string;
  win32ErrorCode: number;
  ntStatus: string;
  message: string;
}

export interface AgentHandshake {
  received: boolean;
  schemaVersion: string;
  operationId: string;
  processId: number;
  threadId: number;
  architecture: string;
  agentVersion: string;
  message: string;
  rawPayload: string;
}

export interface LaunchResult {
  schemaVersion: string;
  operationId: string;
  success: boolean;
  backendMode: BackendMode;
  injectionMethod: string;
  targetPath: string;
  agentPath: string;
  targetProcessId: number;
  targetThreadId: number;
  architecture: string;
  win32ErrorCode: number;
  ntStatus: string;
  subsystem: string;
  operation: string;
  message: string;
  handshake: AgentHandshake;
  auditEvents: AuditEvent[];
}

export interface AgentApiArgument {
  index: number;
  type: string;
  name: string;
  direction: "in" | "out" | "inout" | "return";
  rawValue: string;
  preCallValue: string;
  postCallValue: string;
  decodedValue: string;
  decodeStatus: "decoded" | "partial" | "invalid_pointer" | "unreadable_memory" | "definition_missing" | "truncated";
  decodeAlias?: string;
  captureTiming?: "pre" | "post" | "pre_post";
}

export interface AgentApiCallEvent {
  schemaVersion: string;
  messageType: "api_call";
  operationId: string;
  pid: number;
  tid: number;
  timestampUtc: string;
  sequence: number;
  api: string;
  module: string;
  apiFamily?: string;
  apiCategory?: string;
  apiRisk?: "low" | "medium" | "high" | "critical";
  hookPolicy?: string;
  coverageStatus?: string;
  process: string;
  returnValue: string;
  lastErrorCode: number;
  lastErrorMessage: string;
  durationUs: number;
  arguments: AgentApiArgument[];
  tags: string[];
  stack: string[];
  bufferPreview: string;
}

export interface NativeTraceBatch {
  schemaVersion: string;
  frameType: "trace_batch";
  sessionId: string;
  operationId: string;
  batchSequence: number;
  firstRecordSequence: number;
  lastRecordSequence: number;
  eventCount: number;
  droppedEvents: number;
  recordsStreamed: number;
  hostDroppedBatches: number;
  events: AgentApiCallEvent[];
}

export interface CaptureResult {
  schemaVersion: string;
  operationId: string;
  sessionId?: string;
  sessionState?: string;
  sessionKind?: string;
  ownerProcessId?: number;
  helperProcessId?: number;
  startedUtc?: string;
  updatedUtc?: string;
  stoppedUtc?: string;
  cancellationEventName?: string;
  lastTransportSequence?: number;
  recordsStreamed?: number;
  staleReason?: string;
  recoveryAction?: string;
  sessionShutdownEvidence?: string;
  success: boolean;
  backendMode: BackendMode;
  captureMode: string;
  injectionMethod: string;
  targetPath: string;
  agentPath: string;
  attachProcessId?: number;
  targetProcessId: number;
  targetThreadId: number;
  architecture: string;
  win32ErrorCode: number;
  ntStatus: string;
  subsystem: string;
  operation: string;
  message: string;
  detachPolicy?: string;
  cancelRequested?: boolean;
  cancelObserved?: boolean;
  cancelStage?: string;
  operationState?: string;
  agentCleanupAttempted?: boolean;
  agentCleanupSucceeded?: boolean;
  staleAgentOperationId?: string;
  staleAgentState?: string;
  attachState?: string;
  attachStrategy?: string;
  loadedAgentDetected?: boolean;
  loadedAgentModuleBase?: number;
  loadedAgentPath?: string;
  agentControlStatus?: number;
  agentAbiVersion?: number;
  droppedEvents: number;
  transportMode: string;
  transportCapacity: number;
  transportRecordsProduced: number;
  transportRecordsConsumed: number;
  transportDroppedEvents: number;
  transportHighWaterMark: number;
  hookOverheadMinUs: number;
  hookOverheadAvgUs: number;
  hookOverheadMaxUs: number;
  handshake: AgentHandshake;
  auditEvents: AuditEvent[];
  agentMessages: unknown[];
  capturedEvents: AgentApiCallEvent[];
  session?: SessionInfo | null;
}

export interface ProcessTreeNode {
  processId: number;
  parentProcessId: number;
  isRoot: boolean;
  imageName: string;
  imagePath: string;
  architecture: string;
  firstSeenUtc: string;
  lastSeenUtc: string;
  isAlive: boolean;
  exited: boolean;
  eligibilityStatus: "eligible" | "missing" | "exited" | "unknown_architecture" | "helper_target_mismatch" | "access_denied" | "protected_process" | "unsupported";
  policyDecision: "observe_only" | "attach_allowed" | "attach_skipped" | "attach_failed" | "unsupported";
  message: string;
}

export interface ChildPolicyDecision {
  processId: number;
  parentProcessId: number;
  imageName: string;
  architecture: string;
  eligibilityStatus: ProcessTreeNode["eligibilityStatus"];
  decision: ProcessTreeNode["policyDecision"];
  mutationAttempted: boolean;
  attachSucceeded: boolean;
  reason: string;
}

export interface ProcessTreeResult {
  schemaVersion: string;
  operationId: string;
  sessionId?: string;
  sessionState?: string;
  sessionKind?: string;
  ownerProcessId?: number;
  helperProcessId?: number;
  startedUtc?: string;
  updatedUtc?: string;
  stoppedUtc?: string;
  cancellationEventName?: string;
  lastTransportSequence?: number;
  recordsStreamed?: number;
  staleReason?: string;
  recoveryAction?: string;
  success: boolean;
  backendMode: BackendMode;
  supervisionMode: "process-tree";
  rootProcessId: number;
  durationMs: number;
  childPolicy: "observe" | "attach-supported";
  win32ErrorCode: number;
  ntStatus: string;
  subsystem: string;
  operation: string;
  message: string;
  cancelRequested?: boolean;
  cancelObserved?: boolean;
  cancelStage?: string;
  operationState?: string;
  processNodes: ProcessTreeNode[];
  policyDecisions: ChildPolicyDecision[];
  auditEvents: AuditEvent[];
  childAttachResults: CaptureResult[];
}

export interface SessionInfo {
  schemaVersion: string;
  success: boolean;
  format: string;
  sessionId: string;
  sessionPath: string;
  createdUtc: string;
  finalized: boolean;
  traceEventCount: number;
  agentEventCount: number;
  auditEventCount: number;
  droppedEvents: number;
  transportDroppedEvents: number;
  hostDroppedBatches: number;
  chunkCount: number;
  lastBatchSequence: number;
  lastRecordSequence: number;
  writerState: string;
  win32ErrorCode: number;
  message: string;
  validationErrors: string[];
}

export interface KnMonArgument {
  index: number;
  type: string;
  name: string;
  direction: "in" | "out" | "inout" | "return";
  preCallValue: string;
  postCallValue: string;
  rawValue: string;
  decodedValue: string;
  decodeStatus: "decoded" | "partial" | "invalid_pointer" | "unreadable_memory" | "definition_missing" | "truncated";
  decodeAlias?: string;
  captureTiming?: "pre" | "post" | "pre_post";
}

export interface TraceError {
  kind: "win32" | "ntstatus" | "hresult";
  code: string;
  message: string;
}

export interface TraceEvent {
  schemaVersion: string;
  eventId: number;
  relativeTimeMs: number;
  pid: number;
  tid: number;
  process: string;
  module: string;
  api: string;
  arguments: KnMonArgument[];
  returnValue: string;
  error: TraceError | null;
  durationUs: number;
  tags: string[];
  stack: string[];
  bufferPreview?: string;
}

export interface SessionReplayResult {
  schemaVersion: string;
  success: boolean;
  backendMode: BackendMode;
  captureMode: "session-replay";
  session: SessionInfo;
  message: string;
  traceEvents: TraceEvent[];
}

export interface ApiNode {
  id: string;
  label: string;
  checked: boolean;
  children?: ApiNode[];
}

export interface CaptureProfile {
  id: string;
  name: string;
  description: string;
  enabledApis: string[];
}
