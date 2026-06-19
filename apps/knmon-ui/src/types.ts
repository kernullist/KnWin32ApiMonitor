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
  daemonProcessId: number;
  daemonInstanceId: string;
  daemonStartedUtc: string;
  daemonHeartbeatUtc: string;
  daemonControlEndpoint: string;
  knapmPath: string;
  daemonAlive: boolean;
  sessionProcessAlive: boolean;
  targetAlive: boolean;
  knapmExists: boolean;
  knapmValid: boolean;
  recoveryState: string;
  recoveryReason: string;
  pruneEligible: boolean;
  pruneReason: string;
}

export interface NativeDaemonStatus {
  schemaVersion: string;
  success: boolean;
  backendMode: BackendMode;
  operation: string;
  daemonState: "running" | "stopped" | "not_running" | "start_failed" | "stop_timeout" | string;
  daemonProcessId: number;
  daemonInstanceId: string;
  daemonStartedUtc: string;
  daemonHeartbeatUtc: string;
  controlEndpoint: string;
  runtimeDirectory: string;
  sessionCount: number;
  win32ErrorCode: number;
  message: string;
}

export interface NativeDaemonAudit {
  schemaVersion: string;
  success: boolean;
  backendMode: BackendMode;
  operation: string;
  daemon: NativeDaemonStatus;
  sessions: NativeSession[];
  pruneEligibleCount: number;
  dryRun: boolean;
  mutationAttempted: boolean;
  prunedSessionIds: string[];
  win32ErrorCode: number;
  message: string;
}

export interface NativeDaemonRecoveryPlanItem {
  schemaVersion: string;
  sessionId: string;
  recoveryState: string;
  recoveryReason: string;
  recommendedAction: string;
  safetyState: string;
  automaticRecoveryAllowed: boolean;
  targetMutationAllowed: boolean;
  registryPruneAllowed: boolean;
  replayAllowed: boolean;
  blockedMutations: string[];
  operatorRunbook: string[];
  message: string;
}

export interface NativeDaemonRecoveryPlan {
  schemaVersion: string;
  success: boolean;
  backendMode: BackendMode;
  operation: string;
  daemon: NativeDaemonStatus;
  sessions: NativeSession[];
  recoveryPlans: NativeDaemonRecoveryPlanItem[];
  recoveryPlanCount: number;
  registryPruneAllowedCount: number;
  blockedMutationCount: number;
  automaticRecoveryAllowed: boolean;
  targetMutationAllowed: boolean;
  dryRun: boolean;
  mutationAttempted: boolean;
  win32ErrorCode: number;
  message: string;
}

export interface NativeSessionCatalogRow {
  path: string;
  format: string;
  sessionId: string;
  operationId: string;
  targetProcessId: number;
  targetImage: string;
  targetPath: string;
  targetArchitecture: string;
  ownerKind: string;
  daemonInstanceId: string;
  writerState: string;
  finalized: boolean;
  recoveryState: string;
  recoveryReason: string;
  recoveryAction: string;
  chunkCount: number;
  traceEventCount: number;
  lastBatchSequence: number;
  lastRecordSequence: number;
  compression: string;
  storedBytes: number;
  uncompressedBytes: number;
  validationSuccess: boolean;
  validationErrorCount: number;
  validationStatus: "valid" | "invalid" | string;
  lastValidatedUtc: string;
  contentIdentity: string;
  staleIdentity: boolean;
}

export interface NativeSessionCatalog {
  schemaVersion: string;
  format: string;
  buildTimeUtc: string;
  backendMode: BackendMode;
  operation: string;
  success: boolean;
  rootPath: string;
  catalogPath: string;
  databasePath?: string;
  indexBackend?: string;
  indexSchemaVersion?: number;
  staleIdentityCount?: number;
  sessionCount: number;
  validSessionCount: number;
  invalidSessionCount: number;
  storedBytes: number;
  uncompressedBytes: number;
  dryRun: boolean;
  mutationAttempted: boolean;
  missingSessionPaths: string[];
  sessions: NativeSessionCatalogRow[];
  message: string;
}

export interface NativeTraceIndexEvent {
  sessionPath: string;
  sessionId: string;
  operationId: string;
  eventId: number;
  recordSequence: number;
  chunkSequence: number;
  batchSequence: number;
  targetProcessId: number;
  pid: number;
  tid: number;
  process: string;
  module: string;
  api: string;
  returnValue: string;
  errorText: string;
  durationUs: number;
  relativeTimeMs: number;
  tagsText: string;
  argumentsText: string;
  bufferPreview: string;
  excerpt: string;
  eventJson: string;
}

export interface NativeTraceIndex {
  schemaVersion: string;
  format: string;
  buildTimeUtc: string;
  backendMode: BackendMode;
  operation: string;
  success: boolean;
  rootPath: string;
  databasePath: string;
  indexBackend: string;
  indexSchemaVersion: number;
  sessionCount: number;
  indexedSessionCount: number;
  invalidSessionCount: number;
  eventCount: number;
  matchedEventCount: number;
  dryRun: boolean;
  mutationAttempted: boolean;
  missingSessionPaths: string[];
  events: NativeTraceIndexEvent[];
  message: string;
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
  recoveryState: string;
  recoveryReason: string;
  recoveryAction: string;
  ownerAlive: boolean;
  helperAlive: boolean;
  writerAlive: boolean;
  targetAlive: boolean;
  leaseExpired: boolean;
  restartEligible: boolean;
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
