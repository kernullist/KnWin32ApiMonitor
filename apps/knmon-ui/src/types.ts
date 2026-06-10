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
  attachProcessId?: number;
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

export interface CaptureResult {
  schemaVersion: string;
  operationId: string;
  success: boolean;
  backendMode: BackendMode;
  captureMode: string;
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
  detachPolicy?: string;
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

export interface SessionInfo {
  schemaVersion: string;
  success: boolean;
  sessionId: string;
  sessionPath: string;
  createdUtc: string;
  traceEventCount: number;
  agentEventCount: number;
  auditEventCount: number;
  droppedEvents: number;
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
