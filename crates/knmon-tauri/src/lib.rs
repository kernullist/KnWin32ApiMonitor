#![recursion_limit = "256"]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_MAJOR: u16 = 0;
pub const PROTOCOL_MINOR: u16 = 1;
pub const PROTOCOL_PATCH: u16 = 0;
const STREAM_BATCH_QUEUE_LIMIT: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProcess
{
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_name: String,
    pub image_path: Option<String>,
    pub architecture: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeOperation
{
    pub operation_id: String,
    pub operation_kind: String,
    pub target_process_id: u32,
    pub state: String,
    pub cancel_requested: bool,
    pub elapsed_ms: u64,
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeSession
{
    pub schema_version: String,
    pub session_id: String,
    pub operation_id: String,
    pub session_kind: String,
    pub owner_process_id: u32,
    pub helper_process_id: u32,
    pub target_process_id: u32,
    pub session_state: String,
    pub started_utc: String,
    pub updated_utc: String,
    pub stopped_utc: String,
    pub cancellation_event_name: String,
    pub last_transport_sequence: u64,
    pub records_streamed: u64,
    #[serde(default)]
    pub transport_dropped_events: u64,
    #[serde(default)]
    pub host_dropped_batches: u64,
    pub stale_reason: String,
    pub recovery_action: String,
    pub shutdown_evidence: String,
    pub stop_requested: bool,
    pub agent_cleanup_attempted: bool,
    pub agent_cleanup_succeeded: bool,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub duration_ms: u32,
    #[serde(default)]
    pub daemon_process_id: u32,
    #[serde(default)]
    pub daemon_instance_id: String,
    #[serde(default)]
    pub daemon_started_utc: String,
    #[serde(default)]
    pub daemon_heartbeat_utc: String,
    #[serde(default)]
    pub daemon_control_endpoint: String,
    #[serde(default)]
    pub knapm_path: String,
    #[serde(default)]
    pub daemon_alive: bool,
    #[serde(default)]
    pub session_process_alive: bool,
    #[serde(default)]
    pub target_alive: bool,
    #[serde(default)]
    pub knapm_exists: bool,
    #[serde(default)]
    pub knapm_valid: bool,
    #[serde(default)]
    pub recovery_state: String,
    #[serde(default)]
    pub recovery_reason: String,
    #[serde(default)]
    pub prune_eligible: bool,
    #[serde(default)]
    pub prune_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonStatus
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon_state: String,
    pub daemon_process_id: u32,
    pub daemon_instance_id: String,
    pub daemon_started_utc: String,
    pub daemon_heartbeat_utc: String,
    pub control_endpoint: String,
    pub runtime_directory: String,
    pub session_count: u64,
    pub win32_error_code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonSessionResult
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon: NativeDaemonStatus,
    pub session: NativeSession,
    #[serde(default)]
    pub session_process_id: u32,
    #[serde(default)]
    pub knapm_path: String,
    pub win32_error_code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonSessionList
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon: NativeDaemonStatus,
    pub sessions: Vec<NativeSession>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonAudit
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon: NativeDaemonStatus,
    pub sessions: Vec<NativeSession>,
    pub prune_eligible_count: u64,
    pub dry_run: bool,
    pub mutation_attempted: bool,
    pub pruned_session_ids: Vec<String>,
    pub win32_error_code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonRecoveryPlanItem
{
    pub schema_version: String,
    pub session_id: String,
    pub recovery_state: String,
    pub recovery_reason: String,
    pub recommended_action: String,
    pub safety_state: String,
    pub automatic_recovery_allowed: bool,
    pub target_mutation_allowed: bool,
    pub registry_prune_allowed: bool,
    pub replay_allowed: bool,
    pub blocked_mutations: Vec<String>,
    pub operator_runbook: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonRecoveryPlan
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon: NativeDaemonStatus,
    pub sessions: Vec<NativeSession>,
    pub recovery_plans: Vec<NativeDaemonRecoveryPlanItem>,
    pub recovery_plan_count: u64,
    pub registry_prune_allowed_count: u64,
    pub blocked_mutation_count: u64,
    pub automatic_recovery_allowed: bool,
    pub target_mutation_allowed: bool,
    pub dry_run: bool,
    pub mutation_attempted: bool,
    pub win32_error_code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeDaemonRecoveryApply
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub operation: String,
    pub daemon: NativeDaemonStatus,
    pub sessions: Vec<NativeSession>,
    pub recovery_plans: Vec<NativeDaemonRecoveryPlanItem>,
    pub recovery_plan_count: u64,
    pub registry_prune_allowed_count: u64,
    pub blocked_mutation_count: u64,
    pub automatic_recovery_allowed: bool,
    pub target_mutation_allowed: bool,
    pub dry_run: bool,
    pub mutation_attempted: bool,
    pub pruned_session_ids: Vec<String>,
    pub win32_error_code: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeSessionCatalogRow
{
    pub path: String,
    pub format: String,
    pub session_id: String,
    pub operation_id: String,
    pub target_process_id: u32,
    pub target_image: String,
    pub target_path: String,
    pub target_architecture: String,
    pub owner_kind: String,
    pub daemon_instance_id: String,
    pub writer_state: String,
    pub finalized: bool,
    pub recovery_state: String,
    pub recovery_reason: String,
    pub recovery_action: String,
    pub chunk_count: u64,
    pub trace_event_count: u64,
    pub last_batch_sequence: u64,
    pub last_record_sequence: u64,
    pub compression: String,
    pub stored_bytes: u64,
    pub uncompressed_bytes: u64,
    pub validation_success: bool,
    pub validation_error_count: u64,
    pub validation_status: String,
    pub last_validated_utc: String,
    pub content_identity: String,
    pub stale_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeSessionCatalog
{
    pub schema_version: String,
    pub format: String,
    pub build_time_utc: String,
    pub backend_mode: String,
    pub operation: String,
    pub success: bool,
    pub root_path: String,
    pub catalog_path: String,
    #[serde(default)]
    pub database_path: String,
    #[serde(default)]
    pub index_backend: String,
    #[serde(default)]
    pub index_schema_version: u32,
    #[serde(default)]
    pub stale_identity_count: u64,
    pub session_count: u64,
    pub valid_session_count: u64,
    pub invalid_session_count: u64,
    pub stored_bytes: u64,
    pub uncompressed_bytes: u64,
    pub dry_run: bool,
    pub mutation_attempted: bool,
    pub missing_session_paths: Vec<String>,
    pub sessions: Vec<NativeSessionCatalogRow>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTraceIndexEvent
{
    pub session_path: String,
    pub session_id: String,
    pub operation_id: String,
    pub event_id: u64,
    pub record_sequence: u64,
    pub chunk_sequence: u64,
    pub batch_sequence: u64,
    pub target_process_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub module: String,
    pub api: String,
    pub return_value: String,
    pub error_text: String,
    pub duration_us: u64,
    pub relative_time_ms: u64,
    pub tags_text: String,
    pub arguments_text: String,
    pub buffer_preview: String,
    pub excerpt: String,
    pub event_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTraceIndex
{
    pub schema_version: String,
    pub format: String,
    pub build_time_utc: String,
    pub backend_mode: String,
    pub operation: String,
    pub success: bool,
    pub root_path: String,
    pub database_path: String,
    pub index_backend: String,
    pub index_schema_version: u32,
    pub session_count: u64,
    pub indexed_session_count: u64,
    pub invalid_session_count: u64,
    pub event_count: u64,
    pub matched_event_count: u64,
    pub dry_run: bool,
    pub mutation_attempted: bool,
    pub missing_session_paths: Vec<String>,
    pub events: Vec<NativeTraceIndexEvent>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTraceBatch
{
    pub schema_version: String,
    pub frame_type: String,
    pub session_id: String,
    pub operation_id: String,
    pub batch_sequence: u64,
    pub first_record_sequence: u64,
    pub last_record_sequence: u64,
    pub event_count: u64,
    pub dropped_events: u64,
    pub records_streamed: u64,
    pub host_dropped_batches: u64,
    pub events: Vec<AgentApiCallEvent>,
}

#[derive(Debug, Clone)]
struct NativeOperationRecord
{
    session_id: String,
    operation_id: String,
    operation_kind: String,
    target_process_id: u32,
    state: String,
    cancel_requested: bool,
    started_at: Instant,
    finished_at_ms: u128,
    duration_ms: u32,
    helper_process_id: u32,
    last_transport_sequence: u64,
    records_streamed: u64,
    transport_dropped_events: u64,
    host_dropped_batches: u64,
    last_batch_sequence: u64,
    trace_batches: VecDeque<NativeTraceBatch>,
    stale_reason: String,
    recovery_action: String,
    shutdown_evidence: String,
    agent_cleanup_attempted: bool,
    agent_cleanup_succeeded: bool,
    last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancellationSignalResult
{
    success: bool,
    operation_id: String,
    cancellation_event_name: String,
    win32_error_code: u32,
    operation: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTargetList
{
    pub schema_version: String,
    pub backend_mode: String,
    pub success: bool,
    pub win32_error_code: u32,
    pub subsystem: String,
    pub operation: String,
    pub message: String,
    pub targets: Vec<TargetProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent
{
    pub schema_version: String,
    pub operation_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub subsystem: String,
    pub operation: String,
    pub win32_error_code: u32,
    pub nt_status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHandshake
{
    pub received: bool,
    pub schema_version: String,
    pub operation_id: String,
    pub process_id: u32,
    pub thread_id: u32,
    pub architecture: String,
    pub agent_version: String,
    pub message: String,
    pub raw_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchResult
{
    pub schema_version: String,
    pub operation_id: String,
    pub success: bool,
    pub backend_mode: String,
    pub injection_method: String,
    pub target_path: String,
    pub agent_path: String,
    pub target_process_id: u32,
    pub target_thread_id: u32,
    pub architecture: String,
    pub win32_error_code: u32,
    pub nt_status: String,
    pub subsystem: String,
    pub operation: String,
    pub message: String,
    pub handshake: AgentHandshake,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApiArgument
{
    pub index: u32,
    #[serde(rename = "type")]
    pub argument_type: String,
    pub name: String,
    pub direction: String,
    pub raw_value: String,
    pub pre_call_value: String,
    pub post_call_value: String,
    pub decoded_value: String,
    pub decode_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApiCallEvent
{
    pub schema_version: String,
    pub message_type: String,
    pub operation_id: String,
    pub pid: u32,
    pub tid: u32,
    pub timestamp_utc: String,
    pub sequence: u64,
    pub api: String,
    pub module: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_status: Option<String>,
    pub process: String,
    pub return_value: String,
    pub last_error_code: u32,
    pub last_error_message: String,
    pub duration_us: u64,
    pub arguments: Vec<AgentApiArgument>,
    pub tags: Vec<String>,
    pub stack: Vec<String>,
    #[serde(default)]
    pub buffer_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult
{
    pub schema_version: String,
    pub operation_id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub session_state: String,
    #[serde(default)]
    pub session_kind: String,
    #[serde(default)]
    pub owner_process_id: u32,
    #[serde(default)]
    pub helper_process_id: u32,
    #[serde(default)]
    pub started_utc: String,
    #[serde(default)]
    pub updated_utc: String,
    #[serde(default)]
    pub stopped_utc: String,
    #[serde(default)]
    pub cancellation_event_name: String,
    #[serde(default)]
    pub last_transport_sequence: u64,
    #[serde(default)]
    pub records_streamed: u64,
    #[serde(default)]
    pub stale_reason: String,
    #[serde(default)]
    pub recovery_action: String,
    #[serde(default)]
    pub session_shutdown_evidence: String,
    pub success: bool,
    pub backend_mode: String,
    pub capture_mode: String,
    pub injection_method: String,
    pub target_path: String,
    pub agent_path: String,
    #[serde(default)]
    pub attach_process_id: u32,
    #[serde(default)]
    pub detach_policy: String,
    pub target_process_id: u32,
    pub target_thread_id: u32,
    pub architecture: String,
    pub win32_error_code: u32,
    pub nt_status: String,
    pub subsystem: String,
    pub operation: String,
    pub message: String,
    #[serde(default)]
    pub cancel_requested: bool,
    #[serde(default)]
    pub cancel_observed: bool,
    #[serde(default)]
    pub cancel_stage: String,
    #[serde(default)]
    pub operation_state: String,
    #[serde(default)]
    pub agent_cleanup_attempted: bool,
    #[serde(default)]
    pub agent_cleanup_succeeded: bool,
    #[serde(default)]
    pub stale_agent_operation_id: String,
    #[serde(default)]
    pub stale_agent_state: String,
    #[serde(default)]
    pub attach_state: String,
    #[serde(default)]
    pub attach_strategy: String,
    #[serde(default)]
    pub loaded_agent_detected: bool,
    #[serde(default)]
    pub loaded_agent_module_base: u64,
    #[serde(default)]
    pub loaded_agent_path: String,
    #[serde(default)]
    pub agent_control_status: u32,
    #[serde(default)]
    pub agent_abi_version: u32,
    pub dropped_events: u64,
    #[serde(default)]
    pub transport_mode: String,
    #[serde(default)]
    pub transport_capacity: u64,
    #[serde(default)]
    pub transport_records_produced: u64,
    #[serde(default)]
    pub transport_records_consumed: u64,
    #[serde(default)]
    pub transport_dropped_events: u64,
    #[serde(default)]
    pub transport_high_water_mark: u64,
    #[serde(default)]
    pub hook_overhead_min_us: u64,
    #[serde(default)]
    pub hook_overhead_avg_us: u64,
    #[serde(default)]
    pub hook_overhead_max_us: u64,
    pub handshake: AgentHandshake,
    pub audit_events: Vec<AuditEvent>,
    pub agent_messages: Vec<serde_json::Value>,
    pub captured_events: Vec<AgentApiCallEvent>,
    #[serde(default)]
    pub session: Option<SessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTreeNode
{
    pub process_id: u32,
    pub parent_process_id: u32,
    pub is_root: bool,
    pub image_name: String,
    pub image_path: String,
    pub architecture: String,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub is_alive: bool,
    pub exited: bool,
    pub eligibility_status: String,
    pub policy_decision: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildPolicyDecision
{
    pub process_id: u32,
    pub parent_process_id: u32,
    pub image_name: String,
    pub architecture: String,
    pub eligibility_status: String,
    pub decision: String,
    pub mutation_attempted: bool,
    pub attach_succeeded: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTreeResult
{
    pub schema_version: String,
    pub operation_id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub session_state: String,
    #[serde(default)]
    pub session_kind: String,
    #[serde(default)]
    pub owner_process_id: u32,
    #[serde(default)]
    pub helper_process_id: u32,
    #[serde(default)]
    pub started_utc: String,
    #[serde(default)]
    pub updated_utc: String,
    #[serde(default)]
    pub stopped_utc: String,
    #[serde(default)]
    pub cancellation_event_name: String,
    #[serde(default)]
    pub last_transport_sequence: u64,
    #[serde(default)]
    pub records_streamed: u64,
    #[serde(default)]
    pub stale_reason: String,
    #[serde(default)]
    pub recovery_action: String,
    pub success: bool,
    pub backend_mode: String,
    pub supervision_mode: String,
    pub root_process_id: u32,
    pub duration_ms: u32,
    pub child_policy: String,
    pub win32_error_code: u32,
    pub nt_status: String,
    pub subsystem: String,
    pub operation: String,
    pub message: String,
    #[serde(default)]
    pub cancel_requested: bool,
    #[serde(default)]
    pub cancel_observed: bool,
    #[serde(default)]
    pub cancel_stage: String,
    #[serde(default)]
    pub operation_state: String,
    pub process_nodes: Vec<ProcessTreeNode>,
    pub policy_decisions: Vec<ChildPolicyDecision>,
    pub audit_events: Vec<AuditEvent>,
    pub child_attach_results: Vec<CaptureResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo
{
    pub schema_version: String,
    pub success: bool,
    #[serde(default)]
    pub format: String,
    pub session_id: String,
    pub session_path: String,
    pub created_utc: String,
    #[serde(default)]
    pub finalized: bool,
    pub trace_event_count: u64,
    pub agent_event_count: u64,
    pub audit_event_count: u64,
    pub dropped_events: u64,
    #[serde(default)]
    pub transport_dropped_events: u64,
    #[serde(default)]
    pub host_dropped_batches: u64,
    #[serde(default)]
    pub chunk_count: u64,
    #[serde(default)]
    pub last_batch_sequence: u64,
    #[serde(default)]
    pub last_record_sequence: u64,
    #[serde(default)]
    pub writer_state: String,
    #[serde(default)]
    pub recovery_state: String,
    #[serde(default)]
    pub recovery_reason: String,
    #[serde(default)]
    pub recovery_action: String,
    #[serde(default)]
    pub owner_alive: bool,
    #[serde(default)]
    pub helper_alive: bool,
    #[serde(default)]
    pub writer_alive: bool,
    #[serde(default)]
    pub target_alive: bool,
    #[serde(default)]
    pub lease_expired: bool,
    #[serde(default)]
    pub restart_eligible: bool,
    pub win32_error_code: u32,
    pub message: String,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceError
{
    pub kind: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent
{
    pub schema_version: String,
    pub event_id: u64,
    pub relative_time_ms: f64,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub module: String,
    pub api: String,
    pub arguments: Vec<AgentApiArgument>,
    pub return_value: String,
    pub error: Option<TraceError>,
    pub duration_us: u64,
    pub tags: Vec<String>,
    pub stack: Vec<String>,
    #[serde(default)]
    pub buffer_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReplayResult
{
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub capture_mode: String,
    pub session: SessionInfo,
    pub message: String,
    pub trace_events: Vec<TraceEvent>,
}

static NATIVE_OPERATIONS: OnceLock<Mutex<HashMap<String, NativeOperationRecord>>> = OnceLock::new();

fn operation_registry() -> &'static Mutex<HashMap<String, NativeOperationRecord>>
{
    NATIVE_OPERATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_epoch_ms() -> u128
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis()
}

fn new_operation_id(prefix: &str, process_id: u32) -> String
{
    format!("{prefix}-{process_id}-{}", now_epoch_ms())
}

fn new_session_id(operation_id: &str) -> String
{
    format!("session-{operation_id}")
}

fn timestamp_label(epoch_ms: u128) -> String
{
    format!("epoch-ms:{epoch_ms}")
}

fn sanitize_event_part(value: &str) -> String
{
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
            {
                ch
            }
            else
            {
                '-'
            }
        })
        .collect();

    if sanitized.is_empty()
    {
        "operation".to_string()
    }
    else
    {
        sanitized
    }
}

fn cancellation_event_name(operation_id: &str) -> String
{
    format!("Local\\KNMonCancel_{}", sanitize_event_part(operation_id))
}

fn operation_view(record: &NativeOperationRecord) -> NativeOperation
{
    NativeOperation
    {
        operation_id: record.operation_id.clone(),
        operation_kind: record.operation_kind.clone(),
        target_process_id: record.target_process_id,
        state: record.state.clone(),
        cancel_requested: record.cancel_requested,
        elapsed_ms: record.started_at.elapsed().as_millis() as u64,
        duration_ms: record.duration_ms,
    }
}

fn session_state_from_operation_state(state: &str) -> String
{
    match state {
        "queued" => "created".to_string(),
        "running" => "running".to_string(),
        "cancel_requested" => "stop_requested".to_string(),
        "stopping_agent" => "stopping_agent".to_string(),
        "draining" => "draining".to_string(),
        "completed" | "cancelled" => "stopped".to_string(),
        "cleanup_failed" => "recovery_required".to_string(),
        "failed" => "failed".to_string(),
        other => other.to_string(),
    }
}

fn session_view(record: &NativeOperationRecord) -> NativeSession
{
    let now_ms = now_epoch_ms();
    let elapsed_ms = record.started_at.elapsed().as_millis() as u64;
    let stopped_utc = if record.finished_at_ms == 0
    {
        String::new()
    }
    else
    {
        timestamp_label(record.finished_at_ms)
    };

    NativeSession
    {
        schema_version: "0.1.0".to_string(),
        session_id: record.session_id.clone(),
        operation_id: record.operation_id.clone(),
        session_kind: record.operation_kind.clone(),
        owner_process_id: std::process::id(),
        helper_process_id: record.helper_process_id,
        target_process_id: record.target_process_id,
        session_state: session_state_from_operation_state(&record.state),
        started_utc: timestamp_label(now_ms.saturating_sub(elapsed_ms as u128)),
        updated_utc: timestamp_label(now_ms),
        stopped_utc,
        cancellation_event_name: cancellation_event_name(&record.operation_id),
        last_transport_sequence: record.last_transport_sequence,
        records_streamed: record.records_streamed,
        transport_dropped_events: record.transport_dropped_events,
        host_dropped_batches: record.host_dropped_batches,
        stale_reason: record.stale_reason.clone(),
        recovery_action: record.recovery_action.clone(),
        shutdown_evidence: record.shutdown_evidence.clone(),
        stop_requested: record.cancel_requested,
        agent_cleanup_attempted: record.agent_cleanup_attempted,
        agent_cleanup_succeeded: record.agent_cleanup_succeeded,
        last_error: record.last_error.clone(),
        elapsed_ms,
        duration_ms: record.duration_ms,
        daemon_process_id: 0,
        daemon_instance_id: String::new(),
        daemon_started_utc: String::new(),
        daemon_heartbeat_utc: String::new(),
        daemon_control_endpoint: String::new(),
        knapm_path: String::new(),
        daemon_alive: false,
        session_process_alive: false,
        target_alive: false,
        knapm_exists: false,
        knapm_valid: false,
        recovery_state: String::new(),
        recovery_reason: String::new(),
        prune_eligible: false,
        prune_reason: String::new(),
    }
}

fn register_native_operation(operation_id: &str, operation_kind: &str, target_process_id: u32, duration_ms: u32)
{
    let mut registry = operation_registry().lock().unwrap();
    registry.insert(
        operation_id.to_string(),
        NativeOperationRecord
        {
            session_id: new_session_id(operation_id),
            operation_id: operation_id.to_string(),
            operation_kind: operation_kind.to_string(),
            target_process_id,
            state: "running".to_string(),
            cancel_requested: false,
            started_at: Instant::now(),
            finished_at_ms: 0,
            duration_ms,
            helper_process_id: 0,
            last_transport_sequence: 0,
            records_streamed: 0,
            transport_dropped_events: 0,
            host_dropped_batches: 0,
            last_batch_sequence: 0,
            trace_batches: VecDeque::new(),
            stale_reason: String::new(),
            recovery_action: String::new(),
            shutdown_evidence: String::new(),
            agent_cleanup_attempted: false,
            agent_cleanup_succeeded: false,
            last_error: String::new(),
        },
    );
}

fn finish_native_operation(operation_id: &str, state: &str)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
    }
}

fn finish_native_operation_with_capture(operation_id: &str, state: &str, result: &CaptureResult)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
        record.last_transport_sequence = result.last_transport_sequence;
        record.records_streamed = result.records_streamed;
        record.transport_dropped_events = result.transport_dropped_events;
        record.shutdown_evidence = result.session_shutdown_evidence.clone();
        record.agent_cleanup_attempted = result.agent_cleanup_attempted;
        record.agent_cleanup_succeeded = result.agent_cleanup_succeeded;
        if result.operation_state == "cleanup_failed"
        {
            record.recovery_action = "manual_same_bitness_cleanup_required".to_string();
        }
    }
}

fn finish_native_operation_with_process_tree(operation_id: &str, state: &str, result: &ProcessTreeResult)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
        record.last_transport_sequence = result.last_transport_sequence;
        record.records_streamed = result.records_streamed;
        if result.operation_state == "cleanup_failed"
        {
            record.recovery_action = "manual_same_bitness_cleanup_required".to_string();
        }
    }
}

fn mark_native_operation_helper_pid(operation_id: &str, helper_process_id: u32)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.helper_process_id = helper_process_id;
    }
}

fn update_native_record_from_session(record: &mut NativeOperationRecord, session: &NativeSession)
{
    record.session_id = session.session_id.clone();
    record.operation_id = session.operation_id.clone();
    record.operation_kind = session.session_kind.clone();
    record.target_process_id = session.target_process_id;
    record.state = session.session_state.clone();
    record.cancel_requested = session.stop_requested;
    record.helper_process_id = session.helper_process_id;
    record.last_transport_sequence = session.last_transport_sequence;
    record.records_streamed = session.records_streamed;
    record.transport_dropped_events = session.transport_dropped_events;
    record.host_dropped_batches = session.host_dropped_batches.max(record.host_dropped_batches);
    record.stale_reason = session.stale_reason.clone();
    record.recovery_action = session.recovery_action.clone();
    record.shutdown_evidence = session.shutdown_evidence.clone();
    record.agent_cleanup_attempted = session.agent_cleanup_attempted;
    record.agent_cleanup_succeeded = session.agent_cleanup_succeeded;
    if session.session_state == "stopped" || session.session_state == "failed" || session.session_state == "stale" || session.session_state == "recovery_required"
    {
        record.finished_at_ms = now_epoch_ms();
    }
}

fn push_native_trace_batch(operation_id: &str, mut batch: NativeTraceBatch)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        while record.trace_batches.len() >= STREAM_BATCH_QUEUE_LIMIT
        {
            record.trace_batches.pop_front();
            record.host_dropped_batches = record.host_dropped_batches.saturating_add(1);
        }

        batch.host_dropped_batches = record.host_dropped_batches;
        record.last_batch_sequence = record.last_batch_sequence.max(batch.batch_sequence);
        record.last_transport_sequence = batch.last_record_sequence;
        record.records_streamed = batch.records_streamed;
        record.transport_dropped_events = batch.dropped_events;
        record.trace_batches.push_back(batch);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingFrameHeader
{
    frame_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingSessionFrame
{
    frame_type: String,
    session: NativeSession,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingCaptureResultFrame
{
    session: NativeSession,
    capture_result: CaptureResult,
}

fn update_streaming_error(operation_id: &str, state: &str, message: String)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.state = state.to_string();
        record.last_error = message;
        record.finished_at_ms = now_epoch_ms();
    }
}

fn process_streaming_frame_line(operation_id: &str, line: &str) -> Result<(), String>
{
    let header: StreamingFrameHeader = serde_json::from_str(line)
        .map_err(|error| format!("failed to parse streaming frame header: {error}; line={line}"))?;

    match header.frame_type.as_str() {
        "trace_batch" =>
        {
            let batch: NativeTraceBatch = serde_json::from_str(line)
                .map_err(|error| format!("failed to parse trace_batch frame: {error}; line={line}"))?;
            push_native_trace_batch(operation_id, batch);
        }
        "session_started" | "session_state" | "session_stopping" | "session_stopped" | "session_failed" =>
        {
            let frame: StreamingSessionFrame = serde_json::from_str(line)
                .map_err(|error| format!("failed to parse session frame: {error}; line={line}"))?;
            let mut registry = operation_registry().lock().unwrap();
            if let Some(record) = registry.get_mut(operation_id)
            {
                let state = if frame.frame_type == "session_stopping"
                {
                    "stop_requested".to_string()
                }
                else
                {
                    frame.session.session_state.clone()
                };
                update_native_record_from_session(record, &frame.session);
                record.state = state;
            }
        }
        "capture_result" =>
        {
            let frame: StreamingCaptureResultFrame = serde_json::from_str(line)
                .map_err(|error| format!("failed to parse capture_result frame: {error}; line={line}"))?;
            let operation_state = if frame.capture_result.operation_state.is_empty()
            {
                if frame.capture_result.success
                {
                    "completed".to_string()
                }
                else if frame.capture_result.operation == "operation_cancelled"
                {
                    "cancelled".to_string()
                }
                else
                {
                    "failed".to_string()
                }
            }
            else
            {
                frame.capture_result.operation_state.clone()
            };

            let mut registry = operation_registry().lock().unwrap();
            if let Some(record) = registry.get_mut(operation_id)
            {
                update_native_record_from_session(record, &frame.session);
                record.state = operation_state;
                record.finished_at_ms = now_epoch_ms();
                record.last_transport_sequence = frame.capture_result.last_transport_sequence;
                record.records_streamed = frame.capture_result.records_streamed;
                record.transport_dropped_events = frame.capture_result.transport_dropped_events;
                record.shutdown_evidence = frame.capture_result.session_shutdown_evidence;
                record.agent_cleanup_attempted = frame.capture_result.agent_cleanup_attempted;
                record.agent_cleanup_succeeded = frame.capture_result.agent_cleanup_succeeded;
            }
        }
        other =>
        {
            return Err(format!("unsupported streaming frame type: {other}"));
        }
    }

    Ok(())
}

pub fn native_operation_states() -> Vec<NativeOperation>
{
    let registry = operation_registry().lock().unwrap();
    let mut operations: Vec<NativeOperation> = registry.values().map(operation_view).collect();
    operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    operations
}

pub fn native_session_states() -> Vec<NativeSession>
{
    let registry = operation_registry().lock().unwrap();
    let mut sessions: Vec<NativeSession> = registry.values().map(session_view).collect();
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    sessions
}

pub fn cancel_native_operation(operation_id: String) -> Result<NativeOperation, String>
{
    {
        let mut registry = operation_registry().lock().unwrap();
        let record = registry
            .get_mut(&operation_id)
            .ok_or_else(|| format!("operation not found: {operation_id}"))?;
        record.cancel_requested = true;
        record.state = "cancel_requested".to_string();
    }

    let signal = signal_cancel_operation(&operation_id)?;
    if !signal.success
    {
        return Err(format!(
            "{} failed with {}: {}",
            signal.operation,
            signal.win32_error_code,
            signal.message
        ));
    }

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(operation_view)
        .ok_or_else(|| format!("operation not found after cancel: {operation_id}"))
}

pub fn stop_native_session(session_id: String) -> Result<NativeSession, String>
{
    let operation_id = {
        let mut registry = operation_registry().lock().unwrap();
        let record = registry
            .values_mut()
            .find(|record| record.session_id == session_id)
            .ok_or_else(|| format!("session not found: {session_id}"))?;
        record.cancel_requested = true;
        record.state = "cancel_requested".to_string();
        record.operation_id.clone()
    };

    let signal = signal_cancel_operation(&operation_id)?;
    if !signal.success
    {
        return Err(format!(
            "{} failed with {}: {}",
            signal.operation,
            signal.win32_error_code,
            signal.message
        ));
    }

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(session_view)
        .ok_or_else(|| format!("session not found after stop: {session_id}"))
}

pub fn start_streaming_attach_session(process_id: u32, duration_ms: u32) -> Result<NativeSession, String>
{
    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let operation_id = new_operation_id("ui-stream", process_id);
    let session_id = new_session_id(&operation_id);
    register_native_operation(&operation_id, "attach_capture_stream", process_id, duration);

    let helper_path = find_helper_path()
        .ok_or_else(|| "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string())?;

    let args = vec![
        "attach-session".to_string(),
        "--pid".to_string(),
        process_id.to_string(),
        "--duration-ms".to_string(),
        duration.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--operation-id".to_string(),
        operation_id.clone(),
        "--session-id".to_string(),
        session_id.clone(),
        "--stream-batches".to_string(),
        "--batch-size".to_string(),
        "64".to_string(),
        "--batch-interval-ms".to_string(),
        "100".to_string(),
    ];

    let mut child = Command::new(&helper_path)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run {} attach-session: {error}", helper_path.display()))?;

    mark_native_operation_helper_pid(&operation_id, child.id());

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture attach-session stdout".to_string())?;
    let stderr = child.stderr.take();
    let worker_operation_id = operation_id.clone();
    thread::spawn(move ||
    {
        let stderr_thread = stderr.map(|mut pipe| {
            thread::spawn(move ||
            {
                let mut text = String::new();
                let _ = pipe.read_to_string(&mut text);
                text
            })
        });

        let reader = BufReader::new(stdout);
        for line_result in reader.lines()
        {
            match line_result
            {
                Ok(line) =>
                {
                    let trimmed = line.trim();
                    if trimmed.is_empty()
                    {
                        continue;
                    }

                    if let Err(error) = process_streaming_frame_line(&worker_operation_id, trimmed)
                    {
                        update_streaming_error(&worker_operation_id, "failed", error);
                    }
                }
                Err(error) =>
                {
                    update_streaming_error(&worker_operation_id, "failed", format!("streaming stdout read failed: {error}"));
                    break;
                }
            }
        }

        let status = child.wait();
        let stderr_text = match stderr_thread
        {
            Some(handle) => handle.join().unwrap_or_default(),
            None => String::new(),
        };

        match status
        {
            Ok(exit_status) =>
            {
                if !exit_status.success()
                {
                    update_streaming_error(
                        &worker_operation_id,
                        "failed",
                        format!("attach-session exited with {:?}; stderr={}", exit_status.code(), stderr_text.trim()));
                }
            }
            Err(error) =>
            {
                update_streaming_error(&worker_operation_id, "failed", format!("failed to wait for attach-session: {error}"));
            }
        }
    });

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(session_view)
        .ok_or_else(|| format!("streaming session not found after start: {session_id}"))
}

pub fn start_launch_monitor_session(
    target_path: String,
    working_directory: String,
    launch_arguments: String,
    duration_ms: u32,
) -> Result<NativeSession, String>
{
    let target = target_path.trim();
    if target.is_empty()
    {
        return Err("launch target path is required".to_string());
    }

    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let operation_id = new_operation_id("ui-launch", 0);
    let session_id = new_session_id(&operation_id);
    register_native_operation(&operation_id, "launch_capture_stream", 0, duration);

    let helper_path = find_helper_path()
        .ok_or_else(|| "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string())?;

    let mut args = vec![
        "launch-session".to_string(),
        "--target".to_string(),
        target.to_string(),
        "--duration-ms".to_string(),
        duration.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--operation-id".to_string(),
        operation_id.clone(),
        "--session-id".to_string(),
        session_id.clone(),
        "--stream-batches".to_string(),
        "--batch-size".to_string(),
        "64".to_string(),
    ];

    let cwd = working_directory.trim();
    if !cwd.is_empty()
    {
        args.push("--cwd".to_string());
        args.push(cwd.to_string());
    }

    let command_line_arguments = launch_arguments.trim();
    if !command_line_arguments.is_empty()
    {
        args.push("--args".to_string());
        args.push(command_line_arguments.to_string());
    }

    let mut child = Command::new(&helper_path)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run {} launch-session: {error}", helper_path.display()))?;

    mark_native_operation_helper_pid(&operation_id, child.id());

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture launch-session stdout".to_string())?;
    let stderr = child.stderr.take();
    let worker_operation_id = operation_id.clone();
    thread::spawn(move ||
    {
        let stderr_thread = stderr.map(|mut pipe| {
            thread::spawn(move ||
            {
                let mut text = String::new();
                let _ = pipe.read_to_string(&mut text);
                text
            })
        });

        let reader = BufReader::new(stdout);
        for line_result in reader.lines()
        {
            match line_result
            {
                Ok(line) =>
                {
                    let trimmed = line.trim();
                    if trimmed.is_empty()
                    {
                        continue;
                    }

                    if let Err(error) = process_streaming_frame_line(&worker_operation_id, trimmed)
                    {
                        update_streaming_error(&worker_operation_id, "failed", error);
                    }
                }
                Err(error) =>
                {
                    update_streaming_error(&worker_operation_id, "failed", format!("streaming stdout read failed: {error}"));
                    break;
                }
            }
        }

        let status = child.wait();
        let stderr_text = match stderr_thread
        {
            Some(handle) => handle.join().unwrap_or_default(),
            None => String::new(),
        };

        match status
        {
            Ok(exit_status) =>
            {
                if !exit_status.success()
                {
                    update_streaming_error(
                        &worker_operation_id,
                        "failed",
                        format!("launch-session exited with {:?}; stderr={}", exit_status.code(), stderr_text.trim()));
                }
            }
            Err(error) =>
            {
                update_streaming_error(&worker_operation_id, "failed", format!("failed to wait for launch-session: {error}"));
            }
        }
    });

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(session_view)
        .ok_or_else(|| format!("launch session not found after start: {session_id}"))
}

pub fn start_daemon_if_needed() -> Result<NativeDaemonStatus, String>
{
    let helper_output = run_helper_args(&[
        "daemon-start".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    let status: NativeDaemonStatus = parse_helper_json(&helper_output, "daemon-start")?;
    if !status.success
    {
        return Err(format!("{} failed with {}: {}", status.operation, status.win32_error_code, status.message));
    }

    Ok(status)
}

pub fn native_daemon_status() -> Result<NativeDaemonStatus, String>
{
    let helper_output = run_helper_args(&[
        "daemon-status".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-status")
}

pub fn start_daemon_supervised_session(process_id: u32, duration_ms: u32) -> Result<NativeSession, String>
{
    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let operation_id = new_operation_id("ui-daemon", process_id);
    let session_id = new_session_id(&operation_id);
    let session_path = default_daemon_session_path(&session_id);

    let helper_output = run_helper_args(&[
        "daemon-start-session".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
        "--pid".to_string(),
        process_id.to_string(),
        "--duration-ms".to_string(),
        duration.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--operation-id".to_string(),
        operation_id,
        "--session-id".to_string(),
        session_id,
        "--write-knapm".to_string(),
        session_path.to_string_lossy().to_string(),
    ])?;

    let result: NativeDaemonSessionResult = parse_helper_json(&helper_output, "daemon-start-session")?;
    if !result.success
    {
        return Err(format!("{} failed with {}: {}", result.operation, result.win32_error_code, result.message));
    }

    Ok(result.session)
}

pub fn native_daemon_sessions() -> Result<Vec<NativeSession>, String>
{
    let helper_output = run_helper_args(&[
        "daemon-list-sessions".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    let result: NativeDaemonSessionList = parse_helper_json(&helper_output, "daemon-list-sessions")?;
    Ok(result.sessions)
}

pub fn native_daemon_audit() -> Result<NativeDaemonAudit, String>
{
    let helper_output = run_helper_args(&[
        "daemon-audit".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-audit")
}

pub fn native_daemon_recovery_plan() -> Result<NativeDaemonRecoveryPlan, String>
{
    let helper_output = run_helper_args(&[
        "daemon-recovery-plan".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-recovery-plan")
}

pub fn apply_daemon_recovery(dry_run: bool) -> Result<NativeDaemonRecoveryApply, String>
{
    let mut args = vec![
        "daemon-recovery-apply".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ];
    if dry_run
    {
        args.push("--dry-run".to_string());
    }
    else
    {
        args.push("--apply-registry-prune".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    parse_helper_json(&helper_output, "daemon-recovery-apply")
}

pub fn prune_stale_daemon_sessions(dry_run: bool) -> Result<NativeDaemonAudit, String>
{
    let mut args = vec![
        "daemon-prune-stale".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ];
    if dry_run
    {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    parse_helper_json(&helper_output, "daemon-prune-stale")
}

pub fn catalog_native_sessions() -> Result<NativeSessionCatalog, String>
{
    let root_path = repo_root_path().join("captures");
    let catalog_path = default_session_catalog_path();
    let helper_output = run_helper_args(&[
        "catalog-sessions".to_string(),
        "--root".to_string(),
        root_path.to_string_lossy().to_string(),
        "--catalog".to_string(),
        catalog_path.to_string_lossy().to_string(),
        "--rebuild".to_string(),
    ])?;

    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-sessions")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn query_native_session_catalog(limit: u32, state: String, target: String) -> Result<NativeSessionCatalog, String>
{
    let catalog_path = default_session_catalog_path();
    if !catalog_path.is_file()
    {
        let _ = catalog_native_sessions()?;
    }

    let mut args = vec![
        "catalog-query".to_string(),
        "--catalog".to_string(),
        catalog_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !state.trim().is_empty()
    {
        args.push("--state".to_string());
        args.push(state);
    }

    if !target.trim().is_empty()
    {
        args.push("--target".to_string());
        args.push(target);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-query")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_session_catalog_entries(dry_run: bool) -> Result<NativeSessionCatalog, String>
{
    let catalog_path = default_session_catalog_path();
    if !catalog_path.is_file()
    {
        let _ = catalog_native_sessions()?;
    }

    let mut args = vec![
        "catalog-remove-missing".to_string(),
        "--catalog".to_string(),
        catalog_path.to_string_lossy().to_string(),
    ];
    if dry_run
    {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-remove-missing")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn build_native_session_catalog_index(rebuild: bool) -> Result<NativeSessionCatalog, String>
{
    let root_path = repo_root_path().join("captures");
    let database_path = default_session_catalog_index_path();
    let mut args = vec![
        "catalog-index-build".to_string(),
        "--root".to_string(),
        root_path.to_string_lossy().to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if rebuild
    {
        args.push("--rebuild".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-index-build")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn query_native_session_catalog_index(limit: u32, state: String, target: String) -> Result<NativeSessionCatalog, String>
{
    let database_path = default_session_catalog_index_path();
    if !database_path.is_file()
    {
        let _ = build_native_session_catalog_index(true)?;
    }

    let mut args = vec![
        "catalog-index-query".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !state.trim().is_empty()
    {
        args.push("--state".to_string());
        args.push(state);
    }

    if !target.trim().is_empty()
    {
        args.push("--target".to_string());
        args.push(target);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-index-query")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_session_catalog_index_entries(dry_run: bool) -> Result<NativeSessionCatalog, String>
{
    let database_path = default_session_catalog_index_path();
    if !database_path.is_file()
    {
        let _ = build_native_session_catalog_index(true)?;
    }

    let mut args = vec![
        "catalog-index-remove-missing".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if dry_run
    {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-index-remove-missing")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn build_native_trace_index(rebuild: bool) -> Result<NativeTraceIndex, String>
{
    let root_path = repo_root_path().join("captures");
    let database_path = default_session_trace_index_path();
    let mut args = vec![
        "trace-index-build".to_string(),
        "--root".to_string(),
        root_path.to_string_lossy().to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if rebuild
    {
        args.push("--rebuild".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-build")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn query_native_trace_index(
    limit: u32,
    text: String,
    api: String,
    module: String,
    session: String,
    pid: String,
) -> Result<NativeTraceIndex, String>
{
    let database_path = default_session_trace_index_path();
    if !database_path.is_file()
    {
        let _ = build_native_trace_index(true)?;
    }

    let mut args = vec![
        "trace-index-query".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !text.trim().is_empty()
    {
        args.push("--text".to_string());
        args.push(text);
    }
    if !api.trim().is_empty()
    {
        args.push("--api".to_string());
        args.push(api);
    }
    if !module.trim().is_empty()
    {
        args.push("--module".to_string());
        args.push(module);
    }
    if !session.trim().is_empty()
    {
        args.push("--session".to_string());
        args.push(session);
    }
    if !pid.trim().is_empty()
    {
        args.push("--pid".to_string());
        args.push(pid);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-query")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_trace_index_entries(dry_run: bool) -> Result<NativeTraceIndex, String>
{
    let database_path = default_session_trace_index_path();
    if !database_path.is_file()
    {
        let _ = build_native_trace_index(true)?;
    }

    let mut args = vec![
        "trace-index-remove-missing".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if dry_run
    {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-remove-missing")?;
    if !result.success
    {
        return Err(result.message);
    }

    Ok(result)
}

pub fn stop_daemon_session(session_id: String) -> Result<NativeSession, String>
{
    let helper_output = run_helper_args(&[
        "daemon-stop-session".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
        "--session-id".to_string(),
        session_id,
    ])?;

    let result: NativeDaemonSessionResult = parse_helper_json(&helper_output, "daemon-stop-session")?;
    if !result.success
    {
        return Err(format!("{} failed with {}: {}", result.operation, result.win32_error_code, result.message));
    }

    Ok(result.session)
}

pub fn drain_native_trace_batches(session_id: String, after_batch_sequence: u64) -> Result<Vec<NativeTraceBatch>, String>
{
    let registry = operation_registry().lock().unwrap();
    let record = registry
        .values()
        .find(|record| record.session_id == session_id)
        .ok_or_else(|| format!("session not found: {session_id}"))?;

    Ok(record
        .trace_batches
        .iter()
        .filter(|batch| batch.batch_sequence > after_batch_sequence)
        .cloned()
        .collect())
}

pub fn backend_status() -> &'static str
{
    "native-capture"
}

pub fn native_target_processes() -> Result<Vec<TargetProcess>, String>
{
    let helper_output = run_helper(["list-targets"])?;
    let target_list: NativeTargetList = serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse native target list: {error}; stdout={helper_output}"))?;

    if !target_list.success
    {
        return Err(format!(
            "{} failed with {}: {}",
            target_list.operation,
            target_list.win32_error_code,
            target_list.message
        ));
    }

    Ok(target_list.targets)
}

pub fn launch_sample_early_bird() -> Result<LaunchResult, String>
{
    let helper_output = run_helper(["launch-sample"])?;
    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse launch result: {error}; stdout={helper_output}"))
}

pub fn capture_sample_fileio() -> Result<CaptureResult, String>
{
    let helper_output = run_helper(["capture-sample"])?;
    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse capture result: {error}; stdout={helper_output}"))
}

pub fn capture_sample_fileio_session() -> Result<CaptureResult, String>
{
    let session_path = default_session_path();
    let helper_output = run_helper_args(&[
        "capture-sample".to_string(),
        "--write-session".to_string(),
        session_path.to_string_lossy().to_string(),
    ])?;

    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse capture session result: {error}; stdout={helper_output}"))
}

pub fn replay_last_session() -> Result<SessionReplayResult, String>
{
    let session_path = default_session_path();
    replay_session_at_path(session_path)
}

pub fn replay_session_at_path(session_path: PathBuf) -> Result<SessionReplayResult, String>
{
    let helper_output = run_helper_args(&[
        "replay-session".to_string(),
        "--session".to_string(),
        session_path.to_string_lossy().to_string(),
    ])?;

    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse session replay result: {error}; stdout={helper_output}"))
}

pub fn replay_session_path(session_path: String) -> Result<SessionReplayResult, String>
{
    if session_path.trim().is_empty()
    {
        return Err("session path is empty".to_string());
    }

    replay_session_at_path(PathBuf::from(session_path))
}

pub fn attach_target_process_capture(process_id: u32, duration_ms: u32) -> Result<CaptureResult, String>
{
    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let command_timeout = helper_process_timeout_ms(duration);
    let operation_id = new_operation_id("ui-attach", process_id);
    register_native_operation(&operation_id, "attach_capture", process_id, duration);

    let helper_output = match run_helper_args_with_timeout(&[
        "attach-capture".to_string(),
        "--pid".to_string(),
        process_id.to_string(),
        "--duration-ms".to_string(),
        duration.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--operation-id".to_string(),
        operation_id.clone(),
    ], command_timeout, Some(&operation_id))
    {
        Ok(output) => output,
        Err(error) =>
        {
            finish_native_operation(&operation_id, "failed");
            return Err(error);
        }
    };

    let result: CaptureResult = parse_helper_json(&helper_output, "attach-capture")?;
    let operation_state = if result.operation_state.is_empty()
    {
        if result.success
        {
            "completed"
        }
        else
        {
            "failed"
        }
    }
    else
    {
        result.operation_state.as_str()
    };
    finish_native_operation_with_capture(&operation_id, operation_state, &result);
    Ok(result)
}

pub fn supervise_process_tree(root_process_id: u32, duration_ms: u32, child_policy: String) -> Result<ProcessTreeResult, String>
{
    let normalized_policy = child_policy.trim().to_string();
    if normalized_policy != "observe" && normalized_policy != "attach-supported"
    {
        return Err(format!("unsupported child policy: {normalized_policy}"));
    }

    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let command_timeout = helper_process_timeout_ms(duration);
    let operation_id = new_operation_id("ui-tree", root_process_id);
    register_native_operation(&operation_id, "process_tree_supervision", root_process_id, duration);

    let helper_output = match run_helper_args_with_timeout(&[
        "supervise-tree".to_string(),
        "--pid".to_string(),
        root_process_id.to_string(),
        "--duration-ms".to_string(),
        duration.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--child-policy".to_string(),
        normalized_policy,
        "--operation-id".to_string(),
        operation_id.clone(),
    ], command_timeout, Some(&operation_id))
    {
        Ok(output) => output,
        Err(error) =>
        {
            finish_native_operation(&operation_id, "failed");
            return Err(error);
        }
    };

    let result: ProcessTreeResult = parse_helper_json(&helper_output, "supervise-tree")?;
    let operation_state = if result.operation_state.is_empty()
    {
        if result.success
        {
            "completed"
        }
        else
        {
            "failed"
        }
    }
    else
    {
        result.operation_state.as_str()
    };
    finish_native_operation_with_process_tree(&operation_id, operation_state, &result);
    Ok(result)
}

fn parse_helper_json<T>(helper_output: &str, command_name: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    serde_json::from_str(helper_output)
        .map_err(|error| format!("failed to parse {command_name} result: {error}; stdout={helper_output}"))
}

fn run_helper<const N: usize>(args: [&str; N]) -> Result<String, String>
{
    let owned_args: Vec<String> = args.iter().map(|value| value.to_string()).collect();
    run_helper_args(&owned_args)
}

fn run_helper_args(args: &[String]) -> Result<String, String>
{
    let helper_path = find_helper_path()
        .ok_or_else(|| "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string())?;

    let output = Command::new(&helper_path)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", helper_path.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success()
    {
        return Err(format!(
            "{} exited with {:?}; stderr={}; stdout={}",
            helper_path.display(),
            output.status.code(),
            stderr,
            stdout
        ));
    }

    if stdout.is_empty()
    {
        return Err(format!("{} returned empty stdout; stderr={}", helper_path.display(), stderr));
    }

    Ok(stdout)
}

fn signal_cancel_operation(operation_id: &str) -> Result<CancellationSignalResult, String>
{
    let helper_path = find_helper_path()
        .ok_or_else(|| "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string())?;

    let output = Command::new(&helper_path)
        .args(["cancel-operation", "--operation-id", operation_id])
        .output()
        .map_err(|error| format!("failed to run {} cancel-operation: {error}", helper_path.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success()
    {
        return Err(format!(
            "{} cancel-operation exited with {:?}; stderr={}; stdout={}",
            helper_path.display(),
            output.status.code(),
            stderr,
            stdout
        ));
    }

    parse_helper_json(&stdout, "cancel-operation")
}

fn run_helper_args_with_timeout(args: &[String], timeout_ms: u32, operation_id: Option<&str>) -> Result<String, String>
{
    let helper_path = find_helper_path()
        .ok_or_else(|| "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string())?;

    let mut child = Command::new(&helper_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run {}: {error}", helper_path.display()))?;

    if let Some(id) = operation_id
    {
        mark_native_operation_helper_pid(id, child.id());
    }

    let timeout = Duration::from_millis(timeout_ms as u64);
    let start = Instant::now();

    loop
    {
        if child.try_wait().map_err(|error| format!("failed to poll {}: {error}", helper_path.display()))?.is_some()
        {
            break;
        }

        if start.elapsed() >= timeout
        {
            let mut cancel_note = String::new();
            if let Some(id) = operation_id
            {
                match signal_cancel_operation(id)
                {
                    Ok(signal) =>
                    {
                        cancel_note = format!(" cancelSignal={} message={}", signal.success, signal.message);
                    }
                    Err(error) =>
                    {
                        cancel_note = format!(" cancelSignal=false message={error}");
                    }
                }

                let grace_start = Instant::now();
                let grace_timeout = Duration::from_millis(12_000);
                while grace_start.elapsed() < grace_timeout
                {
                    if child.try_wait().map_err(|error| format!("failed to poll {} after cancel: {error}", helper_path.display()))?.is_some()
                    {
                        break;
                    }

                    thread::sleep(Duration::from_millis(25));
                }

                if child.try_wait().map_err(|error| format!("failed to poll {} after cancel grace: {error}", helper_path.display()))?.is_some()
                {
                    break;
                }
            }

            let _ = child.kill();
            let output = child
                .wait_with_output()
                .map_err(|error| format!("failed to collect timed out {}: {error}", helper_path.display()))?;
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            return Err(format!(
                "{} timed out after {} ms; stderr={}; stdout={};{}",
                helper_path.display(),
                timeout_ms,
                stderr,
                stdout,
                cancel_note
            ));
        }

        thread::sleep(Duration::from_millis(25));
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to collect {} output: {error}", helper_path.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success()
    {
        return Err(format!(
            "{} exited with {:?}; stderr={}; stdout={}",
            helper_path.display(),
            output.status.code(),
            stderr,
            stdout
        ));
    }

    if stdout.is_empty()
    {
        return Err(format!("{} returned empty stdout; stderr={}", helper_path.display(), stderr));
    }

    Ok(stdout)
}

fn normalize_duration_ms(duration_ms: u32) -> u32
{
    duration_ms.clamp(250, 30_000)
}

fn helper_inner_timeout_ms(duration_ms: u32) -> u32
{
    duration_ms.saturating_add(7_000).clamp(7_000, 45_000)
}

fn helper_process_timeout_ms(duration_ms: u32) -> u32
{
    duration_ms.saturating_add(10_000).clamp(10_000, 60_000)
}

fn repo_root_path() -> PathBuf
{
    let manifest_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_root.join("..").join("..")
}

fn default_session_path() -> PathBuf
{
    repo_root_path().join("captures").join("latest-sample-fileio")
}

fn default_daemon_runtime_path() -> PathBuf
{
    repo_root_path().join("captures").join("daemon-runtime")
}

fn default_session_catalog_path() -> PathBuf
{
    repo_root_path().join("captures").join("session-catalog.json")
}

fn default_session_catalog_index_path() -> PathBuf
{
    repo_root_path().join("captures").join("session-catalog.db")
}

fn default_session_trace_index_path() -> PathBuf
{
    repo_root_path().join("captures").join("session-trace-index.db")
}

fn default_daemon_session_path(session_id: &str) -> PathBuf
{
    repo_root_path()
        .join("captures")
        .join("daemon-sessions")
        .join(format!("{}.knapm", sanitize_event_part(session_id)))
}

fn find_helper_path() -> Option<PathBuf>
{
    let repo_root = repo_root_path();
    let current_dir = std::env::current_dir().ok();

    let mut candidates = vec![
        repo_root.join("build").join("native").join("Debug").join("knmon-native-helper.exe"),
        repo_root.join("build").join("native").join("Release").join("knmon-native-helper.exe"),
        repo_root.join("build").join("native").join("RelWithDebInfo").join("knmon-native-helper.exe"),
    ];

    if let Some(dir) = current_dir
    {
        candidates.push(dir.join("build").join("native").join("Debug").join("knmon-native-helper.exe"));
        candidates.push(dir.join("build").join("native").join("Release").join("knmon-native-helper.exe"));
    }

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn test_operation_id(name: &str) -> String
    {
        format!("{name}-{}", now_epoch_ms())
    }

    fn test_event(operation_id: &str, sequence: u64) -> AgentApiCallEvent
    {
        AgentApiCallEvent
        {
            schema_version: "0.1.0".to_string(),
            message_type: "api_call".to_string(),
            operation_id: operation_id.to_string(),
            pid: 100,
            tid: 200,
            timestamp_utc: "2026-06-10T00:00:00.000Z".to_string(),
            sequence,
            api: "CreateFileW".to_string(),
            module: "kernel32.dll".to_string(),
            api_family: Some("file_io".to_string()),
            api_category: Some("file".to_string()),
            api_risk: Some("low".to_string()),
            hook_policy: Some("iat".to_string()),
            coverage_status: Some("smoke_verified".to_string()),
            process: "knmon-sample-fileio.exe".to_string(),
            return_value: "0x1".to_string(),
            last_error_code: 0,
            last_error_message: String::new(),
            duration_us: 10,
            arguments: Vec::new(),
            tags: vec!["fileio".to_string()],
            stack: Vec::new(),
            buffer_preview: String::new(),
        }
    }

    fn test_batch(operation_id: &str, session_id: &str, batch_sequence: u64) -> NativeTraceBatch
    {
        NativeTraceBatch
        {
            schema_version: "0.1.0".to_string(),
            frame_type: "trace_batch".to_string(),
            session_id: session_id.to_string(),
            operation_id: operation_id.to_string(),
            batch_sequence,
            first_record_sequence: batch_sequence,
            last_record_sequence: batch_sequence,
            event_count: 1,
            dropped_events: 0,
            records_streamed: batch_sequence,
            host_dropped_batches: 0,
            events: vec![test_event(operation_id, batch_sequence)],
        }
    }

    #[test]
    fn streaming_trace_batch_cursor_returns_only_new_batches()
    {
        let operation_id = test_operation_id("cursor");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 1234, 1000);

        let batch = test_batch(&operation_id, &session_id, 1);
        let line = serde_json::to_string(&batch).unwrap();
        process_streaming_frame_line(&operation_id, &line).unwrap();

        let first = drain_native_trace_batches(session_id.clone(), 0).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].batch_sequence, 1);

        let second = drain_native_trace_batches(session_id, 1).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn streaming_trace_batch_queue_accounts_host_drops()
    {
        let operation_id = test_operation_id("overflow");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 5678, 1000);

        for sequence in 1..=(STREAM_BATCH_QUEUE_LIMIT as u64 + 3)
        {
            push_native_trace_batch(&operation_id, test_batch(&operation_id, &session_id, sequence));
        }

        let batches = drain_native_trace_batches(session_id, 0).unwrap();
        assert_eq!(batches.len(), STREAM_BATCH_QUEUE_LIMIT);
        assert_eq!(batches[0].batch_sequence, 4);
        assert_eq!(batches.last().unwrap().batch_sequence, STREAM_BATCH_QUEUE_LIMIT as u64 + 3);
        assert_eq!(batches.last().unwrap().host_dropped_batches, 3);
    }

    #[test]
    fn streaming_capture_result_frame_updates_session_cleanup_state()
    {
        let operation_id = test_operation_id("capture-result");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 9012, 1000);

        let frame = serde_json::json!({
            "schemaVersion": "0.1.0",
            "frameType": "capture_result",
            "session": {
                "schemaVersion": "0.1.0",
                "sessionId": session_id,
                "operationId": operation_id,
                "sessionKind": "attach_capture_stream",
                "ownerProcessId": 1,
                "helperProcessId": 2,
                "targetProcessId": 9012,
                "sessionState": "stopped",
                "startedUtc": "2026-06-10T00:00:00.000Z",
                "updatedUtc": "2026-06-10T00:00:01.000Z",
                "stoppedUtc": "2026-06-10T00:00:01.000Z",
                "cancellationEventName": "Local\\\\KNMonCancel_test",
                "lastTransportSequence": 7,
                "recordsStreamed": 7,
                "transportDroppedEvents": 0,
                "hostDroppedBatches": 0,
                "staleReason": "",
                "recoveryAction": "",
                "shutdownEvidence": "agent_shutdown",
                "stopRequested": true,
                "agentCleanupAttempted": true,
                "agentCleanupSucceeded": true
            },
            "captureResult": {
                "schemaVersion": "0.1.0",
                "operationId": operation_id,
                "sessionId": session_id,
                "sessionState": "stopped",
                "sessionKind": "attach_capture_stream",
                "ownerProcessId": 1,
                "helperProcessId": 2,
                "startedUtc": "2026-06-10T00:00:00.000Z",
                "updatedUtc": "2026-06-10T00:00:01.000Z",
                "stoppedUtc": "2026-06-10T00:00:01.000Z",
                "cancellationEventName": "Local\\\\KNMonCancel_test",
                "lastTransportSequence": 7,
                "recordsStreamed": 7,
                "staleReason": "",
                "recoveryAction": "",
                "sessionShutdownEvidence": "agent_shutdown",
                "success": false,
                "backendMode": "native-capture",
                "captureMode": "bounded-native-attach",
                "injectionMethod": "remote LoadLibraryW",
                "targetPath": "",
                "agentPath": "",
                "attachProcessId": 9012,
                "detachPolicy": "self-disable-no-unload",
                "targetProcessId": 9012,
                "targetThreadId": 0,
                "architecture": "x64",
                "win32ErrorCode": 1223,
                "ntStatus": "0x00000000",
                "subsystem": "knmon-core",
                "operation": "operation_cancelled",
                "message": "cancelled",
                "cancelRequested": true,
                "cancelObserved": true,
                "cancelStage": "attach_capture",
                "operationState": "cancelled",
                "agentCleanupAttempted": true,
                "agentCleanupSucceeded": true,
                "droppedEvents": 0,
                "transportMode": "shared-memory",
                "transportCapacity": 64,
                "transportRecordsProduced": 7,
                "transportRecordsConsumed": 7,
                "transportDroppedEvents": 0,
                "transportHighWaterMark": 2,
                "hookOverheadMinUs": 1,
                "hookOverheadAvgUs": 1,
                "hookOverheadMaxUs": 1,
                "handshake": {
                    "received": true,
                    "schemaVersion": "0.1.0",
                    "operationId": operation_id,
                    "processId": 9012,
                    "threadId": 1,
                    "architecture": "x64",
                    "agentVersion": "0.1.0",
                    "message": "ok",
                    "rawPayload": "{}"
                },
                "auditEvents": [],
                "agentMessages": [],
                "capturedEvents": []
            }
        });

        process_streaming_frame_line(&operation_id, &frame.to_string()).unwrap();
        let sessions = native_session_states();
        let session = sessions.iter().find(|item| item.operation_id == operation_id).unwrap();
        assert_eq!(session.session_state, "stopped");
        assert!(session.agent_cleanup_attempted);
        assert!(session.agent_cleanup_succeeded);
        assert_eq!(session.records_streamed, 7);
    }
}
