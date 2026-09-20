#![recursion_limit = "256"]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_MAJOR: u16 = 0;
pub const PROTOCOL_MINOR: u16 = 1;
pub const PROTOCOL_PATCH: u16 = 0;
const STREAM_BATCH_QUEUE_LIMIT: usize = 128;
const STREAM_BATCH_DRAIN_LIMIT: usize = 32;
const STREAM_QUEUE_MAX_BYTES: usize = 32 * 1024 * 1024;
const STREAM_GLOBAL_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;
const OPERATION_HISTORY_LIMIT: usize = 64;
const STREAM_DRAIN_MAX_BYTES: usize = 8 * 1024 * 1024;
const INTERACTIVE_TRANSPORT_CAPACITY: &str = "16384";
const STREAM_CONTROL_TIMEOUT_MS: u32 = 7_000;
const SESSION_STOP_COMPLETION_WAIT_MS: u64 = 15_000;
const API_SELECTION_MAX_BYTES: usize = 30_000;

fn normalize_api_selection(selected_apis: &[String]) -> Result<String, String> {
    let mut tokens: Vec<String> = Vec::new();

    for value in selected_apis {
        let token = value.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }

        if token.len() > 192 || !token.is_ascii() || token.bytes().any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace() || ch == b';' || ch == b',') {
            return Err(format!("invalid API selection token: {token}"));
        }

        if token.matches('!').count() != 1 {
            return Err(format!(
                "API selection token must use module!api format: {token}"
            ));
        }

        tokens.push(token);
    }

    tokens.sort();
    tokens.dedup();

    let selection = tokens.join(";");
    if selection.len() > API_SELECTION_MAX_BYTES {
        return Err(format!(
            "API selection is too large: {} bytes",
            selection.len()
        ));
    }

    Ok(selection)
}

fn append_api_selection_arg(
    args: &mut Vec<String>,
    selected_apis: &[String],
) -> Result<(), String> {
    let selection = normalize_api_selection(selected_apis)?;
    if !selection.is_empty() {
        args.push("--api-selection".to_string());
        args.push(selection);
    }

    Ok(())
}

mod process_liveness;

pub use process_liveness::ensure_unelevated_renderer;

#[cfg(test)]
mod security_tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_name: String,
    pub image_path: Option<String>,
    pub architecture: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeOperation {
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
pub struct NativeSession {
    pub schema_version: String,
    pub session_id: String,
    pub operation_id: String,
    pub session_kind: String,
    pub owner_process_id: u32,
    pub helper_process_id: u32,
    pub target_process_id: u32,
    #[serde(default)]
    pub target_process_creation_time: String,
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
    pub target_exit_observed: bool,
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
pub struct NativeDaemonStatus {
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
pub struct NativeDaemonSessionResult {
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
pub struct NativeDaemonSessionList {
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
pub struct NativeDaemonAudit {
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
pub struct NativeDaemonRecoveryPlanItem {
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
pub struct NativeDaemonRecoveryPlan {
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
pub struct NativeDaemonRecoveryApply {
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
pub struct NativeSessionCatalogRow {
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
pub struct NativeSessionCatalog {
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
pub struct NativeTraceIndexEvent {
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
    pub relative_time_ms: f64,
    pub tags_text: String,
    pub arguments_text: String,
    pub buffer_preview: String,
    pub excerpt: String,
    pub event_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTraceIndex {
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
pub struct NativeTraceBatch {
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
    #[serde(skip)]
    storage_bytes: usize,
}

#[derive(Debug, Clone)]
struct NativeOperationRecord {
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
    helper_handle: Option<process_liveness::RetainedProcess>,
    owned_target: Option<process_liveness::RetainedProcess>,
    target_process_creation_time: String,
    stream_failed: bool,
    stream_result_received: bool,
    last_transport_sequence: u64,
    records_streamed: u64,
    transport_dropped_events: u64,
    host_dropped_batches: u64,
    last_batch_sequence: u64,
    trace_batches: VecDeque<NativeTraceBatch>,
    target_alive_observed: bool,
    target_exit_observed: bool,
    stale_reason: String,
    recovery_action: String,
    shutdown_evidence: String,
    agent_cleanup_attempted: bool,
    agent_cleanup_succeeded: bool,
    last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancellationSignalResult {
    success: bool,
    operation_id: String,
    cancellation_event_name: String,
    win32_error_code: u32,
    operation: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTargetList {
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
pub struct AuditEvent {
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
pub struct AgentHandshake {
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
pub struct LaunchResult {
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
pub struct AgentApiArgument {
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
pub struct CaptureTiming
{
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_scope: Option<String>,
    pub qpc_frequency: String,
    pub qpc_base: String,
    pub utc_base_file_time: String,
    pub anchor_span_qpc: String,
    pub start_qpc: String,
    pub end_qpc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedSemantics
{
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_return_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_return_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_last_error_code: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_winsock_error_code: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winsock_error_sampled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_validity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_predicate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_error: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<CaptureTiming>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApiCallEvent {
    #[serde(flatten)]
    pub semantics: CapturedSemantics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_time_ms: Option<f64>,
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
pub struct RetainedCaptureHistory
{
    pub bounded: bool,
    pub captured_events_total: u64,
    pub omitted_captured_events: u64,
    pub omitted_agent_messages: u64,
    pub omitted_audit_events: u64,
    pub omitted_resolver_pointer_candidates: u64,
    pub omitted_resolver_pointer_unsupported: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    #[serde(default)]
    pub retained_history: Option<RetainedCaptureHistory>,
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
pub struct ProcessTreeNode {
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
pub struct ChildPolicyDecision {
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
pub struct ProcessTreeResult {
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
pub struct SessionInfo {
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
pub struct TraceError {
    pub kind: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    #[serde(flatten)]
    pub semantics: CapturedSemantics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
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
pub struct SessionReplayResult {
    pub schema_version: String,
    pub success: bool,
    pub backend_mode: String,
    pub capture_mode: String,
    pub session: SessionInfo,
    pub message: String,
    pub trace_events: Vec<TraceEvent>,
}

static NATIVE_OPERATIONS: OnceLock<Mutex<HashMap<String, NativeOperationRecord>>> = OnceLock::new();

fn operation_registry() -> &'static Mutex<HashMap<String, NativeOperationRecord>> {
    NATIVE_OPERATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis()
}

fn next_operation_sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

fn new_operation_id(prefix: &str, process_id: u32) -> String {
    // Include monotonic sequence so same-millisecond concurrent starts cannot collide.
    format!(
        "{prefix}-{process_id}-{}-{}",
        now_epoch_ms(),
        next_operation_sequence()
    )
}

fn new_session_id(operation_id: &str) -> String {
    format!("session-{operation_id}")
}

fn timestamp_label(epoch_ms: u128) -> String {
    format!("epoch-ms:{epoch_ms}")
}

fn sanitize_event_part(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();

    if sanitized.is_empty() {
        "operation".to_string()
    } else {
        sanitized
    }
}

fn cancellation_event_name(operation_id: &str) -> String {
    format!("Local\\KNMonCancel_{}", sanitize_event_part(operation_id))
}

fn operation_view(record: &NativeOperationRecord) -> NativeOperation {
    NativeOperation {
        operation_id: record.operation_id.clone(),
        operation_kind: record.operation_kind.clone(),
        target_process_id: record.target_process_id,
        state: record.state.clone(),
        cancel_requested: record.cancel_requested,
        elapsed_ms: record.started_at.elapsed().as_millis() as u64,
        duration_ms: record.duration_ms,
    }
}

fn session_state_from_operation_state(state: &str) -> String {
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

fn is_terminal_operation_state(state: &str) -> bool {
    matches!(
        state,
        "completed"
            | "cancelled"
            | "cleanup_failed"
            | "failed"
            | "stopped"
            | "stale"
            | "recovery_required"
    )
}

fn session_view(record: &NativeOperationRecord) -> NativeSession {
    let now_ms = now_epoch_ms();
    let elapsed_ms = record.started_at.elapsed().as_millis() as u64;
    let helper_alive = record.helper_handle.as_ref().map_or_else(|| process_liveness::is_process_alive(record.helper_process_id), |process| process.alive());
    let target_alive = record.owned_target.as_ref().map_or_else(|| process_liveness::is_process_alive(record.target_process_id), |process| process.alive());
    let target_exit_observed =
        record.target_exit_observed || (record.target_alive_observed && !target_alive);
    let stopped_utc = if record.finished_at_ms == 0 {
        String::new()
    } else {
        timestamp_label(record.finished_at_ms)
    };

    NativeSession {
        schema_version: "0.1.0".to_string(),
        session_id: record.session_id.clone(),
        operation_id: record.operation_id.clone(),
        session_kind: record.operation_kind.clone(),
        owner_process_id: std::process::id(),
        helper_process_id: record.helper_process_id,
        target_process_id: record.target_process_id,
        target_process_creation_time: record.target_process_creation_time.clone(),
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
        session_process_alive: helper_alive,
        target_alive,
        target_exit_observed,
        knapm_exists: false,
        knapm_valid: false,
        recovery_state: String::new(),
        recovery_reason: String::new(),
        prune_eligible: false,
        prune_reason: String::new(),
    }
}

fn reserve_operation_slot(registry: &mut HashMap<String, NativeOperationRecord>) -> Result<(), String>
{
    while registry.len() >= OPERATION_HISTORY_LIMIT
    {
        let removable = registry.iter().filter(|(_, record)|
            is_terminal_operation_state(&record.state) &&
            !matches!(record.state.as_str(), "cleanup_failed" | "recovery_required") &&
            (record.recovery_action.is_empty() || record.recovery_action == "none") &&
            record.helper_handle.as_ref().is_none_or(|helper| !helper.alive()))
            .min_by_key(|(_, record)| record.started_at).map(|(id, _)| id.clone());
        if let Some(id) = removable
        {
            registry.remove(&id);
        }
        else
        {
            return Err("Native operation limit reached; stop an active operation before starting another.".to_string());
        }
    }
    Ok(())
}

fn trim_global_trace_queues(registry: &mut HashMap<String, NativeOperationRecord>)
{
    let mut bytes: usize = registry.values().flat_map(|record| &record.trace_batches)
        .map(|batch| batch.storage_bytes).sum();
    while bytes > STREAM_GLOBAL_QUEUE_MAX_BYTES
    {
        let oldest = registry.values_mut().filter(|record| !record.trace_batches.is_empty())
            .min_by_key(|record| record.started_at);
        if let Some(record) = oldest
        {
            if let Some(batch) = record.trace_batches.pop_front()
            {
                bytes = bytes.saturating_sub(batch.storage_bytes);
                record.host_dropped_batches = record.host_dropped_batches.saturating_add(1);
            }
        }
        else
        {
            break;
        }
    }
}

fn register_native_operation(
    operation_id: &str,
    operation_kind: &str,
    target_process_id: u32,
    duration_ms: u32,
) -> Result<(), String>
{
    let mut registry = operation_registry().lock().unwrap();
    if registry.contains_key(operation_id)
    {
        return Err("Native operation identity is already registered.".to_string());
    }
    reserve_operation_slot(&mut registry)?;
    registry.insert(
        operation_id.to_string(),
        NativeOperationRecord {
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
            helper_handle: None,
            owned_target: None,
            target_process_creation_time: String::new(),
            stream_failed: false,
            stream_result_received: false,
            last_transport_sequence: 0,
            records_streamed: 0,
            transport_dropped_events: 0,
            host_dropped_batches: 0,
            last_batch_sequence: 0,
            trace_batches: VecDeque::new(),
            target_alive_observed: false,
            target_exit_observed: false,
            stale_reason: String::new(),
            recovery_action: String::new(),
            shutdown_evidence: String::new(),
            agent_cleanup_attempted: false,
            agent_cleanup_succeeded: false,
            last_error: String::new(),
        },
    );
    Ok(())
}

fn finish_native_operation(operation_id: &str, state: &str) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
    }
}

fn finish_native_operation_with_capture(operation_id: &str, state: &str, result: &CaptureResult) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
        record.last_transport_sequence = result.last_transport_sequence;
        record.records_streamed = result.records_streamed;
        record.transport_dropped_events = result.transport_dropped_events;
        record.shutdown_evidence = result.session_shutdown_evidence.clone();
        record.agent_cleanup_attempted = result.agent_cleanup_attempted;
        record.agent_cleanup_succeeded = result.agent_cleanup_succeeded;
        if result.operation_state == "cleanup_failed" {
            record.recovery_action = "manual_same_bitness_cleanup_required".to_string();
        }
    }
}

fn finish_native_operation_with_process_tree(
    operation_id: &str,
    state: &str,
    result: &ProcessTreeResult,
) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        record.state = state.to_string();
        record.finished_at_ms = now_epoch_ms();
        record.last_transport_sequence = result.last_transport_sequence;
        record.records_streamed = result.records_streamed;
        if result.operation_state == "cleanup_failed" {
            record.recovery_action = "manual_same_bitness_cleanup_required".to_string();
        }
    }
}

#[cfg(test)]
fn mark_native_operation_helper_pid(operation_id: &str, helper_process_id: u32) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        record.helper_process_id = helper_process_id;
    }
}

fn update_native_record_from_session(record: &mut NativeOperationRecord, session: &NativeSession) {
    if record.stream_failed
    {
        return;
    }
    if record.operation_kind == "launch_capture_stream" && record.owned_target.is_none() && session.target_process_id != 0
    {
        if let Ok(created) = session.target_process_creation_time.parse::<u64>()
        {
            record.owned_target = process_liveness::RetainedProcess::open_identified(session.target_process_id, created, true).ok();
        }
    }
    record.target_process_creation_time = session.target_process_creation_time.clone();
    record.target_process_id = session.target_process_id;
    record.state = session.session_state.clone();
    record.cancel_requested |= session.stop_requested;
    record.last_transport_sequence = session.last_transport_sequence;
    record.records_streamed = session.records_streamed;
    record.transport_dropped_events = session.transport_dropped_events;
    record.host_dropped_batches = session
        .host_dropped_batches
        .max(record.host_dropped_batches);
    if session.target_process_id != 0 {
        if session.target_alive {
            record.target_alive_observed = true;
        } else if record.target_alive_observed || session.target_exit_observed {
            record.target_exit_observed = true;
        }
    }
    record.stale_reason = session.stale_reason.clone();
    record.recovery_action = session.recovery_action.clone();
    record.shutdown_evidence = session.shutdown_evidence.clone();
    record.agent_cleanup_attempted = session.agent_cleanup_attempted;
    record.agent_cleanup_succeeded = session.agent_cleanup_succeeded;
    if session.session_state == "stopped"
        || session.session_state == "failed"
        || session.session_state == "stale"
        || session.session_state == "recovery_required"
    {
        record.finished_at_ms = now_epoch_ms();
    }
}

fn push_native_trace_batch(operation_id: &str, mut batch: NativeTraceBatch) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        if record.stream_failed || record.stream_result_received
        {
            return;
        }
        // Reserve the maximum decimal growth of the host-drop counter after queuing.
        batch.storage_bytes = serde_json::to_vec(&batch).map_or(STREAM_FRAME_MAX_BYTES + 1,
            |bytes| bytes.len().saturating_add(20));
        if batch.storage_bytes > STREAM_FRAME_MAX_BYTES
        {
            record.host_dropped_batches = record.host_dropped_batches.saturating_add(1);
            return;
        }
        let mut queued_bytes: usize = record.trace_batches.iter().map(|item| item.storage_bytes).sum();
        while record.trace_batches.len() >= STREAM_BATCH_QUEUE_LIMIT || queued_bytes + batch.storage_bytes > STREAM_QUEUE_MAX_BYTES
        {
            if let Some(discarded) = record.trace_batches.pop_front()
            {
                queued_bytes = queued_bytes.saturating_sub(discarded.storage_bytes);
                record.host_dropped_batches = record.host_dropped_batches.saturating_add(1);
            }
            else
            {
                break;
            }
        }

        batch.host_dropped_batches = record.host_dropped_batches;
        record.last_batch_sequence = record.last_batch_sequence.max(batch.batch_sequence);
        record.last_transport_sequence = batch.last_record_sequence;
        record.records_streamed = batch.records_streamed;
        record.transport_dropped_events = batch.dropped_events;
        record.trace_batches.push_back(batch);
    }
    trim_global_trace_queues(&mut registry);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingFrameHeader {
    frame_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingSessionFrame {
    frame_type: String,
    session: NativeSession,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamingCaptureResultFrame {
    session: NativeSession,
    capture_result: CaptureResult,
}

fn update_streaming_error(operation_id: &str, state: &str, message: String) {
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id) {
        if record.stream_failed
        {
            return;
        }
        record.stream_failed = true;
        record.state = state.to_string();
        record.last_error = message;
        record.finished_at_ms = now_epoch_ms();
    }
}

fn process_streaming_frame_line(operation_id: &str, line: &str) -> Result<(), String> {
    if line.len() > STREAM_FRAME_MAX_BYTES
    {
        return Err("streaming frame exceeds byte budget".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(line).map_err(|error| format!("invalid streaming frame: {error}"))?;
    let registry = operation_registry().lock().unwrap();
    let record = registry.get(operation_id).ok_or("unknown streaming operation")?;
    if record.stream_failed || record.stream_result_received
    {
        return Err("operation stream is already terminal".to_string());
    }
    if value.get("schemaVersion").and_then(|version| version.as_str()) != Some("0.1.0")
    {
        return Err("unsupported stream schema".to_string());
    }
    let envelope = value.get("session").unwrap_or(&value);
    if envelope.get("operationId").and_then(|v| v.as_str()) != Some(operation_id) ||
        envelope.get("sessionId").and_then(|v| v.as_str()) != Some(record.session_id.as_str())
    {
        return Err("streaming operation or session identity mismatch".to_string());
    }
    if value.get("session").is_some() &&
        (envelope.get("helperProcessId").and_then(|v| v.as_u64()) != Some(record.helper_process_id as u64) ||
         envelope.get("sessionKind").and_then(|v| v.as_str()) != Some(record.operation_kind.as_str()))
    {
        return Err("streaming helper or session kind mismatch".to_string());
    }
    if let Some(result) = value.get("captureResult")
    {
        if result.get("operationId").and_then(|v| v.as_str()) != Some(operation_id)
        {
            return Err("capture result operation mismatch".to_string());
        }
    }
    let expected_pid = record.target_process_id;
    let previous_batch_sequence = record.last_batch_sequence;
    drop(registry);
    let header: StreamingFrameHeader = serde_json::from_str(line)
        .map_err(|error| format!("failed to parse streaming frame header: {error}"))?;

    match header.frame_type.as_str() {
        "trace_batch" => {
            let batch: NativeTraceBatch = serde_json::from_str(line).map_err(|error| {
                format!("failed to parse trace_batch frame: {error}")
            })?;
            if batch.batch_sequence <= previous_batch_sequence || batch.last_record_sequence < batch.first_record_sequence
            {
                return Err("trace batch sequence is duplicate, reordered or invalid".to_string());
            }
            if expected_pid == 0 || batch.event_count != batch.events.len() as u64 || batch.events.len() > 4096 ||
                batch.events.iter().any(|event| event.operation_id != operation_id || event.pid != expected_pid ||
                    event.message_type != "api_call" || event.schema_version != "0.1.0")
            {
                return Err("trace batch count or event identity mismatch".to_string());
            }
            push_native_trace_batch(operation_id, batch);
        }
        "session_started" | "session_state" | "session_stopping" | "session_stopped"
        | "session_failed" => {
            let frame: StreamingSessionFrame = serde_json::from_str(line)
                .map_err(|error| format!("failed to parse session frame: {error}"))?;
            let mut registry = operation_registry().lock().unwrap();
            if let Some(record) = registry.get_mut(operation_id) {
                if record.stream_failed || record.stream_result_received
                {
                    return Err("operation stream became terminal".to_string());
                }
                let state = if frame.frame_type == "session_stopping" {
                    "stop_requested".to_string()
                } else {
                    frame.session.session_state.clone()
                };
                if record.target_process_id != 0 && frame.session.target_process_id != record.target_process_id
                {
                    return Err("target process identity changed within a stream".to_string());
                }
                if record.operation_kind == "launch_capture_stream" && frame.session.target_process_id != 0 &&
                    frame.session.target_process_creation_time.parse::<u64>().unwrap_or(0) == 0
                {
                    return Err("launch target creation time missing".to_string());
                }
                if !record.target_process_creation_time.is_empty() && record.target_process_creation_time != "0" &&
                    record.target_process_creation_time != frame.session.target_process_creation_time
                {
                    return Err("target creation time changed within a stream".to_string());
                }
                update_native_record_from_session(record, &frame.session);
                record.state = if record.cancel_requested && !is_terminal_operation_state(&state)
                {
                    "cancel_requested".to_string()
                }
                else
                {
                    state
                };
            }
        }
        "capture_result" => {
            let frame: StreamingCaptureResultFrame =
                serde_json::from_str(line).map_err(|error| {
                    format!("failed to parse capture_result frame: {error}")
                })?;
            let operation_state = if frame.capture_result.operation_state.is_empty() {
                if frame.capture_result.success {
                    "completed".to_string()
                } else if frame.capture_result.operation == "operation_cancelled" {
                    "cancelled".to_string()
                } else {
                    "failed".to_string()
                }
            } else {
                frame.capture_result.operation_state.clone()
            };

            let mut registry = operation_registry().lock().unwrap();
            if let Some(record) = registry.get_mut(operation_id) {
                if record.stream_failed || record.stream_result_received
                {
                    return Err("operation stream became terminal".to_string());
                }
                if record.target_process_id != 0 && frame.session.target_process_id != record.target_process_id
                {
                    return Err("target process identity changed within a stream".to_string());
                }
                if record.operation_kind == "launch_capture_stream" && frame.session.target_process_id != 0 &&
                    frame.session.target_process_creation_time.parse::<u64>().unwrap_or(0) == 0
                {
                    return Err("launch target creation time missing".to_string());
                }
                if !record.target_process_creation_time.is_empty() && record.target_process_creation_time != "0" &&
                    record.target_process_creation_time != frame.session.target_process_creation_time
                {
                    return Err("target creation time changed within a stream".to_string());
                }
                update_native_record_from_session(record, &frame.session);
                record.stream_result_received = true;
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
        other => {
            return Err(format!("unsupported streaming frame type: {other}"));
        }
    }

    Ok(())
}

pub fn native_operation_states() -> Vec<NativeOperation> {
    let registry = operation_registry().lock().unwrap();
    let mut operations: Vec<NativeOperation> = registry.values().map(operation_view).collect();
    operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    operations
}

pub fn native_session_states() -> Vec<NativeSession> {
    let registry = operation_registry().lock().unwrap();
    let mut sessions: Vec<NativeSession> = registry.values().map(session_view).collect();
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    sessions
}

fn wait_for_native_session_terminal(operation_id: &str, timeout_ms: u64) -> Option<NativeSession> {
    let start = Instant::now();

    loop {
        let terminal_session = {
            let registry = operation_registry().lock().unwrap();
            registry.get(operation_id).map(|record| {
                let session = session_view(record);
                let terminal = is_terminal_operation_state(&record.state);
                (session, terminal)
            })
        };

        match terminal_session {
            Some((session, true)) => {
                return Some(session);
            }
            Some((session, false)) => {
                if start.elapsed() >= Duration::from_millis(timeout_ms) {
                    return Some(session);
                }
            }
            None => {
                return None;
            }
        }

        thread::sleep(Duration::from_millis(50));
    }
}

pub fn cancel_native_operation(operation_id: String) -> Result<NativeOperation, String> {
    {
        let mut registry = operation_registry().lock().unwrap();
        let record = registry
            .get_mut(&operation_id)
            .ok_or_else(|| format!("operation not found: {operation_id}"))?;
        if is_terminal_operation_state(&record.state)
        {
            return Ok(operation_view(record));
        }
        record.cancel_requested = true;
        record.state = "cancel_requested".to_string();
    }

    signal_registered_operation(&operation_id)?;

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(operation_view)
        .ok_or_else(|| format!("operation not found after cancel: {operation_id}"))
}

pub fn stop_native_session(session_id: String) -> Result<NativeSession, String> {
    let operation_id = {
        let mut registry = operation_registry().lock().unwrap();
        let record = registry
            .values_mut()
            .find(|record| record.session_id == session_id)
            .ok_or_else(|| format!("session not found: {session_id}"))?;
        if is_terminal_operation_state(&record.state)
        {
            return Ok(session_view(record));
        }
        record.cancel_requested = true;
        record.state = "cancel_requested".to_string();
        record.operation_id.clone()
    };

    signal_registered_operation(&operation_id)?;

    if let Some(session) =
        wait_for_native_session_terminal(&operation_id, SESSION_STOP_COMPLETION_WAIT_MS)
    {
        return Ok(session);
    }

    let registry = operation_registry().lock().unwrap();
    registry
        .get(&operation_id)
        .map(session_view)
        .ok_or_else(|| format!("session not found after stop: {session_id}"))
}

pub fn cleanup_active_sessions_on_exit() -> Vec<String>
{
    let candidates =
    {
        let registry = operation_registry().lock().unwrap();
        registry.values().filter(|record| !is_terminal_operation_state(&record.state) &&
            (record.operation_kind == "launch_capture_stream" || record.operation_kind == "attach_capture_stream"))
            .map(|record| (record.operation_id.clone(), record.operation_kind.clone(), record.helper_handle.clone(), record.owned_target.clone()))
            .collect::<Vec<_>>()
    };
    let mut notes = Vec::new();
    for (operation_id, kind, helper, target) in candidates
    {
        if kind == "launch_capture_stream"
        {
            if helper.as_ref().is_some_and(|process| process.alive())
            {
                // The helper owns the launch job and watches our original process object.
                notes.push(format!("{operation_id}: owned launch job will close after owner exit."));
            }
            else if let Some(process) = target
            {
                match process.terminate_owned(1)
                {
                    Ok(()) => notes.push(format!("{operation_id}: owned process handle cleanup completed; pid={} created={}.", process.process_id, process.creation_time)),
                    Err(error) => notes.push(format!("{operation_id}: owned process cleanup failed; win32={error}.")),
                }
            }
            continue;
        }
        match signal_cancel_operation(&operation_id)
        {
            Ok(signal) => notes.push(format!("{operation_id}: stop signal success={}", signal.success)),
            Err(error) => notes.push(format!("{operation_id}: stop signal failed: {error}")),
        }
    }
    notes
}

const STREAM_FRAME_MAX_BYTES: usize = 8 * 1024 * 1024;
const STREAM_STDERR_MAX_BYTES: usize = 64 * 1024;

struct OperationStart
{
    operation_id: String,
    committed: bool,
}

impl OperationStart
{
    fn new(operation_id: &str, kind: &str, pid: u32, duration: u32) -> Result<Self, String>
    {
        register_native_operation(operation_id, kind, pid, duration)?;
        Ok(Self { operation_id: operation_id.to_string(), committed: false })
    }

    fn finish<T>(mut self, result: Result<T, String>) -> Result<T, String>
    {
        if let Err(error) = &result
        {
            update_streaming_error(&self.operation_id, "failed", error.clone());
        }
        self.committed = true;
        result
    }
}

impl Drop for OperationStart
{
    fn drop(&mut self)
    {
        if !self.committed
        {
            update_streaming_error(&self.operation_id, "failed", "operation startup rolled back".to_string());
        }
    }
}

struct OwnedChild(std::process::Child);

impl Drop for OwnedChild
{
    fn drop(&mut self)
    {
        if !matches!(self.0.try_wait(), Ok(Some(_)))
        {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn read_stream_line(reader: &mut impl BufRead) -> Result<Option<String>, String>
{
    let mut bytes = Vec::new();
    loop
    {
        let available = reader.fill_buf().map_err(|e| e.to_string())?;
        if available.is_empty()
        {
            if bytes.is_empty()
            {
                return Ok(None);
            }
            return Err("stream ended with an incomplete frame".to_string());
        }
        let newline = available.iter().position(|value| *value == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if bytes.len() + count > STREAM_FRAME_MAX_BYTES
        {
            return Err("streaming frame exceeds byte budget".to_string());
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some()
        {
            return String::from_utf8(bytes).map(Some).map_err(|_| "streaming frame is not UTF-8".to_string());
        }
    }
}

fn read_bounded_stderr(mut pipe: impl Read, stop: Option<&std::sync::atomic::AtomicBool>) -> String
{
    let mut saved = Vec::new();
    let mut buffer = [0u8; 4096];
    loop
    {
        if stop.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        {
            break;
        }
        match pipe.read(&mut buffer)
        {
            Ok(0) | Err(_) => break,
            Ok(count) =>
            {
                let keep = count.min(STREAM_STDERR_MAX_BYTES.saturating_sub(saved.len()));
                saved.extend_from_slice(&buffer[..keep]);
            }
        }
    }
    String::from_utf8_lossy(&saved).into_owned()
}

fn stop_reader<T>(thread: thread::JoinHandle<T>) -> Option<T>
{
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        extern "system"
        {
            fn CancelSynchronousIo(thread: *mut std::ffi::c_void) -> i32;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !thread.is_finished() && Instant::now() < deadline
        {
            unsafe
            {
                CancelSynchronousIo(thread.as_raw_handle());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    if thread.is_finished()
    {
        thread.join().ok()
    }
    else
    {
        None
    }
}

fn spawn_streaming_helper(helper_path: &Path, args: &[String], operation_id: &str) -> Result<NativeSession, String>
{
    let mut child = OwnedChild(Command::new(helper_path)
        .env("KNMON_TRANSPORT_CAPACITY", INTERACTIVE_TRANSPORT_CAPACITY)
        .args(args).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|error| format!("failed to start {}: {error}", helper_path.display()))?);
    let retained = process_liveness::RetainedProcess::from_child(&child.0)?;
    let stdout = child.0.stdout.take().ok_or("helper stdout unavailable")?;
    let stderr = child.0.stderr.take().ok_or("helper stderr unavailable")?;
    {
        let mut registry = operation_registry().lock().unwrap();
        let record = registry.get_mut(operation_id).ok_or("operation missing during helper start")?;
        record.helper_process_id = retained.process_id;
        record.helper_handle = Some(retained);
    }
    let worker_operation_id = operation_id.to_string();
    thread::Builder::new().name("knmon-stream".to_string()).spawn(move ||
    {
        let stop_readers = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stderr_stop = stop_readers.clone();
        let stderr_thread = match thread::Builder::new().name("knmon-stderr".to_string()).spawn(move || read_bounded_stderr(stderr, Some(&stderr_stop)))
        {
            Ok(thread) => thread,
            Err(error) =>
            {
                update_streaming_error(&worker_operation_id, "failed", format!("stderr reader startup failed: {error}"));
                return;
            }
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let stdout_stop = stop_readers.clone();
        let stdout_thread = match thread::Builder::new().name("knmon-stdout".to_string()).spawn(move ||
        {
            let mut reader = BufReader::new(stdout);
            loop
            {
                if stdout_stop.load(std::sync::atomic::Ordering::Acquire)
                {
                    break;
                }
                let line = read_stream_line(&mut reader);
                let done = !matches!(&line, Ok(Some(_)));
                if sender.send(line).is_err() || done
                {
                    break;
                }
            }
            // On a framing fault, keep the native helper's cleanup writes flowing.
            let mut discard = [0u8; 4096];
            while !stdout_stop.load(std::sync::atomic::Ordering::Acquire)
            {
                if !matches!(reader.read(&mut discard), Ok(count) if count > 0)
                {
                    break;
                }
            }
        })
        {
            Ok(thread) => thread,
            Err(error) =>
            {
                update_streaming_error(&worker_operation_id, "failed", format!("stdout reader startup failed: {error}"));
                stop_readers.store(true, std::sync::atomic::Ordering::Release);
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = stop_reader(stderr_thread);
                return;
            }
        };
        let mut saw_result = false;
        let mut failed_at: Option<Instant> = None;
        let mut stdout_done = false;
        let mut stdout_ended_at: Option<Instant> = None;
        let mut exited_at: Option<Instant> = None;
        let mut status = None;
        loop
        {
            let mut failure = None;
            match receiver.recv_timeout(Duration::from_millis(100))
            {
                Ok(Ok(Some(line))) if failed_at.is_none() && !line.trim().is_empty() =>
                {
                    match process_streaming_frame_line(&worker_operation_id, line.trim())
                    {
                        Ok(()) =>
                        {
                            let frame: StreamingFrameHeader = serde_json::from_str(line.trim()).expect("validated frame");
                            saw_result |= frame.frame_type == "capture_result";
                        }
                        Err(error) => failure = Some(error),
                    }
                }
                Ok(Err(error)) =>
                {
                    stdout_done = true;
                    failure = Some(error);
                }
                Ok(Ok(None)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => stdout_done = true,
                _ => {},
            }
            match child.0.try_wait()
            {
                Ok(Some(exit_status)) =>
                {
                    status = Some(exit_status);
                    exited_at.get_or_insert_with(Instant::now);
                }
                Ok(None) => {},
                Err(error) => failure = Some(format!("helper status query failed: {error}")),
            }
            if stdout_done
            {
                stdout_ended_at.get_or_insert_with(Instant::now);
            }
            if stdout_ended_at.is_some_and(|start| start.elapsed() >= Duration::from_secs(2)) && status.is_none() && failed_at.is_none()
            {
                failure = Some("helper closed stdout before exiting".to_string());
            }
            if failed_at.is_none()
            {
                if let Some(error) = failure
                {
                    update_streaming_error(&worker_operation_id, "failed", error);
                    failed_at = Some(Instant::now());
                    let _ = signal_cancel_operation(&worker_operation_id);
                }
            }
            if stdout_done && status.is_some()
            {
                break;
            }
            if stdout_done
            {
                thread::sleep(Duration::from_millis(25));
            }
            if failed_at.is_some_and(|start| start.elapsed() >= Duration::from_secs(15)) ||
                exited_at.is_some_and(|start| start.elapsed() >= Duration::from_secs(2))
            {
                let _ = child.0.kill();
                let _ = child.0.wait();
                update_streaming_error(&worker_operation_id, "failed", "helper cleanup deadline exceeded".to_string());
                break;
            }
        }
        drop(receiver);
        stop_readers.store(true, std::sync::atomic::Ordering::Release);
        let stdout_stopped = stop_reader(stdout_thread).is_some();
        let stderr_result = stop_reader(stderr_thread);
        if !stdout_stopped || stderr_result.is_none()
        {
            update_streaming_error(&worker_operation_id, "failed", "reader shutdown did not complete".to_string());
        }
        let stderr_text = stderr_result.unwrap_or_default();
        if !status.is_some_and(|value| value.success()) || !saw_result
        {
            update_streaming_error(&worker_operation_id, "failed", format!("helper stream ended without successful final result: {status:?}; stderr={stderr_text}"));
        }
    }).map_err(|error| format!("stream worker startup failed: {error}"))?;
    let registry = operation_registry().lock().unwrap();
    registry.get(operation_id).map(session_view).ok_or_else(|| "operation missing after helper start".to_string())
}

pub fn start_streaming_attach_session(
    process_id: u32,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String> {
    let duration = 0;
    let helper_timeout = STREAM_CONTROL_TIMEOUT_MS;
    let operation_id = new_operation_id("ui-stream", process_id);
    let session_id = new_session_id(&operation_id);
    let start = OperationStart::new(&operation_id, "attach_capture_stream", process_id, duration)?;
    let result = (||
    {
        if process_id == 0 || process_id == std::process::id()
        {
            return Err("attach target PID is invalid".to_string());
        }
        let helper_path = find_helper_path().ok_or_else(|| {
            "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string()
        })?;

        let mut args = vec![
            "attach-session".to_string(),
            "--pid".to_string(),
            process_id.to_string(),
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
        append_api_selection_arg(&mut args, &selected_apis)?;

        spawn_streaming_helper(&helper_path, &args, &operation_id)
    })();
    start.finish(result)
}

pub fn start_launch_monitor_session(
    target_path: String,
    working_directory: String,
    launch_arguments: String,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String> {
    let target = target_path.trim();
    if target.is_empty() {
        return Err("launch target path is required".to_string());
    }

    if !Path::new(target).is_absolute() || !Path::new(target).is_file() || target.contains('\0') ||
        launch_arguments.contains('\0') || launch_arguments.encode_utf16().count() + target.encode_utf16().count() + 4 >= 32767
    {
        return Err("launch requires an absolute executable path and a bounded command line".to_string());
    }
    if !working_directory.trim().is_empty() &&
        (!Path::new(working_directory.trim()).is_absolute() || !Path::new(working_directory.trim()).is_dir() || working_directory.contains('\0'))
    {
        return Err("working directory must be an existing absolute directory".to_string());
    }

    let duration = 0;
    let helper_timeout = STREAM_CONTROL_TIMEOUT_MS;
    let operation_id = new_operation_id("ui-launch", 0);
    let session_id = new_session_id(&operation_id);
    let start = OperationStart::new(&operation_id, "launch_capture_stream", 0, duration)?;
    let result = (||
    {
        let helper_path = find_helper_path().ok_or_else(|| {
            "knmon-native-helper.exe was not found. Run `npm run native:build` first.".to_string()
        })?;

        let mut args = vec![
            "launch-session".to_string(),
            "--target".to_string(),
            target.to_string(),
            "--timeout-ms".to_string(),
            helper_timeout.to_string(),
            "--own-launch-job".to_string(),
            "--owner-created".to_string(),
            process_liveness::current_creation_time().to_string(),
            "--owner-pid".to_string(),
            std::process::id().to_string(),
            "--operation-id".to_string(),
            operation_id.clone(),
            "--session-id".to_string(),
            session_id.clone(),
            "--stream-batches".to_string(),
            "--batch-size".to_string(),
            "64".to_string(),
        ];

        let cwd = working_directory.trim();
        if !cwd.is_empty() {
            args.push("--cwd".to_string());
            args.push(cwd.to_string());
        }

        let command_line_arguments = launch_arguments.trim();
        if !command_line_arguments.is_empty() {
            args.push("--args".to_string());
            args.push(command_line_arguments.to_string());
        }
        append_api_selection_arg(&mut args, &selected_apis)?;

        spawn_streaming_helper(&helper_path, &args, &operation_id)
    })();
    start.finish(result)
}

pub fn start_daemon_if_needed() -> Result<NativeDaemonStatus, String> {
    let helper_output = run_helper_args(&[
        "daemon-start".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    let status: NativeDaemonStatus = parse_helper_json(&helper_output, "daemon-start")?;
    if !status.success {
        return Err(format!(
            "{} failed with {}: {}",
            status.operation, status.win32_error_code, status.message
        ));
    }

    Ok(status)
}

pub fn native_daemon_status() -> Result<NativeDaemonStatus, String> {
    let helper_output = run_helper_args(&[
        "daemon-status".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-status")
}

pub fn start_daemon_supervised_session(
    process_id: u32,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String> {
    let helper_timeout = STREAM_CONTROL_TIMEOUT_MS;
    let operation_id = new_operation_id("ui-daemon", process_id);
    let session_id = new_session_id(&operation_id);
    let session_path = default_daemon_session_path(&session_id);

    let mut args = vec![
        "daemon-start-session".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
        "--pid".to_string(),
        process_id.to_string(),
        "--timeout-ms".to_string(),
        helper_timeout.to_string(),
        "--operation-id".to_string(),
        operation_id,
        "--session-id".to_string(),
        session_id,
        "--write-knapm".to_string(),
        session_path.to_string_lossy().to_string(),
    ];
    append_api_selection_arg(&mut args, &selected_apis)?;

    let helper_output = run_helper_args(&args)?;

    let result: NativeDaemonSessionResult =
        parse_helper_json(&helper_output, "daemon-start-session")?;
    if !result.success {
        return Err(format!(
            "{} failed with {}: {}",
            result.operation, result.win32_error_code, result.message
        ));
    }

    Ok(result.session)
}

pub fn native_daemon_sessions() -> Result<Vec<NativeSession>, String> {
    let helper_output = run_helper_args(&[
        "daemon-list-sessions".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    let result: NativeDaemonSessionList =
        parse_helper_json(&helper_output, "daemon-list-sessions")?;
    Ok(result.sessions)
}

pub fn native_daemon_audit() -> Result<NativeDaemonAudit, String> {
    let helper_output = run_helper_args(&[
        "daemon-audit".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-audit")
}

pub fn native_daemon_recovery_plan() -> Result<NativeDaemonRecoveryPlan, String> {
    let helper_output = run_helper_args(&[
        "daemon-recovery-plan".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ])?;
    parse_helper_json(&helper_output, "daemon-recovery-plan")
}

pub fn apply_daemon_recovery(dry_run: bool) -> Result<NativeDaemonRecoveryApply, String> {
    let mut args = vec![
        "daemon-recovery-apply".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    } else {
        args.push("--apply-registry-prune".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    parse_helper_json(&helper_output, "daemon-recovery-apply")
}

pub fn prune_stale_daemon_sessions(dry_run: bool) -> Result<NativeDaemonAudit, String> {
    let mut args = vec![
        "daemon-prune-stale".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    parse_helper_json(&helper_output, "daemon-prune-stale")
}

pub fn catalog_native_sessions() -> Result<NativeSessionCatalog, String> {
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
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn query_native_session_catalog(
    limit: u32,
    state: String,
    target: String,
) -> Result<NativeSessionCatalog, String> {
    let catalog_path = default_session_catalog_path();
    if !catalog_path.is_file() {
        let _ = catalog_native_sessions()?;
    }

    let mut args = vec![
        "catalog-query".to_string(),
        "--catalog".to_string(),
        catalog_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !state.trim().is_empty() {
        args.push("--state".to_string());
        args.push(state);
    }

    if !target.trim().is_empty() {
        args.push("--target".to_string());
        args.push(target);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-query")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_session_catalog_entries(
    dry_run: bool,
) -> Result<NativeSessionCatalog, String> {
    let catalog_path = default_session_catalog_path();
    if !catalog_path.is_file() {
        let _ = catalog_native_sessions()?;
    }

    let mut args = vec![
        "catalog-remove-missing".to_string(),
        "--catalog".to_string(),
        catalog_path.to_string_lossy().to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-remove-missing")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn build_native_session_catalog_index(rebuild: bool) -> Result<NativeSessionCatalog, String> {
    let root_path = repo_root_path().join("captures");
    let database_path = default_session_catalog_index_path();
    let mut args = vec![
        "catalog-index-build".to_string(),
        "--root".to_string(),
        root_path.to_string_lossy().to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if rebuild {
        args.push("--rebuild".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-index-build")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn query_native_session_catalog_index(
    limit: u32,
    state: String,
    target: String,
) -> Result<NativeSessionCatalog, String> {
    let database_path = default_session_catalog_index_path();
    if !database_path.is_file() {
        let _ = build_native_session_catalog_index(true)?;
    }

    let mut args = vec![
        "catalog-index-query".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !state.trim().is_empty() {
        args.push("--state".to_string());
        args.push(state);
    }

    if !target.trim().is_empty() {
        args.push("--target".to_string());
        args.push(target);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog = parse_helper_json(&helper_output, "catalog-index-query")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_session_catalog_index_entries(
    dry_run: bool,
) -> Result<NativeSessionCatalog, String> {
    let database_path = default_session_catalog_index_path();
    if !database_path.is_file() {
        let _ = build_native_session_catalog_index(true)?;
    }

    let mut args = vec![
        "catalog-index-remove-missing".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeSessionCatalog =
        parse_helper_json(&helper_output, "catalog-index-remove-missing")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn build_native_trace_index(rebuild: bool) -> Result<NativeTraceIndex, String> {
    let root_path = repo_root_path().join("captures");
    let database_path = default_session_trace_index_path();
    let mut args = vec![
        "trace-index-build".to_string(),
        "--root".to_string(),
        root_path.to_string_lossy().to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if rebuild {
        args.push("--rebuild".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-build")?;
    if !result.success {
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
) -> Result<NativeTraceIndex, String> {
    let database_path = default_session_trace_index_path();
    if !database_path.is_file() {
        let _ = build_native_trace_index(true)?;
    }

    let mut args = vec![
        "trace-index-query".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !text.trim().is_empty() {
        args.push("--text".to_string());
        args.push(text);
    }
    if !api.trim().is_empty() {
        args.push("--api".to_string());
        args.push(api);
    }
    if !module.trim().is_empty() {
        args.push("--module".to_string());
        args.push(module);
    }
    if !session.trim().is_empty() {
        args.push("--session".to_string());
        args.push(session);
    }
    if !pid.trim().is_empty() {
        args.push("--pid".to_string());
        args.push(pid);
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-query")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn remove_missing_native_trace_index_entries(
    dry_run: bool,
) -> Result<NativeTraceIndex, String> {
    let database_path = default_session_trace_index_path();
    if !database_path.is_file() {
        let _ = build_native_trace_index(true)?;
    }

    let mut args = vec![
        "trace-index-remove-missing".to_string(),
        "--database".to_string(),
        database_path.to_string_lossy().to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }

    let helper_output = run_helper_args(&args)?;
    let result: NativeTraceIndex = parse_helper_json(&helper_output, "trace-index-remove-missing")?;
    if !result.success {
        return Err(result.message);
    }

    Ok(result)
}

pub fn stop_daemon_session(session_id: String) -> Result<NativeSession, String> {
    let helper_output = run_helper_args(&[
        "daemon-stop-session".to_string(),
        "--runtime-dir".to_string(),
        default_daemon_runtime_path().to_string_lossy().to_string(),
        "--session-id".to_string(),
        session_id,
    ])?;

    let result: NativeDaemonSessionResult =
        parse_helper_json(&helper_output, "daemon-stop-session")?;
    if !result.success {
        return Err(format!(
            "{} failed with {}: {}",
            result.operation, result.win32_error_code, result.message
        ));
    }

    Ok(result.session)
}

pub fn drain_native_trace_batches(
    session_id: String,
    after_batch_sequence: u64,
) -> Result<Vec<NativeTraceBatch>, String> {
    let mut registry = operation_registry().lock().unwrap();
    let record = registry
        .values_mut()
        .find(|record| record.session_id == session_id)
        .ok_or_else(|| format!("session not found: {session_id}"))?;

    if after_batch_sequence > record.last_batch_sequence
    {
        return Err("trace batch cursor exceeds the produced sequence".to_string());
    }

    // The consumer confirmed every batch at or before the cursor; drop them so
    // queue-capacity eviction only ever counts genuinely undelivered batches.
    while record
        .trace_batches
        .front()
        .is_some_and(|batch| batch.batch_sequence <= after_batch_sequence)
    {
        record.trace_batches.pop_front();
    }

    let mut bytes = 0;
    let mut batches = Vec::new();
    for batch in record.trace_batches.iter().take(STREAM_BATCH_DRAIN_LIMIT)
    {
        if !batches.is_empty() && bytes + batch.storage_bytes > STREAM_DRAIN_MAX_BYTES
        {
            break;
        }
        bytes += batch.storage_bytes;
        let mut copy = batch.clone();
        copy.host_dropped_batches = record.host_dropped_batches;
        batches.push(copy);
    }

    Ok(batches)
}

pub fn backend_status() -> &'static str {
    "native-capture"
}

pub fn native_helper_architecture() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "x64"
    } else if cfg!(target_pointer_width = "32") {
        "x86"
    } else {
        "unknown"
    }
}

pub fn query_binary_architecture(path: String) -> Result<String, String>
{
    let target_path = path.trim();
    if target_path.is_empty()
    {
        return Err("target path is empty".to_string());
    }

    let mut file = std::fs::File::open(target_path)
        .map_err(|error| format!("failed to open target binary: {error}"))?;

    let mut dos_header = [0u8; 64];
    file.read_exact(&mut dos_header)
        .map_err(|error| format!("failed to read target DOS header: {error}"))?;

    if dos_header[0] != b'M' || dos_header[1] != b'Z'
    {
        return Err("target binary is not a valid PE image: missing MZ signature".to_string());
    }

    let pe_offset = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]);
    if pe_offset == 0 || pe_offset > 256 * 1024 * 1024
    {
        return Err("target binary has an invalid PE header offset".to_string());
    }

    file.seek(SeekFrom::Start(u64::from(pe_offset)))
        .map_err(|error| format!("failed to seek target PE header: {error}"))?;

    let mut file_header = [0u8; 6];
    file.read_exact(&mut file_header)
        .map_err(|error| format!("failed to read target PE header: {error}"))?;

    if file_header[0] != b'P'
        || file_header[1] != b'E'
        || file_header[2] != 0
        || file_header[3] != 0
    {
        return Err("target binary is not a valid PE image: missing PE signature".to_string());
    }

    let machine = u16::from_le_bytes([file_header[4], file_header[5]]);
    match machine
    {
        0x014c => Ok("x86".to_string()),
        0x8664 => Ok("x64".to_string()),
        0xaa64 => Ok("arm64".to_string()),
        _ => Ok(format!("unknown-0x{machine:04x}")),
    }
}

pub fn native_target_processes() -> Result<Vec<TargetProcess>, String> {
    let helper_output = run_helper(["list-targets"])?;
    let target_list: NativeTargetList = serde_json::from_str(&helper_output).map_err(|error| {
        format!("failed to parse native target list: {error}; stdout={helper_output}")
    })?;

    if !target_list.success {
        return Err(format!(
            "{} failed with {}: {}",
            target_list.operation, target_list.win32_error_code, target_list.message
        ));
    }

    Ok(target_list.targets)
}

pub fn launch_sample_early_bird() -> Result<LaunchResult, String> {
    let helper_output = run_helper(["launch-sample"])?;
    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse launch result: {error}; stdout={helper_output}"))
}

pub fn capture_sample_fileio() -> Result<CaptureResult, String> {
    let helper_output = run_helper(["capture-sample"])?;
    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse capture result: {error}; stdout={helper_output}"))
}

pub fn capture_sample_fileio_session() -> Result<CaptureResult, String> {
    let session_path = default_session_path();
    let helper_output = run_helper_args(&[
        "capture-sample".to_string(),
        "--write-session".to_string(),
        session_path.to_string_lossy().to_string(),
    ])?;

    serde_json::from_str(&helper_output).map_err(|error| {
        format!("failed to parse capture session result: {error}; stdout={helper_output}")
    })
}

pub fn replay_last_session() -> Result<SessionReplayResult, String> {
    let session_path = default_session_path();
    replay_session_at_path(session_path)
}

pub fn replay_session_at_path(session_path: PathBuf) -> Result<SessionReplayResult, String>
{
    replay_session_window(session_path, None)
}

fn replay_session_window(session_path: PathBuf, selected_event_id: Option<u64>) -> Result<SessionReplayResult, String>
{
    let mut args = vec!["replay-session".to_string(), "--session".to_string(),
        session_path.to_string_lossy().to_string(), "--window-limit".to_string(), "5000".to_string()];
    if let Some(event_id) = selected_event_id
    {
        args.extend(["--selected-event-id".to_string(), event_id.to_string()]);
    }
    let helper_output = run_helper_args(&args)?;
    serde_json::from_str(&helper_output).map_err(|error| format!("failed to parse session replay result: {error}"))
}

pub fn replay_session_path(session_path: String, selected_event_id: Option<u64>) -> Result<SessionReplayResult, String> {
    if session_path.trim().is_empty() {
        return Err("session path is empty".to_string());
    }

    replay_session_window(PathBuf::from(session_path), selected_event_id)
}

pub fn attach_target_process_capture(
    process_id: u32,
    duration_ms: u32,
    selected_apis: Vec<String>,
) -> Result<CaptureResult, String> {
    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let command_timeout = helper_process_timeout_ms(duration);
    let operation_id = new_operation_id("ui-attach", process_id);
    let start = OperationStart::new(&operation_id, "attach_capture", process_id, duration)?;
    let outcome = (||
    {
        let mut args = vec![
            "attach-capture".to_string(),
            "--pid".to_string(),
            process_id.to_string(),
            "--duration-ms".to_string(),
            duration.to_string(),
            "--timeout-ms".to_string(),
            helper_timeout.to_string(),
            "--operation-id".to_string(),
            operation_id.clone(),
        ];
        append_api_selection_arg(&mut args, &selected_apis)?;

        let helper_output =
            match run_helper_args_with_timeout(&args, command_timeout, Some(&operation_id)) {
                Ok(output) => output,
                Err(error) => {
                    finish_native_operation(&operation_id, "failed");
                    return Err(error);
                }
            };

        let result: CaptureResult = parse_helper_json(&helper_output, "attach-capture")?;
        let operation_state = if result.operation_state.is_empty() {
            if result.success {
                "completed"
            } else {
                "failed"
            }
        } else {
            result.operation_state.as_str()
        };
        finish_native_operation_with_capture(&operation_id, operation_state, &result);
        Ok(result)
    })();
    start.finish(outcome)
}

pub fn supervise_process_tree(
    root_process_id: u32,
    duration_ms: u32,
    child_policy: String,
    selected_apis: Vec<String>,
) -> Result<ProcessTreeResult, String> {
    let normalized_policy = child_policy.trim().to_string();
    if normalized_policy != "observe" && normalized_policy != "attach-supported" {
        return Err(format!("unsupported child policy: {normalized_policy}"));
    }

    let duration = normalize_duration_ms(duration_ms);
    let helper_timeout = helper_inner_timeout_ms(duration);
    let command_timeout = helper_process_timeout_ms(duration);
    let operation_id = new_operation_id("ui-tree", root_process_id);
    let start = OperationStart::new(&operation_id, "process_tree_supervision", root_process_id, duration)?;
    let outcome = (||
    {
        let mut args = vec![
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
        ];
        append_api_selection_arg(&mut args, &selected_apis)?;

        let helper_output =
            match run_helper_args_with_timeout(&args, command_timeout, Some(&operation_id)) {
                Ok(output) => output,
                Err(error) => {
                    finish_native_operation(&operation_id, "failed");
                    return Err(error);
                }
            };

        let result: ProcessTreeResult = parse_helper_json(&helper_output, "supervise-tree")?;
        let operation_state = if result.operation_state.is_empty() {
            if result.success {
                "completed"
            } else {
                "failed"
            }
        } else {
            result.operation_state.as_str()
        };
        finish_native_operation_with_process_tree(&operation_id, operation_state, &result);
        Ok(result)
    })();
    start.finish(outcome)
}

fn parse_helper_json<T>(helper_output: &str, command_name: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    serde_json::from_str(helper_output).map_err(|error| {
        format!("failed to parse {command_name} result: {error}")
    })
}

fn run_helper<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let owned_args: Vec<String> = args.iter().map(|value| value.to_string()).collect();
    run_helper_args(&owned_args)
}

fn run_helper_args(args: &[String]) -> Result<String, String>
{
    run_helper_args_with_timeout(args, 120_000, None)
}

fn read_bounded_output(mut pipe: impl Read, limit: usize, stop: &std::sync::atomic::AtomicBool) -> Result<String, String>
{
    let mut saved = Vec::new();
    let mut buffer = [0u8; 8192];
    loop
    {
        if stop.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err("helper output reader was cancelled before EOF".to_string());
        }
        let count = pipe.read(&mut buffer).map_err(|error| format!("helper output read failed: {error}"))?;
        if count == 0
        {
            break;
        }
        if count > limit.saturating_sub(saved.len())
        {
            return Err("helper output exceeds byte budget".to_string());
        }
        saved.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(saved).map_err(|_| "helper output is not UTF-8".to_string())
}

fn signal_cancel_operation(operation_id: &str) -> Result<CancellationSignalResult, String>
{
    let name = cancellation_event_name(operation_id);
    let result = process_liveness::signal_cancel_event(&name);
    Ok(CancellationSignalResult
    {
        success: result.is_ok(),
        operation_id: operation_id.to_string(),
        cancellation_event_name: name,
        win32_error_code: result.err().unwrap_or(0),
        operation: "cancel_operation".to_string(),
        message: "Cancellation event signal attempted.".to_string(),
    })
}

fn signal_registered_operation(operation_id: &str) -> Result<(), String>
{
    let deadline = Instant::now() + Duration::from_millis(STREAM_CONTROL_TIMEOUT_MS as u64);
    loop
    {
        {
            let registry = operation_registry().lock().unwrap();
            let record = registry.get(operation_id).ok_or("operation disappeared during cancellation")?;
            if is_terminal_operation_state(&record.state)
            {
                return Ok(());
            }
        }
        let signal = signal_cancel_operation(operation_id)?;
        if signal.success
        {
            return Ok(());
        }
        if signal.win32_error_code != 2 || Instant::now() >= deadline
        {
            return Err(format!("cancel event signal failed: win32={}", signal.win32_error_code));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_helper_args_with_timeout(
    args: &[String],
    timeout_ms: u32,
    operation_id: Option<&str>,
) -> Result<String, String>
{
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let helper_path = find_helper_path().ok_or("knmon-native-helper.exe was not found")?;
    let mut child = OwnedChild(Command::new(&helper_path).args(args)
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|error| format!("failed to run {}: {error}", helper_path.display()))?);
    if let Some(id) = operation_id
    {
        let retained = process_liveness::RetainedProcess::from_child(&child.0)?;
        if let Some(record) = operation_registry().lock().unwrap().get_mut(id)
        {
            record.helper_process_id = retained.process_id;
            record.helper_handle = Some(retained);
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let stdout_pipe = child.0.stdout.take().ok_or("missing stdout pipe")?;
    let stderr_pipe = child.0.stderr.take().ok_or("missing stderr pipe")?;
    let output_stop = stop.clone();
    let output_failed = failed.clone();
    let stdout_reader = thread::Builder::new().name("knmon-output".to_string()).spawn(move ||
    {
        let result = read_bounded_output(stdout_pipe, 64 * 1024 * 1024, &output_stop);
        if result.is_err()
        {
            output_failed.store(true, Ordering::Release);
        }
        result
    }).map_err(|error| error.to_string())?;
    let error_stop = stop.clone();
    let stderr_reader = match thread::Builder::new().name("knmon-error".to_string()).spawn(move ||
        read_bounded_stderr(stderr_pipe, Some(&error_stop)))
    {
        Ok(reader) => reader,
        Err(error) =>
        {
            stop.store(true, Ordering::Release);
            let _ = child.0.kill();
            let _ = child.0.wait();
            let _ = stop_reader(stdout_reader);
            return Err(error.to_string());
        }
    };
    let started = Instant::now();
    let mut reason = None;
    loop
    {
        match child.0.try_wait()
        {
            Ok(Some(_)) => break,
            Ok(None) => {},
            Err(error) =>
            {
                reason = Some(format!("helper wait failed: {error}"));
                break;
            }
        }
        if failed.load(Ordering::Acquire) || started.elapsed() >= Duration::from_millis(timeout_ms as u64)
        {
            reason = Some(if failed.load(Ordering::Acquire)
            {
                "helper output failed".to_string()
            }
            else
            {
                format!("helper timed out after {timeout_ms} ms")
            });
            if let Some(id) = operation_id
            {
                let _ = signal_cancel_operation(id);
                let deadline = Instant::now() + Duration::from_secs(12);
                while Instant::now() < deadline
                {
                    if child.0.try_wait().ok().flatten().is_some()
                    {
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if child.0.try_wait().ok().flatten().is_none()
    {
        let _ = child.0.kill();
    }
    let status = child.0.wait();
    let deadline = Instant::now() + Duration::from_secs(2);
    while (!stdout_reader.is_finished() || !stderr_reader.is_finished()) && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    let readers_finished = stdout_reader.is_finished() && stderr_reader.is_finished();
    stop.store(true, Ordering::Release);
    let stdout = stop_reader(stdout_reader);
    let stderr = stop_reader(stderr_reader).unwrap_or_default();
    let stdout = stdout.ok_or("helper stdout reader did not stop")?;
    if let Some(reason) = reason
    {
        return Err(format!("{reason}; stderr={stderr}"));
    }
    if !readers_finished
    {
        return Err("helper pipes did not reach EOF after process exit".to_string());
    }
    if !status.map_err(|error| error.to_string())?.success()
    {
        return Err(format!("helper returned a failing exit status; stderr={stderr}"));
    }
    let stdout = stdout?;
    if stdout.trim().is_empty()
    {
        return Err(format!("helper returned empty stdout; stderr={stderr}"));
    }
    Ok(stdout)
}

fn normalize_duration_ms(duration_ms: u32) -> u32 {
    duration_ms.clamp(250, 600_000)
}

fn helper_inner_timeout_ms(duration_ms: u32) -> u32 {
    // Keep the tight historical cap for short captures but let long captures
    // actually finish: a 45 s inner ceiling would guarantee a kill for any
    // duration above ~38 s.
    duration_ms
        .saturating_add(7_000)
        .clamp(7_000, 607_000)
}

fn helper_process_timeout_ms(duration_ms: u32) -> u32 {
    duration_ms.saturating_add(10_000).clamp(10_000, 610_000)
}

fn repo_root_path() -> PathBuf {
    let manifest_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_root.join("..").join("..")
}

fn default_session_path() -> PathBuf {
    runtime_root_path()
        .join("captures")
        .join("latest-sample-fileio")
}

fn default_daemon_runtime_path() -> PathBuf {
    runtime_root_path().join("captures").join("daemon-runtime")
}

fn default_session_catalog_path() -> PathBuf {
    runtime_root_path()
        .join("captures")
        .join("session-catalog.json")
}

fn default_session_catalog_index_path() -> PathBuf {
    runtime_root_path().join("captures").join("session-catalog.db")
}

fn default_session_trace_index_path() -> PathBuf {
    runtime_root_path()
        .join("captures")
        .join("session-trace-index.db")
}

fn default_daemon_session_path(session_id: &str) -> PathBuf {
    runtime_root_path()
        .join("captures")
        .join("daemon-sessions")
        .join(format!("{}.knapm", sanitize_event_part(session_id)))
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn portable_root_candidates() -> Vec<PathBuf>
{
    std::env::current_exe().ok().and_then(|path| path.parent().map(Path::to_path_buf)).into_iter().collect()
}

fn runtime_root_path() -> PathBuf {
    for root in portable_root_candidates() {
        let flat_helper = root.join("knmon-native-helper.exe");
        let grouped_helper = root
            .join("native")
            .join("x64")
            .join("knmon-native-helper.exe");

        if flat_helper.is_file() || grouped_helper.is_file() {
            return root;
        }
    }

    repo_root_path()
}

fn find_helper_path() -> Option<PathBuf>
{
    let mut candidates = Vec::new();
    for root in portable_root_candidates()
    {
        push_unique_path(&mut candidates, root.join("knmon-native-helper.exe"));
        push_unique_path(&mut candidates, root.join("native/x64/knmon-native-helper.exe"));
    }
    if cfg!(debug_assertions)
    {
        for directory in ["build/native-msvc/Debug", "build/native/Debug", "build/native-msvc/Release", "build/native/Release"]
        {
            push_unique_path(&mut candidates, repo_root_path().join(directory).join("knmon-native-helper.exe"));
        }
    }
    candidates.into_iter().find(|candidate| candidate.is_file()).and_then(|path| path.canonicalize().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_operation_id(name: &str) -> String {
        format!("{name}-{}", now_epoch_ms())
    }

    fn test_event(operation_id: &str, sequence: u64) -> AgentApiCallEvent {
        AgentApiCallEvent {
            semantics: CapturedSemantics::default(),
            relative_time_ms: None,
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

    pub(super) fn test_batch(operation_id: &str, session_id: &str, batch_sequence: u64) -> NativeTraceBatch {
        let mut event = test_event(operation_id, batch_sequence);
        event.pid = operation_registry().lock().unwrap().get(operation_id).unwrap().target_process_id;
        NativeTraceBatch {
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
            events: vec![event],
            storage_bytes: 0,
        }
    }

    #[test]
    fn streaming_trace_batch_cursor_returns_only_new_batches() {
        let operation_id = test_operation_id("cursor");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 1234, 1000).unwrap();

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
    fn streaming_trace_batch_queue_accounts_host_drops() {
        let operation_id = test_operation_id("overflow");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 5678, 1000).unwrap();

        for sequence in 1..=(STREAM_BATCH_QUEUE_LIMIT as u64 + 3) {
            push_native_trace_batch(
                &operation_id,
                test_batch(&operation_id, &session_id, sequence),
            );
        }

        let batches = drain_native_trace_batches(session_id, 0).unwrap();
        assert_eq!(batches.len(), STREAM_BATCH_DRAIN_LIMIT);
        assert_eq!(
            batches[0].batch_sequence,
            4
        );
        assert_eq!(
            batches.last().unwrap().batch_sequence,
            STREAM_BATCH_DRAIN_LIMIT as u64 + 3
        );
        assert_eq!(batches.last().unwrap().host_dropped_batches, 3);
    }

    #[test]
    fn wait_for_native_session_terminal_returns_updated_terminal_session() {
        let operation_id = test_operation_id("stop-wait");
        register_native_operation(&operation_id, "attach_capture_stream", 6789, 1000).unwrap();

        let updater_operation_id = operation_id.clone();
        let updater = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            finish_native_operation(&updater_operation_id, "cancelled");
        });

        let session = wait_for_native_session_terminal(&operation_id, 1000).unwrap();
        updater.join().unwrap();

        assert_eq!(session.session_state, "stopped");
        assert_eq!(session.operation_id, operation_id);
    }

    #[test]
    fn streaming_capture_result_frame_updates_session_cleanup_state() {
        let operation_id = test_operation_id("capture-result");
        let session_id = new_session_id(&operation_id);
        register_native_operation(&operation_id, "attach_capture_stream", 9012, 1000).unwrap();

        mark_native_operation_helper_pid(&operation_id, 2);
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
        let session = sessions
            .iter()
            .find(|item| item.operation_id == operation_id)
            .unwrap();
        assert_eq!(session.session_state, "stopped");
        assert!(session.agent_cleanup_attempted);
        assert!(session.agent_cleanup_succeeded);
        assert_eq!(session.records_streamed, 7);
    }
    #[test]
    fn captured_semantics_preserve_exact_clock_and_error_fields()
    {
        let mut source = serde_json::to_value(test_event("qpc-test", 1)).unwrap();
        source["relativeTimeMs"] = serde_json::json!(0.125);
        source["timeSource"] = serde_json::json!("qpc");
        source["collectedAtUtc"] = serde_json::json!("2026-09-20T00:00:00Z");
        source["rawReturnValue"] = serde_json::json!("18446744073709551615");
        source["rawReturnBits"] = serde_json::json!(64);
        source["rawLastErrorCode"] = serde_json::json!(10038);
        source["rawWinsockErrorCode"] = serde_json::json!(10038);
        source["errorDomain"] = serde_json::json!("winsock");
        source["outcome"] = serde_json::json!("failure");
        source["errorValidity"] = serde_json::json!("valid");
        source["successPredicate"] = serde_json::json!("return != INVALID_SOCKET");
        source["winsockErrorSampled"] = serde_json::json!(true);
        source["hasError"] = serde_json::json!(true);
        source["timing"] = serde_json::json!({
            "qpcFrequency": "10000000", "qpcBase": "9007199254740993",
            "utcBaseFileTime": "133000000000000000", "anchorSpanQpc": "4",
            "startQpc": "9007199254742243", "endQpc": "9007199255742243"
        });
        let parsed: AgentApiCallEvent = serde_json::from_value(source.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), source);
    }

}
