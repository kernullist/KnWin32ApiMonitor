use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_MAJOR: u16 = 0;
pub const PROTOCOL_MINOR: u16 = 1;
pub const PROTOCOL_PATCH: u16 = 0;

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
pub struct CaptureSessionState
{
    pub state: String,
    pub backend_mode: String,
    pub event_count: u64,
    pub dropped_events: u64,
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

#[derive(Debug, Clone)]
struct NativeOperationRecord
{
    operation_id: String,
    operation_kind: String,
    target_process_id: u32,
    state: String,
    cancel_requested: bool,
    started_at: Instant,
    duration_ms: u32,
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
    pub session_id: String,
    pub session_path: String,
    pub created_utc: String,
    pub trace_event_count: u64,
    pub agent_event_count: u64,
    pub audit_event_count: u64,
    pub dropped_events: u64,
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

impl CaptureSessionState
{
    pub fn running_mock() -> Self
    {
        Self
        {
            state: "running".to_string(),
            backend_mode: "mock".to_string(),
            event_count: 0,
            dropped_events: 0,
        }
    }

    pub fn stopped_mock() -> Self
    {
        Self
        {
            state: "stopped".to_string(),
            backend_mode: "mock".to_string(),
            event_count: 0,
            dropped_events: 0,
        }
    }
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

fn register_native_operation(operation_id: &str, operation_kind: &str, target_process_id: u32, duration_ms: u32)
{
    let mut registry = operation_registry().lock().unwrap();
    registry.insert(
        operation_id.to_string(),
        NativeOperationRecord
        {
            operation_id: operation_id.to_string(),
            operation_kind: operation_kind.to_string(),
            target_process_id,
            state: "running".to_string(),
            cancel_requested: false,
            started_at: Instant::now(),
            duration_ms,
        },
    );
}

fn finish_native_operation(operation_id: &str, state: &str)
{
    let mut registry = operation_registry().lock().unwrap();
    if let Some(record) = registry.get_mut(operation_id)
    {
        record.state = state.to_string();
    }
}

pub fn native_operation_states() -> Vec<NativeOperation>
{
    let registry = operation_registry().lock().unwrap();
    let mut operations: Vec<NativeOperation> = registry.values().map(operation_view).collect();
    operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    operations
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

pub fn backend_status() -> &'static str
{
    "mock"
}

pub fn mock_target_processes() -> Vec<TargetProcess>
{
    vec![
        TargetProcess
        {
            pid: 8840,
            parent_pid: Some(672),
            image_name: "notepad.exe".to_string(),
            image_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
            architecture: "x64".to_string(),
            status: "available".to_string(),
        },
        TargetProcess
        {
            pid: 4216,
            parent_pid: Some(812),
            image_name: "explorer.exe".to_string(),
            image_path: Some("C:\\Windows\\explorer.exe".to_string()),
            architecture: "x64".to_string(),
            status: "available".to_string(),
        },
        TargetProcess
        {
            pid: 13064,
            parent_pid: Some(8840),
            image_name: "sample-fileio.exe".to_string(),
            image_path: Some("F:\\kernullist\\kn-win32apimon\\samples\\targets\\sample-fileio.exe".to_string()),
            architecture: "x64".to_string(),
            status: "mock-target".to_string(),
        },
        TargetProcess
        {
            pid: 4,
            parent_pid: None,
            image_name: "System".to_string(),
            image_path: None,
            architecture: "kernel".to_string(),
            status: "unsupported".to_string(),
        },
    ]
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
    let helper_output = run_helper_args(&[
        "replay-session".to_string(),
        "--session".to_string(),
        session_path.to_string_lossy().to_string(),
    ])?;

    serde_json::from_str(&helper_output)
        .map_err(|error| format!("failed to parse session replay result: {error}; stdout={helper_output}"))
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
    finish_native_operation(&operation_id, operation_state);
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
    finish_native_operation(&operation_id, operation_state);
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
