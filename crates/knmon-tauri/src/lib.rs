use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn run_helper<const N: usize>(args: [&str; N]) -> Result<String, String>
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

fn find_helper_path() -> Option<PathBuf>
{
    let manifest_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_root.join("..").join("..").join("..");
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
