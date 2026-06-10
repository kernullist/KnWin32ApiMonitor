#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use knmon_tauri::{
    attach_target_process_capture as attach_target_process_capture_backend,
    backend_status,
    capture_sample_fileio,
    capture_sample_fileio_session,
    launch_sample_early_bird,
    mock_target_processes,
    native_target_processes,
    native_operation_states,
    native_session_states,
    replay_last_session,
    supervise_process_tree as supervise_process_tree_backend,
    cancel_native_operation as cancel_native_operation_backend,
    stop_native_session as stop_native_session_backend,
    CaptureSessionState,
    CaptureResult,
    LaunchResult,
    NativeOperation,
    NativeSession,
    ProcessTreeResult,
    SessionReplayResult,
    TargetProcess,
};

#[tauri::command]
fn list_target_processes() -> Result<Vec<TargetProcess>, String>
{
    Ok(mock_target_processes())
}

#[tauri::command]
fn list_native_target_processes() -> Result<Vec<TargetProcess>, String>
{
    native_target_processes()
}

#[tauri::command]
fn launch_sample_early_bird_capture() -> Result<LaunchResult, String>
{
    launch_sample_early_bird()
}

#[tauri::command]
fn capture_sample_fileio_events() -> Result<CaptureResult, String>
{
    capture_sample_fileio()
}

#[tauri::command]
fn capture_sample_fileio_session_events() -> Result<CaptureResult, String>
{
    capture_sample_fileio_session()
}

#[tauri::command]
fn replay_last_sample_session() -> Result<SessionReplayResult, String>
{
    replay_last_session()
}

#[tauri::command]
fn attach_target_process_capture(pid: u32, duration_ms: u32) -> Result<CaptureResult, String>
{
    attach_target_process_capture_backend(pid, duration_ms)
}

#[tauri::command]
fn supervise_process_tree(root_pid: u32, duration_ms: u32, child_policy: String) -> Result<ProcessTreeResult, String>
{
    supervise_process_tree_backend(root_pid, duration_ms, child_policy)
}

#[tauri::command]
fn list_native_operations() -> Result<Vec<NativeOperation>, String>
{
    Ok(native_operation_states())
}

#[tauri::command]
fn cancel_native_operation(operation_id: String) -> Result<NativeOperation, String>
{
    cancel_native_operation_backend(operation_id)
}

#[tauri::command]
fn list_native_sessions() -> Result<Vec<NativeSession>, String>
{
    Ok(native_session_states())
}

#[tauri::command]
fn stop_native_session(session_id: String) -> Result<NativeSession, String>
{
    stop_native_session_backend(session_id)
}

#[tauri::command]
fn get_backend_status() -> Result<String, String>
{
    Ok(backend_status().to_string())
}

#[tauri::command]
fn start_mock_capture_session() -> Result<CaptureSessionState, String>
{
    Ok(CaptureSessionState::running_mock())
}

#[tauri::command]
fn stop_mock_capture_session() -> Result<CaptureSessionState, String>
{
    Ok(CaptureSessionState::stopped_mock())
}

fn main()
{
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_target_processes,
            list_native_target_processes,
            launch_sample_early_bird_capture,
            capture_sample_fileio_events,
            capture_sample_fileio_session_events,
            replay_last_sample_session,
            attach_target_process_capture,
            supervise_process_tree,
            list_native_operations,
            cancel_native_operation,
            list_native_sessions,
            stop_native_session,
            get_backend_status,
            start_mock_capture_session,
            stop_mock_capture_session
        ])
        .run(tauri::generate_context!())
        .expect("failed to run KN Win32 API Monitor");
}
