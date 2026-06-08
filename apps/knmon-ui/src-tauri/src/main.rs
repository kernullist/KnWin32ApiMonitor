#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use knmon_tauri::{
    backend_status,
    capture_sample_fileio,
    capture_sample_fileio_session,
    launch_sample_early_bird,
    mock_target_processes,
    native_target_processes,
    replay_last_session,
    CaptureSessionState,
    CaptureResult,
    LaunchResult,
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
            get_backend_status,
            start_mock_capture_session,
            stop_mock_capture_session
        ])
        .run(tauri::generate_context!())
        .expect("failed to run KN Win32 API Monitor");
}
