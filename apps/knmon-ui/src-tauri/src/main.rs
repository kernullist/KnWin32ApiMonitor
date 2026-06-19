#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use knmon_tauri::{
    attach_target_process_capture as attach_target_process_capture_backend,
    apply_daemon_recovery as apply_daemon_recovery_backend,
    backend_status,
    build_native_session_catalog_index as build_native_session_catalog_index_backend,
    build_native_trace_index as build_native_trace_index_backend,
    capture_sample_fileio,
    capture_sample_fileio_session,
    catalog_native_sessions as catalog_native_sessions_backend,
    launch_sample_early_bird,
    mock_target_processes,
    drain_native_trace_batches as drain_native_trace_batches_backend,
    native_target_processes,
    native_operation_states,
    native_session_states,
    replay_last_session,
    replay_session_path as replay_session_path_backend,
    native_daemon_audit as native_daemon_audit_backend,
    native_daemon_recovery_plan as native_daemon_recovery_plan_backend,
    native_daemon_sessions,
    native_daemon_status as native_daemon_status_backend,
    prune_stale_daemon_sessions as prune_stale_daemon_sessions_backend,
    query_native_session_catalog as query_native_session_catalog_backend,
    query_native_session_catalog_index as query_native_session_catalog_index_backend,
    query_native_trace_index as query_native_trace_index_backend,
    remove_missing_native_session_catalog_entries as remove_missing_native_session_catalog_entries_backend,
    remove_missing_native_session_catalog_index_entries as remove_missing_native_session_catalog_index_entries_backend,
    remove_missing_native_trace_index_entries as remove_missing_native_trace_index_entries_backend,
    start_streaming_attach_session as start_streaming_attach_session_backend,
    start_daemon_if_needed as start_daemon_if_needed_backend,
    start_daemon_supervised_session as start_daemon_supervised_session_backend,
    supervise_process_tree as supervise_process_tree_backend,
    cancel_native_operation as cancel_native_operation_backend,
    stop_daemon_session as stop_daemon_session_backend,
    stop_native_session as stop_native_session_backend,
    CaptureSessionState,
    CaptureResult,
    LaunchResult,
    NativeDaemonAudit,
    NativeDaemonRecoveryApply,
    NativeDaemonRecoveryPlan,
    NativeDaemonStatus,
    NativeOperation,
    NativeSession,
    NativeSessionCatalog,
    NativeTraceIndex,
    NativeTraceBatch,
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
fn replay_session_path(session_path: String) -> Result<SessionReplayResult, String>
{
    replay_session_path_backend(session_path)
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
fn start_streaming_attach_session(pid: u32, duration_ms: u32) -> Result<NativeSession, String>
{
    start_streaming_attach_session_backend(pid, duration_ms)
}

#[tauri::command]
fn start_daemon_if_needed() -> Result<NativeDaemonStatus, String>
{
    start_daemon_if_needed_backend()
}

#[tauri::command]
fn native_daemon_status() -> Result<NativeDaemonStatus, String>
{
    native_daemon_status_backend()
}

#[tauri::command]
fn list_daemon_sessions() -> Result<Vec<NativeSession>, String>
{
    native_daemon_sessions()
}

#[tauri::command]
fn audit_daemon_sessions() -> Result<NativeDaemonAudit, String>
{
    native_daemon_audit_backend()
}

#[tauri::command]
fn plan_daemon_recovery() -> Result<NativeDaemonRecoveryPlan, String>
{
    native_daemon_recovery_plan_backend()
}

#[tauri::command]
fn apply_daemon_recovery(dry_run: bool) -> Result<NativeDaemonRecoveryApply, String>
{
    apply_daemon_recovery_backend(dry_run)
}

#[tauri::command]
fn prune_stale_daemon_sessions(dry_run: bool) -> Result<NativeDaemonAudit, String>
{
    prune_stale_daemon_sessions_backend(dry_run)
}

#[tauri::command]
fn catalog_native_sessions() -> Result<NativeSessionCatalog, String>
{
    catalog_native_sessions_backend()
}

#[tauri::command]
fn query_native_session_catalog(limit: u32, state: String, target: String) -> Result<NativeSessionCatalog, String>
{
    query_native_session_catalog_backend(limit, state, target)
}

#[tauri::command]
fn remove_missing_native_session_catalog_entries(dry_run: bool) -> Result<NativeSessionCatalog, String>
{
    remove_missing_native_session_catalog_entries_backend(dry_run)
}

#[tauri::command]
fn build_native_session_catalog_index(rebuild: bool) -> Result<NativeSessionCatalog, String>
{
    build_native_session_catalog_index_backend(rebuild)
}

#[tauri::command]
fn query_native_session_catalog_index(
    limit: u32,
    state: String,
    target: String,
) -> Result<NativeSessionCatalog, String>
{
    query_native_session_catalog_index_backend(limit, state, target)
}

#[tauri::command]
fn remove_missing_native_session_catalog_index_entries(
    dry_run: bool,
) -> Result<NativeSessionCatalog, String>
{
    remove_missing_native_session_catalog_index_entries_backend(dry_run)
}

#[tauri::command]
fn build_native_trace_index(rebuild: bool) -> Result<NativeTraceIndex, String>
{
    build_native_trace_index_backend(rebuild)
}

#[tauri::command]
fn query_native_trace_index(
    limit: u32,
    text: String,
    api: String,
    module: String,
    session: String,
    pid: String,
) -> Result<NativeTraceIndex, String>
{
    query_native_trace_index_backend(limit, text, api, module, session, pid)
}

#[tauri::command]
fn remove_missing_native_trace_index_entries(
    dry_run: bool,
) -> Result<NativeTraceIndex, String>
{
    remove_missing_native_trace_index_entries_backend(dry_run)
}

#[tauri::command]
fn start_daemon_supervised_session(pid: u32, duration_ms: u32) -> Result<NativeSession, String>
{
    start_daemon_supervised_session_backend(pid, duration_ms)
}

#[tauri::command]
fn stop_daemon_session(session_id: String) -> Result<NativeSession, String>
{
    stop_daemon_session_backend(session_id)
}

#[tauri::command]
fn drain_native_trace_batches(session_id: String, after_batch_sequence: u64) -> Result<Vec<NativeTraceBatch>, String>
{
    drain_native_trace_batches_backend(session_id, after_batch_sequence)
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
            replay_session_path,
            attach_target_process_capture,
            supervise_process_tree,
            list_native_operations,
            cancel_native_operation,
            list_native_sessions,
            stop_native_session,
            start_streaming_attach_session,
            start_daemon_if_needed,
            native_daemon_status,
            list_daemon_sessions,
            audit_daemon_sessions,
            plan_daemon_recovery,
            apply_daemon_recovery,
            prune_stale_daemon_sessions,
            catalog_native_sessions,
            query_native_session_catalog,
            remove_missing_native_session_catalog_entries,
            build_native_session_catalog_index,
            query_native_session_catalog_index,
            remove_missing_native_session_catalog_index_entries,
            build_native_trace_index,
            query_native_trace_index,
            remove_missing_native_trace_index_entries,
            start_daemon_supervised_session,
            stop_daemon_session,
            drain_native_trace_batches,
            get_backend_status,
            start_mock_capture_session,
            stop_mock_capture_session
        ])
        .run(tauri::generate_context!())
        .expect("failed to run KN Win32 API Monitor");
}
