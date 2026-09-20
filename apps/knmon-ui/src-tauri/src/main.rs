#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use knmon_tauri::{
    attach_target_process_capture as attach_target_process_capture_backend,
    apply_daemon_recovery as apply_daemon_recovery_backend,
    backend_status,
    build_native_session_catalog_index as build_native_session_catalog_index_backend,
    build_native_trace_index as build_native_trace_index_backend,
    cancel_native_operation as cancel_native_operation_backend,
    capture_sample_fileio,
    capture_sample_fileio_session,
    catalog_native_sessions as catalog_native_sessions_backend,
    cleanup_active_sessions_on_exit as cleanup_active_sessions_on_exit_backend,
    drain_native_trace_batches as drain_native_trace_batches_backend,
    launch_sample_early_bird,
    native_daemon_audit as native_daemon_audit_backend,
    native_daemon_recovery_plan as native_daemon_recovery_plan_backend,
    native_daemon_sessions,
    native_daemon_status as native_daemon_status_backend,
    native_helper_architecture,
    native_operation_states,
    native_session_states,
    native_target_processes,
    prune_stale_daemon_sessions as prune_stale_daemon_sessions_backend,
    query_binary_architecture as query_binary_architecture_backend,
    query_native_session_catalog as query_native_session_catalog_backend,
    query_native_session_catalog_index as query_native_session_catalog_index_backend,
    query_native_trace_index as query_native_trace_index_backend,
    remove_missing_native_session_catalog_entries as remove_missing_native_session_catalog_entries_backend,
    remove_missing_native_session_catalog_index_entries as remove_missing_native_session_catalog_index_entries_backend,
    remove_missing_native_trace_index_entries as remove_missing_native_trace_index_entries_backend,
    replay_last_session,
    replay_session_path as replay_session_path_backend,
    start_daemon_if_needed as start_daemon_if_needed_backend,
    start_daemon_supervised_session as start_daemon_supervised_session_backend,
    start_launch_monitor_session as start_launch_monitor_session_backend,
    start_streaming_attach_session as start_streaming_attach_session_backend,
    stop_daemon_session as stop_daemon_session_backend,
    stop_native_session as stop_native_session_backend,
    supervise_process_tree as supervise_process_tree_backend,
    CaptureResult,
    LaunchResult,
    NativeDaemonAudit,
    NativeDaemonRecoveryApply,
    NativeDaemonRecoveryPlan,
    NativeDaemonStatus,
    NativeOperation,
    NativeSession,
    NativeSessionCatalog,
    NativeTraceBatch,
    NativeTraceIndex,
    ProcessTreeResult,
    SessionReplayResult,
    TargetProcess,
};

#[tauri::command]
fn list_native_target_processes() -> Result<Vec<TargetProcess>, String>
{
    native_target_processes()
}

#[tauri::command]
async fn launch_sample_early_bird_capture() -> Result<LaunchResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || launch_sample_early_bird())
        .await
        .map_err(|error| format!("launch_sample_early_bird_capture task failed: {error}"))?
}

#[tauri::command]
async fn capture_sample_fileio_events() -> Result<CaptureResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || capture_sample_fileio())
        .await
        .map_err(|error| format!("capture_sample_fileio_events task failed: {error}"))?
}

#[tauri::command]
async fn capture_sample_fileio_session_events() -> Result<CaptureResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || capture_sample_fileio_session())
        .await
        .map_err(|error| format!("capture_sample_fileio_session_events task failed: {error}"))?
}

#[tauri::command]
async fn replay_last_sample_session() -> Result<SessionReplayResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || replay_last_session())
        .await
        .map_err(|error| format!("replay_last_sample_session task failed: {error}"))?
}

#[tauri::command]
async fn replay_session_path(session_path: String, selected_event_id: Option<u64>) -> Result<SessionReplayResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || replay_session_path_backend(session_path, selected_event_id))
        .await
        .map_err(|error| format!("replay_session_path task failed: {error}"))?
}

#[tauri::command]
async fn attach_target_process_capture(
    pid: u32,
    duration_ms: u32,
    selected_apis: Vec<String>,
) -> Result<CaptureResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || attach_target_process_capture_backend(pid, duration_ms, selected_apis))
        .await
        .map_err(|error| format!("attach_target_process_capture task failed: {error}"))?
}

#[tauri::command]
async fn supervise_process_tree(
    root_pid: u32,
    duration_ms: u32,
    child_policy: String,
    selected_apis: Vec<String>,
) -> Result<ProcessTreeResult, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || supervise_process_tree_backend(root_pid, duration_ms, child_policy, selected_apis))
        .await
        .map_err(|error| format!("supervise_process_tree task failed: {error}"))?
}

#[tauri::command]
fn list_native_operations() -> Result<Vec<NativeOperation>, String>
{
    Ok(native_operation_states())
}

#[tauri::command]
async fn cancel_native_operation(operation_id: String) -> Result<NativeOperation, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || cancel_native_operation_backend(operation_id))
        .await
        .map_err(|error| format!("cancel_native_operation task failed: {error}"))?
}

#[tauri::command]
fn list_native_sessions() -> Result<Vec<NativeSession>, String>
{
    Ok(native_session_states())
}

#[tauri::command]
async fn stop_native_session(session_id: String) -> Result<NativeSession, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || stop_native_session_backend(session_id))
        .await
        .map_err(|error| format!("stop_native_session task failed: {error}"))?
}

#[tauri::command]
fn start_streaming_attach_session(
    pid: u32,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String>
{
    start_streaming_attach_session_backend(pid, selected_apis)
}

#[tauri::command]
fn start_launch_monitor_session(
    target_path: String,
    working_directory: String,
    launch_arguments: String,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String>
{
    start_launch_monitor_session_backend(
        target_path,
        working_directory,
        launch_arguments,
        selected_apis,
    )
}

#[tauri::command]
async fn start_daemon_if_needed() -> Result<NativeDaemonStatus, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || start_daemon_if_needed_backend())
        .await
        .map_err(|error| format!("start_daemon_if_needed task failed: {error}"))?
}

#[tauri::command]
fn native_daemon_status() -> Result<NativeDaemonStatus, String>
{
    native_daemon_status_backend()
}

#[tauri::command]
async fn list_daemon_sessions() -> Result<Vec<NativeSession>, String>
{
    tauri::async_runtime::spawn_blocking(native_daemon_sessions)
        .await
        .map_err(|error| format!("list_daemon_sessions task failed: {error}"))?
}

#[tauri::command]
async fn audit_daemon_sessions() -> Result<NativeDaemonAudit, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || native_daemon_audit_backend())
        .await
        .map_err(|error| format!("audit_daemon_sessions task failed: {error}"))?
}

#[tauri::command]
async fn plan_daemon_recovery() -> Result<NativeDaemonRecoveryPlan, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || native_daemon_recovery_plan_backend())
        .await
        .map_err(|error| format!("plan_daemon_recovery task failed: {error}"))?
}

#[tauri::command]
async fn apply_daemon_recovery(dry_run: bool) -> Result<NativeDaemonRecoveryApply, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || apply_daemon_recovery_backend(dry_run))
        .await
        .map_err(|error| format!("apply_daemon_recovery task failed: {error}"))?
}

#[tauri::command]
async fn prune_stale_daemon_sessions(dry_run: bool) -> Result<NativeDaemonAudit, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || prune_stale_daemon_sessions_backend(dry_run))
        .await
        .map_err(|error| format!("prune_stale_daemon_sessions task failed: {error}"))?
}

#[tauri::command]
async fn catalog_native_sessions() -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || catalog_native_sessions_backend())
        .await
        .map_err(|error| format!("catalog_native_sessions task failed: {error}"))?
}

#[tauri::command]
async fn query_native_session_catalog(
    limit: u32,
    state: String,
    target: String,
) -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || query_native_session_catalog_backend(limit, state, target))
        .await
        .map_err(|error| format!("query_native_session_catalog task failed: {error}"))?
}

#[tauri::command]
async fn remove_missing_native_session_catalog_entries(
    dry_run: bool,
) -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || remove_missing_native_session_catalog_entries_backend(dry_run))
        .await
        .map_err(|error| format!("remove_missing_native_session_catalog_entries task failed: {error}"))?
}

#[tauri::command]
async fn build_native_session_catalog_index(
    rebuild: bool,
) -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || build_native_session_catalog_index_backend(rebuild))
        .await
        .map_err(|error| format!("build_native_session_catalog_index task failed: {error}"))?
}

#[tauri::command]
async fn query_native_session_catalog_index(
    limit: u32,
    state: String,
    target: String,
) -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || query_native_session_catalog_index_backend(limit, state, target))
        .await
        .map_err(|error| format!("query_native_session_catalog_index task failed: {error}"))?
}

#[tauri::command]
async fn remove_missing_native_session_catalog_index_entries(
    dry_run: bool,
) -> Result<NativeSessionCatalog, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || remove_missing_native_session_catalog_index_entries_backend(dry_run))
        .await
        .map_err(|error| format!("remove_missing_native_session_catalog_index_entries task failed: {error}"))?
}

#[tauri::command]
async fn build_native_trace_index(rebuild: bool) -> Result<NativeTraceIndex, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || build_native_trace_index_backend(rebuild))
        .await
        .map_err(|error| format!("build_native_trace_index task failed: {error}"))?
}

#[tauri::command]
async fn query_native_trace_index(
    limit: u32,
    text: String,
    api: String,
    module: String,
    session: String,
    pid: String,
) -> Result<NativeTraceIndex, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || query_native_trace_index_backend(limit, text, api, module, session, pid))
        .await
        .map_err(|error| format!("query_native_trace_index task failed: {error}"))?
}

#[tauri::command]
async fn remove_missing_native_trace_index_entries(
    dry_run: bool,
) -> Result<NativeTraceIndex, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || remove_missing_native_trace_index_entries_backend(dry_run))
        .await
        .map_err(|error| format!("remove_missing_native_trace_index_entries task failed: {error}"))?
}

#[tauri::command]
async fn start_daemon_supervised_session(
    pid: u32,
    selected_apis: Vec<String>,
) -> Result<NativeSession, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || start_daemon_supervised_session_backend(pid, selected_apis))
        .await
        .map_err(|error| format!("start_daemon_supervised_session task failed: {error}"))?
}

#[tauri::command]
async fn stop_daemon_session(session_id: String) -> Result<NativeSession, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || stop_daemon_session_backend(session_id))
        .await
        .map_err(|error| format!("stop_daemon_session task failed: {error}"))?
}

#[tauri::command]
fn drain_native_trace_batches(
    session_id: String,
    after_batch_sequence: u64,
) -> Result<Vec<NativeTraceBatch>, String>
{
    drain_native_trace_batches_backend(session_id, after_batch_sequence)
}

#[tauri::command]
fn get_backend_status() -> Result<String, String>
{
    Ok(backend_status().to_string())
}

#[tauri::command]
fn get_native_helper_architecture() -> Result<String, String>
{
    Ok(native_helper_architecture().to_string())
}

#[tauri::command]
async fn query_target_binary_architecture(path: String) -> Result<String, String>
{
    // Blocking helper work runs on the async runtime so the UI thread stays responsive.
    tauri::async_runtime::spawn_blocking(move || query_binary_architecture_backend(path))
        .await
        .map_err(|error| format!("query_target_binary_architecture task failed: {error}"))?
}

fn allowed_navigation(url: &tauri::Url, development: bool) -> bool
{
    if !url.username().is_empty() || url.password().is_some()
    {
        return false;
    }
    let bundled = (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none()) ||
        (url.scheme() == "http" && url.host_str() == Some("tauri.localhost") && url.port_or_known_default() == Some(80));
    let local_dev = development && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port() == Some(5173);
    bundled || local_dev
}

fn main()
{
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app|
        {
            knmon_tauri::ensure_unelevated_renderer().map_err(std::io::Error::other)?;
            let config = app.config().app.windows.first().ok_or("main window configuration missing")?;
            tauri::WebviewWindowBuilder::from_config(app, config)?
                .on_navigation(|url|
                {
                    allowed_navigation(url, cfg!(debug_assertions))
                })
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .on_window_event(|_window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. })
            {
                let _ = cleanup_active_sessions_on_exit_backend();
            }
        })
        .invoke_handler(tauri::generate_handler![
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
            start_launch_monitor_session,
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
            get_native_helper_architecture,
            query_target_binary_architecture
        ])
        .run(tauri::generate_context!())
        .expect("failed to run KN Win32 API Monitor");
}

#[cfg(test)]
mod security_tests
{
    use super::allowed_navigation;

    #[cfg(windows)]
    #[test]
    fn desktop_process_enforces_control_flow_guard()
    {
        #[link(name = "kernel32")]
        extern "system"
        {
            fn GetCurrentProcess() -> *mut core::ffi::c_void;
            fn GetProcessMitigationPolicy(process: *mut core::ffi::c_void, policy: u32,
                buffer: *mut core::ffi::c_void, length: usize) -> i32;
        }
        let mut flags = 0u32;
        // PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY is a DWORD bitfield; policy ID is 7.
        let queried = unsafe
        {
            GetProcessMitigationPolicy(GetCurrentProcess(), 7,
                (&mut flags as *mut u32).cast(), core::mem::size_of_val(&flags))
        };
        assert_ne!(queried, 0, "Cannot query the process CFG policy");
        assert_ne!(flags & 1, 0, "Desktop tests must run with CFG enabled");
    }

    #[test]
    fn navigation_restricts_exact_origin_and_dev_mode()
    {
        for address in ["http://tauri.localhost/", "tauri://localhost/index.html"]
        {
            assert!(allowed_navigation(&address.parse().unwrap(), false));
        }
        for address in ["https://example.com/", "http://tauri.localhost.evil/", "http://tauri.localhost:8080/", "file:///C:/test.html",
            "data:text/html,hello", "javascript:alert(1)", "http://user@tauri.localhost/", "http://127.0.0.1:5173/"]
        {
            assert!(!allowed_navigation(&address.parse().unwrap(), false), "{address}");
        }
        assert!(allowed_navigation(&"http://127.0.0.1:5173/".parse().unwrap(), true));
        assert!(!allowed_navigation(&"http://127.0.0.1:5174/".parse().unwrap(), true));
    }

    #[test]
    fn framework_authority_rejects_remote_and_ungranted_commands()
    {
        use tauri::ipc::Origin;
        use tauri::utils::acl::resolved::Resolved;
        let acl = serde_json::from_str(include_str!("../gen/schemas/acl-manifests.json")).unwrap();
        let capabilities = serde_json::from_str(include_str!("../gen/schemas/capabilities.json")).unwrap();
        let resolved = Resolved::resolve(&acl, capabilities, tauri::utils::platform::Target::Windows).unwrap();
        assert!(resolved.has_app_acl);
        let authority = tauri::runtime_authority!(acl, resolved);
        for command in ["start_launch_monitor_session", "start_streaming_attach_session", "list_daemon_sessions", "plugin:dialog|open"]
        {
            assert!(authority.resolve_access(command, "main", "main", &Origin::Local).is_some(), "{command}");
            assert!(authority.resolve_access(command, "foreign", "foreign", &Origin::Local).is_none(), "{command}");
            assert!(authority.resolve_access(command, "main", "main", &Origin::Remote
            {
                url: "https://example.com/".parse().unwrap(),
            }).is_none(), "{command}");
        }
        for command in ["unregistered_command", "plugin:fs|read_file", "plugin:window|create", "plugin:shell|execute"]
        {
            assert!(authority.resolve_access(command, "main", "main", &Origin::Local).is_none(), "{command}");
        }
    }
}
