use super::*;

fn operation_id(prefix: &str) -> String
{
    new_operation_id(prefix, std::process::id())
}

#[test]
fn startup_failures_are_terminal_and_keep_the_reason()
{
    let id = operation_id("rollback");
    {
        let _start = OperationStart::new(&id, "attach_capture_stream", 42, 0);
    }
    let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    assert_eq!(record.state, "failed");
    assert_ne!(record.finished_at_ms, 0);
    assert_eq!(record.last_error, "operation startup rolled back");

    let id = operation_id("spawn-failure");
    let start = OperationStart::new(&id, "attach_capture_stream", 42, 0);
    let result = spawn_streaming_helper(Path::new("Z:/knmon-nonexistent/helper.exe"), &[], &id);
    assert!(start.finish(result).is_err());
    let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    assert_eq!(record.state, "failed");
    assert!(record.last_error.starts_with("failed to start"));
    update_streaming_error(&id, "failed", "secondary error".to_string());
    assert_eq!(operation_registry().lock().unwrap().get(&id).unwrap().last_error, record.last_error);
    assert_eq!(cancel_native_operation(id.clone()).unwrap().state, "failed");
    assert_eq!(stop_native_session(new_session_id(&id)).unwrap().session_state, "failed");
}

#[test]
fn stream_framing_has_a_bound_and_requires_a_complete_utf8_line()
{
    assert_eq!(read_stream_line(&mut std::io::Cursor::new(b"{}\n")).unwrap(), Some("{}\n".to_string()));
    assert!(read_stream_line(&mut std::io::Cursor::new(b"{}")).is_err());
    assert!(read_stream_line(&mut std::io::Cursor::new([0xff, b'\n'])).is_err());
    let large = vec![b'x'; STREAM_FRAME_MAX_BYTES + 1];
    assert!(read_stream_line(&mut std::io::Cursor::new(large)).is_err());
    assert_eq!(read_bounded_stderr(std::io::Cursor::new(vec![b'a'; STREAM_STDERR_MAX_BYTES * 2]), None).len(), STREAM_STDERR_MAX_BYTES);
}

#[test]
fn stream_rejects_foreign_identity_and_cannot_revive_after_failure()
{
    let id = operation_id("foreign-frame");
    register_native_operation(&id, "attach_capture_stream", 42, 0);
    let wrong = serde_json::json!({"schemaVersion":"0.1.0", "frameType":"trace_batch", "operationId":"other", "sessionId":new_session_id(&id)});
    assert!(process_streaming_frame_line(&id, &wrong.to_string()).unwrap_err().contains("identity mismatch"));
    update_streaming_error(&id, "failed", "foreign identity".to_string());
    let original = serde_json::json!({"schemaVersion":"0.1.0", "frameType":"trace_batch", "operationId":id, "sessionId":new_session_id(&id)});
    assert!(process_streaming_frame_line(&id, &original.to_string()).unwrap_err().contains("terminal"));
    let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    assert_eq!(record.state, "failed");
    assert!(record.trace_batches.is_empty());
}

#[cfg(windows)]
#[test]
fn retained_process_refuses_reused_identity_and_rollback_closes_child()
{
    use std::os::windows::process::CommandExt;
    let executable = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/ping.exe");
    let child = OwnedChild(Command::new(executable).args(["127.0.0.1", "-n", "30"])
        .creation_flags(0x08000000).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let process = process_liveness::RetainedProcess::from_child(&child.0).unwrap();
    assert!(process.alive());
    assert!(process_liveness::RetainedProcess::open_identified(process.process_id, process.creation_time + 1, true).is_err());
    assert!(process.alive());
    let original = process_liveness::RetainedProcess::open_identified(process.process_id, process.creation_time, true).unwrap();
    drop(child);
    assert!(!original.alive());
    original.terminate_owned(1).unwrap();
}

#[cfg(windows)]
#[test]
fn synchronous_reader_cancellation_does_not_require_the_writer_to_exit()
{
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system"
    {
        fn CreatePipe(read: *mut *mut c_void, write: *mut *mut c_void, attributes: *mut c_void, size: u32) -> i32;
    }
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    assert_ne!(unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 4096) }, 0);
    let reader = unsafe { std::fs::File::from_raw_handle(read) };
    let _writer = unsafe { OwnedHandle::from_raw_handle(write) };
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_stop = stop.clone();
    let worker = thread::spawn(move || read_bounded_stderr(reader, Some(&worker_stop)));
    thread::sleep(Duration::from_millis(50));
    assert!(!worker.is_finished());
    stop.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(stop_reader(worker), Some(String::new()));
}

#[cfg(windows)]
#[test]
fn cancellation_waits_for_event_creation_without_losing_the_request()
{
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system"
    {
        fn CreateEventW(attributes: *mut c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, timeout: u32) -> u32;
    }
    let id = operation_id("early-cancel");
    register_native_operation(&id, "attach_capture_stream", 42, 0);
    assert_eq!(signal_cancel_operation(&id).unwrap().win32_error_code, 2);
    let name = cancellation_event_name(&id);
    let worker = thread::spawn(move ||
    {
        thread::sleep(Duration::from_millis(100));
        let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let raw = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, wide.as_ptr()) };
        assert!(!raw.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert_eq!(unsafe { WaitForSingleObject(event.as_raw_handle(), 3000) }, 0);
    });
    assert!(cancel_native_operation(id.clone()).unwrap().cancel_requested);
    worker.join().unwrap();
    finish_native_operation(&id, "cancelled");
}

#[cfg(windows)]
#[test]
#[ignore = "requires KNMON_TEST_NATIVE_HELPER pointing to the built native helper"]
fn actual_helper_stream_finishes_and_retains_launch_identity()
{
    let helper = PathBuf::from(std::env::var_os("KNMON_TEST_NATIVE_HELPER").expect("native helper path required"));
    let target = helper.parent().unwrap().join("knmon-sample-fileio.exe");
    let id = operation_id("native-stream");
    let start = OperationStart::new(&id, "launch_capture_stream", 0, 0);
    let args = vec!["launch-session".to_string(), "--target".to_string(), target.to_string_lossy().into_owned(),
        "--own-launch-job".to_string(), "--owner-pid".to_string(), std::process::id().to_string(),
        "--owner-created".to_string(), process_liveness::current_creation_time().to_string(),
        "--operation-id".to_string(), id.clone(), "--session-id".to_string(), new_session_id(&id), "--stream-batches".to_string()];
    start.finish(spawn_streaming_helper(&helper, &args, &id)).unwrap();
    let begin = Instant::now();
    loop
    {
        let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
        if record.helper_handle.as_ref().is_some_and(|process| !process.alive()) &&
            is_terminal_operation_state(&record.state) && (record.stream_result_received || record.stream_failed)
        {
            assert!(!record.stream_failed, "{}", record.last_error);
            assert!(record.stream_result_received);
            assert_ne!(record.target_process_creation_time, "0");
            assert!(record.owned_target.is_some());
            break;
        }
        assert!(begin.elapsed() < Duration::from_secs(40), "{}", record.last_error);
        thread::sleep(Duration::from_millis(100));
    }
}
