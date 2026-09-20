use super::*;

#[test]
fn registry_and_global_trace_memory_remain_bounded()
{
    let id = operation_id("registry-bound");
    register_native_operation(&id, "attach_capture_stream", 42, 0).unwrap();
    assert!(register_native_operation(&id, "attach_capture_stream", 43, 0).is_err());
    let template = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    let mut registry = HashMap::new();
    for index in 0..OPERATION_HISTORY_LIMIT
    {
        registry.insert(index.to_string(), template.clone());
    }
    assert!(reserve_operation_slot(&mut registry).is_err());
    assert_eq!(registry.len(), OPERATION_HISTORY_LIMIT);
    registry.get_mut("0").unwrap().state = "recovery_required".to_string();
    assert!(reserve_operation_slot(&mut registry).is_err());
    registry.get_mut("0").unwrap().state = "completed".to_string();
    reserve_operation_slot(&mut registry).unwrap();
    assert!(!registry.contains_key("0"));
    assert_eq!(registry.len(), OPERATION_HISTORY_LIMIT - 1);

    registry.clear();
    let mut batch = tests::test_batch(&id, &new_session_id(&id), 1);
    batch.events[0].last_error_message = "M".repeat(1024 * 1024);
    batch.storage_bytes = serde_json::to_vec(&batch).unwrap().len() + 20;
    for index in 0..4
    {
        let mut record = template.clone();
        record.started_at += Duration::from_millis(index);
        for _ in 0..20
        {
            record.trace_batches.push_back(batch.clone());
        }
        registry.insert(index.to_string(), record);
    }
    trim_global_trace_queues(&mut registry);
    let bytes: usize = registry.values().flat_map(|record| &record.trace_batches).map(|batch| batch.storage_bytes).sum();
    assert!(bytes <= STREAM_GLOBAL_QUEUE_MAX_BYTES);
    assert!(registry.get("0").unwrap().host_dropped_batches > 0);
    assert_eq!(registry.get("3").unwrap().trace_batches.len(), 20);
}

#[test]
fn bounded_command_output_refuses_invalid_or_incomplete_data()
{
    let stop = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(read_bounded_output(&b"abcd"[..], 4, &stop).unwrap(), "abcd");
    assert!(read_bounded_output(&b"abcde"[..], 4, &stop).unwrap_err().contains("budget"));
    assert!(read_bounded_output(&b"\xff"[..], 4, &stop).unwrap_err().contains("UTF-8"));
    stop.store(true, std::sync::atomic::Ordering::Release);
    assert!(read_bounded_output(&b"abcd"[..], 4, &stop).unwrap_err().contains("cancelled"));
}

#[test]
fn batch_drain_is_replayable_until_ack_and_byte_bounded()
{
    let id = operation_id("byte-queue");
    register_native_operation(&id, "attach_capture_stream", 42, 0).unwrap();
    let session = new_session_id(&id);
    for sequence in 1..=50
    {
        let mut batch = tests::test_batch(&id, &session, sequence);
        batch.events[0].last_error_message = "A".repeat(1024 * 1024);
        push_native_trace_batch(&id, batch);
    }
    let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    assert!(record.trace_batches.iter().map(|batch| batch.storage_bytes).sum::<usize>() <= STREAM_QUEUE_MAX_BYTES);
    assert!(record.host_dropped_batches > 0);
    let first = drain_native_trace_batches(session.clone(), 0).unwrap();
    let repeat = drain_native_trace_batches(session.clone(), 0).unwrap();
    assert_eq!(first.len(), repeat.len());
    assert_eq!(first.first().unwrap().batch_sequence, repeat.first().unwrap().batch_sequence);
    assert!(first.iter().map(|batch| batch.storage_bytes).sum::<usize>() <= STREAM_DRAIN_MAX_BYTES);
    let ack = first.last().unwrap().batch_sequence;
    let next = drain_native_trace_batches(session, ack).unwrap();
    assert_eq!(next.first().unwrap().batch_sequence, ack + 1);
    assert_eq!(operation_registry().lock().unwrap().get(&id).unwrap().host_dropped_batches, record.host_dropped_batches);
}

fn operation_id(prefix: &str) -> String
{
    new_operation_id(prefix, std::process::id())
}

#[test]
fn startup_failures_are_terminal_and_keep_the_reason()
{
    let id = operation_id("rollback");
    {
        let _start = OperationStart::new(&id, "attach_capture_stream", 42, 0).unwrap();
    }
    let record = operation_registry().lock().unwrap().get(&id).unwrap().clone();
    assert_eq!(record.state, "failed");
    assert_ne!(record.finished_at_ms, 0);
    assert_eq!(record.last_error, "operation startup rolled back");

    let id = operation_id("spawn-failure");
    let start = OperationStart::new(&id, "attach_capture_stream", 42, 0).unwrap();
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
    register_native_operation(&id, "attach_capture_stream", 42, 0).unwrap();
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
    register_native_operation(&id, "attach_capture_stream", 42, 0).unwrap();
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
fn actual_helper_result(helper: &std::path::Path, target: &std::path::Path, label: &str) -> NativeOperationRecord
{
    let id = operation_id(label);
    let start = OperationStart::new(&id, "launch_capture_stream", 0, 0).unwrap();
    let args = vec!["launch-session".to_string(), "--target".to_string(), target.to_string_lossy().into_owned(),
        "--cwd".to_string(), target.parent().unwrap().to_string_lossy().into_owned(),
        "--own-launch-job".to_string(), "--owner-pid".to_string(), std::process::id().to_string(),
        "--owner-created".to_string(), process_liveness::current_creation_time().to_string(),
        "--operation-id".to_string(), id.clone(), "--session-id".to_string(), new_session_id(&id), "--stream-batches".to_string()];
    start.finish(spawn_streaming_helper(helper, &args, &id)).unwrap();
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
            break record;
        }
        assert!(begin.elapsed() < Duration::from_secs(40), "{}", record.last_error);
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires KNMON_TEST_NATIVE_HELPER pointing to the built native helper"]
fn actual_helper_stream_finishes_and_retains_launch_identity()
{
    let helper = PathBuf::from(std::env::var_os("KNMON_TEST_NATIVE_HELPER").expect("native helper path required"));
    let target = helper.parent().unwrap().join("knmon-sample-fileio.exe");
    let record = actual_helper_result(&helper, &target, "native-stream");
    assert_eq!(record.state, "completed", "{}", record.last_error);
    assert!(record.records_streamed > 0);
    assert!(!record.trace_batches.is_empty());
    assert_eq!(record.transport_dropped_events, 0);
    assert_eq!(record.host_dropped_batches, 0);
}

#[cfg(windows)]
#[test]
#[ignore = "requires KNMON_TEST_NATIVE_HELPER pointing to the built native helper"]
fn actual_helper_failed_target_is_terminal_and_keeps_error()
{
    let helper = PathBuf::from(std::env::var_os("KNMON_TEST_NATIVE_HELPER").expect("native helper path required"));
    let directory = std::env::temp_dir().join(operation_id("missing-probe"));
    std::fs::create_dir(&directory).unwrap();
    let target = directory.join("knmon-sample-fileio.exe");
    std::fs::copy(helper.parent().unwrap().join("knmon-sample-fileio.exe"), &target).unwrap();
    assert!(!directory.join("knmon-dynamic-probe.dll").exists());
    let begin = Instant::now();
    let record = actual_helper_result(&helper, &target, "native-failure");
    assert!(begin.elapsed() < Duration::from_secs(15));
    assert_eq!(record.state, "failed");
    assert!(record.last_error.contains("nonzero or unknown exit status"), "{}", record.last_error);
    assert_eq!(record.shutdown_evidence, "released_by_process_exit");
    assert!(record.owned_target.as_ref().is_some_and(|process| !process.alive()));
    std::fs::remove_file(target).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn duplicate_batches_and_future_ack_are_rejected()
{
    let id = operation_id("duplicate-batch");
    register_native_operation(&id, "attach_capture_stream", 42, 0).unwrap();
    let session = new_session_id(&id);
    let batch = tests::test_batch(&id, &session, 1);
    let frame = serde_json::to_string(&batch).unwrap();
    process_streaming_frame_line(&id, &frame).unwrap();
    assert!(process_streaming_frame_line(&id, &frame).unwrap_err().contains("sequence"));
    assert!(drain_native_trace_batches(session.clone(), 2).is_err());
    assert_eq!(drain_native_trace_batches(session, 0).unwrap().len(), 1);
}
