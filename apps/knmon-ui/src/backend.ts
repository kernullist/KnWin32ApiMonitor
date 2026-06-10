import { invoke } from "@tauri-apps/api/core";
import { mockTargets } from "./mockData";
import type { CaptureResult, CaptureSessionState, LaunchResult, NativeDaemonAudit, NativeDaemonStatus, NativeOperation, NativeSession, NativeTraceBatch, ProcessTreeResult, SessionReplayResult, TargetProcess } from "./types";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function listTargetProcesses(): Promise<{ targets: TargetProcess[]; mode: "mock" | "native-enum" }> {
  if (!isTauriRuntime()) {
    return {
      targets: mockTargets,
      mode: "mock"
    };
  }

  try {
    const targets = await invoke<TargetProcess[]>("list_target_processes");
    return {
      targets,
      mode: "mock"
    };
  } catch (error) {
    console.warn("Falling back to mock targets", error);
    return {
      targets: mockTargets,
      mode: "mock"
    };
  }
}

export async function listNativeTargetProcesses(): Promise<{ targets: TargetProcess[]; mode: "native-enum" }> {
  if (!isTauriRuntime()) {
    throw new Error("Native process enumeration requires the Tauri desktop runtime. Run `npm run tauri:dev` after building native helper targets.");
  }

  const targets = await invoke<TargetProcess[]>("list_native_target_processes");
  return {
    targets,
    mode: "native-enum"
  };
}

export async function launchSampleEarlyBirdCapture(): Promise<LaunchResult> {
  if (!isTauriRuntime()) {
    throw new Error("Controlled early-bird launch requires the Tauri desktop runtime and build/native/Debug/knmon-native-helper.exe.");
  }

  return invoke<LaunchResult>("launch_sample_early_bird_capture");
}

export async function captureSampleFileIoEvents(): Promise<CaptureResult> {
  if (!isTauriRuntime()) {
    throw new Error("Controlled File I/O capture requires the Tauri desktop runtime and build/native/Debug/knmon-native-helper.exe.");
  }

  return invoke<CaptureResult>("capture_sample_fileio_events");
}

export async function captureSampleFileIoSession(): Promise<CaptureResult> {
  if (!isTauriRuntime()) {
    throw new Error("Capture And Save requires the Tauri desktop runtime and build/native/Debug/knmon-native-helper.exe.");
  }

  return invoke<CaptureResult>("capture_sample_fileio_session_events");
}

export async function replayLastSampleSession(): Promise<SessionReplayResult> {
  if (!isTauriRuntime()) {
    throw new Error("Replay Last Session requires the Tauri desktop runtime and a saved captures/latest-sample-fileio session.");
  }

  return invoke<SessionReplayResult>("replay_last_sample_session");
}

export async function replaySessionPath(sessionPath: string): Promise<SessionReplayResult> {
  if (!isTauriRuntime()) {
    throw new Error("Session replay by path requires the Tauri desktop runtime.");
  }

  return invoke<SessionReplayResult>("replay_session_path", {
    sessionPath
  });
}

export async function attachTargetProcessCapture(pid: number, durationMs: number): Promise<CaptureResult> {
  if (!isTauriRuntime()) {
    throw new Error("Bounded attach capture requires the Tauri desktop runtime and build/native/Debug/knmon-native-helper.exe.");
  }

  return invoke<CaptureResult>("attach_target_process_capture", {
    pid,
    durationMs
  });
}

export async function superviseProcessTree(pid: number, durationMs: number, childPolicy: ProcessTreeResult["childPolicy"]): Promise<ProcessTreeResult> {
  if (!isTauriRuntime()) {
    throw new Error("Process-tree supervision requires the Tauri desktop runtime and build/native/Debug/knmon-native-helper.exe.");
  }

  return invoke<ProcessTreeResult>("supervise_process_tree", {
    rootPid: pid,
    durationMs,
    childPolicy
  });
}

export async function listNativeOperations(): Promise<NativeOperation[]> {
  if (!isTauriRuntime()) {
    return [];
  }

  return invoke<NativeOperation[]>("list_native_operations");
}

export async function cancelNativeOperation(operationId: string): Promise<NativeOperation> {
  if (!isTauriRuntime()) {
    throw new Error("Native operation cancellation requires the Tauri desktop runtime.");
  }

  return invoke<NativeOperation>("cancel_native_operation", {
    operationId
  });
}

export async function listNativeSessions(): Promise<NativeSession[]> {
  if (!isTauriRuntime()) {
    return [];
  }

  return invoke<NativeSession[]>("list_native_sessions");
}

export async function stopNativeSession(sessionId: string): Promise<NativeSession> {
  if (!isTauriRuntime()) {
    throw new Error("Native session stop requires the Tauri desktop runtime.");
  }

  return invoke<NativeSession>("stop_native_session", {
    sessionId
  });
}

export async function startStreamingAttachSession(pid: number, durationMs: number): Promise<NativeSession> {
  if (!isTauriRuntime()) {
    throw new Error("Streaming attach sessions require the Tauri desktop runtime.");
  }

  return invoke<NativeSession>("start_streaming_attach_session", {
    pid,
    durationMs
  });
}

export async function startDaemonIfNeeded(): Promise<NativeDaemonStatus> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon supervision requires the Tauri desktop runtime.");
  }

  return invoke<NativeDaemonStatus>("start_daemon_if_needed");
}

export async function nativeDaemonStatus(): Promise<NativeDaemonStatus> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon status requires the Tauri desktop runtime.");
  }

  return invoke<NativeDaemonStatus>("native_daemon_status");
}

export async function listDaemonSessions(): Promise<NativeSession[]> {
  if (!isTauriRuntime()) {
    return [];
  }

  return invoke<NativeSession[]>("list_daemon_sessions");
}

export async function auditDaemonSessions(): Promise<NativeDaemonAudit> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon audit requires the Tauri desktop runtime.");
  }

  return invoke<NativeDaemonAudit>("audit_daemon_sessions");
}

export async function pruneStaleDaemonSessions(dryRun: boolean): Promise<NativeDaemonAudit> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon stale registry pruning requires the Tauri desktop runtime.");
  }

  return invoke<NativeDaemonAudit>("prune_stale_daemon_sessions", {
    dryRun
  });
}

export async function startDaemonSupervisedSession(pid: number, durationMs: number): Promise<NativeSession> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon-supervised sessions require the Tauri desktop runtime.");
  }

  return invoke<NativeSession>("start_daemon_supervised_session", {
    pid,
    durationMs
  });
}

export async function stopDaemonSession(sessionId: string): Promise<NativeSession> {
  if (!isTauriRuntime()) {
    throw new Error("Daemon session stop requires the Tauri desktop runtime.");
  }

  return invoke<NativeSession>("stop_daemon_session", {
    sessionId
  });
}

export async function drainNativeTraceBatches(sessionId: string, afterBatchSequence: number): Promise<NativeTraceBatch[]> {
  if (!isTauriRuntime()) {
    return [];
  }

  return invoke<NativeTraceBatch[]>("drain_native_trace_batches", {
    sessionId,
    afterBatchSequence
  });
}

export async function startBackendSession(): Promise<CaptureSessionState> {
  if (!isTauriRuntime()) {
    return {
      state: "running",
      backendMode: "mock",
      eventCount: 0,
      droppedEvents: 0
    };
  }

  return invoke<CaptureSessionState>("start_mock_capture_session");
}

export async function stopBackendSession(): Promise<CaptureSessionState> {
  if (!isTauriRuntime()) {
    return {
      state: "stopped",
      backendMode: "mock",
      eventCount: 0,
      droppedEvents: 0
    };
  }

  return invoke<CaptureSessionState>("stop_mock_capture_session");
}
