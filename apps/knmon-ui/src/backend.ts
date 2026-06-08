import { invoke } from "@tauri-apps/api/core";
import { mockTargets } from "./mockData";
import type { CaptureResult, CaptureSessionState, LaunchResult, TargetProcess } from "./types";

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
