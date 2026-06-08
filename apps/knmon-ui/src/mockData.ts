import type { ApiNode, CaptureProfile, KnMonArgument, TargetProcess, TraceEvent } from "./types";

export const mockTargets: TargetProcess[] = [
  {
    pid: 8840,
    parentPid: 672,
    imageName: "notepad.exe",
    imagePath: "C:\\Windows\\System32\\notepad.exe",
    architecture: "x64",
    status: "available"
  },
  {
    pid: 4216,
    parentPid: 812,
    imageName: "explorer.exe",
    imagePath: "C:\\Windows\\explorer.exe",
    architecture: "x64",
    status: "available"
  },
  {
    pid: 13064,
    parentPid: 8840,
    imageName: "sample-fileio.exe",
    imagePath: "F:\\kernullist\\kn-win32apimon\\samples\\targets\\sample-fileio.exe",
    architecture: "x64",
    status: "mock-target"
  },
  {
    pid: 4,
    parentPid: null,
    imageName: "System",
    imagePath: null,
    architecture: "kernel",
    status: "unsupported"
  }
];

export const apiTree: ApiNode[] = [
  {
    id: "file-services",
    label: "File Services",
    checked: true,
    children: [
      {
        id: "kernel32",
        label: "Kernel32.dll",
        checked: true,
        children: [
          { id: "CreateFileW", label: "CreateFileW", checked: true },
          { id: "CreateFileA", label: "CreateFileA", checked: true },
          { id: "ReadFile", label: "ReadFile", checked: true },
          { id: "WriteFile", label: "WriteFile", checked: true },
          { id: "CloseHandle", label: "CloseHandle", checked: true }
        ]
      },
      {
        id: "ntdll",
        label: "Ntdll.dll",
        checked: true,
        children: [
          { id: "NtCreateFile", label: "NtCreateFile", checked: true }
        ]
      }
    ]
  },
  {
    id: "future-families",
    label: "Future Profiles",
    checked: false,
    children: [
      { id: "registry", label: "Registry", checked: false },
      { id: "process-thread", label: "Process and Thread", checked: false },
      { id: "memory", label: "Memory", checked: false },
      { id: "network", label: "Network", checked: false }
    ]
  }
];

export const captureProfiles: CaptureProfile[] = [
  {
    id: "file-io",
    name: "File I/O MVP",
    description: "Create/open/read/write/close coverage for the first safe capture path.",
    enabledApis: ["CreateFileW", "CreateFileA", "NtCreateFile", "ReadFile", "WriteFile", "CloseHandle"]
  },
  {
    id: "file-errors",
    name: "File errors",
    description: "Highlight failed opens and short reads for triage.",
    enabledApis: ["CreateFileW", "NtCreateFile", "ReadFile"]
  },
  {
    id: "anti-cheat-research",
    name: "Anti-cheat research",
    description: "Future profile for image loads, handles, memory, and telemetry boundaries.",
    enabledApis: ["CreateFileW", "NtCreateFile"]
  }
];

const filePaths = [
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "C:\\Users\\kernullist\\AppData\\Local\\Temp\\knmon.trace",
  "F:\\kernullist\\kn-win32apimon\\samples\\targets\\sample.dat",
  "C:\\ProgramData\\KNMon\\session.knapm"
];

const stackFrames = [
  "KERNELBASE.dll!CreateFileW + 0x35e",
  "kernel32.dll!CreateFileW + 0x4a",
  "sample-fileio.exe!OpenTraceTarget + 0x91",
  "sample-fileio.exe!main + 0x42"
];

function arg(index: number, type: string, name: string, value: string, decodedValue = value): KnMonArgument {
  return {
    index,
    type,
    name,
    direction: "in",
    preCallValue: value,
    postCallValue: value,
    rawValue: value,
    decodedValue,
    decodeStatus: "decoded"
  };
}

function createArguments(api: string, path: string, eventId: number): KnMonArgument[] {
  if (api === "CreateFileW" || api === "CreateFileA") {
    return [
      arg(0, api.endsWith("W") ? "LPCWSTR" : "LPCSTR", "lpFileName", `"${path}"`),
      arg(1, "DWORD", "dwDesiredAccess", "0x80000000", "GENERIC_READ"),
      arg(2, "DWORD", "dwShareMode", "0x00000003", "FILE_SHARE_READ | FILE_SHARE_WRITE"),
      arg(3, "LPSECURITY_ATTRIBUTES", "lpSecurityAttributes", "NULL"),
      arg(4, "DWORD", "dwCreationDisposition", "3", "OPEN_EXISTING"),
      arg(5, "DWORD", "dwFlagsAndAttributes", "0x00000080", "FILE_ATTRIBUTE_NORMAL"),
      arg(6, "HANDLE", "hTemplateFile", "NULL")
    ];
  }

  if (api === "NtCreateFile") {
    return [
      arg(0, "PHANDLE", "FileHandle", "0x000000000030f1f8"),
      arg(1, "ACCESS_MASK", "DesiredAccess", "0x0012019f", "FILE_GENERIC_READ | SYNCHRONIZE"),
      arg(2, "POBJECT_ATTRIBUTES", "ObjectAttributes", `ObjectName="${path}"`),
      arg(3, "PIO_STATUS_BLOCK", "IoStatusBlock", "0x000000000030f140"),
      arg(4, "PLARGE_INTEGER", "AllocationSize", "NULL"),
      arg(5, "ULONG", "FileAttributes", "0x80", "FILE_ATTRIBUTE_NORMAL")
    ];
  }

  if (api === "ReadFile") {
    return [
      arg(0, "HANDLE", "hFile", "0x00000000000001a4"),
      arg(1, "LPVOID", "lpBuffer", "0x0000000000452000"),
      arg(2, "DWORD", "nNumberOfBytesToRead", eventId % 3 === 0 ? "4096" : "512"),
      arg(3, "LPDWORD", "lpNumberOfBytesRead", "0x000000000030f154", eventId % 3 === 0 ? "4096" : "128"),
      arg(4, "LPOVERLAPPED", "lpOverlapped", "NULL")
    ];
  }

  if (api === "WriteFile") {
    return [
      arg(0, "HANDLE", "hFile", "0x00000000000001a4"),
      arg(1, "LPCVOID", "lpBuffer", "0x0000000000453000"),
      arg(2, "DWORD", "nNumberOfBytesToWrite", "174"),
      arg(3, "LPDWORD", "lpNumberOfBytesWritten", "0x000000000030f158", "174"),
      arg(4, "LPOVERLAPPED", "lpOverlapped", "NULL")
    ];
  }

  return [
    arg(0, "HANDLE", "hObject", "0x00000000000001a4")
  ];
}

export function createMockFileIoEvent(eventId: number): TraceEvent {
  const apis = ["CreateFileW", "NtCreateFile", "ReadFile", "WriteFile", "CreateFileA", "CloseHandle"];
  const api = apis[eventId % apis.length];
  const failedOpen = api.includes("CreateFile") && eventId % 7 === 0;
  const path = filePaths[eventId % filePaths.length];
  const module = api === "NtCreateFile" ? "ntdll.dll" : "KERNELBASE.dll";
  const returnValue = failedOpen ? "INVALID_HANDLE_VALUE" : api === "CloseHandle" ? "TRUE" : "0x00000000000001a4";

  return {
    schemaVersion: "0.1.0",
    eventId,
    relativeTimeMs: eventId * 137,
    pid: eventId % 4 === 0 ? 8840 : 13064,
    tid: 6200 + (eventId % 5) * 64,
    process: eventId % 4 === 0 ? "notepad.exe" : "sample-fileio.exe",
    module,
    api,
    arguments: createArguments(api, path, eventId),
    returnValue,
    error: failedOpen
      ? {
          kind: "win32",
          code: "0x00000005",
          message: "Access is denied."
        }
      : null,
    durationUs: 18 + (eventId % 9) * 11,
    tags: failedOpen ? ["file", "error", "access-denied"] : ["file", api.startsWith("Read") ? "read" : "io"],
    stack: stackFrames,
    bufferPreview: api === "ReadFile" || api === "WriteFile"
      ? "4b 4e 4d 4f 4e 00 01 00 53 65 73 73 69 6f 6e 00"
      : undefined
  };
}

export const initialTraceEvents: TraceEvent[] = Array.from({ length: 18 }, (_, index) => createMockFileIoEvent(index + 1));
