import type { ApiNode, CaptureProfile } from "./types";

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
    label: "Expansion Profiles",
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
    name: "File I/O",
    description: "Create/open/read/write/close coverage for the current stable capture path.",
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
    description: "Profile placeholder for image loads, handles, memory, and telemetry boundaries.",
    enabledApis: ["CreateFileW", "NtCreateFile"]
  }
];
