import type { TargetProcess } from "./types";

export type NativeArchitecture = "x64" | "x86" | "unknown";

export function normalizeNativeArchitecture(value: string): NativeArchitecture
{
  if (value === "x86-wow64")
  {
    return "x86";
  }
  return value === "x64" || value === "x86" ? value : "unknown";
}

function toolLabelForArchitecture(architecture: NativeArchitecture): string
{
  if (architecture === "x86")
  {
    return "Win32/x86 KN Win32 API Monitor";
  }
  if (architecture === "x64")
  {
    return "x64 KN Win32 API Monitor";
  }
  return "matching-bitness KN Win32 API Monitor";
}

export function architectureMismatchMessage(targetArchitecture: NativeArchitecture, helperArchitecture: NativeArchitecture): string
{
  return `Target architecture ${targetArchitecture} does not match this ${helperArchitecture} build. Run the ${toolLabelForArchitecture(targetArchitecture)} tool to monitor this target.`;
}

export function targetEligibilityReason(target: TargetProcess | null, helperArchitecture: NativeArchitecture): string | null
{
  let reason: string | null = null;
  do
  {
    if (!target)
    {
      reason = "Select a target row.";
      break;
    }
    if (target.status !== "available")
    {
      reason = `Target status is ${target.status}.`;
      break;
    }
    const architecture = normalizeNativeArchitecture(target.architecture);
    if (architecture === "unknown")
    {
      reason = `Architecture ${target.architecture} is unsupported.`;
      break;
    }
    if (helperArchitecture !== "unknown" && architecture !== helperArchitecture)
    {
      reason = architectureMismatchMessage(architecture, helperArchitecture);
    }
  }
  while (false);
  return reason;
}
