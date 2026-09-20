#include <Windows.h>
#include <winver.h>

extern "C" __declspec(dllexport) DWORD WINAPI Probe()
{
    return GetCurrentProcessId();
}

#if defined(KNMON_DELAY_PROBE)
extern "C" __declspec(dllexport) DWORD WINAPI ProbeDelay()
{
    DWORD handle = 0;
    return GetFileVersionInfoSizeW(L"C:\\knmon-module-test-missing-file", &handle);
}
#endif

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:Probe=_Probe@0")
#if defined(KNMON_DELAY_PROBE)
#pragma comment(linker, "/EXPORT:ProbeDelay=_ProbeDelay@0")
#endif
#endif
