#include <knmon/common/AttachConfig.h>
#include <knmon/common/Protocol.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <psapi.h>
#include <bcrypt.h>
#include <rpc.h>
#include <objbase.h>
#include <roapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <winver.h>
#include <winhttp.h>
#include <wininet.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <intrin.h>
#include <new>
#include <sstream>
#include <string>

#ifdef GetAddrInfo
#undef GetAddrInfo
#endif

#ifdef FreeAddrInfo
#undef FreeAddrInfo
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef RPC_S_UUID_LOCAL_ONLY
#define RPC_S_UUID_LOCAL_ONLY 1824L
#endif

#ifndef KNMON_AGENT_ARCHITECTURE
#define KNMON_AGENT_ARCHITECTURE "unknown"
#endif

#ifndef KNMON_AGENT_DLL_NAME
#define KNMON_AGENT_DLL_NAME "knmon-agent.dll"
#endif

#ifndef KNMON_AGENT_HELLO_MESSAGE
#define KNMON_AGENT_HELLO_MESSAGE "KNMon agent loaded by controlled early-bird APC"
#endif

namespace
{
constexpr const wchar_t* AgentVersion = L"0.2.0";
constexpr DWORD AgentVersionPacked = 0x00020000;
constexpr std::size_t MaxBufferPreviewBytes = 16;
constexpr std::size_t MaxNtObjectNameBytes = 512;
constexpr std::size_t MaxRegistryStringChars = 256;
constexpr int MaxGuidStringChars = 64;
constexpr std::size_t MaxRegistryDataPreviewBytes = 128;

struct KnMonPebLdrData
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct KnMonLdrDataTableEntry
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

struct KnMonPeb
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    KnMonPebLdrData* Ldr;
};

struct VersionTranslation
{
    WORD Language;
    WORD CodePage;
};

struct KnownFolderIdentity
{
    const char* Name;
    std::uint32_t Code;
    bool AllowPath;
};

enum class ShellFolderPathStatus : std::uint32_t
{
    None = 0,
    DecodedSafePath = 1,
    NonAllowlistedNoPath = 2,
    DecodeFailed = 3,
};

constexpr GUID FolderIdWindows = { 0xf38bf404, 0x1d43, 0x42f2, { 0x93, 0x05, 0x67, 0xde, 0x0b, 0x28, 0xfc, 0x23 } };
constexpr GUID FolderIdSystem = { 0x1ac14e77, 0x02e7, 0x4e5d, { 0xb7, 0x44, 0x2e, 0xb1, 0xae, 0x51, 0x98, 0xb7 } };
constexpr GUID FolderIdProgramFiles = { 0x905e63b6, 0xc1bf, 0x494e, { 0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a } };
constexpr GUID FolderIdFonts = { 0xfd228cb7, 0xae11, 0x4ae3, { 0x86, 0x4c, 0x16, 0xf3, 0x91, 0x0a, 0xb8, 0xfe } };

using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFreeFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);
using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using VirtualQueryFn = SIZE_T(WINAPI*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
using CreateFileMappingWFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
using OpenFileMappingWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
using MapViewOfFileFn = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
using UnmapViewOfFileFn = BOOL(WINAPI*)(LPCVOID);
using GetCurrentProcessFn = HANDLE(WINAPI*)();
using GetCurrentProcessIdFn = DWORD(WINAPI*)();
using GetCurrentThreadFn = HANDLE(WINAPI*)();
using GetCurrentThreadIdFn = DWORD(WINAPI*)();
using GetProcessIdFn = DWORD(WINAPI*)(HANDLE);
using GetThreadIdFn = DWORD(WINAPI*)(HANDLE);
using CreateThreadFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using OpenThreadFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using WaitForSingleObjectFn = DWORD(WINAPI*)(HANDLE, DWORD);
using GetExitCodeThreadFn = BOOL(WINAPI*)(HANDLE, LPDWORD);
using CreateEventWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
using OpenEventWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
using SetEventFn = BOOL(WINAPI*)(HANDLE);
using ResetEventFn = BOOL(WINAPI*)(HANDLE);
using WaitForSingleObjectExFn = DWORD(WINAPI*)(HANDLE, DWORD, BOOL);
using CreateMutexWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
using OpenMutexWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
using ReleaseMutexFn = BOOL(WINAPI*)(HANDLE);
using CreateSemaphoreWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR);
using OpenSemaphoreWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
using ReleaseSemaphoreFn = BOOL(WINAPI*)(HANDLE, LONG, LPLONG);
using WaitForMultipleObjectsExFn = DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD, BOOL);
using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
using LoadLibraryAFn = HMODULE(WINAPI*)(LPCSTR);
using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using LoadLibraryExAFn = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using RegOpenKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegCreateKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const SECURITY_ATTRIBUTES*, PHKEY, LPDWORD);
using RegQueryValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegSetValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
using RegDeleteValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
using RegCloseKeyFn = LSTATUS(WINAPI*)(HKEY);
using OpenProcessTokenFn = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
using LookupPrivilegeValueWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, PLUID);
using BCryptOpenAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
using BCryptCloseAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, ULONG);
using BCryptGetPropertyFn = NTSTATUS(WINAPI*)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
using BCryptGenRandomFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
using CertOpenStoreFn = HCERTSTORE(WINAPI*)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
using CertCloseStoreFn = BOOL(WINAPI*)(HCERTSTORE, DWORD);
using CryptMsgOpenToDecodeFn = HCRYPTMSG(WINAPI*)(DWORD, DWORD, DWORD, HCRYPTPROV_LEGACY, PCERT_INFO, PCMSG_STREAM_INFO);
using CryptMsgCloseFn = BOOL(WINAPI*)(HCRYPTMSG);
using InternetOpenWFn = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using InternetCloseHandleFn = BOOL(WINAPI*)(HINTERNET);
using WinHttpOpenFn = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using WinHttpCloseHandleFn = BOOL(WINAPI*)(HINTERNET);
using GetSystemMetricsFn = int(WINAPI*)(int);
using GetDesktopWindowFn = HWND(WINAPI*)();
using GetForegroundWindowFn = HWND(WINAPI*)();
using GetWindowThreadProcessIdFn = DWORD(WINAPI*)(HWND, LPDWORD);
using CreateCompatibleDCFn = HDC(WINAPI*)(HDC);
using GetDeviceCapsFn = int(WINAPI*)(HDC, int);
using DeleteDCFn = BOOL(WINAPI*)(HDC);
using EnumProcessModulesFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD);
using GetModuleInformationFn = BOOL(WINAPI*)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
using GetModuleBaseNameWFn = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
using GetModuleFileNameExWFn = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
using GetFileVersionInfoSizeWFn = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
using GetFileVersionInfoWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
using VerQueryValueWFn = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
using SHGetKnownFolderPathFn = HRESULT(WINAPI*)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*);
using SHGetSpecialFolderPathWFn = BOOL(WINAPI*)(HWND, LPWSTR, int, BOOL);
using CoInitializeExFn = HRESULT(WINAPI*)(LPVOID, DWORD);
using CoUninitializeFn = void(WINAPI*)();
using CoCreateGuidFn = HRESULT(WINAPI*)(GUID*);
using StringFromGUID2Fn = int(WINAPI*)(REFGUID, LPOLESTR, int);
using RoInitializeFn = HRESULT(WINAPI*)(RO_INIT_TYPE);
using RoUninitializeFn = void(WINAPI*)();
using RoGetApartmentIdentifierFn = HRESULT(WINAPI*)(UINT64*);
using RpcStringBindingComposeWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
using RpcBindingFromStringBindingWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR, RPC_BINDING_HANDLE*);
using RpcStringFreeWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR*);
using RpcBindingFreeFn = RPC_STATUS(RPC_ENTRY*)(RPC_BINDING_HANDLE*);
using UuidCreateFn = RPC_STATUS(RPC_ENTRY*)(UUID*);
using UuidToStringWFn = RPC_STATUS(RPC_ENTRY*)(UUID*, RPC_WSTR*);
using UuidFromStringWFn = RPC_STATUS(RPC_ENTRY*)(RPC_WSTR, UUID*);
using WSAStartupFn = int(WINAPI*)(WORD, LPWSADATA);
using WSACleanupFn = int(WINAPI*)();
using SocketFn = SOCKET(WINAPI*)(int, int, int);
using ClosesocketFn = int(WINAPI*)(SOCKET);
using GetAddrInfoFn = int(WINAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using FreeAddrInfoFn = void(WINAPI*)(PADDRINFOA);
using WSAGetLastErrorFn = int(WINAPI*)();
using NtCreateFileFn = NTSTATUS(NTAPI*)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG);
using LdrLoadDllFn = NTSTATUS(NTAPI*)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
using LdrGetProcedureAddressFn = NTSTATUS(NTAPI*)(HMODULE, PANSI_STRING, ULONG, PVOID*);
using RtlNtStatusToDosErrorFn = ULONG(WINAPI*)(NTSTATUS);

HMODULE g_agentModule = nullptr;
HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;
HANDLE g_transportMapping = nullptr;
knmon::KnMonTransportHeader* g_transportHeader = nullptr;
knmon::KnMonTransportRecord* g_transportRecords = nullptr;
std::uint32_t g_transportCapacity = 0;
SRWLOCK g_pipeLock = SRWLOCK_INIT;
volatile LONG64 g_sequence = 0;
volatile LONG64 g_droppedEvents = 0;
thread_local bool g_inHook = false;

CreateFileWFn g_originalCreateFileW = nullptr;
CreateFileAFn g_originalCreateFileA = nullptr;
ReadFileFn g_originalReadFile = nullptr;
WriteFileFn g_originalWriteFile = nullptr;
CloseHandleFn g_originalCloseHandle = nullptr;
VirtualAllocFn g_originalVirtualAlloc = nullptr;
VirtualFreeFn g_originalVirtualFree = nullptr;
VirtualProtectFn g_originalVirtualProtect = nullptr;
VirtualQueryFn g_originalVirtualQuery = nullptr;
CreateFileMappingWFn g_originalCreateFileMappingW = nullptr;
OpenFileMappingWFn g_originalOpenFileMappingW = nullptr;
MapViewOfFileFn g_originalMapViewOfFile = nullptr;
UnmapViewOfFileFn g_originalUnmapViewOfFile = nullptr;
GetCurrentProcessFn g_originalGetCurrentProcess = nullptr;
GetCurrentProcessIdFn g_originalGetCurrentProcessId = nullptr;
GetCurrentThreadFn g_originalGetCurrentThread = nullptr;
GetCurrentThreadIdFn g_originalGetCurrentThreadId = nullptr;
GetProcessIdFn g_originalGetProcessId = nullptr;
GetThreadIdFn g_originalGetThreadId = nullptr;
CreateThreadFn g_originalCreateThread = nullptr;
OpenThreadFn g_originalOpenThread = nullptr;
WaitForSingleObjectFn g_originalWaitForSingleObject = nullptr;
GetExitCodeThreadFn g_originalGetExitCodeThread = nullptr;
CreateEventWFn g_originalCreateEventW = nullptr;
OpenEventWFn g_originalOpenEventW = nullptr;
SetEventFn g_originalSetEvent = nullptr;
ResetEventFn g_originalResetEvent = nullptr;
WaitForSingleObjectExFn g_originalWaitForSingleObjectEx = nullptr;
CreateMutexWFn g_originalCreateMutexW = nullptr;
OpenMutexWFn g_originalOpenMutexW = nullptr;
ReleaseMutexFn g_originalReleaseMutex = nullptr;
CreateSemaphoreWFn g_originalCreateSemaphoreW = nullptr;
OpenSemaphoreWFn g_originalOpenSemaphoreW = nullptr;
ReleaseSemaphoreFn g_originalReleaseSemaphore = nullptr;
WaitForMultipleObjectsExFn g_originalWaitForMultipleObjectsEx = nullptr;
LoadLibraryWFn g_originalLoadLibraryW = nullptr;
LoadLibraryAFn g_originalLoadLibraryA = nullptr;
LoadLibraryExWFn g_originalLoadLibraryExW = nullptr;
LoadLibraryExAFn g_originalLoadLibraryExA = nullptr;
GetProcAddressFn g_originalGetProcAddress = nullptr;
RegOpenKeyExWFn g_originalRegOpenKeyExW = nullptr;
RegCreateKeyExWFn g_originalRegCreateKeyExW = nullptr;
RegQueryValueExWFn g_originalRegQueryValueExW = nullptr;
RegSetValueExWFn g_originalRegSetValueExW = nullptr;
RegDeleteValueWFn g_originalRegDeleteValueW = nullptr;
RegCloseKeyFn g_originalRegCloseKey = nullptr;
OpenProcessTokenFn g_originalOpenProcessToken = nullptr;
LookupPrivilegeValueWFn g_originalLookupPrivilegeValueW = nullptr;
BCryptOpenAlgorithmProviderFn g_originalBCryptOpenAlgorithmProvider = nullptr;
BCryptCloseAlgorithmProviderFn g_originalBCryptCloseAlgorithmProvider = nullptr;
BCryptGetPropertyFn g_originalBCryptGetProperty = nullptr;
BCryptGenRandomFn g_originalBCryptGenRandom = nullptr;
CertOpenStoreFn g_originalCertOpenStore = nullptr;
CertCloseStoreFn g_originalCertCloseStore = nullptr;
CryptMsgOpenToDecodeFn g_originalCryptMsgOpenToDecode = nullptr;
CryptMsgCloseFn g_originalCryptMsgClose = nullptr;
InternetOpenWFn g_originalInternetOpenW = nullptr;
InternetCloseHandleFn g_originalInternetCloseHandle = nullptr;
WinHttpOpenFn g_originalWinHttpOpen = nullptr;
WinHttpCloseHandleFn g_originalWinHttpCloseHandle = nullptr;
GetSystemMetricsFn g_originalGetSystemMetrics = nullptr;
GetDesktopWindowFn g_originalGetDesktopWindow = nullptr;
GetForegroundWindowFn g_originalGetForegroundWindow = nullptr;
GetWindowThreadProcessIdFn g_originalGetWindowThreadProcessId = nullptr;
CreateCompatibleDCFn g_originalCreateCompatibleDC = nullptr;
GetDeviceCapsFn g_originalGetDeviceCaps = nullptr;
DeleteDCFn g_originalDeleteDC = nullptr;
EnumProcessModulesFn g_originalEnumProcessModules = nullptr;
GetModuleInformationFn g_originalGetModuleInformation = nullptr;
GetModuleBaseNameWFn g_originalGetModuleBaseNameW = nullptr;
GetModuleFileNameExWFn g_originalGetModuleFileNameExW = nullptr;
GetFileVersionInfoSizeWFn g_originalGetFileVersionInfoSizeW = nullptr;
GetFileVersionInfoWFn g_originalGetFileVersionInfoW = nullptr;
VerQueryValueWFn g_originalVerQueryValueW = nullptr;
SHGetKnownFolderPathFn g_originalSHGetKnownFolderPath = nullptr;
SHGetSpecialFolderPathWFn g_originalSHGetSpecialFolderPathW = nullptr;
CoInitializeExFn g_originalCoInitializeEx = nullptr;
CoUninitializeFn g_originalCoUninitialize = nullptr;
CoCreateGuidFn g_originalCoCreateGuid = nullptr;
StringFromGUID2Fn g_originalStringFromGUID2 = nullptr;
RoInitializeFn g_originalRoInitialize = nullptr;
RoUninitializeFn g_originalRoUninitialize = nullptr;
RoGetApartmentIdentifierFn g_originalRoGetApartmentIdentifier = nullptr;
RpcStringBindingComposeWFn g_originalRpcStringBindingComposeW = nullptr;
RpcBindingFromStringBindingWFn g_originalRpcBindingFromStringBindingW = nullptr;
RpcStringFreeWFn g_originalRpcStringFreeW = nullptr;
RpcBindingFreeFn g_originalRpcBindingFree = nullptr;
UuidCreateFn g_originalUuidCreate = nullptr;
UuidToStringWFn g_originalUuidToStringW = nullptr;
UuidFromStringWFn g_originalUuidFromStringW = nullptr;
WSAStartupFn g_originalWSAStartup = nullptr;
WSACleanupFn g_originalWSACleanup = nullptr;
SocketFn g_originalSocket = nullptr;
ClosesocketFn g_originalClosesocket = nullptr;
GetAddrInfoFn g_originalGetAddrInfo = nullptr;
FreeAddrInfoFn g_originalFreeAddrInfo = nullptr;
WSAGetLastErrorFn g_originalWSAGetLastError = nullptr;
NtCreateFileFn g_originalNtCreateFile = nullptr;
LdrLoadDllFn g_originalLdrLoadDll = nullptr;
LdrGetProcedureAddressFn g_originalLdrGetProcedureAddress = nullptr;
std::wstring g_operationId;
volatile LONG g_workerStarted = 0;

enum class AgentLifecycleState : LONG
{
    Starting = 0,
    Running = 1,
    Stopping = 2,
    Disabled = 3,
    Failed = 4,
};

struct HookRecord
{
    char ApiName[64] = {};
    char ImportModuleName[64] = {};
    char OwnerModuleName[128] = {};
    HMODULE OwnerModule = nullptr;
    ULONG_PTR* ThunkAddress = nullptr;
    void* OriginalFunction = nullptr;
    void* ReplacementFunction = nullptr;
    bool Installed = false;
    bool Restored = false;
    bool Failed = false;
};

struct HookLifecycleCounts
{
    int InstalledHooks = 0;
    int RestoredHooks = 0;
    int FailedHooks = 0;
};

struct AgentWorkerConfig
{
    std::wstring PipeName;
    std::wstring TransportName;
    std::wstring OperationId;
    bool TransportRequired = false;
};

struct ModuleInfo
{
    HMODULE Base = nullptr;
    std::uint32_t SizeOfImage = 0;
    char Name[128] = {};
    char FullPath[512] = {};
    bool IsAgent = false;
    bool IsSystem = false;
    bool HasImports = false;
    bool Eligible = false;
};

struct SweepStats
{
    std::uint32_t ScannedModules = 0;
    std::uint32_t EligibleModules = 0;
    std::uint32_t SkippedModules = 0;
    std::uint32_t ModulesWithPatches = 0;
    std::uint32_t PatchedSlots = 0;
    std::uint32_t DuplicateSlots = 0;
    std::uint32_t FailedSlots = 0;
};

struct HookDefinition
{
    const char* ImportModuleName = "";
    const char* ApiName = "";
    void* ReplacementFunction = nullptr;
    void** OriginalFunction = nullptr;
    bool Required = false;
    bool ReportStatus = false;
    bool LoaderApi = false;
    WORD ImportOrdinal = 0;
    std::uint32_t LastPatchedSlots = 0;
};

constexpr std::size_t MaxHookRecords = 1024;
constexpr std::size_t MaxModuleRecords = 256;
constexpr std::size_t HookDefinitionCount = 100;
constexpr std::size_t MaxResolverNameBytes = 512;
std::array<HookRecord, MaxHookRecords> g_hookRecords = {};
std::size_t g_hookRecordCount = 0;
SRWLOCK g_hookLock = SRWLOCK_INIT;
volatile LONG g_lifecycleState = static_cast<LONG>(AgentLifecycleState::Starting);
volatile LONG g_hooksEnabled = 0;
volatile LONG g_failedHooks = 0;

void SetLifecycleState(AgentLifecycleState state)
{
    InterlockedExchange(&g_lifecycleState, static_cast<LONG>(state));
}

AgentLifecycleState GetLifecycleState()
{
    return static_cast<AgentLifecycleState>(InterlockedCompareExchange(&g_lifecycleState, 0, 0));
}

bool HooksEnabled()
{
    return InterlockedCompareExchange(&g_hooksEnabled, 0, 0) != 0 && GetLifecycleState() == AgentLifecycleState::Running;
}

const char* LifecycleStateName(AgentLifecycleState state)
{
    const char* name = "unknown";

    switch (state)
    {
    case AgentLifecycleState::Starting:
        name = "starting";
        break;
    case AgentLifecycleState::Running:
        name = "running";
        break;
    case AgentLifecycleState::Stopping:
        name = "stopping";
        break;
    case AgentLifecycleState::Disabled:
        name = "disabled";
        break;
    case AgentLifecycleState::Failed:
        name = "failed";
        break;
    default:
        break;
    }

    return name;
}

std::uint32_t PublicLifecycleState(AgentLifecycleState state)
{
    std::uint32_t value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Unknown);

    switch (state)
    {
    case AgentLifecycleState::Starting:
        value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Starting);
        break;
    case AgentLifecycleState::Running:
        value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Running);
        break;
    case AgentLifecycleState::Stopping:
        value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Stopping);
        break;
    case AgentLifecycleState::Disabled:
        value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Disabled);
        break;
    case AgentLifecycleState::Failed:
        value = static_cast<std::uint32_t>(knmon::KnMonAgentLifecycleState::Failed);
        break;
    default:
        break;
    }

    return value;
}

class HookReentryGuard
{
public:
    HookReentryGuard()
    {
        g_inHook = true;
    }

    ~HookReentryGuard()
    {
        g_inHook = false;
    }
};

std::string WideToUtf8(const wchar_t* value)
{
    std::string result;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
        {
            break;
        }

        result.resize(static_cast<std::size_t>(required - 1));
        const int converted = WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), required, nullptr, nullptr);
        if (converted <= 0)
        {
            result.clear();
            break;
        }
    }
    while (false);

    return result;
}

std::wstring ReadEnv(const wchar_t* name)
{
    std::wstring result;
    std::array<wchar_t, 2048> buffer = {};
    const DWORD length = GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));

    if (length > 0 && length < buffer.size())
    {
        result.assign(buffer.data(), length);
    }

    return result;
}

bool EnvEnabled(const wchar_t* name)
{
    const std::wstring value = ReadEnv(name);
    return value == L"1" || value == L"true" || value == L"TRUE";
}

template <std::size_t Count>
bool WideBufferTerminated(const wchar_t (&value)[Count])
{
    bool terminated = false;

    for (std::size_t index = 0; index < Count; ++index)
    {
        if (value[index] == L'\0')
        {
            terminated = true;
            break;
        }
    }

    return terminated;
}

template <std::size_t Count>
std::wstring WideBufferToString(const wchar_t (&value)[Count])
{
    std::wstring result;

    for (std::size_t index = 0; index < Count && value[index] != L'\0'; ++index)
    {
        result.push_back(value[index]);
    }

    return result;
}

knmon::KnMonAgentControlStatus CopyAttachConfig(
    const knmon::KnMonAttachConfigV1* config,
    AgentWorkerConfig* workerConfig)
{
    knmon::KnMonAgentControlStatus status = knmon::KnMonAgentControlStatus::InvalidConfig;

    do
    {
        if (config == nullptr || workerConfig == nullptr)
        {
            break;
        }

        if (config->Magic != knmon::KnMonAttachConfigMagic)
        {
            break;
        }

        if (config->AbiVersion != knmon::KnMonAttachConfigAbiVersion)
        {
            status = knmon::KnMonAgentControlStatus::UnsupportedAbi;
            break;
        }

        if (config->StructSize < sizeof(knmon::KnMonAttachConfigV1))
        {
            status = knmon::KnMonAgentControlStatus::UnsupportedAbi;
            break;
        }

        if (config->AttachMode != static_cast<std::uint32_t>(knmon::KnMonAttachMode::RunningProcess))
        {
            break;
        }

        if (
            !WideBufferTerminated(config->OperationId) ||
            !WideBufferTerminated(config->PipeName) ||
            !WideBufferTerminated(config->TransportName))
        {
            break;
        }

        AgentWorkerConfig copied;
        copied.OperationId = WideBufferToString(config->OperationId);
        copied.PipeName = WideBufferToString(config->PipeName);
        copied.TransportName = WideBufferToString(config->TransportName);
        copied.TransportRequired = true;

        if (copied.OperationId.empty() || copied.PipeName.empty() || copied.TransportName.empty())
        {
            break;
        }

        *workerConfig = copied;
        status = knmon::KnMonAgentControlStatus::Success;
    }
    while (false);

    return status;
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream stream;

    for (const char ch : value)
    {
        const unsigned char byte = static_cast<unsigned char>(ch);
        switch (ch)
        {
        case '\\':
            stream << "\\\\";
            break;
        case '"':
            stream << "\\\"";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if (byte < 0x20)
            {
                const char* hex = "0123456789abcdef";
                stream << "\\u00" << hex[(byte >> 4) & 0x0f] << hex[byte & 0x0f];
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

std::string Q(const std::string& value)
{
    return "\"" + JsonEscape(value) + "\"";
}

std::string NowUtc()
{
    SYSTEMTIME time = {};
    GetSystemTime(&time);

    std::ostringstream stream;
    stream << std::setfill('0')
           << std::setw(4) << time.wYear << "-"
           << std::setw(2) << time.wMonth << "-"
           << std::setw(2) << time.wDay << "T"
           << std::setw(2) << time.wHour << ":"
           << std::setw(2) << time.wMinute << ":"
           << std::setw(2) << time.wSecond << "."
           << std::setw(3) << time.wMilliseconds << "Z";
    return stream.str();
}

void CopyAsciiText(char* destination, std::uint32_t* length, std::size_t capacity, const char* source)
{
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            break;
        }

        while (copied + 1 < capacity && source[copied] != '\0')
        {
            destination[copied] = source[copied];
            ++copied;
        }

        destination[copied] = '\0';
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

void CopyWideText(char* destination, std::uint32_t* length, std::size_t capacity, const wchar_t* source)
{
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            break;
        }

        const int converted = WideCharToMultiByte(CP_UTF8, 0, source, -1, destination, static_cast<int>(capacity), nullptr, nullptr);
        if (converted <= 0)
        {
            break;
        }

        copied = static_cast<std::uint32_t>(converted - 1);
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

void CopyWideCountText(char* destination, std::size_t capacity, const wchar_t* source, std::size_t charCount)
{
    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (source == nullptr || charCount == 0)
        {
            break;
        }

        const std::size_t boundedChars = charCount < 511 ? charCount : 511;
        std::array<wchar_t, 512> buffer = {};
        for (std::size_t index = 0; index < boundedChars; ++index)
        {
            buffer[index] = source[index];
        }

        buffer[boundedChars] = L'\0';
        CopyWideText(destination, nullptr, capacity, buffer.data());
    }
    while (false);
}

void LowerAsciiInPlace(char* value)
{
    if (value == nullptr)
    {
        return;
    }

    for (std::size_t index = 0; value[index] != '\0'; ++index)
    {
        if (value[index] >= 'A' && value[index] <= 'Z')
        {
            value[index] = static_cast<char>(value[index] - 'A' + 'a');
        }
    }
}

const char* FileNameFromPathText(const char* path)
{
    const char* result = path;

    if (path != nullptr)
    {
        for (const char* current = path; *current != '\0'; ++current)
        {
            if (*current == '\\' || *current == '/')
            {
                result = current + 1;
            }
        }
    }

    return result == nullptr ? "" : result;
}

bool TextContains(const char* value, const char* pattern)
{
    bool contains = false;

    do
    {
        if (value == nullptr || pattern == nullptr)
        {
            break;
        }

        if (std::strstr(value, pattern) != nullptr)
        {
            contains = true;
        }
    }
    while (false);

    return contains;
}

bool IsWindowsSystemModule(const ModuleInfo& module)
{
    bool systemModule = false;

    if (
        TextContains(module.FullPath, "\\windows\\system32\\") ||
        TextContains(module.FullPath, "\\windows\\syswow64\\") ||
        std::strcmp(module.Name, "ntdll.dll") == 0 ||
        std::strcmp(module.Name, "kernel32.dll") == 0 ||
        std::strcmp(module.Name, "kernelbase.dll") == 0)
    {
        systemModule = true;
    }

    return systemModule;
}

void CopyHexPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const void* value)
{
    int written = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        written = std::snprintf(
            destination,
            capacity,
            sizeof(void*) == 8 ? "0x%016llx" : "0x%08llx",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value)));
        if (written < 0)
        {
            written = 0;
            destination[0] = '\0';
        }
    }
    while (false);

    if (length != nullptr)
    {
        *length = static_cast<std::uint32_t>(written < 0 ? 0 : written);
    }
}

void CopyBufferPreviewText(char* destination, std::uint32_t* length, std::size_t capacity, const void* buffer, DWORD bytes)
{
    std::uint32_t copied = 0;
    static constexpr char Hex[] = "0123456789abcdef";

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (buffer == nullptr || bytes == 0)
        {
            break;
        }

        const auto* source = static_cast<const unsigned char*>(buffer);
        const DWORD captured = bytes < MaxBufferPreviewBytes ? bytes : static_cast<DWORD>(MaxBufferPreviewBytes);
        for (DWORD index = 0; index < captured; ++index)
        {
            if (copied + 3 >= capacity)
            {
                break;
            }

            if (index != 0)
            {
                destination[copied] = ' ';
                ++copied;
            }

            destination[copied] = Hex[(source[index] >> 4) & 0x0f];
            ++copied;
            destination[copied] = Hex[source[index] & 0x0f];
            ++copied;
        }

        destination[copied] = '\0';
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

std::uint32_t CopyWidePointerText(char* destination, std::uint32_t* length, std::size_t capacity, const wchar_t* source)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
    std::array<wchar_t, MaxRegistryStringChars + 1> localBuffer = {};
    std::uint32_t copiedChars = 0;
    bool terminated = false;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            break;
        }

        while (copiedChars < MaxRegistryStringChars)
        {
            wchar_t ch = L'\0';
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), source + copiedChars, &ch, sizeof(ch), &bytesRead) || bytesRead != sizeof(ch))
            {
                status = copiedChars == 0 ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
                break;
            }

            if (ch == L'\0')
            {
                terminated = true;
                break;
            }

            localBuffer[copiedChars] = ch;
            ++copiedChars;
        }

        if (!terminated && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        CopyWideCountText(destination, capacity, localBuffer.data(), copiedChars);
    }
    while (false);

    if (length != nullptr)
    {
        *length = destination == nullptr ? 0 : static_cast<std::uint32_t>(std::strlen(destination));
    }

    return status;
}

void CopyLocalHexPreviewText(char* destination, std::uint32_t* length, std::size_t capacity, const unsigned char* buffer, DWORD bytes)
{
    std::uint32_t copied = 0;
    static constexpr char Hex[] = "0123456789abcdef";

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        if (buffer == nullptr || bytes == 0)
        {
            break;
        }

        const DWORD captured = bytes < MaxBufferPreviewBytes ? bytes : static_cast<DWORD>(MaxBufferPreviewBytes);
        for (DWORD index = 0; index < captured; ++index)
        {
            if (copied + 3 >= capacity)
            {
                break;
            }

            if (index != 0)
            {
                destination[copied] = ' ';
                ++copied;
            }

            destination[copied] = Hex[(buffer[index] >> 4) & 0x0f];
            ++copied;
            destination[copied] = Hex[buffer[index] & 0x0f];
            ++copied;
        }

        destination[copied] = '\0';
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }
}

std::uint32_t CopyRegistryDataPreviewText(
    char* destination,
    std::uint32_t* length,
    std::size_t capacity,
    DWORD valueType,
    const BYTE* data,
    DWORD bytes)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (data == nullptr || bytes == 0)
        {
            break;
        }

        DWORD capturedBytes = bytes < MaxRegistryDataPreviewBytes ? bytes : static_cast<DWORD>(MaxRegistryDataPreviewBytes);
        if (capturedBytes < bytes)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
        {
            capturedBytes -= capturedBytes % sizeof(wchar_t);
            if (capturedBytes == 0)
            {
                break;
            }

            std::array<wchar_t, (MaxRegistryDataPreviewBytes / sizeof(wchar_t)) + 1> localWide = {};
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), data, localWide.data(), capturedBytes, &bytesRead) || bytesRead == 0)
            {
                CopyHexPointerText(destination, length, capacity, data);
                status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
                break;
            }

            bytesRead -= bytesRead % sizeof(wchar_t);
            std::size_t charCount = bytesRead / sizeof(wchar_t);
            if (charCount >= localWide.size())
            {
                charCount = localWide.size() - 1;
            }

            while (charCount > 0 && localWide[charCount - 1] == L'\0')
            {
                --charCount;
            }

            CopyWideCountText(destination, capacity, localWide.data(), charCount);
            if (bytesRead < capturedBytes && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
            {
                status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
            }
            break;
        }

        if (valueType == REG_DWORD && bytes >= sizeof(DWORD))
        {
            DWORD localDword = 0;
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), data, &localDword, sizeof(localDword), &bytesRead) || bytesRead != sizeof(localDword))
            {
                CopyHexPointerText(destination, length, capacity, data);
                status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
                break;
            }

            char buffer[32] = {};
            std::snprintf(buffer, sizeof(buffer), "dword=0x%08lx", static_cast<unsigned long>(localDword));
            CopyAsciiText(destination, length, capacity, buffer);
            break;
        }

        std::array<unsigned char, MaxRegistryDataPreviewBytes> localBytes = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), data, localBytes.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            CopyHexPointerText(destination, length, capacity, data);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        CopyLocalHexPreviewText(destination, length, capacity, localBytes.data(), static_cast<DWORD>(bytesRead));
        if (bytesRead < capturedBytes && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
        }
    }
    while (false);

    if (length != nullptr && destination != nullptr)
    {
        *length = static_cast<std::uint32_t>(std::strlen(destination));
    }

    return status;
}

bool IsOrdinalProcName(LPCSTR procName)
{
    const std::uintptr_t value = reinterpret_cast<std::uintptr_t>(procName);
    return value != 0 && (value >> 16) == 0;
}

bool IsLowPointerValue(const void* value)
{
    const std::uintptr_t pointerValue = reinterpret_cast<std::uintptr_t>(value);
    return pointerValue != 0 && pointerValue <= 0xFFFF;
}

std::uint32_t CopyAnsiPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const char* source)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
    std::uint32_t copied = 0;
    bool terminated = false;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (source == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        while (copied + 1 < capacity)
        {
            char ch = '\0';
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), source + copied, &ch, sizeof(ch), &bytesRead) || bytesRead != sizeof(ch))
            {
                status = copied == 0 ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
                break;
            }

            if (ch == '\0')
            {
                terminated = true;
                break;
            }

            destination[copied] = ch;
            ++copied;
        }

        destination[copied] = '\0';
        if (!terminated && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }
    }
    while (false);

    if (length != nullptr)
    {
        *length = copied;
    }

    return status;
}

std::uint32_t CopyCertStoreProviderText(char* destination, std::uint32_t* length, std::size_t capacity, LPCSTR provider)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (length != nullptr)
        {
            *length = 0;
        }

        if (provider == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        if (IsLowPointerValue(provider))
        {
            char buffer[32] = {};
            std::snprintf(buffer, sizeof(buffer), "provider_id:%u", static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(provider)));
            CopyAsciiText(destination, length, capacity, buffer);
            break;
        }

        status = CopyAnsiPointerText(destination, length, capacity, provider);
    }
    while (false);

    return status;
}

template <typename T>
bool ReadCurrentProcessValue(const T* address, T* value);

std::uint64_t DurationUs(const LARGE_INTEGER& start, const LARGE_INTEGER& end);

std::uint32_t CopyAnsiStringText(char* destination, std::uint32_t* length, std::size_t capacity, const ANSI_STRING* value)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
    std::uint32_t copied = 0;

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (value == nullptr)
        {
            break;
        }

        ANSI_STRING local = {};
        if (!ReadCurrentProcessValue(value, &local))
        {
            CopyHexPointerText(destination, length, capacity, value);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        if (local.Buffer == nullptr || local.Length == 0)
        {
            break;
        }

        std::size_t capturedBytes = local.Length;
        if (capturedBytes > MaxResolverNameBytes)
        {
            capturedBytes = MaxResolverNameBytes;
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        if (capturedBytes + 1 > capacity)
        {
            capturedBytes = capacity - 1;
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        if (capturedBytes == 0)
        {
            break;
        }

        std::array<char, MaxResolverNameBytes + 1> localBuffer = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), local.Buffer, localBuffer.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            CopyHexPointerText(destination, length, capacity, local.Buffer);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        copied = static_cast<std::uint32_t>(bytesRead < capturedBytes ? bytesRead : capturedBytes);
        for (std::uint32_t index = 0; index < copied; ++index)
        {
            destination[index] = localBuffer[index];
        }
        destination[copied] = '\0';

        if (bytesRead < local.Length && status == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
        }
    }
    while (false);

    if (length != nullptr && status != static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory))
    {
        *length = copied;
    }

    return status;
}

std::uint32_t CopyUnicodeStringText(char* destination, std::uint32_t* length, std::size_t capacity, const UNICODE_STRING* value)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (value == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        UNICODE_STRING local = {};
        if (!ReadCurrentProcessValue(value, &local))
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        if (local.Buffer == nullptr || local.Length == 0)
        {
            break;
        }

        std::size_t capturedBytes = local.Length;
        if (capturedBytes > MaxNtObjectNameBytes)
        {
            capturedBytes = MaxNtObjectNameBytes;
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
        }

        capturedBytes -= capturedBytes % sizeof(wchar_t);
        if (capturedBytes == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        std::array<wchar_t, (MaxNtObjectNameBytes / sizeof(wchar_t)) + 1> localBuffer = {};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), local.Buffer, localBuffer.data(), capturedBytes, &bytesRead) || bytesRead == 0)
        {
            CopyHexPointerText(destination, length, capacity, local.Buffer);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        bytesRead -= bytesRead % sizeof(wchar_t);
        localBuffer[bytesRead / sizeof(wchar_t)] = L'\0';
        CopyWideText(destination, length, capacity, localBuffer.data());
    }
    while (false);

    return status;
}

std::uint32_t CopyObjectAttributesName(char* destination, std::uint32_t* length, std::size_t capacity, const OBJECT_ATTRIBUTES* objectAttributes)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (objectAttributes == nullptr)
        {
            CopyAsciiText(destination, length, capacity, "");
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        OBJECT_ATTRIBUTES local = {};
        if (!ReadCurrentProcessValue(objectAttributes, &local))
        {
            CopyHexPointerText(destination, length, capacity, objectAttributes);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        status = CopyUnicodeStringText(destination, length, capacity, local.ObjectName);
        if (destination != nullptr && destination[0] == '\0')
        {
            CopyHexPointerText(destination, length, capacity, local.ObjectName);
        }
    }
    while (false);

    return status;
}

std::uint32_t CopyIoStatusBlockText(char* destination, std::uint32_t* length, std::size_t capacity, const IO_STATUS_BLOCK* ioStatusBlock)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (ioStatusBlock == nullptr)
        {
            CopyAsciiText(destination, length, capacity, "");
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        IO_STATUS_BLOCK local = {};
        if (!ReadCurrentProcessValue(ioStatusBlock, &local))
        {
            CopyHexPointerText(destination, length, capacity, ioStatusBlock);
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            break;
        }

        char buffer[96] = {};
        std::snprintf(
            buffer,
            sizeof(buffer),
            sizeof(void*) == 8 ? "Status=0x%08lx,Information=0x%016llx" : "Status=0x%08lx,Information=0x%08llx",
            static_cast<unsigned long>(static_cast<std::uint32_t>(local.Status)),
            static_cast<unsigned long long>(static_cast<std::uintptr_t>(local.Information)));
        CopyAsciiText(destination, length, capacity, buffer);
    }
    while (false);

    return status;
}

void CountDroppedTransportEvent()
{
    InterlockedIncrement64(&g_droppedEvents);
    if (g_transportHeader != nullptr)
    {
        InterlockedIncrement64(&g_transportHeader->DroppedEvents);
    }
}

void UpdateTransportHighWaterMark(std::int64_t depth)
{
    if (g_transportHeader == nullptr)
    {
        return;
    }

    for (;;)
    {
        const std::int64_t current = InterlockedCompareExchange64(&g_transportHeader->HighWaterMark, 0, 0);
        if (depth <= current)
        {
            break;
        }

        if (InterlockedCompareExchange64(&g_transportHeader->HighWaterMark, depth, current) == current)
        {
            break;
        }
    }
}

knmon::KnMonTransportRecord* ReserveTransportRecord()
{
    knmon::KnMonTransportRecord* record = nullptr;

    do
    {
        if (g_transportHeader == nullptr || g_transportRecords == nullptr || g_transportCapacity == 0)
        {
            CountDroppedTransportEvent();
            break;
        }

        for (;;)
        {
            const std::int64_t producer = InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, 0, 0);
            const std::int64_t consumer = InterlockedCompareExchange64(&g_transportHeader->ConsumerSequence, 0, 0);
            const std::int64_t depth = producer - consumer;
            if (depth >= static_cast<std::int64_t>(g_transportCapacity))
            {
                CountDroppedTransportEvent();
                break;
            }

            if (InterlockedCompareExchange64(&g_transportHeader->ProducerSequence, producer + 1, producer) == producer)
            {
                UpdateTransportHighWaterMark(depth + 1);
                record = &g_transportRecords[producer % g_transportCapacity];
                if (InterlockedCompareExchange(
                        reinterpret_cast<volatile LONG*>(&record->State),
                        static_cast<LONG>(knmon::KnMonTransportRecordState::Writing),
                        static_cast<LONG>(knmon::KnMonTransportRecordState::Free)) != static_cast<LONG>(knmon::KnMonTransportRecordState::Free))
                {
                    record = nullptr;
                    CountDroppedTransportEvent();
                    break;
                }

                std::memset(record, 0, sizeof(*record));
                record->State = static_cast<LONG>(knmon::KnMonTransportRecordState::Writing);
                record->Sequence = producer;
                record->RecordSize = sizeof(knmon::KnMonTransportRecord);
                record->EventKind = static_cast<std::uint16_t>(knmon::KnMonTransportEventKind::ApiCall);
                record->ProcessId = GetCurrentProcessId();
                record->ThreadId = GetCurrentThreadId();
                break;
            }
        }
    }
    while (false);

    return record;
}

void CommitTransportRecord(knmon::KnMonTransportRecord* record, const LARGE_INTEGER& overheadStart)
{
    if (record != nullptr)
    {
        LARGE_INTEGER overheadEnd = {};
        QueryPerformanceCounter(&overheadEnd);
        record->HookOverheadUs = DurationUs(overheadStart, overheadEnd);
        MemoryBarrier();
        InterlockedExchange(reinterpret_cast<volatile LONG*>(&record->State), static_cast<LONG>(knmon::KnMonTransportRecordState::Committed));
    }
}

std::uint16_t ModuleId(const char* moduleName)
{
    std::uint16_t result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Unknown);

    if (std::strcmp(moduleName, "kernel32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Kernel32);
    }
    else if (std::strcmp(moduleName, "ntdll.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Ntdll);
    }
    else if (std::strcmp(moduleName, "kernelbase.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::KernelBase);
    }
    else if (_stricmp(moduleName, "advapi32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Advapi32);
    }
    else if (_stricmp(moduleName, "bcrypt.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Bcrypt);
    }
    else if (_stricmp(moduleName, "crypt32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Crypt32);
    }
    else if (_stricmp(moduleName, "ws2_32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Ws2_32);
    }
    else if (_stricmp(moduleName, "rpcrt4.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Rpcrt4);
    }
    else if (_stricmp(moduleName, "wininet.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Wininet);
    }
    else if (_stricmp(moduleName, "winhttp.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Winhttp);
    }
    else if (_stricmp(moduleName, "user32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::User32);
    }
    else if (_stricmp(moduleName, "gdi32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Gdi32);
    }
    else if (_stricmp(moduleName, "psapi.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Psapi);
    }
    else if (_stricmp(moduleName, "version.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Version);
    }
    else if (_stricmp(moduleName, "shell32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Shell32);
    }
    else if (_stricmp(moduleName, "ole32.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::Ole32);
    }
    else if (_stricmp(moduleName, "api-ms-win-core-winrt-l1-1-0.dll") == 0)
    {
        result = static_cast<std::uint16_t>(knmon::KnMonTransportModuleId::ApiMsWinCoreWinrtL110);
    }

    return result;
}

bool OpenTransport(const std::wstring& mappingName)
{
    bool opened = false;

    do
    {
        if (mappingName.empty())
        {
            break;
        }

        g_transportMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName.c_str());
        if (g_transportMapping == nullptr)
        {
            break;
        }

        auto* header = static_cast<knmon::KnMonTransportHeader*>(MapViewOfFile(g_transportMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
        if (header == nullptr)
        {
            break;
        }

        if (
            header->Magic != knmon::KnMonTransportMagic ||
            header->AbiVersion != knmon::KnMonTransportAbiVersion ||
            header->RecordSize != sizeof(knmon::KnMonTransportRecord) ||
            header->Capacity < knmon::KnMonTransportMinCapacity)
        {
            UnmapViewOfFile(header);
            break;
        }

        g_transportHeader = header;
        g_transportRecords = reinterpret_cast<knmon::KnMonTransportRecord*>(reinterpret_cast<unsigned char*>(header) + sizeof(knmon::KnMonTransportHeader));
        g_transportCapacity = header->Capacity;
        opened = true;
    }
    while (false);

    if (!opened)
    {
        if (g_transportHeader != nullptr)
        {
            UnmapViewOfFile(g_transportHeader);
            g_transportHeader = nullptr;
            g_transportRecords = nullptr;
            g_transportCapacity = 0;
        }

        if (g_transportMapping != nullptr)
        {
            CloseHandle(g_transportMapping);
            g_transportMapping = nullptr;
        }
    }

    return opened;
}

void CloseTransport()
{
    if (g_transportHeader != nullptr)
    {
        UnmapViewOfFile(g_transportHeader);
        g_transportHeader = nullptr;
        g_transportRecords = nullptr;
        g_transportCapacity = 0;
    }

    if (g_transportMapping != nullptr)
    {
        CloseHandle(g_transportMapping);
        g_transportMapping = nullptr;
    }
}

template <typename T>
bool ReadCurrentProcessValue(const T* address, T* value)
{
    bool read = false;

    do
    {
        if (address == nullptr || value == nullptr)
        {
            break;
        }

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), address, value, sizeof(T), &bytesRead))
        {
            break;
        }

        read = bytesRead == sizeof(T);
    }
    while (false);

    return read;
}

DWORD NtStatusToDosError(NTSTATUS status)
{
    DWORD result = 0;

    do
    {
        if (NT_SUCCESS(status))
        {
            break;
        }

        HMODULE module = GetModuleHandleW(L"ntdll.dll");
        if (module == nullptr)
        {
            result = ERROR_MR_MID_NOT_FOUND;
            break;
        }

        auto rtlNtStatusToDosError = reinterpret_cast<RtlNtStatusToDosErrorFn>(GetProcAddress(module, "RtlNtStatusToDosError"));
        if (rtlNtStatusToDosError == nullptr)
        {
            result = ERROR_MR_MID_NOT_FOUND;
            break;
        }

        result = rtlNtStatusToDosError(status);
    }
    while (false);

    return result;
}

std::uint64_t DurationUs(const LARGE_INTEGER& start, const LARGE_INTEGER& end)
{
    LARGE_INTEGER frequency = {};
    QueryPerformanceFrequency(&frequency);
    if (frequency.QuadPart == 0)
    {
        return 0;
    }

    return static_cast<std::uint64_t>(((end.QuadPart - start.QuadPart) * 1000000LL) / frequency.QuadPart);
}

LONG64 NextSequence()
{
    return InterlockedIncrement64(&g_sequence);
}

std::string MessagePrefix(const char* messageType, LONG64 sequence)
{
    std::ostringstream stream;
    stream << "{";
    stream << "\"schemaVersion\":\"0.1.0\",";
    stream << "\"messageType\":" << Q(messageType) << ",";
    stream << "\"operationId\":" << Q(WideToUtf8(g_operationId.c_str())) << ",";
    stream << "\"pid\":" << GetCurrentProcessId() << ",";
    stream << "\"tid\":" << GetCurrentThreadId() << ",";
    stream << "\"timestampUtc\":" << Q(NowUtc()) << ",";
    stream << "\"sequence\":" << sequence;
    return stream.str();
}

bool SendJson(const std::string& payload)
{
    bool sent = false;

    AcquireSRWLockExclusive(&g_pipeLock);
    do
    {
        if (g_pipeHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(g_pipeHandle, payload.data(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr))
        {
            break;
        }

        sent = bytesWritten == payload.size();
    }
    while (false);
    ReleaseSRWLockExclusive(&g_pipeLock);

    if (!sent)
    {
        InterlockedIncrement64(&g_droppedEvents);
    }

    return sent;
}

void SendHello()
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("agent_hello", sequence) << ",";
    stream << "\"architecture\":" << Q(KNMON_AGENT_ARCHITECTURE) << ",";
    stream << "\"agentVersion\":" << Q(WideToUtf8(AgentVersion)) << ",";
    stream << "\"message\":" << Q(KNMON_AGENT_HELLO_MESSAGE);
    stream << "}";
    SendJson(stream.str());
}

void SendHookStatus(const char* moduleName, const char* apiName, bool installed, const std::string& message)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix(installed ? "hook_installed" : "hook_install_failed", sequence) << ",";
    stream << "\"api\":" << Q(apiName) << ",";
    stream << "\"module\":" << Q(moduleName) << ",";
    stream << "\"hookMethod\":\"iat\",";
    stream << "\"message\":" << Q(message);
    stream << "}";
    SendJson(stream.str());
}

void SendModuleInventoryStatus(const SweepStats& stats)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("module_inventory", sequence) << ",";
    stream << "\"scannedModules\":" << stats.ScannedModules << ",";
    stream << "\"eligibleModules\":" << stats.EligibleModules << ",";
    stream << "\"skippedModules\":" << stats.SkippedModules << ",";
    stream << "\"message\":\"Module inventory captured from PEB loader list.\"";
    stream << "}";
    SendJson(stream.str());
}

void SendIatSweepStatus(const char* reason, const SweepStats& stats)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("iat_sweep", sequence) << ",";
    stream << "\"reason\":" << Q(reason == nullptr ? "unknown" : reason) << ",";
    stream << "\"scannedModules\":" << stats.ScannedModules << ",";
    stream << "\"eligibleModules\":" << stats.EligibleModules << ",";
    stream << "\"skippedModules\":" << stats.SkippedModules << ",";
    stream << "\"patchedModules\":" << stats.ModulesWithPatches << ",";
    stream << "\"patchedSlots\":" << stats.PatchedSlots << ",";
    stream << "\"duplicateSlots\":" << stats.DuplicateSlots << ",";
    stream << "\"failedSlots\":" << stats.FailedSlots << ",";
    stream << "\"message\":\"Loaded-module IAT sweep completed.\"";
    stream << "}";
    SendJson(stream.str());
}

void SendDroppedEvents()
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("dropped_events", sequence) << ",";
    stream << "\"droppedCount\":" << static_cast<LONG64>(g_droppedEvents) << ",";
    stream << "\"message\":\"Current agent dropped event counter\"";
    stream << "}";
    SendJson(stream.str());
}

HookLifecycleCounts SnapshotHookCounts()
{
    HookLifecycleCounts counts;

    AcquireSRWLockShared(&g_hookLock);
    for (std::size_t index = 0; index < g_hookRecordCount; ++index)
    {
        const HookRecord& record = g_hookRecords[index];
        if (record.Installed)
        {
            ++counts.InstalledHooks;
        }

        if (record.Restored)
        {
            ++counts.RestoredHooks;
        }

        if (record.Failed)
        {
            ++counts.FailedHooks;
        }
    }
    ReleaseSRWLockShared(&g_hookLock);

    counts.FailedHooks += static_cast<int>(InterlockedCompareExchange(&g_failedHooks, 0, 0));
    return counts;
}

void SendAgentShutdown(const char* reason, const HookLifecycleCounts& counts)
{
    const LONG64 sequence = NextSequence();
    std::ostringstream stream;
    stream << MessagePrefix("agent_shutdown", sequence) << ",";
    stream << "\"reason\":" << Q(reason == nullptr ? "unknown" : reason) << ",";
    stream << "\"lifecycleState\":" << Q(LifecycleStateName(GetLifecycleState())) << ",";
    stream << "\"installedHooks\":" << counts.InstalledHooks << ",";
    stream << "\"restoredHooks\":" << counts.RestoredHooks << ",";
    stream << "\"failedHooks\":" << counts.FailedHooks << ",";
    stream << "\"droppedCount\":" << static_cast<LONG64>(g_droppedEvents) << ",";
    stream << "\"message\":\"Agent lifecycle shutdown completed.\"";
    stream << "}";
    SendJson(stream.str());
}

void FillTransportCommon(
    knmon::KnMonTransportRecord* record,
    knmon::KnMonTransportApiId apiId,
    const char* moduleName,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD errorCode)
{
    if (record != nullptr)
    {
        record->ApiId = static_cast<std::uint16_t>(apiId);
        record->ModuleId = ModuleId(moduleName);
        record->StartQpc = static_cast<std::uint64_t>(start.QuadPart);
        record->EndQpc = static_cast<std::uint64_t>(end.QuadPart);
        record->DurationUs = DurationUs(start, end);
        record->LastErrorCode = errorCode;
    }
}

void EmitCreateFileWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    DWORD creationDisposition)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateFileW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = shareMode;
        record->Values32[2] = creationDisposition;
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateFileAEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    DWORD creationDisposition)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateFileA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = shareMode;
        record->Values32[2] = creationDisposition;
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitReadFileEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE file,
    LPVOID buffer,
    DWORD bytesToRead,
    DWORD bytesRead)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::ReadFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values32[0] = bytesToRead;
        record->Values32[1] = bytesRead;
        CopyBufferPreviewText(record->Text0, &record->Text0Length, sizeof(record->Text0), result ? buffer : nullptr, bytesRead);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWriteFileEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE file,
    LPCVOID buffer,
    DWORD bytesToWrite,
    DWORD bytesWritten)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WriteFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values32[0] = bytesToWrite;
        record->Values32[1] = bytesWritten;
        CopyBufferPreviewText(record->Text0, &record->Text0Length, sizeof(record->Text0), buffer, bytesToWrite);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCloseHandleEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE handle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CloseHandle, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitVirtualAllocEvent(
    LPVOID result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPVOID address,
    SIZE_T size,
    DWORD allocationType,
    DWORD protect)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::VirtualAlloc, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address));
        record->Values64[1] = static_cast<std::uint64_t>(size);
        record->Values32[0] = allocationType;
        record->Values32[1] = protect;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitVirtualFreeEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPVOID address,
    SIZE_T size,
    DWORD freeType)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::VirtualFree, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address));
        record->Values64[1] = static_cast<std::uint64_t>(size);
        record->Values32[0] = freeType;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitVirtualProtectEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPVOID address,
    SIZE_T size,
    DWORD newProtect,
    PDWORD oldProtect)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        DWORD oldProtectValue = 0;
        std::uint32_t oldProtectStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result != FALSE)
        {
            if (oldProtect == nullptr)
            {
                oldProtectStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            }
            else if (ReadCurrentProcessValue(oldProtect, &oldProtectValue))
            {
                oldProtectStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                oldProtectStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        FillTransportCommon(record, knmon::KnMonTransportApiId::VirtualProtect, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address));
        record->Values64[1] = static_cast<std::uint64_t>(size);
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(oldProtect));
        record->Values32[0] = newProtect;
        record->Values32[1] = oldProtectStatus;
        record->Values32[2] = oldProtectValue;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitVirtualQueryEvent(
    SIZE_T result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCVOID address,
    PMEMORY_BASIC_INFORMATION buffer,
    SIZE_T length)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        MEMORY_BASIC_INFORMATION localInfo = {};
        std::uint32_t infoStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result != 0)
        {
            if (buffer == nullptr)
            {
                infoStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            }
            else if (ReadCurrentProcessValue(buffer, &localInfo))
            {
                infoStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                infoStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        FillTransportCommon(record, knmon::KnMonTransportApiId::VirtualQuery, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values64[2] = static_cast<std::uint64_t>(length);
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localInfo.BaseAddress));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localInfo.AllocationBase));
        record->Values64[5] = static_cast<std::uint64_t>(localInfo.RegionSize);
        record->Values32[0] = infoStatus;
        record->Values32[1] = localInfo.AllocationProtect;
        record->Values32[2] = localInfo.State;
        record->Values32[3] = localInfo.Protect;
        record->Values32[4] = localInfo.Type;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateFileMappingWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE file,
    LPSECURITY_ATTRIBUTES mappingAttributes,
    DWORD protect,
    DWORD maximumSizeHigh,
    DWORD maximumSizeLow,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateFileMappingW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mappingAttributes));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = protect;
        record->Values32[1] = maximumSizeHigh;
        record->Values32[2] = maximumSizeLow;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenFileMappingWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD desiredAccess,
    BOOL inheritHandle,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenFileMappingW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = inheritHandle ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitMapViewOfFileEvent(
    LPVOID result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE mapping,
    DWORD desiredAccess,
    DWORD fileOffsetHigh,
    DWORD fileOffsetLow,
    SIZE_T bytesToMap)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::MapViewOfFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mapping));
        record->Values64[1] = static_cast<std::uint64_t>(bytesToMap);
        record->Values32[0] = desiredAccess;
        record->Values32[1] = fileOffsetHigh;
        record->Values32[2] = fileOffsetLow;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitUnmapViewOfFileEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCVOID baseAddress)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::UnmapViewOfFile, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(baseAddress));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetCurrentProcessEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetCurrentProcess, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetCurrentProcessIdEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetCurrentProcessId, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetCurrentThreadEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetCurrentThread, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetCurrentThreadIdEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetCurrentThreadId, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetProcessIdEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetProcessId, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetThreadIdEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE thread)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetThreadId, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(thread));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateThreadEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPSECURITY_ATTRIBUTES threadAttributes,
    SIZE_T stackSize,
    LPTHREAD_START_ROUTINE startAddress,
    LPVOID parameter,
    DWORD creationFlags,
    LPDWORD threadId)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        DWORD threadIdValue = 0;
        std::uint32_t threadIdStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result != nullptr)
        {
            if (threadId == nullptr)
            {
                threadIdStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
            }
            else if (ReadCurrentProcessValue(threadId, &threadIdValue))
            {
                threadIdStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                threadIdStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateThread, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(threadAttributes));
        record->Values64[1] = static_cast<std::uint64_t>(stackSize);
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(startAddress));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(parameter));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(threadId));
        record->Values32[0] = creationFlags;
        record->Values32[1] = threadIdStatus;
        record->Values32[2] = threadIdValue;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenThreadEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD desiredAccess,
    BOOL inheritHandle,
    DWORD threadId)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenThread, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = inheritHandle ? 1U : 0U;
        record->Values32[2] = threadId;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWaitForSingleObjectEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE handle,
    DWORD milliseconds)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WaitForSingleObject, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
        record->Values32[0] = milliseconds;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetExitCodeThreadEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE thread,
    LPDWORD exitCode)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        DWORD exitCodeValue = 0;
        std::uint32_t exitCodeStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result != FALSE)
        {
            if (exitCode == nullptr)
            {
                exitCodeStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            }
            else if (ReadCurrentProcessValue(exitCode, &exitCodeValue))
            {
                exitCodeStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                exitCodeStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        FillTransportCommon(record, knmon::KnMonTransportApiId::GetExitCodeThread, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(thread));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(exitCode));
        record->Values32[0] = exitCodeStatus;
        record->Values32[1] = exitCodeValue;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateEventWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPSECURITY_ATTRIBUTES eventAttributes,
    BOOL manualReset,
    BOOL initialState,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateEventW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(eventAttributes));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = manualReset ? 1U : 0U;
        record->Values32[1] = initialState ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenEventWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD desiredAccess,
    BOOL inheritHandle,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenEventW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = inheritHandle ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitSetEventEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE eventHandle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::SetEvent, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(eventHandle));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitResetEventEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE eventHandle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::ResetEvent, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(eventHandle));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWaitForSingleObjectExEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE handle,
    DWORD milliseconds,
    BOOL alertable)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WaitForSingleObjectEx, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
        record->Values32[0] = milliseconds;
        record->Values32[1] = alertable ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateMutexWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPSECURITY_ATTRIBUTES mutexAttributes,
    BOOL initialOwner,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateMutexW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mutexAttributes));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = initialOwner ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenMutexWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD desiredAccess,
    BOOL inheritHandle,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenMutexW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = inheritHandle ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitReleaseMutexEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE mutexHandle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::ReleaseMutex, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mutexHandle));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateSemaphoreWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPSECURITY_ATTRIBUTES semaphoreAttributes,
    LONG initialCount,
    LONG maximumCount,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateSemaphoreW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(semaphoreAttributes));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = static_cast<std::uint32_t>(initialCount);
        record->Values32[1] = static_cast<std::uint32_t>(maximumCount);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenSemaphoreWEvent(
    HANDLE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD desiredAccess,
    BOOL inheritHandle,
    LPCWSTR name)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenSemaphoreW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = inheritHandle ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitReleaseSemaphoreEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE semaphoreHandle,
    LONG releaseCount,
    LPLONG previousCount)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        LONG previousCountValue = 0;
        std::uint32_t previousCountStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result != FALSE)
        {
            if (previousCount == nullptr)
            {
                previousCountStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            }
            else if (ReadCurrentProcessValue(previousCount, &previousCountValue))
            {
                previousCountStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                previousCountStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        FillTransportCommon(record, knmon::KnMonTransportApiId::ReleaseSemaphore, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result ? 1 : 0;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(semaphoreHandle));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(previousCount));
        record->Values32[0] = static_cast<std::uint32_t>(releaseCount);
        record->Values32[1] = previousCountStatus;
        record->Values32[2] = static_cast<std::uint32_t>(previousCountValue);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWaitForMultipleObjectsExEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD count,
    const HANDLE* handles,
    BOOL waitAll,
    DWORD milliseconds,
    BOOL alertable)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WaitForMultipleObjectsEx, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = result;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handles));
        record->Values32[0] = count;
        record->Values32[1] = waitAll ? 1U : 0U;
        record->Values32[2] = milliseconds;
        record->Values32[3] = alertable ? 1U : 0U;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitNtCreateFileEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    PHANDLE fileHandle,
    ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PIO_STATUS_BLOCK ioStatusBlock,
    PLARGE_INTEGER allocationSize,
    ULONG fileAttributes,
    ULONG shareAccess,
    ULONG createDisposition,
    ULONG createOptions,
    PVOID eaBuffer,
    ULONG eaLength)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::NtCreateFile, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fileHandle));
        HANDLE localHandle = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(fileHandle, &localHandle))
        {
            record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localHandle));
        }
        else
        {
            record->Values64[1] = record->Values64[0];
        }
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(objectAttributes));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(ioStatusBlock));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(allocationSize));
        record->Values64[5] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(eaBuffer));
        record->Values32[0] = desiredAccess;
        record->Values32[1] = fileAttributes;
        record->Values32[2] = shareAccess;
        record->Values32[3] = createDisposition;
        record->Values32[4] = createOptions;
        record->Values32[5] = eaLength;
        record->Values32[6] = CopyObjectAttributesName(record->Text0, &record->Text0Length, sizeof(record->Text0), objectAttributes);
        record->Values32[7] = CopyIoStatusBlockText(record->Text1, &record->Text1Length, sizeof(record->Text1), ioStatusBlock);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryWEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryAEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryExWEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    HANDLE file,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryExW, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values32[0] = flags;
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLoadLibraryExAEvent(
    HMODULE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR fileName,
    HANDLE file,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LoadLibraryExA, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(file));
        record->Values32[0] = flags;
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLdrLoadDllEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    PWSTR pathToFile,
    ULONG flags,
    PUNICODE_STRING moduleFileName,
    PHANDLE moduleHandle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LdrLoadDll, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values32[0] = flags;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(moduleHandle));
        HANDLE loadedModule = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(moduleHandle, &loadedModule))
        {
            record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(loadedModule));
        }
        CopyWideText(record->Text0, &record->Text0Length, sizeof(record->Text0), pathToFile);
        record->Values32[1] = CopyUnicodeStringText(record->Text1, &record->Text1Length, sizeof(record->Text1), moduleFileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetProcAddressEvent(
    FARPROC result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HMODULE module,
    LPCSTR procName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetProcAddress, "kernel32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(procName));

        const bool ordinal = IsOrdinalProcName(procName);
        record->Values32[0] = ordinal ? 1 : 0;
        if (ordinal)
        {
            record->Values32[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(procName) & 0xffffu);
            char ordinalText[32] = {};
            std::snprintf(ordinalText, sizeof(ordinalText), "ordinal:%lu", static_cast<unsigned long>(record->Values32[1]));
            CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), ordinalText);
            record->Values32[2] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        }
        else
        {
            record->Values32[2] = CopyAnsiPointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), procName);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLdrGetProcedureAddressEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HMODULE module,
    PANSI_STRING functionName,
    ULONG ordinal,
    PVOID* functionAddress)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LdrGetProcedureAddress, "ntdll.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(functionName));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(functionAddress));
        record->Values32[0] = ordinal;
        record->Values32[1] = CopyAnsiStringText(record->Text0, &record->Text0Length, sizeof(record->Text0), functionName);

        PVOID resolvedAddress = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(functionAddress, &resolvedAddress))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resolvedAddress));
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegOpenKeyExWEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key,
    LPCWSTR subKey,
    DWORD options,
    REGSAM desiredAccess,
    PHKEY resultKey)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegOpenKeyExW, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resultKey));

        HKEY openedKey = nullptr;
        if (result == ERROR_SUCCESS && ReadCurrentProcessValue(resultKey, &openedKey))
        {
            record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(openedKey));
        }

        record->Values32[0] = options;
        record->Values32[1] = desiredAccess;
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), subKey);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegCreateKeyExWEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key,
    LPCWSTR subKey,
    DWORD reserved,
    LPWSTR keyClass,
    DWORD options,
    REGSAM desiredAccess,
    const SECURITY_ATTRIBUTES* securityAttributes,
    PHKEY resultKey,
    LPDWORD disposition)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegCreateKeyExW, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(securityAttributes));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resultKey));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(disposition));

        HKEY createdKey = nullptr;
        if (result == ERROR_SUCCESS && ReadCurrentProcessValue(resultKey, &createdKey))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(createdKey));
        }

        DWORD dispositionValue = 0;
        if (result == ERROR_SUCCESS && ReadCurrentProcessValue(disposition, &dispositionValue))
        {
            record->Values32[3] = dispositionValue;
        }

        record->Values32[0] = reserved;
        record->Values32[1] = options;
        record->Values32[2] = desiredAccess;
        record->Values32[4] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), subKey);
        record->Values32[5] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), keyClass);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegQueryValueExWEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key,
    LPCWSTR valueName,
    LPDWORD reserved,
    LPDWORD valueType,
    LPBYTE data,
    LPDWORD dataBytes)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegQueryValueExW, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(reserved));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(valueType));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(data));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dataBytes));

        DWORD localType = 0;
        if (ReadCurrentProcessValue(valueType, &localType))
        {
            record->Values32[0] = localType;
        }

        DWORD localBytes = 0;
        if (ReadCurrentProcessValue(dataBytes, &localBytes))
        {
            record->Values32[1] = localBytes;
        }

        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), valueName);
        if (result == ERROR_SUCCESS)
        {
            record->Values32[3] = CopyRegistryDataPreviewText(record->Text1, &record->Text1Length, sizeof(record->Text1), localType, data, localBytes);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegSetValueExWEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key,
    LPCWSTR valueName,
    DWORD reserved,
    DWORD valueType,
    const BYTE* data,
    DWORD dataBytes)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegSetValueExW, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        record->Values64[1] = reserved;
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(data));
        record->Values32[0] = valueType;
        record->Values32[1] = dataBytes;
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), valueName);
        record->Values32[3] = CopyRegistryDataPreviewText(record->Text1, &record->Text1Length, sizeof(record->Text1), valueType, data, dataBytes);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegDeleteValueWEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key,
    LPCWSTR valueName)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegDeleteValueW, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        record->Values32[0] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), valueName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRegCloseKeyEvent(
    LSTATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HKEY key)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RegCloseKey, "advapi32.dll", start, end, result == ERROR_SUCCESS ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(key));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitOpenProcessTokenEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process,
    DWORD desiredAccess,
    PHANDLE token)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::OpenProcessToken, "advapi32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(token));

        HANDLE tokenValue = nullptr;
        if (result != FALSE && ReadCurrentProcessValue(token, &tokenValue))
        {
            record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(tokenValue));
        }

        record->Values32[0] = desiredAccess;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitLookupPrivilegeValueWEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR systemName,
    LPCWSTR name,
    PLUID luid)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::LookupPrivilegeValueW, "advapi32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(systemName));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(luid));
        record->Values32[0] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), systemName);
        record->Values32[1] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), name);

        LUID localLuid = {};
        if (result != FALSE && ReadCurrentProcessValue(luid, &localLuid))
        {
            record->Values32[2] = localLuid.LowPart;
            record->Values32[3] = static_cast<std::uint32_t>(localLuid.HighPart);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitBCryptOpenAlgorithmProviderEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    BCRYPT_ALG_HANDLE* algorithm,
    LPCWSTR algorithmId,
    LPCWSTR implementation,
    ULONG flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::BCryptOpenAlgorithmProvider, "bcrypt.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(algorithm));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(algorithmId));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(implementation));
        record->Values32[0] = flags;

        BCRYPT_ALG_HANDLE algorithmValue = nullptr;
        if (NT_SUCCESS(status) && ReadCurrentProcessValue(algorithm, &algorithmValue))
        {
            record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(algorithmValue));
        }

        record->Values32[1] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), algorithmId);
        record->Values32[2] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), implementation);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitBCryptCloseAlgorithmProviderEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    BCRYPT_ALG_HANDLE algorithm,
    ULONG flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::BCryptCloseAlgorithmProvider, "bcrypt.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(algorithm));
        record->Values32[0] = flags;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitBCryptGetPropertyEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    BCRYPT_HANDLE object,
    LPCWSTR property,
    PUCHAR output,
    ULONG outputBytes,
    ULONG* resultBytes,
    ULONG flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::BCryptGetProperty, "bcrypt.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(object));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(property));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(output));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resultBytes));
        record->Values32[0] = outputBytes;
        record->Values32[1] = flags;

        ULONG resultByteCount = 0;
        if (ReadCurrentProcessValue(resultBytes, &resultByteCount))
        {
            record->Values32[2] = resultByteCount;
        }

        record->Values32[3] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), property);
        record->Values32[4] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        if (NT_SUCCESS(status) && std::strcmp(record->Text0, "AlgorithmName") == 0)
        {
            record->Values32[4] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), reinterpret_cast<const wchar_t*>(output));
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitBCryptGenRandomEvent(
    NTSTATUS status,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    BCRYPT_ALG_HANDLE algorithm,
    PUCHAR buffer,
    ULONG bufferBytes,
    ULONG flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::BCryptGenRandom, "bcrypt.dll", start, end, errorCode);
        record->ReturnCode = static_cast<std::uint32_t>(status);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(algorithm));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buffer));
        record->Values32[0] = bufferBytes;
        record->Values32[1] = flags;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCertOpenStoreEvent(
    HCERTSTORE result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCSTR provider,
    DWORD encodingType,
    HCRYPTPROV_LEGACY cryptProvider,
    DWORD flags,
    const void* parameters)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CertOpenStore, "crypt32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(provider));
        record->Values64[1] = static_cast<std::uint64_t>(static_cast<std::uintptr_t>(cryptProvider));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(parameters));
        record->Values32[0] = encodingType;
        record->Values32[1] = flags;
        record->Values32[2] = CopyCertStoreProviderText(record->Text0, &record->Text0Length, sizeof(record->Text0), provider);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCertCloseStoreEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HCERTSTORE store,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CertCloseStore, "crypt32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(store));
        record->Values32[0] = flags;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCryptMsgOpenToDecodeEvent(
    HCRYPTMSG result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    DWORD encodingType,
    DWORD flags,
    DWORD messageType,
    HCRYPTPROV_LEGACY cryptProvider,
    PCERT_INFO recipientInfo,
    PCMSG_STREAM_INFO streamInfo)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CryptMsgOpenToDecode, "crypt32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(static_cast<std::uintptr_t>(cryptProvider));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(recipientInfo));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(streamInfo));
        record->Values32[0] = encodingType;
        record->Values32[1] = flags;
        record->Values32[2] = messageType;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCryptMsgCloseEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HCRYPTMSG message)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CryptMsgClose, "crypt32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(message));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitInternetOpenWEvent(
    HINTERNET result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR agent,
    DWORD accessType,
    LPCWSTR proxy,
    LPCWSTR proxyBypass,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::InternetOpenW, "wininet.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(agent));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(proxy));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(proxyBypass));
        record->Values32[0] = accessType;
        record->Values32[1] = flags;
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), agent);
        record->Values32[3] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), proxy);
        record->Values32[4] = CopyWidePointerText(record->Text2, &record->Text2Length, sizeof(record->Text2), proxyBypass);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitInternetCloseHandleEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HINTERNET internet)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::InternetCloseHandle, "wininet.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(internet));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWinHttpOpenEvent(
    HINTERNET result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR agent,
    DWORD accessType,
    LPCWSTR proxy,
    LPCWSTR proxyBypass,
    DWORD flags)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WinHttpOpen, "winhttp.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(agent));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(proxy));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(proxyBypass));
        record->Values32[0] = accessType;
        record->Values32[1] = flags;
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), agent);
        record->Values32[3] = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), proxy);
        record->Values32[4] = CopyWidePointerText(record->Text2, &record->Text2Length, sizeof(record->Text2), proxyBypass);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWinHttpCloseHandleEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HINTERNET internet)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WinHttpCloseHandle, "winhttp.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(internet));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetSystemMetricsEvent(
    int result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    int index)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetSystemMetrics, "user32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values32[0] = static_cast<std::uint32_t>(index);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetDesktopWindowEvent(
    HWND result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetDesktopWindow, "user32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetForegroundWindowEvent(
    HWND result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetForegroundWindow, "user32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetWindowThreadProcessIdEvent(
    DWORD result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HWND window,
    LPDWORD processId)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetWindowThreadProcessId, "user32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(window));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(processId));
        if (processId != nullptr)
        {
            record->Values32[0] = *processId;
            record->Values32[1] = 1;
        }
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCreateCompatibleDCEvent(
    HDC result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HDC dc)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CreateCompatibleDC, "gdi32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dc));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetDeviceCapsEvent(
    int result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HDC dc,
    int index)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetDeviceCaps, "gdi32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dc));
        record->Values32[0] = static_cast<std::uint32_t>(index);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitDeleteDCEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HDC dc)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::DeleteDC, "gdi32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dc));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitEnumProcessModulesEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process,
    HMODULE* modules,
    DWORD requestedBytes,
    LPDWORD neededBytes)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::EnumProcessModules, "psapi.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(modules));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(neededBytes));
        record->Values32[0] = requestedBytes;

        DWORD localNeededBytes = 0;
        if (result != FALSE && ReadCurrentProcessValue(neededBytes, &localNeededBytes))
        {
            record->Values32[1] = localNeededBytes;
            record->Values32[2] = 1;
        }

        HMODULE firstModule = nullptr;
        if (result != FALSE && requestedBytes >= sizeof(HMODULE) && ReadCurrentProcessValue(modules, &firstModule))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(firstModule));
            record->Values32[3] = 1;
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetModuleInformationEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process,
    HMODULE module,
    LPMODULEINFO moduleInfo,
    DWORD requestedBytes)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetModuleInformation, "psapi.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(moduleInfo));
        record->Values32[0] = requestedBytes;

        MODULEINFO localModuleInfo = {};
        if (result != FALSE && ReadCurrentProcessValue(moduleInfo, &localModuleInfo))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localModuleInfo.lpBaseOfDll));
            record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localModuleInfo.EntryPoint));
            record->Values32[1] = localModuleInfo.SizeOfImage;
            record->Values32[2] = 1;
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetModuleBaseNameWEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process,
    HMODULE module,
    LPWSTR baseName,
    DWORD sizeChars)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetModuleBaseNameW, "psapi.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(baseName));
        record->Values32[0] = sizeChars;
        if (result != 0)
        {
            record->Values32[1] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), baseName);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetModuleFileNameExWEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HANDLE process,
    HMODULE module,
    LPWSTR fileName,
    DWORD sizeChars)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetModuleFileNameExW, "psapi.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fileName));
        record->Values32[0] = sizeChars;
        if (result != 0)
        {
            record->Values32[1] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void SetFormattedTextLength(char* destination, std::uint32_t* length, std::size_t capacity, int written)
{
    if (length != nullptr)
    {
        if (destination == nullptr || capacity == 0 || written < 0)
        {
            *length = 0;
        }
        else if (static_cast<std::size_t>(written) >= capacity)
        {
            *length = static_cast<std::uint32_t>(capacity - 1);
        }
        else
        {
            *length = static_cast<std::uint32_t>(written);
        }
    }
}

void FormatFixedFileInfoText(knmon::KnMonTransportRecord* record, const VS_FIXEDFILEINFO& info)
{
    if (record != nullptr)
    {
        const int fixedVersionWritten = std::snprintf(
            record->Text1,
            sizeof(record->Text1),
            "sig=0x%08lx,fileMS=0x%08lx,fileLS=0x%08lx,prodMS=0x%08lx,prodLS=0x%08lx",
            static_cast<unsigned long>(info.dwSignature),
            static_cast<unsigned long>(info.dwFileVersionMS),
            static_cast<unsigned long>(info.dwFileVersionLS),
            static_cast<unsigned long>(info.dwProductVersionMS),
            static_cast<unsigned long>(info.dwProductVersionLS));
        SetFormattedTextLength(record->Text1, &record->Text1Length, sizeof(record->Text1), fixedVersionWritten);

        const int fixedFlagsWritten = std::snprintf(
            record->Text2,
            sizeof(record->Text2),
            "mask=0x%08lx,flags=0x%08lx,os=0x%08lx,type=0x%08lx,sub=0x%08lx",
            static_cast<unsigned long>(info.dwFileFlagsMask),
            static_cast<unsigned long>(info.dwFileFlags),
            static_cast<unsigned long>(info.dwFileOS),
            static_cast<unsigned long>(info.dwFileType),
            static_cast<unsigned long>(info.dwFileSubtype));
        SetFormattedTextLength(record->Text2, &record->Text2Length, sizeof(record->Text2), fixedFlagsWritten);
    }
}

void FormatTranslationText(knmon::KnMonTransportRecord* record, const VersionTranslation& translation)
{
    if (record != nullptr)
    {
        const int written = std::snprintf(
            record->Text1,
            sizeof(record->Text1),
            "translation=lang=0x%04x,codepage=0x%04x",
            static_cast<unsigned int>(translation.Language),
            static_cast<unsigned int>(translation.CodePage));
        SetFormattedTextLength(record->Text1, &record->Text1Length, sizeof(record->Text1), written);
    }
}

bool GuidEquals(const GUID& left, const GUID& right)
{
    return left.Data1 == right.Data1 &&
        left.Data2 == right.Data2 &&
        left.Data3 == right.Data3 &&
        std::memcmp(left.Data4, right.Data4, sizeof(left.Data4)) == 0;
}

KnownFolderIdentity ClassifyKnownFolderId(const GUID& value)
{
    KnownFolderIdentity result = { "UNKNOWN", 0, false };

    if (GuidEquals(value, FolderIdWindows))
    {
        result = { "FOLDERID_Windows", 1, true };
    }
    else if (GuidEquals(value, FolderIdSystem))
    {
        result = { "FOLDERID_System", 2, true };
    }
    else if (GuidEquals(value, FolderIdProgramFiles))
    {
        result = { "FOLDERID_ProgramFiles", 3, true };
    }
    else if (GuidEquals(value, FolderIdFonts))
    {
        result = { "FOLDERID_Fonts", 4, false };
    }

    return result;
}

int BaseCsidlValue(int csidl)
{
    return csidl & 0x00ff;
}

KnownFolderIdentity ClassifyCsidlValue(int csidl)
{
    KnownFolderIdentity result = { "CSIDL_UNKNOWN", 0, false };
    const int baseCsidl = BaseCsidlValue(csidl);

    switch (baseCsidl)
    {
    case CSIDL_WINDOWS:
        result = { "CSIDL_WINDOWS", 1, true };
        break;
    case CSIDL_SYSTEM:
        result = { "CSIDL_SYSTEM", 2, true };
        break;
    case CSIDL_PROGRAM_FILES:
        result = { "CSIDL_PROGRAM_FILES", 3, true };
        break;
    case CSIDL_FONTS:
        result = { "CSIDL_FONTS", 4, false };
        break;
    default:
        break;
    }

    return result;
}

const char* ShellFolderPathStatusText(std::uint32_t value)
{
    const char* result = "none";

    switch (static_cast<ShellFolderPathStatus>(value))
    {
    case ShellFolderPathStatus::DecodedSafePath:
        result = "decoded_safe_path";
        break;
    case ShellFolderPathStatus::NonAllowlistedNoPath:
        result = "non_allowlisted_no_path";
        break;
    case ShellFolderPathStatus::DecodeFailed:
        result = "decode_failed";
        break;
    case ShellFolderPathStatus::None:
    default:
        result = "none";
        break;
    }

    return result;
}

void FormatGuidText(char* destination, std::uint32_t* length, std::size_t capacity, const GUID& value, const char* name)
{
    if (length != nullptr)
    {
        *length = 0;
    }

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        const int written = std::snprintf(
            destination,
            capacity,
            "%s={%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            name == nullptr ? "GUID" : name,
            static_cast<unsigned long>(value.Data1),
            static_cast<unsigned int>(value.Data2),
            static_cast<unsigned int>(value.Data3),
            static_cast<unsigned int>(value.Data4[0]),
            static_cast<unsigned int>(value.Data4[1]),
            static_cast<unsigned int>(value.Data4[2]),
            static_cast<unsigned int>(value.Data4[3]),
            static_cast<unsigned int>(value.Data4[4]),
            static_cast<unsigned int>(value.Data4[5]),
            static_cast<unsigned int>(value.Data4[6]),
            static_cast<unsigned int>(value.Data4[7]));
        SetFormattedTextLength(destination, length, capacity, written);
    }
    while (false);
}

bool IsHexTextChar(char value)
{
    return
        (value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'f') ||
        (value >= 'A' && value <= 'F');
}

bool IsCanonicalGuidStringText(const char* value)
{
    bool result = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        if (std::strlen(value) != 38)
        {
            break;
        }

        if (value[0] != '{' || value[9] != '-' || value[14] != '-' || value[19] != '-' || value[24] != '-' || value[37] != '}')
        {
            break;
        }

        result = true;
        for (std::size_t index = 1; index < 37; ++index)
        {
            if (index == 9 || index == 14 || index == 19 || index == 24)
            {
                continue;
            }

            if (!IsHexTextChar(value[index]))
            {
                result = false;
                break;
            }
        }
    }
    while (false);

    return result;
}

bool IsCanonicalUuidStringText(const char* value)
{
    bool result = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        if (std::strlen(value) != 36)
        {
            break;
        }

        if (value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-')
        {
            break;
        }

        result = true;
        for (std::size_t index = 0; index < 36; ++index)
        {
            if (index == 8 || index == 13 || index == 18 || index == 23)
            {
                continue;
            }

            if (!IsHexTextChar(value[index]))
            {
                result = false;
                break;
            }
        }
    }
    while (false);

    return result;
}

std::uint32_t CopyGuidStringPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const wchar_t* source, int cchMax)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (length != nullptr)
        {
            *length = 0;
        }

        if (source == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        if (cchMax <= 0 || cchMax > MaxGuidStringChars)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        status = CopyWidePointerText(destination, length, capacity, source);
        if (status != static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            break;
        }

        if (!IsCanonicalGuidStringText(destination))
        {
            destination[0] = '\0';
            if (length != nullptr)
            {
                *length = 0;
            }

            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
        }
    }
    while (false);

    return status;
}

std::uint32_t CopyUuidStringPointerText(char* destination, std::uint32_t* length, std::size_t capacity, const wchar_t* source)
{
    std::uint32_t status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Truncated);
            break;
        }

        destination[0] = '\0';
        if (length != nullptr)
        {
            *length = 0;
        }

        if (source == nullptr)
        {
            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer);
            break;
        }

        status = CopyWidePointerText(destination, length, capacity, source);
        if (status != static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded))
        {
            break;
        }

        if (!IsCanonicalUuidStringText(destination))
        {
            destination[0] = '\0';
            if (length != nullptr)
            {
                *length = 0;
            }

            status = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);
        }
    }
    while (false);

    return status;
}

void FormatCsidlText(char* destination, std::uint32_t* length, std::size_t capacity, int csidl, const char* name)
{
    if (length != nullptr)
    {
        *length = 0;
    }

    do
    {
        if (destination == nullptr || capacity == 0)
        {
            break;
        }

        destination[0] = '\0';
        const int written = std::snprintf(
            destination,
            capacity,
            "%s(%d)",
            name == nullptr ? "CSIDL_UNKNOWN" : name,
            BaseCsidlValue(csidl));
        SetFormattedTextLength(destination, length, capacity, written);
    }
    while (false);
}

void EmitGetFileVersionInfoSizeWEvent(
    DWORD result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    LPDWORD handle)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetFileVersionInfoSizeW, "version.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fileName));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);

        DWORD localHandle = 0;
        if (ReadCurrentProcessValue(handle, &localHandle))
        {
            record->Values32[0] = localHandle;
            record->Values32[1] = 1;
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetFileVersionInfoWEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCWSTR fileName,
    DWORD handle,
    DWORD length,
    LPVOID data)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetFileVersionInfoW, "version.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fileName));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(data));
        record->Values32[0] = handle;
        record->Values32[1] = length;
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), fileName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitVerQueryValueWEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPCVOID block,
    LPCWSTR subBlock,
    LPVOID* value,
    PUINT length)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::VerQueryValueW, "version.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(block));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(subBlock));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(value));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(length));
        record->Values32[2] = CopyWidePointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), subBlock);

        UINT localLength = 0;
        if (result != FALSE && ReadCurrentProcessValue(length, &localLength))
        {
            record->Values32[0] = localLength;
            record->Values32[1] = 1;
        }

        LPVOID localValue = nullptr;
        if (result != FALSE && ReadCurrentProcessValue(value, &localValue))
        {
            record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localValue));
            record->Values32[4] = 1;
        }

        if (result != FALSE && record->Values32[4] != 0 && std::strcmp(record->Text0, "\\") == 0 && localLength >= sizeof(VS_FIXEDFILEINFO))
        {
            VS_FIXEDFILEINFO localInfo = {};
            if (ReadCurrentProcessValue(static_cast<const VS_FIXEDFILEINFO*>(localValue), &localInfo))
            {
                record->Values32[3] = 1;
                FormatFixedFileInfoText(record, localInfo);
            }
        }
        else if (
            result != FALSE &&
            record->Values32[4] != 0 &&
            _stricmp(record->Text0, "\\VarFileInfo\\Translation") == 0 &&
            localLength >= sizeof(VersionTranslation))
        {
            VersionTranslation translation = {};
            if (ReadCurrentProcessValue(static_cast<const VersionTranslation*>(localValue), &translation))
            {
                record->Values32[3] = 2;
                record->Values32[5] = translation.Language;
                record->Values32[6] = translation.CodePage;
                FormatTranslationText(record, translation);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitSHGetKnownFolderPathEvent(
    HRESULT result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    REFKNOWNFOLDERID knownFolderId,
    DWORD flags,
    HANDLE token,
    PWSTR* path)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        const KnownFolderIdentity identity = ClassifyKnownFolderId(knownFolderId);
        FillTransportCommon(record, knmon::KnMonTransportApiId::SHGetKnownFolderPath, "shell32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->ReturnCode = static_cast<std::uint32_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&knownFolderId));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(token));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(path));
        record->Values32[0] = flags;
        record->Values32[1] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        record->Values32[2] = static_cast<std::uint32_t>(ShellFolderPathStatus::None);
        record->Values32[3] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        record->Values32[4] = identity.Code;
        FormatGuidText(record->Text0, &record->Text0Length, sizeof(record->Text0), knownFolderId, identity.Name);

        PWSTR localPath = nullptr;
        if (SUCCEEDED(result) && ReadCurrentProcessValue(path, &localPath))
        {
            record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localPath));
        }

        if (SUCCEEDED(result) && identity.AllowPath && record->Values64[3] != 0)
        {
            const std::uint32_t pathStatus = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), localPath);
            record->Values32[3] = pathStatus;
            record->Values32[2] = pathStatus == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded) ?
                static_cast<std::uint32_t>(ShellFolderPathStatus::DecodedSafePath) :
                static_cast<std::uint32_t>(ShellFolderPathStatus::DecodeFailed);
        }
        else if (!identity.AllowPath)
        {
            record->Values32[2] = static_cast<std::uint32_t>(ShellFolderPathStatus::NonAllowlistedNoPath);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitSHGetSpecialFolderPathWEvent(
    BOOL result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    HWND window,
    LPWSTR path,
    int csidl,
    BOOL create)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        const KnownFolderIdentity identity = ClassifyCsidlValue(csidl);
        FillTransportCommon(record, knmon::KnMonTransportApiId::SHGetSpecialFolderPathW, "shell32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(window));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(path));
        record->Values32[0] = static_cast<std::uint32_t>(csidl);
        record->Values32[1] = static_cast<std::uint32_t>(create);
        record->Values32[2] = static_cast<std::uint32_t>(BaseCsidlValue(csidl));
        record->Values32[3] = static_cast<std::uint32_t>(ShellFolderPathStatus::None);
        record->Values32[4] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        record->Values32[5] = identity.Code;
        FormatCsidlText(record->Text0, &record->Text0Length, sizeof(record->Text0), csidl, identity.Name);

        if (result != FALSE && identity.AllowPath)
        {
            const std::uint32_t pathStatus = CopyWidePointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), path);
            record->Values32[4] = pathStatus;
            record->Values32[3] = pathStatus == static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded) ?
                static_cast<std::uint32_t>(ShellFolderPathStatus::DecodedSafePath) :
                static_cast<std::uint32_t>(ShellFolderPathStatus::DecodeFailed);
        }
        else if (!identity.AllowPath)
        {
            record->Values32[3] = static_cast<std::uint32_t>(ShellFolderPathStatus::NonAllowlistedNoPath);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCoInitializeExEvent(
    HRESULT result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    LPVOID reserved,
    DWORD coInit)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CoInitializeEx, "ole32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->ReturnCode = static_cast<std::uint32_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(reserved));
        record->Values32[0] = coInit;
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCoUninitializeEvent(
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CoUninitialize, "ole32.dll", start, end, 0);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitCoCreateGuidEvent(
    HRESULT result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    GUID* guid)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::CoCreateGuid, "ole32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->ReturnCode = static_cast<std::uint32_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(guid));
        record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

        if (SUCCEEDED(result))
        {
            GUID localGuid = {};
            if (ReadCurrentProcessValue(guid, &localGuid))
            {
                FormatGuidText(record->Text0, &record->Text0Length, sizeof(record->Text0), localGuid, "GUID");
            }
            else
            {
                record->Values32[0] = guid == nullptr ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitStringFromGUID2Event(
    int result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    REFGUID guid,
    LPOLESTR string,
    int cchMax)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::StringFromGUID2, "ole32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guid));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(string));
        record->Values32[0] = static_cast<std::uint32_t>(cchMax);
        record->Values32[1] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        record->Values32[2] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
        FormatGuidText(record->Text0, &record->Text0Length, sizeof(record->Text0), guid, "GUID");

        if (result > 0)
        {
            record->Values32[2] = CopyGuidStringPointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), string, cchMax);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRoInitializeEvent(
    HRESULT result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RO_INIT_TYPE initType)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RoInitialize, "api-ms-win-core-winrt-l1-1-0.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->ReturnCode = static_cast<std::uint32_t>(result);
        record->Values32[0] = static_cast<std::uint32_t>(initType);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRoUninitializeEvent(
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RoUninitialize, "api-ms-win-core-winrt-l1-1-0.dll", start, end, 0);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRoGetApartmentIdentifierEvent(
    HRESULT result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    UINT64* apartmentIdentifier)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RoGetApartmentIdentifier, "api-ms-win-core-winrt-l1-1-0.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->ReturnCode = static_cast<std::uint32_t>(result);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(apartmentIdentifier));
        record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (SUCCEEDED(result))
        {
            UINT64 localIdentifier = 0;
            if (ReadCurrentProcessValue(apartmentIdentifier, &localIdentifier))
            {
                record->Values64[1] = static_cast<std::uint64_t>(localIdentifier);
                record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            }
            else
            {
                record->Values32[0] = apartmentIdentifier == nullptr ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

std::uint32_t CopyRpcWideStringText(char* destination, std::uint32_t* length, std::size_t capacity, RPC_WSTR source)
{
    return CopyWidePointerText(destination, length, capacity, reinterpret_cast<const wchar_t*>(source));
}

bool RpcStatusProducedUuid(RPC_STATUS result)
{
    return result == RPC_S_OK || result == RPC_S_UUID_LOCAL_ONLY;
}

void EmitRpcStringBindingComposeWEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RPC_WSTR objUuid,
    RPC_WSTR protSeq,
    RPC_WSTR networkAddr,
    RPC_WSTR endpoint,
    RPC_WSTR options,
    RPC_WSTR* stringBinding)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RpcStringBindingComposeW, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(objUuid));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(protSeq));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(networkAddr));
        record->Values64[3] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(endpoint));
        record->Values64[4] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(options));
        record->Values64[5] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(stringBinding));

        RPC_WSTR composedBinding = nullptr;
        if (result == RPC_S_OK && ReadCurrentProcessValue(stringBinding, &composedBinding))
        {
            record->Values64[6] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(composedBinding));
        }

        record->Values32[0] = CopyRpcWideStringText(record->Text0, &record->Text0Length, sizeof(record->Text0), composedBinding);
        record->Values32[1] = CopyRpcWideStringText(record->Text1, &record->Text1Length, sizeof(record->Text1), protSeq);
        record->Values32[2] = CopyRpcWideStringText(record->Text2, &record->Text2Length, sizeof(record->Text2), endpoint);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRpcBindingFromStringBindingWEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RPC_WSTR stringBinding,
    RPC_BINDING_HANDLE* binding)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RpcBindingFromStringBindingW, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(stringBinding));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(binding));

        RPC_BINDING_HANDLE bindingValue = nullptr;
        if (result == RPC_S_OK && ReadCurrentProcessValue(binding, &bindingValue))
        {
            record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(bindingValue));
        }

        record->Values32[0] = CopyRpcWideStringText(record->Text0, &record->Text0Length, sizeof(record->Text0), stringBinding);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRpcStringFreeWEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RPC_WSTR* string,
    RPC_WSTR preString,
    RPC_WSTR postString,
    const char* preStringText,
    std::uint32_t preStringTextStatus)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RpcStringFreeW, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(string));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(preString));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(postString));
        record->Values32[0] = preStringTextStatus;
        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), preStringText);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitRpcBindingFreeEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RPC_BINDING_HANDLE* binding,
    RPC_BINDING_HANDLE preBinding,
    RPC_BINDING_HANDLE postBinding)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::RpcBindingFree, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(binding));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(preBinding));
        record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(postBinding));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitUuidCreateEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    UUID* uuid)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::UuidCreate, "rpcrt4.dll", start, end, RpcStatusProducedUuid(result) ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(uuid));
        record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (RpcStatusProducedUuid(result))
        {
            UUID localUuid = {};
            if (ReadCurrentProcessValue(uuid, &localUuid))
            {
                record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
                FormatGuidText(record->Text0, &record->Text0Length, sizeof(record->Text0), localUuid, "UUID");
            }
            else
            {
                record->Values32[0] = uuid == nullptr ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitUuidToStringWEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    UUID* uuid,
    RPC_WSTR* stringUuid)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::UuidToStringW, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(uuid));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(stringUuid));
        record->Values32[0] = uuid == nullptr ?
            static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
            static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
        record->Values32[1] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        UUID localUuid = {};
        if (ReadCurrentProcessValue(uuid, &localUuid))
        {
            record->Values32[0] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
            FormatGuidText(record->Text0, &record->Text0Length, sizeof(record->Text0), localUuid, "UUID");
        }

        RPC_WSTR localString = nullptr;
        if (result == RPC_S_OK)
        {
            if (ReadCurrentProcessValue(stringUuid, &localString))
            {
                record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(localString));
                record->Values32[1] = CopyUuidStringPointerText(record->Text1, &record->Text1Length, sizeof(record->Text1), reinterpret_cast<const wchar_t*>(localString));
            }
            else
            {
                record->Values32[1] = stringUuid == nullptr ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitUuidFromStringWEvent(
    RPC_STATUS result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    RPC_WSTR stringUuid,
    UUID* uuid)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::UuidFromStringW, "rpcrt4.dll", start, end, result == RPC_S_OK ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(stringUuid));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(uuid));
        record->Values32[0] = CopyUuidStringPointerText(record->Text0, &record->Text0Length, sizeof(record->Text0), reinterpret_cast<const wchar_t*>(stringUuid));
        record->Values32[1] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Partial);

        if (result == RPC_S_OK)
        {
            UUID localUuid = {};
            if (ReadCurrentProcessValue(uuid, &localUuid))
            {
                record->Values32[1] = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);
                FormatGuidText(record->Text1, &record->Text1Length, sizeof(record->Text1), localUuid, "UUID");
            }
            else
            {
                record->Values32[1] = uuid == nullptr ?
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
                    static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
            }
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWSAStartupEvent(
    int result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    WORD versionRequested,
    LPWSADATA data)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WSAStartup, "ws2_32.dll", start, end, result == 0 ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values32[0] = versionRequested;
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(data));

        WSADATA localData = {};
        if (result == 0 && ReadCurrentProcessValue(data, &localData))
        {
            CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), localData.szDescription);
            CopyAsciiText(record->Text1, &record->Text1Length, sizeof(record->Text1), localData.szSystemStatus);
        }

        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWSACleanupEvent(
    int result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WSACleanup, "ws2_32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitSocketEvent(
    SOCKET result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    int af,
    int type,
    int protocol)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::Socket, "ws2_32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uintptr_t>(result));
        record->Values32[0] = static_cast<std::uint32_t>(af);
        record->Values32[1] = static_cast<std::uint32_t>(type);
        record->Values32[2] = static_cast<std::uint32_t>(protocol);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitClosesocketEvent(
    int result,
    DWORD errorCode,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    SOCKET socketValue)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::Closesocket, "ws2_32.dll", start, end, errorCode);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(static_cast<std::uintptr_t>(socketValue));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitGetAddrInfoEvent(
    int result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    PCSTR nodeName,
    PCSTR serviceName,
    const ADDRINFOA* hints,
    PADDRINFOA* resolved)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::GetAddrInfo, "ws2_32.dll", start, end, result == 0 ? 0 : static_cast<DWORD>(result));
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(hints));
        record->Values64[1] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resolved));

        PADDRINFOA resolvedValue = nullptr;
        if (result == 0 && ReadCurrentProcessValue(resolved, &resolvedValue))
        {
            record->Values64[2] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(resolvedValue));
        }

        ADDRINFOA localHints = {};
        if (ReadCurrentProcessValue(hints, &localHints))
        {
            record->Values32[0] = static_cast<std::uint32_t>(localHints.ai_family);
            record->Values32[1] = static_cast<std::uint32_t>(localHints.ai_socktype);
            record->Values32[2] = static_cast<std::uint32_t>(localHints.ai_protocol);
        }

        CopyAsciiText(record->Text0, &record->Text0Length, sizeof(record->Text0), nodeName);
        CopyAsciiText(record->Text1, &record->Text1Length, sizeof(record->Text1), serviceName);
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitFreeAddrInfoEvent(
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end,
    PADDRINFOA addrInfo)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::FreeAddrInfo, "ws2_32.dll", start, end, 0);
        record->Values64[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(addrInfo));
        CommitTransportRecord(record, overheadStart);
    }
}

void EmitWSAGetLastErrorEvent(
    int result,
    const LARGE_INTEGER& start,
    const LARGE_INTEGER& end)
{
    LARGE_INTEGER overheadStart = {};
    QueryPerformanceCounter(&overheadStart);
    knmon::KnMonTransportRecord* record = ReserveTransportRecord();
    if (record != nullptr)
    {
        FillTransportCommon(record, knmon::KnMonTransportApiId::WSAGetLastError, "ws2_32.dll", start, end, 0);
        record->ReturnValue = static_cast<std::uint64_t>(static_cast<std::uint32_t>(result));
        CommitTransportRecord(record, overheadStart);
    }
}

void* ResolveExport(const char* moduleName, const char* name)
{
    void* result = nullptr;

    do
    {
        HMODULE module = GetModuleHandleA(moduleName);
        if (module == nullptr)
        {
            break;
        }

        result = reinterpret_cast<void*>(GetProcAddress(module, name));
    }
    while (false);

    return result;
}

KnMonPeb* CurrentPeb()
{
#if defined(_M_X64)
    return reinterpret_cast<KnMonPeb*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<KnMonPeb*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

bool ImageRangeContains(const std::uint8_t* base, std::uint32_t size, const void* address, std::size_t bytes)
{
    bool contains = false;

    do
    {
        if (base == nullptr || address == nullptr || size == 0)
        {
            break;
        }

        const auto* current = static_cast<const std::uint8_t*>(address);
        if (current < base)
        {
            break;
        }

        const std::uintptr_t offset = static_cast<std::uintptr_t>(current - base);
        if (offset > size)
        {
            break;
        }

        contains = bytes <= (static_cast<std::size_t>(size) - static_cast<std::size_t>(offset));
    }
    while (false);

    return contains;
}

template <typename T>
T* ImageRvaToPointer(std::uint8_t* base, std::uint32_t size, DWORD rva, std::size_t minBytes = sizeof(T))
{
    T* result = nullptr;

    do
    {
        if (base == nullptr || rva == 0 || rva >= size)
        {
            break;
        }

        auto* pointer = reinterpret_cast<T*>(base + rva);
        if (!ImageRangeContains(base, size, pointer, minBytes))
        {
            break;
        }

        result = pointer;
    }
    while (false);

    return result;
}

bool ReadImageImportDirectory(HMODULE module, std::uint32_t size, IMAGE_IMPORT_DESCRIPTOR** imports)
{
    bool present = false;

    do
    {
        if (module == nullptr || imports == nullptr)
        {
            break;
        }

        *imports = nullptr;
        auto* base = reinterpret_cast<std::uint8_t*>(module);
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!ImageRangeContains(base, size, dosHeader, sizeof(*dosHeader)) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        if (dosHeader->e_lfanew <= 0 || static_cast<std::uint32_t>(dosHeader->e_lfanew) >= size)
        {
            break;
        }

        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (!ImageRangeContains(base, size, ntHeaders, sizeof(*ntHeaders)) || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }

        const IMAGE_DATA_DIRECTORY& importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0 || importDirectory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            break;
        }

        auto* importDescriptor = ImageRvaToPointer<IMAGE_IMPORT_DESCRIPTOR>(
            base,
            size,
            importDirectory.VirtualAddress,
            sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (importDescriptor == nullptr)
        {
            break;
        }

        *imports = importDescriptor;
        present = true;
    }
    while (false);

    return present;
}

bool ModuleHasImports(HMODULE module, std::uint32_t size)
{
    IMAGE_IMPORT_DESCRIPTOR* imports = nullptr;
    return ReadImageImportDirectory(module, size, &imports);
}

std::size_t CaptureModuleSnapshot(std::array<ModuleInfo, MaxModuleRecords>& modules, SweepStats* stats)
{
    std::size_t count = 0;

    do
    {
        KnMonPeb* peb = CurrentPeb();
        if (peb == nullptr || peb->Ldr == nullptr)
        {
            break;
        }

        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* current = head->Flink;
        while (current != nullptr && current != head && count < modules.size())
        {
            auto* entry = CONTAINING_RECORD(current, KnMonLdrDataTableEntry, InMemoryOrderLinks);
            current = current->Flink;

            if (entry == nullptr || entry->DllBase == nullptr)
            {
                continue;
            }

            ModuleInfo& module = modules[count];
            module = {};
            module.Base = static_cast<HMODULE>(entry->DllBase);
            module.SizeOfImage = entry->SizeOfImage;
            CopyWideCountText(module.FullPath, sizeof(module.FullPath), entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));
            CopyWideCountText(module.Name, sizeof(module.Name), entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
            if (module.Name[0] == '\0')
            {
                CopyAsciiText(module.Name, nullptr, sizeof(module.Name), FileNameFromPathText(module.FullPath));
            }

            LowerAsciiInPlace(module.Name);
            LowerAsciiInPlace(module.FullPath);
            module.IsAgent = module.Base == g_agentModule || std::strcmp(module.Name, KNMON_AGENT_DLL_NAME) == 0;
            module.IsSystem = IsWindowsSystemModule(module);
            module.HasImports = ModuleHasImports(module.Base, module.SizeOfImage);
            module.Eligible = !module.IsAgent && !module.IsSystem && module.HasImports;

            if (stats != nullptr)
            {
                ++stats->ScannedModules;
                if (module.Eligible)
                {
                    ++stats->EligibleModules;
                }
                else
                {
                    ++stats->SkippedModules;
                }
            }

            ++count;
        }
    }
    while (false);

    return count;
}

HookRecord* FindHookRecordByThunkNoLock(ULONG_PTR* thunkAddress)
{
    HookRecord* result = nullptr;

    if (thunkAddress != nullptr)
    {
        for (std::size_t index = 0; index < g_hookRecordCount; ++index)
        {
            if (g_hookRecords[index].ThunkAddress == thunkAddress)
            {
                result = &g_hookRecords[index];
                break;
            }
        }
    }

    return result;
}

bool AppendHookRecordNoLock(
    const ModuleInfo& ownerModule,
    const char* importModuleName,
    const char* apiName,
    ULONG_PTR* thunkAddress,
    void* originalFunction,
    void* replacementFunction,
    bool* duplicate)
{
    bool appended = false;

    do
    {
        if (duplicate != nullptr)
        {
            *duplicate = false;
        }

        if (FindHookRecordByThunkNoLock(thunkAddress) != nullptr)
        {
            if (duplicate != nullptr)
            {
                *duplicate = true;
            }
            break;
        }

        if (g_hookRecordCount >= g_hookRecords.size())
        {
            break;
        }

        HookRecord& record = g_hookRecords[g_hookRecordCount];
        CopyAsciiText(record.ApiName, nullptr, sizeof(record.ApiName), apiName);
        CopyAsciiText(record.ImportModuleName, nullptr, sizeof(record.ImportModuleName), importModuleName);
        CopyAsciiText(record.OwnerModuleName, nullptr, sizeof(record.OwnerModuleName), ownerModule.Name);
        record.OwnerModule = ownerModule.Base;
        record.ThunkAddress = thunkAddress;
        record.OriginalFunction = originalFunction;
        record.ReplacementFunction = replacementFunction;
        record.Installed = true;
        record.Restored = false;
        record.Failed = false;
        ++g_hookRecordCount;
        appended = true;
    }
    while (false);

    return appended;
}

HANDLE WINAPI HookedCreateFileW(LPCWSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile);
HANDLE WINAPI HookedCreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile);
BOOL WINAPI HookedReadFile(HANDLE file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped);
BOOL WINAPI HookedWriteFile(HANDLE file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten, LPOVERLAPPED overlapped);
BOOL WINAPI HookedCloseHandle(HANDLE handle);
LPVOID WINAPI HookedVirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
BOOL WINAPI HookedVirtualFree(LPVOID address, SIZE_T size, DWORD freeType);
BOOL WINAPI HookedVirtualProtect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
SIZE_T WINAPI HookedVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
HANDLE WINAPI HookedCreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES mappingAttributes, DWORD protect, DWORD maximumSizeHigh, DWORD maximumSizeLow, LPCWSTR name);
HANDLE WINAPI HookedOpenFileMappingW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
LPVOID WINAPI HookedMapViewOfFile(HANDLE mapping, DWORD desiredAccess, DWORD fileOffsetHigh, DWORD fileOffsetLow, SIZE_T bytesToMap);
BOOL WINAPI HookedUnmapViewOfFile(LPCVOID baseAddress);
HANDLE WINAPI HookedGetCurrentProcess();
DWORD WINAPI HookedGetCurrentProcessId();
HANDLE WINAPI HookedGetCurrentThread();
DWORD WINAPI HookedGetCurrentThreadId();
DWORD WINAPI HookedGetProcessId(HANDLE process);
DWORD WINAPI HookedGetThreadId(HANDLE thread);
HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES threadAttributes, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameter, DWORD creationFlags, LPDWORD threadId);
HANDLE WINAPI HookedOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
DWORD WINAPI HookedWaitForSingleObject(HANDLE handle, DWORD milliseconds);
BOOL WINAPI HookedGetExitCodeThread(HANDLE thread, LPDWORD exitCode);
HANDLE WINAPI HookedCreateEventW(LPSECURITY_ATTRIBUTES eventAttributes, BOOL manualReset, BOOL initialState, LPCWSTR name);
HANDLE WINAPI HookedOpenEventW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
BOOL WINAPI HookedSetEvent(HANDLE eventHandle);
BOOL WINAPI HookedResetEvent(HANDLE eventHandle);
DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable);
HANDLE WINAPI HookedCreateMutexW(LPSECURITY_ATTRIBUTES mutexAttributes, BOOL initialOwner, LPCWSTR name);
HANDLE WINAPI HookedOpenMutexW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
BOOL WINAPI HookedReleaseMutex(HANDLE mutexHandle);
HANDLE WINAPI HookedCreateSemaphoreW(LPSECURITY_ATTRIBUTES semaphoreAttributes, LONG initialCount, LONG maximumCount, LPCWSTR name);
HANDLE WINAPI HookedOpenSemaphoreW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name);
BOOL WINAPI HookedReleaseSemaphore(HANDLE semaphoreHandle, LONG releaseCount, LPLONG previousCount);
DWORD WINAPI HookedWaitForMultipleObjectsEx(DWORD count, const HANDLE* handles, BOOL waitAll, DWORD milliseconds, BOOL alertable);
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR fileName);
HMODULE WINAPI HookedLoadLibraryA(LPCSTR fileName);
HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags);
HMODULE WINAPI HookedLoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags);
FARPROC WINAPI HookedGetProcAddress(HMODULE module, LPCSTR procName);
LSTATUS WINAPI HookedRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options, REGSAM desiredAccess, PHKEY resultKey);
LSTATUS WINAPI HookedRegCreateKeyExW(HKEY key, LPCWSTR subKey, DWORD reserved, LPWSTR keyClass, DWORD options, REGSAM desiredAccess, const SECURITY_ATTRIBUTES* securityAttributes, PHKEY resultKey, LPDWORD disposition);
LSTATUS WINAPI HookedRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD valueType, LPBYTE data, LPDWORD dataBytes);
LSTATUS WINAPI HookedRegSetValueExW(HKEY key, LPCWSTR valueName, DWORD reserved, DWORD valueType, const BYTE* data, DWORD dataBytes);
LSTATUS WINAPI HookedRegDeleteValueW(HKEY key, LPCWSTR valueName);
LSTATUS WINAPI HookedRegCloseKey(HKEY key);
BOOL WINAPI HookedOpenProcessToken(HANDLE process, DWORD desiredAccess, PHANDLE token);
BOOL WINAPI HookedLookupPrivilegeValueW(LPCWSTR systemName, LPCWSTR name, PLUID luid);
NTSTATUS WINAPI HookedBCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* algorithm, LPCWSTR algorithmId, LPCWSTR implementation, ULONG flags);
NTSTATUS WINAPI HookedBCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE algorithm, ULONG flags);
NTSTATUS WINAPI HookedBCryptGetProperty(BCRYPT_HANDLE object, LPCWSTR property, PUCHAR output, ULONG outputBytes, ULONG* resultBytes, ULONG flags);
NTSTATUS WINAPI HookedBCryptGenRandom(BCRYPT_ALG_HANDLE algorithm, PUCHAR buffer, ULONG bufferBytes, ULONG flags);
HCERTSTORE WINAPI HookedCertOpenStore(LPCSTR provider, DWORD encodingType, HCRYPTPROV_LEGACY cryptProvider, DWORD flags, const void* parameters);
BOOL WINAPI HookedCertCloseStore(HCERTSTORE store, DWORD flags);
HCRYPTMSG WINAPI HookedCryptMsgOpenToDecode(DWORD encodingType, DWORD flags, DWORD messageType, HCRYPTPROV_LEGACY cryptProvider, PCERT_INFO recipientInfo, PCMSG_STREAM_INFO streamInfo);
BOOL WINAPI HookedCryptMsgClose(HCRYPTMSG message);
HINTERNET WINAPI HookedInternetOpenW(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR proxyBypass, DWORD flags);
BOOL WINAPI HookedInternetCloseHandle(HINTERNET internet);
HINTERNET WINAPI HookedWinHttpOpen(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR proxyBypass, DWORD flags);
BOOL WINAPI HookedWinHttpCloseHandle(HINTERNET internet);
int WINAPI HookedGetSystemMetrics(int index);
HWND WINAPI HookedGetDesktopWindow();
HWND WINAPI HookedGetForegroundWindow();
DWORD WINAPI HookedGetWindowThreadProcessId(HWND window, LPDWORD processId);
HDC WINAPI HookedCreateCompatibleDC(HDC dc);
int WINAPI HookedGetDeviceCaps(HDC dc, int index);
BOOL WINAPI HookedDeleteDC(HDC dc);
BOOL WINAPI HookedEnumProcessModules(HANDLE process, HMODULE* modules, DWORD requestedBytes, LPDWORD neededBytes);
BOOL WINAPI HookedGetModuleInformation(HANDLE process, HMODULE module, LPMODULEINFO moduleInfo, DWORD requestedBytes);
DWORD WINAPI HookedGetModuleBaseNameW(HANDLE process, HMODULE module, LPWSTR baseName, DWORD sizeChars);
DWORD WINAPI HookedGetModuleFileNameExW(HANDLE process, HMODULE module, LPWSTR fileName, DWORD sizeChars);
DWORD WINAPI HookedGetFileVersionInfoSizeW(LPCWSTR fileName, LPDWORD handle);
BOOL WINAPI HookedGetFileVersionInfoW(LPCWSTR fileName, DWORD handle, DWORD length, LPVOID data);
BOOL WINAPI HookedVerQueryValueW(LPCVOID block, LPCWSTR subBlock, LPVOID* value, PUINT length);
HRESULT WINAPI HookedSHGetKnownFolderPath(REFKNOWNFOLDERID knownFolderId, DWORD flags, HANDLE token, PWSTR* path);
BOOL WINAPI HookedSHGetSpecialFolderPathW(HWND window, LPWSTR path, int csidl, BOOL create);
HRESULT WINAPI HookedCoInitializeEx(LPVOID reserved, DWORD coInit);
void WINAPI HookedCoUninitialize();
HRESULT WINAPI HookedCoCreateGuid(GUID* guid);
int WINAPI HookedStringFromGUID2(REFGUID guid, LPOLESTR string, int cchMax);
HRESULT WINAPI HookedRoInitialize(RO_INIT_TYPE initType);
void WINAPI HookedRoUninitialize();
HRESULT WINAPI HookedRoGetApartmentIdentifier(UINT64* apartmentIdentifier);
RPC_STATUS RPC_ENTRY HookedRpcStringBindingComposeW(RPC_WSTR objUuid, RPC_WSTR protSeq, RPC_WSTR networkAddr, RPC_WSTR endpoint, RPC_WSTR options, RPC_WSTR* stringBinding);
RPC_STATUS RPC_ENTRY HookedRpcBindingFromStringBindingW(RPC_WSTR stringBinding, RPC_BINDING_HANDLE* binding);
RPC_STATUS RPC_ENTRY HookedRpcStringFreeW(RPC_WSTR* string);
RPC_STATUS RPC_ENTRY HookedRpcBindingFree(RPC_BINDING_HANDLE* binding);
RPC_STATUS RPC_ENTRY HookedUuidCreate(UUID* uuid);
RPC_STATUS RPC_ENTRY HookedUuidToStringW(UUID* uuid, RPC_WSTR* stringUuid);
RPC_STATUS RPC_ENTRY HookedUuidFromStringW(RPC_WSTR stringUuid, UUID* uuid);
int WINAPI HookedWSAStartup(WORD versionRequested, LPWSADATA data);
int WINAPI HookedWSACleanup();
SOCKET WINAPI HookedSocket(int af, int type, int protocol);
int WINAPI HookedClosesocket(SOCKET socketValue);
int WINAPI HookedGetAddrInfo(PCSTR nodeName, PCSTR serviceName, const ADDRINFOA* hints, PADDRINFOA* result);
void WINAPI HookedFreeAddrInfo(PADDRINFOA addrInfo);
int WINAPI HookedWSAGetLastError();
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE fileHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER allocationSize, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBuffer, ULONG eaLength);
NTSTATUS NTAPI HookedLdrLoadDll(PWSTR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle);
NTSTATUS NTAPI HookedLdrGetProcedureAddress(HMODULE module, PANSI_STRING functionName, ULONG ordinal, PVOID* functionAddress);

std::array<HookDefinition, HookDefinitionCount> BuildHookDefinitions()
{
    return {
        HookDefinition { "kernel32.dll", "CreateFileW", reinterpret_cast<void*>(HookedCreateFileW), reinterpret_cast<void**>(&g_originalCreateFileW), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateFileA", reinterpret_cast<void*>(HookedCreateFileA), reinterpret_cast<void**>(&g_originalCreateFileA), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "ReadFile", reinterpret_cast<void*>(HookedReadFile), reinterpret_cast<void**>(&g_originalReadFile), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "WriteFile", reinterpret_cast<void*>(HookedWriteFile), reinterpret_cast<void**>(&g_originalWriteFile), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CloseHandle", reinterpret_cast<void*>(HookedCloseHandle), reinterpret_cast<void**>(&g_originalCloseHandle), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "VirtualAlloc", reinterpret_cast<void*>(HookedVirtualAlloc), reinterpret_cast<void**>(&g_originalVirtualAlloc), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "VirtualFree", reinterpret_cast<void*>(HookedVirtualFree), reinterpret_cast<void**>(&g_originalVirtualFree), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "VirtualProtect", reinterpret_cast<void*>(HookedVirtualProtect), reinterpret_cast<void**>(&g_originalVirtualProtect), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "VirtualQuery", reinterpret_cast<void*>(HookedVirtualQuery), reinterpret_cast<void**>(&g_originalVirtualQuery), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateFileMappingW", reinterpret_cast<void*>(HookedCreateFileMappingW), reinterpret_cast<void**>(&g_originalCreateFileMappingW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "OpenFileMappingW", reinterpret_cast<void*>(HookedOpenFileMappingW), reinterpret_cast<void**>(&g_originalOpenFileMappingW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "MapViewOfFile", reinterpret_cast<void*>(HookedMapViewOfFile), reinterpret_cast<void**>(&g_originalMapViewOfFile), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "UnmapViewOfFile", reinterpret_cast<void*>(HookedUnmapViewOfFile), reinterpret_cast<void**>(&g_originalUnmapViewOfFile), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetCurrentProcess", reinterpret_cast<void*>(HookedGetCurrentProcess), reinterpret_cast<void**>(&g_originalGetCurrentProcess), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetCurrentProcessId", reinterpret_cast<void*>(HookedGetCurrentProcessId), reinterpret_cast<void**>(&g_originalGetCurrentProcessId), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetCurrentThread", reinterpret_cast<void*>(HookedGetCurrentThread), reinterpret_cast<void**>(&g_originalGetCurrentThread), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetCurrentThreadId", reinterpret_cast<void*>(HookedGetCurrentThreadId), reinterpret_cast<void**>(&g_originalGetCurrentThreadId), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetProcessId", reinterpret_cast<void*>(HookedGetProcessId), reinterpret_cast<void**>(&g_originalGetProcessId), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetThreadId", reinterpret_cast<void*>(HookedGetThreadId), reinterpret_cast<void**>(&g_originalGetThreadId), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateThread", reinterpret_cast<void*>(HookedCreateThread), reinterpret_cast<void**>(&g_originalCreateThread), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "OpenThread", reinterpret_cast<void*>(HookedOpenThread), reinterpret_cast<void**>(&g_originalOpenThread), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "WaitForSingleObject", reinterpret_cast<void*>(HookedWaitForSingleObject), reinterpret_cast<void**>(&g_originalWaitForSingleObject), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "GetExitCodeThread", reinterpret_cast<void*>(HookedGetExitCodeThread), reinterpret_cast<void**>(&g_originalGetExitCodeThread), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateEventW", reinterpret_cast<void*>(HookedCreateEventW), reinterpret_cast<void**>(&g_originalCreateEventW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "OpenEventW", reinterpret_cast<void*>(HookedOpenEventW), reinterpret_cast<void**>(&g_originalOpenEventW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "SetEvent", reinterpret_cast<void*>(HookedSetEvent), reinterpret_cast<void**>(&g_originalSetEvent), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "ResetEvent", reinterpret_cast<void*>(HookedResetEvent), reinterpret_cast<void**>(&g_originalResetEvent), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "WaitForSingleObjectEx", reinterpret_cast<void*>(HookedWaitForSingleObjectEx), reinterpret_cast<void**>(&g_originalWaitForSingleObjectEx), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateMutexW", reinterpret_cast<void*>(HookedCreateMutexW), reinterpret_cast<void**>(&g_originalCreateMutexW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "OpenMutexW", reinterpret_cast<void*>(HookedOpenMutexW), reinterpret_cast<void**>(&g_originalOpenMutexW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "ReleaseMutex", reinterpret_cast<void*>(HookedReleaseMutex), reinterpret_cast<void**>(&g_originalReleaseMutex), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "CreateSemaphoreW", reinterpret_cast<void*>(HookedCreateSemaphoreW), reinterpret_cast<void**>(&g_originalCreateSemaphoreW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "OpenSemaphoreW", reinterpret_cast<void*>(HookedOpenSemaphoreW), reinterpret_cast<void**>(&g_originalOpenSemaphoreW), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "ReleaseSemaphore", reinterpret_cast<void*>(HookedReleaseSemaphore), reinterpret_cast<void**>(&g_originalReleaseSemaphore), false, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "WaitForMultipleObjectsEx", reinterpret_cast<void*>(HookedWaitForMultipleObjectsEx), reinterpret_cast<void**>(&g_originalWaitForMultipleObjectsEx), false, true, false, 0, 0 },
        HookDefinition { "ntdll.dll", "NtCreateFile", reinterpret_cast<void*>(HookedNtCreateFile), reinterpret_cast<void**>(&g_originalNtCreateFile), true, true, false, 0, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryW", reinterpret_cast<void*>(HookedLoadLibraryW), reinterpret_cast<void**>(&g_originalLoadLibraryW), false, true, true, 0, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryA", reinterpret_cast<void*>(HookedLoadLibraryA), reinterpret_cast<void**>(&g_originalLoadLibraryA), false, true, true, 0, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryExW", reinterpret_cast<void*>(HookedLoadLibraryExW), reinterpret_cast<void**>(&g_originalLoadLibraryExW), false, true, true, 0, 0 },
        HookDefinition { "kernel32.dll", "LoadLibraryExA", reinterpret_cast<void*>(HookedLoadLibraryExA), reinterpret_cast<void**>(&g_originalLoadLibraryExA), false, true, true, 0, 0 },
        HookDefinition { "ntdll.dll", "LdrLoadDll", reinterpret_cast<void*>(HookedLdrLoadDll), reinterpret_cast<void**>(&g_originalLdrLoadDll), false, true, true, 0, 0 },
        HookDefinition { "kernel32.dll", "GetProcAddress", reinterpret_cast<void*>(HookedGetProcAddress), reinterpret_cast<void**>(&g_originalGetProcAddress), false, true, false, 0, 0 },
        HookDefinition { "ntdll.dll", "LdrGetProcedureAddress", reinterpret_cast<void*>(HookedLdrGetProcedureAddress), reinterpret_cast<void**>(&g_originalLdrGetProcedureAddress), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegOpenKeyExW", reinterpret_cast<void*>(HookedRegOpenKeyExW), reinterpret_cast<void**>(&g_originalRegOpenKeyExW), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegCreateKeyExW", reinterpret_cast<void*>(HookedRegCreateKeyExW), reinterpret_cast<void**>(&g_originalRegCreateKeyExW), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegQueryValueExW", reinterpret_cast<void*>(HookedRegQueryValueExW), reinterpret_cast<void**>(&g_originalRegQueryValueExW), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegSetValueExW", reinterpret_cast<void*>(HookedRegSetValueExW), reinterpret_cast<void**>(&g_originalRegSetValueExW), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegDeleteValueW", reinterpret_cast<void*>(HookedRegDeleteValueW), reinterpret_cast<void**>(&g_originalRegDeleteValueW), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "RegCloseKey", reinterpret_cast<void*>(HookedRegCloseKey), reinterpret_cast<void**>(&g_originalRegCloseKey), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "OpenProcessToken", reinterpret_cast<void*>(HookedOpenProcessToken), reinterpret_cast<void**>(&g_originalOpenProcessToken), false, true, false, 0, 0 },
        HookDefinition { "advapi32.dll", "LookupPrivilegeValueW", reinterpret_cast<void*>(HookedLookupPrivilegeValueW), reinterpret_cast<void**>(&g_originalLookupPrivilegeValueW), false, true, false, 0, 0 },
        HookDefinition { "bcrypt.dll", "BCryptOpenAlgorithmProvider", reinterpret_cast<void*>(HookedBCryptOpenAlgorithmProvider), reinterpret_cast<void**>(&g_originalBCryptOpenAlgorithmProvider), false, true, false, 0, 0 },
        HookDefinition { "bcrypt.dll", "BCryptCloseAlgorithmProvider", reinterpret_cast<void*>(HookedBCryptCloseAlgorithmProvider), reinterpret_cast<void**>(&g_originalBCryptCloseAlgorithmProvider), false, true, false, 0, 0 },
        HookDefinition { "bcrypt.dll", "BCryptGetProperty", reinterpret_cast<void*>(HookedBCryptGetProperty), reinterpret_cast<void**>(&g_originalBCryptGetProperty), false, true, false, 0, 0 },
        HookDefinition { "bcrypt.dll", "BCryptGenRandom", reinterpret_cast<void*>(HookedBCryptGenRandom), reinterpret_cast<void**>(&g_originalBCryptGenRandom), false, true, false, 0, 0 },
        HookDefinition { "crypt32.dll", "CertOpenStore", reinterpret_cast<void*>(HookedCertOpenStore), reinterpret_cast<void**>(&g_originalCertOpenStore), false, true, false, 0, 0 },
        HookDefinition { "crypt32.dll", "CertCloseStore", reinterpret_cast<void*>(HookedCertCloseStore), reinterpret_cast<void**>(&g_originalCertCloseStore), false, true, false, 0, 0 },
        HookDefinition { "crypt32.dll", "CryptMsgOpenToDecode", reinterpret_cast<void*>(HookedCryptMsgOpenToDecode), reinterpret_cast<void**>(&g_originalCryptMsgOpenToDecode), false, true, false, 0, 0 },
        HookDefinition { "crypt32.dll", "CryptMsgClose", reinterpret_cast<void*>(HookedCryptMsgClose), reinterpret_cast<void**>(&g_originalCryptMsgClose), false, true, false, 0, 0 },
        HookDefinition { "wininet.dll", "InternetOpenW", reinterpret_cast<void*>(HookedInternetOpenW), reinterpret_cast<void**>(&g_originalInternetOpenW), false, true, false, 0, 0 },
        HookDefinition { "wininet.dll", "InternetCloseHandle", reinterpret_cast<void*>(HookedInternetCloseHandle), reinterpret_cast<void**>(&g_originalInternetCloseHandle), false, true, false, 0, 0 },
        HookDefinition { "winhttp.dll", "WinHttpOpen", reinterpret_cast<void*>(HookedWinHttpOpen), reinterpret_cast<void**>(&g_originalWinHttpOpen), false, true, false, 0, 0 },
        HookDefinition { "winhttp.dll", "WinHttpCloseHandle", reinterpret_cast<void*>(HookedWinHttpCloseHandle), reinterpret_cast<void**>(&g_originalWinHttpCloseHandle), false, true, false, 0, 0 },
        HookDefinition { "user32.dll", "GetSystemMetrics", reinterpret_cast<void*>(HookedGetSystemMetrics), reinterpret_cast<void**>(&g_originalGetSystemMetrics), false, true, false, 0, 0 },
        HookDefinition { "user32.dll", "GetDesktopWindow", reinterpret_cast<void*>(HookedGetDesktopWindow), reinterpret_cast<void**>(&g_originalGetDesktopWindow), false, true, false, 0, 0 },
        HookDefinition { "user32.dll", "GetForegroundWindow", reinterpret_cast<void*>(HookedGetForegroundWindow), reinterpret_cast<void**>(&g_originalGetForegroundWindow), false, true, false, 0, 0 },
        HookDefinition { "user32.dll", "GetWindowThreadProcessId", reinterpret_cast<void*>(HookedGetWindowThreadProcessId), reinterpret_cast<void**>(&g_originalGetWindowThreadProcessId), false, true, false, 0, 0 },
        HookDefinition { "gdi32.dll", "CreateCompatibleDC", reinterpret_cast<void*>(HookedCreateCompatibleDC), reinterpret_cast<void**>(&g_originalCreateCompatibleDC), false, true, false, 0, 0 },
        HookDefinition { "gdi32.dll", "GetDeviceCaps", reinterpret_cast<void*>(HookedGetDeviceCaps), reinterpret_cast<void**>(&g_originalGetDeviceCaps), false, true, false, 0, 0 },
        HookDefinition { "gdi32.dll", "DeleteDC", reinterpret_cast<void*>(HookedDeleteDC), reinterpret_cast<void**>(&g_originalDeleteDC), false, true, false, 0, 0 },
        HookDefinition { "psapi.dll", "EnumProcessModules", reinterpret_cast<void*>(HookedEnumProcessModules), reinterpret_cast<void**>(&g_originalEnumProcessModules), false, true, false, 0, 0 },
        HookDefinition { "psapi.dll", "GetModuleInformation", reinterpret_cast<void*>(HookedGetModuleInformation), reinterpret_cast<void**>(&g_originalGetModuleInformation), false, true, false, 0, 0 },
        HookDefinition { "psapi.dll", "GetModuleBaseNameW", reinterpret_cast<void*>(HookedGetModuleBaseNameW), reinterpret_cast<void**>(&g_originalGetModuleBaseNameW), false, true, false, 0, 0 },
        HookDefinition { "psapi.dll", "GetModuleFileNameExW", reinterpret_cast<void*>(HookedGetModuleFileNameExW), reinterpret_cast<void**>(&g_originalGetModuleFileNameExW), false, true, false, 0, 0 },
        HookDefinition { "version.dll", "GetFileVersionInfoSizeW", reinterpret_cast<void*>(HookedGetFileVersionInfoSizeW), reinterpret_cast<void**>(&g_originalGetFileVersionInfoSizeW), false, true, false, 0, 0 },
        HookDefinition { "version.dll", "GetFileVersionInfoW", reinterpret_cast<void*>(HookedGetFileVersionInfoW), reinterpret_cast<void**>(&g_originalGetFileVersionInfoW), false, true, false, 0, 0 },
        HookDefinition { "version.dll", "VerQueryValueW", reinterpret_cast<void*>(HookedVerQueryValueW), reinterpret_cast<void**>(&g_originalVerQueryValueW), false, true, false, 0, 0 },
        HookDefinition { "shell32.dll", "SHGetKnownFolderPath", reinterpret_cast<void*>(HookedSHGetKnownFolderPath), reinterpret_cast<void**>(&g_originalSHGetKnownFolderPath), false, true, false, 0, 0 },
        HookDefinition { "shell32.dll", "SHGetSpecialFolderPathW", reinterpret_cast<void*>(HookedSHGetSpecialFolderPathW), reinterpret_cast<void**>(&g_originalSHGetSpecialFolderPathW), false, true, false, 0, 0 },
        HookDefinition { "ole32.dll", "CoInitializeEx", reinterpret_cast<void*>(HookedCoInitializeEx), reinterpret_cast<void**>(&g_originalCoInitializeEx), false, true, false, 0, 0 },
        HookDefinition { "ole32.dll", "CoUninitialize", reinterpret_cast<void*>(HookedCoUninitialize), reinterpret_cast<void**>(&g_originalCoUninitialize), false, true, false, 0, 0 },
        HookDefinition { "ole32.dll", "CoCreateGuid", reinterpret_cast<void*>(HookedCoCreateGuid), reinterpret_cast<void**>(&g_originalCoCreateGuid), false, true, false, 0, 0 },
        HookDefinition { "ole32.dll", "StringFromGUID2", reinterpret_cast<void*>(HookedStringFromGUID2), reinterpret_cast<void**>(&g_originalStringFromGUID2), false, true, false, 0, 0 },
        HookDefinition { "api-ms-win-core-winrt-l1-1-0.dll", "RoInitialize", reinterpret_cast<void*>(HookedRoInitialize), reinterpret_cast<void**>(&g_originalRoInitialize), false, true, false, 0, 0 },
        HookDefinition { "api-ms-win-core-winrt-l1-1-0.dll", "RoUninitialize", reinterpret_cast<void*>(HookedRoUninitialize), reinterpret_cast<void**>(&g_originalRoUninitialize), false, true, false, 0, 0 },
        HookDefinition { "api-ms-win-core-winrt-l1-1-0.dll", "RoGetApartmentIdentifier", reinterpret_cast<void*>(HookedRoGetApartmentIdentifier), reinterpret_cast<void**>(&g_originalRoGetApartmentIdentifier), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "RpcStringBindingComposeW", reinterpret_cast<void*>(HookedRpcStringBindingComposeW), reinterpret_cast<void**>(&g_originalRpcStringBindingComposeW), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "RpcBindingFromStringBindingW", reinterpret_cast<void*>(HookedRpcBindingFromStringBindingW), reinterpret_cast<void**>(&g_originalRpcBindingFromStringBindingW), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "RpcStringFreeW", reinterpret_cast<void*>(HookedRpcStringFreeW), reinterpret_cast<void**>(&g_originalRpcStringFreeW), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "RpcBindingFree", reinterpret_cast<void*>(HookedRpcBindingFree), reinterpret_cast<void**>(&g_originalRpcBindingFree), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "UuidCreate", reinterpret_cast<void*>(HookedUuidCreate), reinterpret_cast<void**>(&g_originalUuidCreate), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "UuidToStringW", reinterpret_cast<void*>(HookedUuidToStringW), reinterpret_cast<void**>(&g_originalUuidToStringW), false, true, false, 0, 0 },
        HookDefinition { "rpcrt4.dll", "UuidFromStringW", reinterpret_cast<void*>(HookedUuidFromStringW), reinterpret_cast<void**>(&g_originalUuidFromStringW), false, true, false, 0, 0 },
        HookDefinition { "ws2_32.dll", "WSAStartup", reinterpret_cast<void*>(HookedWSAStartup), reinterpret_cast<void**>(&g_originalWSAStartup), false, true, false, 115, 0 },
        HookDefinition { "ws2_32.dll", "WSACleanup", reinterpret_cast<void*>(HookedWSACleanup), reinterpret_cast<void**>(&g_originalWSACleanup), false, true, false, 116, 0 },
        HookDefinition { "ws2_32.dll", "socket", reinterpret_cast<void*>(HookedSocket), reinterpret_cast<void**>(&g_originalSocket), false, true, false, 23, 0 },
        HookDefinition { "ws2_32.dll", "closesocket", reinterpret_cast<void*>(HookedClosesocket), reinterpret_cast<void**>(&g_originalClosesocket), false, true, false, 3, 0 },
        HookDefinition { "ws2_32.dll", "getaddrinfo", reinterpret_cast<void*>(HookedGetAddrInfo), reinterpret_cast<void**>(&g_originalGetAddrInfo), false, true, false, 0, 0 },
        HookDefinition { "ws2_32.dll", "freeaddrinfo", reinterpret_cast<void*>(HookedFreeAddrInfo), reinterpret_cast<void**>(&g_originalFreeAddrInfo), false, true, false, 0, 0 },
        HookDefinition { "ws2_32.dll", "WSAGetLastError", reinterpret_cast<void*>(HookedWSAGetLastError), reinterpret_cast<void**>(&g_originalWSAGetLastError), false, true, false, 111, 0 },
    };
}

bool ImportMatchesDefinition(std::uint8_t* base, std::uint32_t size, IMAGE_THUNK_DATA* originalThunk, const HookDefinition& definition)
{
    bool matches = false;

    do
    {
        if (base == nullptr || originalThunk == nullptr || definition.ApiName == nullptr)
        {
            break;
        }

        if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
        {
            if (definition.ImportOrdinal != 0 && IMAGE_ORDINAL(originalThunk->u1.Ordinal) == definition.ImportOrdinal)
            {
                matches = true;
            }
            break;
        }

        auto* importByName = ImageRvaToPointer<IMAGE_IMPORT_BY_NAME>(
            base,
            size,
            static_cast<DWORD>(originalThunk->u1.AddressOfData),
            sizeof(WORD) + 1);
        if (importByName == nullptr)
        {
            break;
        }

        if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), definition.ApiName) == 0)
        {
            matches = true;
        }
    }
    while (false);

    return matches;
}

void PatchImportInModule(ModuleInfo& module, HookDefinition& definition, SweepStats& stats)
{
    do
    {
        if (!module.Eligible || definition.ImportModuleName == nullptr || definition.ApiName == nullptr || definition.ReplacementFunction == nullptr)
        {
            break;
        }

        if (definition.OriginalFunction == nullptr || *definition.OriginalFunction == nullptr)
        {
            break;
        }

        auto* base = reinterpret_cast<std::uint8_t*>(module.Base);
        IMAGE_IMPORT_DESCRIPTOR* importDescriptor = nullptr;
        if (!ReadImageImportDirectory(module.Base, module.SizeOfImage, &importDescriptor))
        {
            break;
        }

        for (; importDescriptor->Name != 0; ++importDescriptor)
        {
            const char* importedModuleName = ImageRvaToPointer<char>(base, module.SizeOfImage, importDescriptor->Name, 1);
            if (importedModuleName == nullptr || _stricmp(importedModuleName, definition.ImportModuleName) != 0)
            {
                continue;
            }

            auto* firstThunk = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, module.SizeOfImage, importDescriptor->FirstThunk);
            if (firstThunk == nullptr)
            {
                continue;
            }

            auto* originalThunk = ImageRvaToPointer<IMAGE_THUNK_DATA>(base, module.SizeOfImage, importDescriptor->OriginalFirstThunk);
            if (importDescriptor->OriginalFirstThunk == 0)
            {
                originalThunk = firstThunk;
            }

            if (originalThunk == nullptr)
            {
                continue;
            }

            for (
                std::size_t thunkIndex = 0;
                ImageRangeContains(base, module.SizeOfImage, &originalThunk[thunkIndex], sizeof(IMAGE_THUNK_DATA)) &&
                    ImageRangeContains(base, module.SizeOfImage, &firstThunk[thunkIndex], sizeof(IMAGE_THUNK_DATA)) &&
                    originalThunk[thunkIndex].u1.AddressOfData != 0;
                ++thunkIndex)
            {
                if (!ImportMatchesDefinition(base, module.SizeOfImage, &originalThunk[thunkIndex], definition))
                {
                    continue;
                }

                auto* thunkAddress = reinterpret_cast<ULONG_PTR*>(&firstThunk[thunkIndex].u1.Function);
                if (FindHookRecordByThunkNoLock(thunkAddress) != nullptr || *thunkAddress == reinterpret_cast<ULONG_PTR>(definition.ReplacementFunction))
                {
                    ++stats.DuplicateSlots;
                    continue;
                }

                void* originalFunction = reinterpret_cast<void*>(*thunkAddress);
                DWORD oldProtect = 0;
                if (!VirtualProtect(thunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
                {
                    ++stats.FailedSlots;
                    continue;
                }

                *thunkAddress = reinterpret_cast<ULONG_PTR>(definition.ReplacementFunction);
                FlushInstructionCache(GetCurrentProcess(), thunkAddress, sizeof(void*));

                DWORD ignored = 0;
                VirtualProtect(thunkAddress, sizeof(void*), oldProtect, &ignored);

                bool duplicate = false;
                if (AppendHookRecordNoLock(module, definition.ImportModuleName, definition.ApiName, thunkAddress, originalFunction, definition.ReplacementFunction, &duplicate))
                {
                    ++definition.LastPatchedSlots;
                    ++stats.PatchedSlots;
                }
                else
                {
                    if (VirtualProtect(thunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
                    {
                        *thunkAddress = reinterpret_cast<ULONG_PTR>(originalFunction);
                        FlushInstructionCache(GetCurrentProcess(), thunkAddress, sizeof(void*));
                        VirtualProtect(thunkAddress, sizeof(void*), oldProtect, &ignored);
                    }

                    if (duplicate)
                    {
                        ++stats.DuplicateSlots;
                    }
                    else
                    {
                        ++stats.FailedSlots;
                        InterlockedIncrement(&g_failedHooks);
                    }
                }
            }
        }
    }
    while (false);
}

void ResolveHookDefinitions(std::array<HookDefinition, HookDefinitionCount>& definitions)
{
    for (HookDefinition& definition : definitions)
    {
        if (definition.OriginalFunction != nullptr && *definition.OriginalFunction == nullptr)
        {
            *definition.OriginalFunction = ResolveExport(definition.ImportModuleName, definition.ApiName);
        }
    }
}

bool AddressBelongsToLoadedModule(const void* address)
{
    bool loaded = false;
    HMODULE module = nullptr;

    if (address != nullptr)
    {
        loaded = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &module) != FALSE;
    }

    return loaded;
}

bool SweepLoadedModules(const char* reason, bool reportHookStatus, SweepStats* outStats)
{
    bool requiredCoverage = true;
    SweepStats stats = {};
    std::array<ModuleInfo, MaxModuleRecords> modules = {};
    std::array<HookDefinition, HookDefinitionCount> definitions = BuildHookDefinitions();
    ResolveHookDefinitions(definitions);
    const std::size_t moduleCount = CaptureModuleSnapshot(modules, &stats);

    AcquireSRWLockExclusive(&g_hookLock);
    for (std::size_t moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex)
    {
        ModuleInfo& module = modules[moduleIndex];
        const std::uint32_t patchedBefore = stats.PatchedSlots;

        for (HookDefinition& definition : definitions)
        {
            PatchImportInModule(module, definition, stats);
        }

        if (stats.PatchedSlots > patchedBefore)
        {
            ++stats.ModulesWithPatches;
        }
    }
    ReleaseSRWLockExclusive(&g_hookLock);

    if (reportHookStatus)
    {
        SendModuleInventoryStatus(stats);
    }

    SendIatSweepStatus(reason, stats);

    for (HookDefinition& definition : definitions)
    {
        if (reportHookStatus && definition.Required && definition.LastPatchedSlots == 0)
        {
            requiredCoverage = false;
            InterlockedIncrement(&g_failedHooks);
        }

        if (reportHookStatus && definition.ReportStatus)
        {
            if (definition.LastPatchedSlots > 0)
            {
                std::ostringstream message;
                message << "Loaded-module IAT sweep patched " << definition.LastPatchedSlots << " import slot(s).";
                SendHookStatus(definition.ImportModuleName, definition.ApiName, true, message.str());
            }
            else if (definition.Required)
            {
                SendHookStatus(definition.ImportModuleName, definition.ApiName, false, "Required IAT entry was not found in eligible loaded modules.");
            }
        }
    }

    if (outStats != nullptr)
    {
        *outStats = stats;
    }

    return requiredCoverage;
}

HookLifecycleCounts UninstallHooks()
{
    HookLifecycleCounts counts;

    InterlockedExchange(&g_hooksEnabled, 0);
    AcquireSRWLockExclusive(&g_hookLock);
    for (std::size_t index = 0; index < g_hookRecordCount; ++index)
    {
        HookRecord& record = g_hookRecords[index];
        if (!record.Installed || record.Restored || record.ThunkAddress == nullptr || record.OriginalFunction == nullptr)
        {
            if (record.Installed)
            {
                ++counts.InstalledHooks;
            }

            if (record.Restored)
            {
                ++counts.RestoredHooks;
            }

            if (record.Failed)
            {
                ++counts.FailedHooks;
            }
            continue;
        }

        ++counts.InstalledHooks;

        if (!AddressBelongsToLoadedModule(record.ThunkAddress))
        {
            record.Restored = true;
            ++counts.RestoredHooks;
            continue;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(record.ThunkAddress, sizeof(void*), PAGE_READWRITE, &oldProtect))
        {
            if (!AddressBelongsToLoadedModule(record.ThunkAddress))
            {
                record.Restored = true;
                ++counts.RestoredHooks;
                continue;
            }

            record.Failed = true;
            ++counts.FailedHooks;
            continue;
        }

        if (*record.ThunkAddress == reinterpret_cast<ULONG_PTR>(record.ReplacementFunction))
        {
            *record.ThunkAddress = reinterpret_cast<ULONG_PTR>(record.OriginalFunction);
            FlushInstructionCache(GetCurrentProcess(), record.ThunkAddress, sizeof(void*));
            record.Restored = true;
            ++counts.RestoredHooks;
        }
        else
        {
            record.Restored = true;
            ++counts.RestoredHooks;
        }

        DWORD ignored = 0;
        if (!VirtualProtect(record.ThunkAddress, sizeof(void*), oldProtect, &ignored))
        {
            record.Failed = true;
            ++counts.FailedHooks;
        }
    }
    ReleaseSRWLockExclusive(&g_hookLock);

    counts.FailedHooks += static_cast<int>(InterlockedCompareExchange(&g_failedHooks, 0, 0));
    return counts;
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateFileW == nullptr)
    {
        if (g_originalCreateFileW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        return g_originalCreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const bool failed = result == INVALID_HANDLE_VALUE;
    const DWORD eventError = failed ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateFileWEvent(result, eventError, start, end, fileName, desiredAccess, shareMode, creationDisposition);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateFileA(
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateFileA == nullptr)
    {
        if (g_originalCreateFileA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        return g_originalCreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const bool failed = result == INVALID_HANDLE_VALUE;
    const DWORD eventError = failed ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateFileAEvent(result, eventError, start, end, fileName, desiredAccess, shareMode, creationDisposition);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedReadFile(HANDLE file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped)
{
    if (g_inHook || !HooksEnabled() || g_originalReadFile == nullptr)
    {
        if (g_originalReadFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalReadFile(file, buffer, bytesToRead, bytesRead, overlapped);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalReadFile(file, buffer, bytesToRead, bytesRead, overlapped);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD actualBytes = bytesRead == nullptr ? 0 : *bytesRead;
    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitReadFileEvent(result, eventError, start, end, file, buffer, bytesToRead, actualBytes);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedWriteFile(HANDLE file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten, LPOVERLAPPED overlapped)
{
    if (g_inHook || !HooksEnabled() || g_originalWriteFile == nullptr)
    {
        if (g_originalWriteFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalWriteFile(file, buffer, bytesToWrite, bytesWritten, overlapped);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalWriteFile(file, buffer, bytesToWrite, bytesWritten, overlapped);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD actualBytes = bytesWritten == nullptr ? 0 : *bytesWritten;
    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitWriteFileEvent(result, eventError, start, end, file, buffer, bytesToWrite, actualBytes);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedCloseHandle(HANDLE handle)
{
    if (g_inHook || !HooksEnabled() || g_originalCloseHandle == nullptr)
    {
        if (g_originalCloseHandle == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalCloseHandle(handle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalCloseHandle(handle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitCloseHandleEvent(result, eventError, start, end, handle);
    }

    SetLastError(lastError);
    return result;
}

LPVOID WINAPI HookedVirtualAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect)
{
    if (g_inHook || !HooksEnabled() || g_originalVirtualAlloc == nullptr)
    {
        if (g_originalVirtualAlloc == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalVirtualAlloc(address, size, allocationType, protect);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    LPVOID result = g_originalVirtualAlloc(address, size, allocationType, protect);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitVirtualAllocEvent(result, eventError, start, end, address, size, allocationType, protect);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedVirtualFree(LPVOID address, SIZE_T size, DWORD freeType)
{
    if (g_inHook || !HooksEnabled() || g_originalVirtualFree == nullptr)
    {
        if (g_originalVirtualFree == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalVirtualFree(address, size, freeType);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalVirtualFree(address, size, freeType);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitVirtualFreeEvent(result, eventError, start, end, address, size, freeType);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedVirtualProtect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect)
{
    if (g_inHook || !HooksEnabled() || g_originalVirtualProtect == nullptr)
    {
        if (g_originalVirtualProtect == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalVirtualProtect(address, size, newProtect, oldProtect);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalVirtualProtect(address, size, newProtect, oldProtect);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitVirtualProtectEvent(result, eventError, start, end, address, size, newProtect, oldProtect);
    }

    SetLastError(lastError);
    return result;
}

SIZE_T WINAPI HookedVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length)
{
    if (g_inHook || !HooksEnabled() || g_originalVirtualQuery == nullptr)
    {
        if (g_originalVirtualQuery == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalVirtualQuery(address, buffer, length);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    SIZE_T result = g_originalVirtualQuery(address, buffer, length);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitVirtualQueryEvent(result, eventError, start, end, address, buffer, length);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateFileMappingW(
    HANDLE file,
    LPSECURITY_ATTRIBUTES mappingAttributes,
    DWORD protect,
    DWORD maximumSizeHigh,
    DWORD maximumSizeLow,
    LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateFileMappingW == nullptr)
    {
        if (g_originalCreateFileMappingW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateFileMappingW(file, mappingAttributes, protect, maximumSizeHigh, maximumSizeLow, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateFileMappingW(file, mappingAttributes, protect, maximumSizeHigh, maximumSizeLow, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateFileMappingWEvent(result, eventError, start, end, file, mappingAttributes, protect, maximumSizeHigh, maximumSizeLow, name);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedOpenFileMappingW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenFileMappingW == nullptr)
    {
        if (g_originalOpenFileMappingW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalOpenFileMappingW(desiredAccess, inheritHandle, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalOpenFileMappingW(desiredAccess, inheritHandle, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenFileMappingWEvent(result, eventError, start, end, desiredAccess, inheritHandle, name);
    }

    SetLastError(lastError);
    return result;
}

LPVOID WINAPI HookedMapViewOfFile(HANDLE mapping, DWORD desiredAccess, DWORD fileOffsetHigh, DWORD fileOffsetLow, SIZE_T bytesToMap)
{
    if (g_inHook || !HooksEnabled() || g_originalMapViewOfFile == nullptr)
    {
        if (g_originalMapViewOfFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalMapViewOfFile(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    LPVOID result = g_originalMapViewOfFile(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitMapViewOfFileEvent(result, eventError, start, end, mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedUnmapViewOfFile(LPCVOID baseAddress)
{
    if (g_inHook || !HooksEnabled() || g_originalUnmapViewOfFile == nullptr)
    {
        if (g_originalUnmapViewOfFile == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalUnmapViewOfFile(baseAddress);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalUnmapViewOfFile(baseAddress);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitUnmapViewOfFileEvent(result, eventError, start, end, baseAddress);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedGetCurrentProcess()
{
    if (g_inHook || !HooksEnabled() || g_originalGetCurrentProcess == nullptr)
    {
        if (g_originalGetCurrentProcess == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetCurrentProcess();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalGetCurrentProcess();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetCurrentProcessEvent(result, eventError, start, end);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetCurrentProcessId()
{
    if (g_inHook || !HooksEnabled() || g_originalGetCurrentProcessId == nullptr)
    {
        if (g_originalGetCurrentProcessId == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetCurrentProcessId();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalGetCurrentProcessId();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetCurrentProcessIdEvent(result, eventError, start, end);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedGetCurrentThread()
{
    if (g_inHook || !HooksEnabled() || g_originalGetCurrentThread == nullptr)
    {
        if (g_originalGetCurrentThread == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetCurrentThread();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalGetCurrentThread();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetCurrentThreadEvent(result, eventError, start, end);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetCurrentThreadId()
{
    if (g_inHook || !HooksEnabled() || g_originalGetCurrentThreadId == nullptr)
    {
        if (g_originalGetCurrentThreadId == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetCurrentThreadId();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalGetCurrentThreadId();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetCurrentThreadIdEvent(result, eventError, start, end);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetProcessId(HANDLE process)
{
    if (g_inHook || !HooksEnabled() || g_originalGetProcessId == nullptr)
    {
        if (g_originalGetProcessId == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetProcessId(process);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalGetProcessId(process);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetProcessIdEvent(result, eventError, start, end, process);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetThreadId(HANDLE thread)
{
    if (g_inHook || !HooksEnabled() || g_originalGetThreadId == nullptr)
    {
        if (g_originalGetThreadId == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetThreadId(thread);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalGetThreadId(thread);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetThreadIdEvent(result, eventError, start, end, thread);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateThread(
    LPSECURITY_ATTRIBUTES threadAttributes,
    SIZE_T stackSize,
    LPTHREAD_START_ROUTINE startAddress,
    LPVOID parameter,
    DWORD creationFlags,
    LPDWORD threadId)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateThread == nullptr)
    {
        if (g_originalCreateThread == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateThread(threadAttributes, stackSize, startAddress, parameter, creationFlags, threadId);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateThread(threadAttributes, stackSize, startAddress, parameter, creationFlags, threadId);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateThreadEvent(result, eventError, start, end, threadAttributes, stackSize, startAddress, parameter, creationFlags, threadId);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenThread == nullptr)
    {
        if (g_originalOpenThread == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalOpenThread(desiredAccess, inheritHandle, threadId);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalOpenThread(desiredAccess, inheritHandle, threadId);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenThreadEvent(result, eventError, start, end, desiredAccess, inheritHandle, threadId);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedWaitForSingleObject(HANDLE handle, DWORD milliseconds)
{
    if (g_inHook || !HooksEnabled() || g_originalWaitForSingleObject == nullptr)
    {
        if (g_originalWaitForSingleObject == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return WAIT_FAILED;
        }

        return g_originalWaitForSingleObject(handle, milliseconds);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalWaitForSingleObject(handle, milliseconds);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == WAIT_FAILED ? lastError : 0;
    if (HooksEnabled())
    {
        EmitWaitForSingleObjectEvent(result, eventError, start, end, handle, milliseconds);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedGetExitCodeThread(HANDLE thread, LPDWORD exitCode)
{
    if (g_inHook || !HooksEnabled() || g_originalGetExitCodeThread == nullptr)
    {
        if (g_originalGetExitCodeThread == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalGetExitCodeThread(thread, exitCode);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalGetExitCodeThread(thread, exitCode);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitGetExitCodeThreadEvent(result, eventError, start, end, thread, exitCode);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateEventW(LPSECURITY_ATTRIBUTES eventAttributes, BOOL manualReset, BOOL initialState, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateEventW == nullptr)
    {
        if (g_originalCreateEventW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateEventW(eventAttributes, manualReset, initialState, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateEventW(eventAttributes, manualReset, initialState, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateEventWEvent(result, eventError, start, end, eventAttributes, manualReset, initialState, name);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedOpenEventW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenEventW == nullptr)
    {
        if (g_originalOpenEventW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalOpenEventW(desiredAccess, inheritHandle, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalOpenEventW(desiredAccess, inheritHandle, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenEventWEvent(result, eventError, start, end, desiredAccess, inheritHandle, name);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedSetEvent(HANDLE eventHandle)
{
    if (g_inHook || !HooksEnabled() || g_originalSetEvent == nullptr)
    {
        if (g_originalSetEvent == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalSetEvent(eventHandle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalSetEvent(eventHandle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitSetEventEvent(result, eventError, start, end, eventHandle);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedResetEvent(HANDLE eventHandle)
{
    if (g_inHook || !HooksEnabled() || g_originalResetEvent == nullptr)
    {
        if (g_originalResetEvent == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalResetEvent(eventHandle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalResetEvent(eventHandle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitResetEventEvent(result, eventError, start, end, eventHandle);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedWaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable)
{
    if (g_inHook || !HooksEnabled() || g_originalWaitForSingleObjectEx == nullptr)
    {
        if (g_originalWaitForSingleObjectEx == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return WAIT_FAILED;
        }

        return g_originalWaitForSingleObjectEx(handle, milliseconds, alertable);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalWaitForSingleObjectEx(handle, milliseconds, alertable);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == WAIT_FAILED ? lastError : 0;
    if (HooksEnabled())
    {
        EmitWaitForSingleObjectExEvent(result, eventError, start, end, handle, milliseconds, alertable);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateMutexW(LPSECURITY_ATTRIBUTES mutexAttributes, BOOL initialOwner, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateMutexW == nullptr)
    {
        if (g_originalCreateMutexW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateMutexW(mutexAttributes, initialOwner, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateMutexW(mutexAttributes, initialOwner, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateMutexWEvent(result, eventError, start, end, mutexAttributes, initialOwner, name);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedOpenMutexW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenMutexW == nullptr)
    {
        if (g_originalOpenMutexW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalOpenMutexW(desiredAccess, inheritHandle, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalOpenMutexW(desiredAccess, inheritHandle, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenMutexWEvent(result, eventError, start, end, desiredAccess, inheritHandle, name);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedReleaseMutex(HANDLE mutexHandle)
{
    if (g_inHook || !HooksEnabled() || g_originalReleaseMutex == nullptr)
    {
        if (g_originalReleaseMutex == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalReleaseMutex(mutexHandle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalReleaseMutex(mutexHandle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitReleaseMutexEvent(result, eventError, start, end, mutexHandle);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedCreateSemaphoreW(LPSECURITY_ATTRIBUTES semaphoreAttributes, LONG initialCount, LONG maximumCount, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateSemaphoreW == nullptr)
    {
        if (g_originalCreateSemaphoreW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateSemaphoreW(semaphoreAttributes, initialCount, maximumCount, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalCreateSemaphoreW(semaphoreAttributes, initialCount, maximumCount, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateSemaphoreWEvent(result, eventError, start, end, semaphoreAttributes, initialCount, maximumCount, name);
    }

    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookedOpenSemaphoreW(DWORD desiredAccess, BOOL inheritHandle, LPCWSTR name)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenSemaphoreW == nullptr)
    {
        if (g_originalOpenSemaphoreW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalOpenSemaphoreW(desiredAccess, inheritHandle, name);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HANDLE result = g_originalOpenSemaphoreW(desiredAccess, inheritHandle, name);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenSemaphoreWEvent(result, eventError, start, end, desiredAccess, inheritHandle, name);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedReleaseSemaphore(HANDLE semaphoreHandle, LONG releaseCount, LPLONG previousCount)
{
    if (g_inHook || !HooksEnabled() || g_originalReleaseSemaphore == nullptr)
    {
        if (g_originalReleaseSemaphore == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalReleaseSemaphore(semaphoreHandle, releaseCount, previousCount);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    BOOL result = g_originalReleaseSemaphore(semaphoreHandle, releaseCount, previousCount);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result ? 0 : lastError;
    if (HooksEnabled())
    {
        EmitReleaseSemaphoreEvent(result, eventError, start, end, semaphoreHandle, releaseCount, previousCount);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedWaitForMultipleObjectsEx(DWORD count, const HANDLE* handles, BOOL waitAll, DWORD milliseconds, BOOL alertable)
{
    if (g_inHook || !HooksEnabled() || g_originalWaitForMultipleObjectsEx == nullptr)
    {
        if (g_originalWaitForMultipleObjectsEx == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return WAIT_FAILED;
        }

        return g_originalWaitForMultipleObjectsEx(count, handles, waitAll, milliseconds, alertable);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    DWORD result = g_originalWaitForMultipleObjectsEx(count, handles, waitAll, milliseconds, alertable);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == WAIT_FAILED ? lastError : 0;
    if (HooksEnabled())
    {
        EmitWaitForMultipleObjectsExEvent(result, eventError, start, end, count, handles, waitAll, milliseconds, alertable);
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR fileName)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryW == nullptr)
    {
        if (g_originalLoadLibraryW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryW(fileName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryW(fileName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryWEvent(result, eventError, start, end, fileName);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR fileName)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryA == nullptr)
    {
        if (g_originalLoadLibraryA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryA(fileName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryA(fileName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryAEvent(result, eventError, start, end, fileName);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryExW == nullptr)
    {
        if (g_originalLoadLibraryExW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryExW(fileName, file, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryExW(fileName, file, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryExWEvent(result, eventError, start, end, fileName, file, flags);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalLoadLibraryExA == nullptr)
    {
        if (g_originalLoadLibraryExA == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalLoadLibraryExA(fileName, file, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HMODULE result = g_originalLoadLibraryExA(fileName, file, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLoadLibraryExAEvent(result, eventError, start, end, fileName, file, flags);
        if (result != nullptr)
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    SetLastError(lastError);
    return result;
}

FARPROC WINAPI HookedGetProcAddress(HMODULE module, LPCSTR procName)
{
    if (g_inHook || !HooksEnabled() || g_originalGetProcAddress == nullptr)
    {
        if (g_originalGetProcAddress == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetProcAddress(module, procName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    FARPROC result = g_originalGetProcAddress(module, procName);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetProcAddressEvent(result, eventError, start, end, module, procName);
    }

    SetLastError(lastError);
    return result;
}

NTSTATUS NTAPI HookedNtCreateFile(
    PHANDLE fileHandle,
    ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PIO_STATUS_BLOCK ioStatusBlock,
    PLARGE_INTEGER allocationSize,
    ULONG fileAttributes,
    ULONG shareAccess,
    ULONG createDisposition,
    ULONG createOptions,
    PVOID eaBuffer,
    ULONG eaLength)
{
    if (g_inHook || !HooksEnabled() || g_originalNtCreateFile == nullptr)
    {
        if (g_originalNtCreateFile == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalNtCreateFile(
            fileHandle,
            desiredAccess,
            objectAttributes,
            ioStatusBlock,
            allocationSize,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            eaBuffer,
            eaLength);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalNtCreateFile(
        fileHandle,
        desiredAccess,
        objectAttributes,
        ioStatusBlock,
        allocationSize,
        fileAttributes,
        shareAccess,
        createDisposition,
        createOptions,
        eaBuffer,
        eaLength);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitNtCreateFileEvent(
            status,
            eventError,
            start,
            end,
            fileHandle,
            desiredAccess,
            objectAttributes,
            ioStatusBlock,
            allocationSize,
            fileAttributes,
            shareAccess,
            createDisposition,
            createOptions,
            eaBuffer,
            eaLength);
    }

    return status;
}

NTSTATUS NTAPI HookedLdrLoadDll(PWSTR pathToFile, ULONG flags, PUNICODE_STRING moduleFileName, PHANDLE moduleHandle)
{
    if (g_inHook || !HooksEnabled() || g_originalLdrLoadDll == nullptr)
    {
        if (g_originalLdrLoadDll == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalLdrLoadDll(pathToFile, flags, moduleFileName, moduleHandle);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitLdrLoadDllEvent(status, eventError, start, end, pathToFile, flags, moduleFileName, moduleHandle);
        if (NT_SUCCESS(status))
        {
            SweepLoadedModules("dynamic_load", false, nullptr);
        }
    }

    return status;
}

NTSTATUS NTAPI HookedLdrGetProcedureAddress(HMODULE module, PANSI_STRING functionName, ULONG ordinal, PVOID* functionAddress)
{
    if (g_inHook || !HooksEnabled() || g_originalLdrGetProcedureAddress == nullptr)
    {
        if (g_originalLdrGetProcedureAddress == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalLdrGetProcedureAddress(module, functionName, ordinal, functionAddress);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    NTSTATUS status = g_originalLdrGetProcedureAddress(module, functionName, ordinal, functionAddress);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitLdrGetProcedureAddressEvent(status, eventError, start, end, module, functionName, ordinal, functionAddress);
    }

    return status;
}

LSTATUS WINAPI HookedRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options, REGSAM desiredAccess, PHKEY resultKey)
{
    if (g_inHook || !HooksEnabled() || g_originalRegOpenKeyExW == nullptr)
    {
        if (g_originalRegOpenKeyExW == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegOpenKeyExW(key, subKey, options, desiredAccess, resultKey);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegOpenKeyExW(key, subKey, options, desiredAccess, resultKey);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegOpenKeyExWEvent(result, start, end, key, subKey, options, desiredAccess, resultKey);
    }

    return result;
}

LSTATUS WINAPI HookedRegCreateKeyExW(
    HKEY key,
    LPCWSTR subKey,
    DWORD reserved,
    LPWSTR keyClass,
    DWORD options,
    REGSAM desiredAccess,
    const SECURITY_ATTRIBUTES* securityAttributes,
    PHKEY resultKey,
    LPDWORD disposition)
{
    if (g_inHook || !HooksEnabled() || g_originalRegCreateKeyExW == nullptr)
    {
        if (g_originalRegCreateKeyExW == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegCreateKeyExW(key, subKey, reserved, keyClass, options, desiredAccess, securityAttributes, resultKey, disposition);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegCreateKeyExW(key, subKey, reserved, keyClass, options, desiredAccess, securityAttributes, resultKey, disposition);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegCreateKeyExWEvent(result, start, end, key, subKey, reserved, keyClass, options, desiredAccess, securityAttributes, resultKey, disposition);
    }

    return result;
}

LSTATUS WINAPI HookedRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD valueType, LPBYTE data, LPDWORD dataBytes)
{
    if (g_inHook || !HooksEnabled() || g_originalRegQueryValueExW == nullptr)
    {
        if (g_originalRegQueryValueExW == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegQueryValueExW(key, valueName, reserved, valueType, data, dataBytes);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegQueryValueExW(key, valueName, reserved, valueType, data, dataBytes);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegQueryValueExWEvent(result, start, end, key, valueName, reserved, valueType, data, dataBytes);
    }

    return result;
}

LSTATUS WINAPI HookedRegSetValueExW(HKEY key, LPCWSTR valueName, DWORD reserved, DWORD valueType, const BYTE* data, DWORD dataBytes)
{
    if (g_inHook || !HooksEnabled() || g_originalRegSetValueExW == nullptr)
    {
        if (g_originalRegSetValueExW == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegSetValueExW(key, valueName, reserved, valueType, data, dataBytes);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegSetValueExW(key, valueName, reserved, valueType, data, dataBytes);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegSetValueExWEvent(result, start, end, key, valueName, reserved, valueType, data, dataBytes);
    }

    return result;
}

LSTATUS WINAPI HookedRegDeleteValueW(HKEY key, LPCWSTR valueName)
{
    if (g_inHook || !HooksEnabled() || g_originalRegDeleteValueW == nullptr)
    {
        if (g_originalRegDeleteValueW == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegDeleteValueW(key, valueName);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegDeleteValueW(key, valueName);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegDeleteValueWEvent(result, start, end, key, valueName);
    }

    return result;
}

LSTATUS WINAPI HookedRegCloseKey(HKEY key)
{
    if (g_inHook || !HooksEnabled() || g_originalRegCloseKey == nullptr)
    {
        if (g_originalRegCloseKey == nullptr)
        {
            return ERROR_PROC_NOT_FOUND;
        }

        return g_originalRegCloseKey(key);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const LSTATUS result = g_originalRegCloseKey(key);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRegCloseKeyEvent(result, start, end, key);
    }

    return result;
}

BOOL WINAPI HookedOpenProcessToken(HANDLE process, DWORD desiredAccess, PHANDLE token)
{
    if (g_inHook || !HooksEnabled() || g_originalOpenProcessToken == nullptr)
    {
        if (g_originalOpenProcessToken == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalOpenProcessToken(process, desiredAccess, token);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalOpenProcessToken(process, desiredAccess, token);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitOpenProcessTokenEvent(result, eventError, start, end, process, desiredAccess, token);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedLookupPrivilegeValueW(LPCWSTR systemName, LPCWSTR name, PLUID luid)
{
    if (g_inHook || !HooksEnabled() || g_originalLookupPrivilegeValueW == nullptr)
    {
        if (g_originalLookupPrivilegeValueW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalLookupPrivilegeValueW(systemName, name, luid);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalLookupPrivilegeValueW(systemName, name, luid);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitLookupPrivilegeValueWEvent(result, eventError, start, end, systemName, name, luid);
    }

    SetLastError(lastError);
    return result;
}

NTSTATUS WINAPI HookedBCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* algorithm, LPCWSTR algorithmId, LPCWSTR implementation, ULONG flags)
{
    if (g_inHook || !HooksEnabled() || g_originalBCryptOpenAlgorithmProvider == nullptr)
    {
        if (g_originalBCryptOpenAlgorithmProvider == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalBCryptOpenAlgorithmProvider(algorithm, algorithmId, implementation, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const NTSTATUS status = g_originalBCryptOpenAlgorithmProvider(algorithm, algorithmId, implementation, flags);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitBCryptOpenAlgorithmProviderEvent(status, eventError, start, end, algorithm, algorithmId, implementation, flags);
    }

    return status;
}

NTSTATUS WINAPI HookedBCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE algorithm, ULONG flags)
{
    if (g_inHook || !HooksEnabled() || g_originalBCryptCloseAlgorithmProvider == nullptr)
    {
        if (g_originalBCryptCloseAlgorithmProvider == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalBCryptCloseAlgorithmProvider(algorithm, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const NTSTATUS status = g_originalBCryptCloseAlgorithmProvider(algorithm, flags);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitBCryptCloseAlgorithmProviderEvent(status, eventError, start, end, algorithm, flags);
    }

    return status;
}

NTSTATUS WINAPI HookedBCryptGetProperty(BCRYPT_HANDLE object, LPCWSTR property, PUCHAR output, ULONG outputBytes, ULONG* resultBytes, ULONG flags)
{
    if (g_inHook || !HooksEnabled() || g_originalBCryptGetProperty == nullptr)
    {
        if (g_originalBCryptGetProperty == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalBCryptGetProperty(object, property, output, outputBytes, resultBytes, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const NTSTATUS status = g_originalBCryptGetProperty(object, property, output, outputBytes, resultBytes, flags);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitBCryptGetPropertyEvent(status, eventError, start, end, object, property, output, outputBytes, resultBytes, flags);
    }

    return status;
}

NTSTATUS WINAPI HookedBCryptGenRandom(BCRYPT_ALG_HANDLE algorithm, PUCHAR buffer, ULONG bufferBytes, ULONG flags)
{
    if (g_inHook || !HooksEnabled() || g_originalBCryptGenRandom == nullptr)
    {
        if (g_originalBCryptGenRandom == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000007AL);
        }

        return g_originalBCryptGenRandom(algorithm, buffer, bufferBytes, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const NTSTATUS status = g_originalBCryptGenRandom(algorithm, buffer, bufferBytes, flags);
    QueryPerformanceCounter(&end);

    const DWORD eventError = NtStatusToDosError(status);
    if (HooksEnabled())
    {
        EmitBCryptGenRandomEvent(status, eventError, start, end, algorithm, buffer, bufferBytes, flags);
    }

    return status;
}

HCERTSTORE WINAPI HookedCertOpenStore(LPCSTR provider, DWORD encodingType, HCRYPTPROV_LEGACY cryptProvider, DWORD flags, const void* parameters)
{
    if (g_inHook || !HooksEnabled() || g_originalCertOpenStore == nullptr)
    {
        if (g_originalCertOpenStore == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCertOpenStore(provider, encodingType, cryptProvider, flags, parameters);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HCERTSTORE result = g_originalCertOpenStore(provider, encodingType, cryptProvider, flags, parameters);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCertOpenStoreEvent(result, eventError, start, end, provider, encodingType, cryptProvider, flags, parameters);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedCertCloseStore(HCERTSTORE store, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalCertCloseStore == nullptr)
    {
        if (g_originalCertCloseStore == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalCertCloseStore(store, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalCertCloseStore(store, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCertCloseStoreEvent(result, eventError, start, end, store, flags);
    }

    SetLastError(lastError);
    return result;
}

HCRYPTMSG WINAPI HookedCryptMsgOpenToDecode(
    DWORD encodingType,
    DWORD flags,
    DWORD messageType,
    HCRYPTPROV_LEGACY cryptProvider,
    PCERT_INFO recipientInfo,
    PCMSG_STREAM_INFO streamInfo)
{
    if (g_inHook || !HooksEnabled() || g_originalCryptMsgOpenToDecode == nullptr)
    {
        if (g_originalCryptMsgOpenToDecode == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCryptMsgOpenToDecode(encodingType, flags, messageType, cryptProvider, recipientInfo, streamInfo);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HCRYPTMSG result = g_originalCryptMsgOpenToDecode(encodingType, flags, messageType, cryptProvider, recipientInfo, streamInfo);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCryptMsgOpenToDecodeEvent(result, eventError, start, end, encodingType, flags, messageType, cryptProvider, recipientInfo, streamInfo);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedCryptMsgClose(HCRYPTMSG message)
{
    if (g_inHook || !HooksEnabled() || g_originalCryptMsgClose == nullptr)
    {
        if (g_originalCryptMsgClose == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalCryptMsgClose(message);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalCryptMsgClose(message);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCryptMsgCloseEvent(result, eventError, start, end, message);
    }

    SetLastError(lastError);
    return result;
}

HINTERNET WINAPI HookedInternetOpenW(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR proxyBypass, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalInternetOpenW == nullptr)
    {
        if (g_originalInternetOpenW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalInternetOpenW(agent, accessType, proxy, proxyBypass, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HINTERNET result = g_originalInternetOpenW(agent, accessType, proxy, proxyBypass, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitInternetOpenWEvent(result, eventError, start, end, agent, accessType, proxy, proxyBypass, flags);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedInternetCloseHandle(HINTERNET internet)
{
    if (g_inHook || !HooksEnabled() || g_originalInternetCloseHandle == nullptr)
    {
        if (g_originalInternetCloseHandle == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalInternetCloseHandle(internet);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalInternetCloseHandle(internet);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitInternetCloseHandleEvent(result, eventError, start, end, internet);
    }

    SetLastError(lastError);
    return result;
}

HINTERNET WINAPI HookedWinHttpOpen(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR proxyBypass, DWORD flags)
{
    if (g_inHook || !HooksEnabled() || g_originalWinHttpOpen == nullptr)
    {
        if (g_originalWinHttpOpen == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalWinHttpOpen(agent, accessType, proxy, proxyBypass, flags);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HINTERNET result = g_originalWinHttpOpen(agent, accessType, proxy, proxyBypass, flags);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitWinHttpOpenEvent(result, eventError, start, end, agent, accessType, proxy, proxyBypass, flags);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedWinHttpCloseHandle(HINTERNET internet)
{
    if (g_inHook || !HooksEnabled() || g_originalWinHttpCloseHandle == nullptr)
    {
        if (g_originalWinHttpCloseHandle == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalWinHttpCloseHandle(internet);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalWinHttpCloseHandle(internet);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitWinHttpCloseHandleEvent(result, eventError, start, end, internet);
    }

    SetLastError(lastError);
    return result;
}

int WINAPI HookedGetSystemMetrics(int index)
{
    if (g_inHook || !HooksEnabled() || g_originalGetSystemMetrics == nullptr)
    {
        if (g_originalGetSystemMetrics == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetSystemMetrics(index);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalGetSystemMetrics(index);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetSystemMetricsEvent(result, start, end, index);
    }

    SetLastError(lastError);
    return result;
}

HWND WINAPI HookedGetDesktopWindow()
{
    if (g_inHook || !HooksEnabled() || g_originalGetDesktopWindow == nullptr)
    {
        if (g_originalGetDesktopWindow == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetDesktopWindow();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HWND result = g_originalGetDesktopWindow();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetDesktopWindowEvent(result, start, end);
    }

    SetLastError(lastError);
    return result;
}

HWND WINAPI HookedGetForegroundWindow()
{
    if (g_inHook || !HooksEnabled() || g_originalGetForegroundWindow == nullptr)
    {
        if (g_originalGetForegroundWindow == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalGetForegroundWindow();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HWND result = g_originalGetForegroundWindow();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetForegroundWindowEvent(result, start, end);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetWindowThreadProcessId(HWND window, LPDWORD processId)
{
    if (g_inHook || !HooksEnabled() || g_originalGetWindowThreadProcessId == nullptr)
    {
        if (g_originalGetWindowThreadProcessId == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetWindowThreadProcessId(window, processId);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const DWORD result = g_originalGetWindowThreadProcessId(window, processId);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetWindowThreadProcessIdEvent(result, start, end, window, processId);
    }

    SetLastError(lastError);
    return result;
}

HDC WINAPI HookedCreateCompatibleDC(HDC dc)
{
    if (g_inHook || !HooksEnabled() || g_originalCreateCompatibleDC == nullptr)
    {
        if (g_originalCreateCompatibleDC == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return nullptr;
        }

        return g_originalCreateCompatibleDC(dc);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    HDC result = g_originalCreateCompatibleDC(dc);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == nullptr ? lastError : 0;
    if (HooksEnabled())
    {
        EmitCreateCompatibleDCEvent(result, eventError, start, end, dc);
    }

    SetLastError(lastError);
    return result;
}

int WINAPI HookedGetDeviceCaps(HDC dc, int index)
{
    if (g_inHook || !HooksEnabled() || g_originalGetDeviceCaps == nullptr)
    {
        if (g_originalGetDeviceCaps == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetDeviceCaps(dc, index);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalGetDeviceCaps(dc, index);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetDeviceCapsEvent(result, start, end, dc, index);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedDeleteDC(HDC dc)
{
    if (g_inHook || !HooksEnabled() || g_originalDeleteDC == nullptr)
    {
        if (g_originalDeleteDC == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalDeleteDC(dc);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalDeleteDC(dc);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitDeleteDCEvent(result, eventError, start, end, dc);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedEnumProcessModules(HANDLE process, HMODULE* modules, DWORD requestedBytes, LPDWORD neededBytes)
{
    if (g_inHook || !HooksEnabled() || g_originalEnumProcessModules == nullptr)
    {
        if (g_originalEnumProcessModules == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalEnumProcessModules(process, modules, requestedBytes, neededBytes);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalEnumProcessModules(process, modules, requestedBytes, neededBytes);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitEnumProcessModulesEvent(result, eventError, start, end, process, modules, requestedBytes, neededBytes);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedGetModuleInformation(HANDLE process, HMODULE module, LPMODULEINFO moduleInfo, DWORD requestedBytes)
{
    if (g_inHook || !HooksEnabled() || g_originalGetModuleInformation == nullptr)
    {
        if (g_originalGetModuleInformation == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalGetModuleInformation(process, module, moduleInfo, requestedBytes);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalGetModuleInformation(process, module, moduleInfo, requestedBytes);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetModuleInformationEvent(result, eventError, start, end, process, module, moduleInfo, requestedBytes);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetModuleBaseNameW(HANDLE process, HMODULE module, LPWSTR baseName, DWORD sizeChars)
{
    if (g_inHook || !HooksEnabled() || g_originalGetModuleBaseNameW == nullptr)
    {
        if (g_originalGetModuleBaseNameW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetModuleBaseNameW(process, module, baseName, sizeChars);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const DWORD result = g_originalGetModuleBaseNameW(process, module, baseName, sizeChars);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetModuleBaseNameWEvent(result, eventError, start, end, process, module, baseName, sizeChars);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetModuleFileNameExW(HANDLE process, HMODULE module, LPWSTR fileName, DWORD sizeChars)
{
    if (g_inHook || !HooksEnabled() || g_originalGetModuleFileNameExW == nullptr)
    {
        if (g_originalGetModuleFileNameExW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetModuleFileNameExW(process, module, fileName, sizeChars);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const DWORD result = g_originalGetModuleFileNameExW(process, module, fileName, sizeChars);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetModuleFileNameExWEvent(result, eventError, start, end, process, module, fileName, sizeChars);
    }

    SetLastError(lastError);
    return result;
}

DWORD WINAPI HookedGetFileVersionInfoSizeW(LPCWSTR fileName, LPDWORD handle)
{
    if (g_inHook || !HooksEnabled() || g_originalGetFileVersionInfoSizeW == nullptr)
    {
        if (g_originalGetFileVersionInfoSizeW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalGetFileVersionInfoSizeW(fileName, handle);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const DWORD result = g_originalGetFileVersionInfoSizeW(fileName, handle);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == 0 ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetFileVersionInfoSizeWEvent(result, eventError, start, end, fileName, handle);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedGetFileVersionInfoW(LPCWSTR fileName, DWORD handle, DWORD length, LPVOID data)
{
    if (g_inHook || !HooksEnabled() || g_originalGetFileVersionInfoW == nullptr)
    {
        if (g_originalGetFileVersionInfoW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalGetFileVersionInfoW(fileName, handle, length, data);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalGetFileVersionInfoW(fileName, handle, length, data);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitGetFileVersionInfoWEvent(result, eventError, start, end, fileName, handle, length, data);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedVerQueryValueW(LPCVOID block, LPCWSTR subBlock, LPVOID* value, PUINT length)
{
    if (g_inHook || !HooksEnabled() || g_originalVerQueryValueW == nullptr)
    {
        if (g_originalVerQueryValueW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalVerQueryValueW(block, subBlock, value, length);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalVerQueryValueW(block, subBlock, value, length);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitVerQueryValueWEvent(result, eventError, start, end, block, subBlock, value, length);
    }

    SetLastError(lastError);
    return result;
}

HRESULT WINAPI HookedSHGetKnownFolderPath(REFKNOWNFOLDERID knownFolderId, DWORD flags, HANDLE token, PWSTR* path)
{
    if (g_inHook || !HooksEnabled() || g_originalSHGetKnownFolderPath == nullptr)
    {
        if (g_originalSHGetKnownFolderPath == nullptr)
        {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        return g_originalSHGetKnownFolderPath(knownFolderId, flags, token, path);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const HRESULT result = g_originalSHGetKnownFolderPath(knownFolderId, flags, token, path);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = FAILED(result) ? static_cast<DWORD>(result) : 0;
    if (HooksEnabled())
    {
        EmitSHGetKnownFolderPathEvent(result, eventError, start, end, knownFolderId, flags, token, path);
    }

    SetLastError(lastError);
    return result;
}

BOOL WINAPI HookedSHGetSpecialFolderPathW(HWND window, LPWSTR path, int csidl, BOOL create)
{
    if (g_inHook || !HooksEnabled() || g_originalSHGetSpecialFolderPathW == nullptr)
    {
        if (g_originalSHGetSpecialFolderPathW == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }

        return g_originalSHGetSpecialFolderPathW(window, path, csidl, create);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const BOOL result = g_originalSHGetSpecialFolderPathW(window, path, csidl, create);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = result == FALSE ? lastError : 0;
    if (HooksEnabled())
    {
        EmitSHGetSpecialFolderPathWEvent(result, eventError, start, end, window, path, csidl, create);
    }

    SetLastError(lastError);
    return result;
}

HRESULT WINAPI HookedCoInitializeEx(LPVOID reserved, DWORD coInit)
{
    if (g_inHook || !HooksEnabled() || g_originalCoInitializeEx == nullptr)
    {
        if (g_originalCoInitializeEx == nullptr)
        {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        return g_originalCoInitializeEx(reserved, coInit);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const HRESULT result = g_originalCoInitializeEx(reserved, coInit);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = FAILED(result) ? static_cast<DWORD>(result) : 0;
    if (HooksEnabled())
    {
        EmitCoInitializeExEvent(result, eventError, start, end, reserved, coInit);
    }

    SetLastError(lastError);
    return result;
}

void WINAPI HookedCoUninitialize()
{
    if (g_inHook || !HooksEnabled() || g_originalCoUninitialize == nullptr)
    {
        if (g_originalCoUninitialize == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return;
        }

        g_originalCoUninitialize();
        return;
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    g_originalCoUninitialize();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitCoUninitializeEvent(start, end);
    }

    SetLastError(lastError);
}

HRESULT WINAPI HookedCoCreateGuid(GUID* guid)
{
    if (g_inHook || !HooksEnabled() || g_originalCoCreateGuid == nullptr)
    {
        if (g_originalCoCreateGuid == nullptr)
        {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        return g_originalCoCreateGuid(guid);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const HRESULT result = g_originalCoCreateGuid(guid);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = FAILED(result) ? static_cast<DWORD>(result) : 0;
    if (HooksEnabled())
    {
        EmitCoCreateGuidEvent(result, eventError, start, end, guid);
    }

    SetLastError(lastError);
    return result;
}

int WINAPI HookedStringFromGUID2(REFGUID guid, LPOLESTR string, int cchMax)
{
    if (g_inHook || !HooksEnabled() || g_originalStringFromGUID2 == nullptr)
    {
        if (g_originalStringFromGUID2 == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return 0;
        }

        return g_originalStringFromGUID2(guid, string, cchMax);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalStringFromGUID2(guid, string, cchMax);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitStringFromGUID2Event(result, 0, start, end, guid, string, cchMax);
    }

    SetLastError(lastError);
    return result;
}

HRESULT WINAPI HookedRoInitialize(RO_INIT_TYPE initType)
{
    if (g_inHook || !HooksEnabled() || g_originalRoInitialize == nullptr)
    {
        if (g_originalRoInitialize == nullptr)
        {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        return g_originalRoInitialize(initType);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const HRESULT result = g_originalRoInitialize(initType);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = FAILED(result) ? static_cast<DWORD>(result) : 0;
    if (HooksEnabled())
    {
        EmitRoInitializeEvent(result, eventError, start, end, initType);
    }

    SetLastError(lastError);
    return result;
}

void WINAPI HookedRoUninitialize()
{
    if (g_inHook || !HooksEnabled() || g_originalRoUninitialize == nullptr)
    {
        if (g_originalRoUninitialize == nullptr)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return;
        }

        g_originalRoUninitialize();
        return;
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    g_originalRoUninitialize();
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRoUninitializeEvent(start, end);
    }

    SetLastError(lastError);
}

HRESULT WINAPI HookedRoGetApartmentIdentifier(UINT64* apartmentIdentifier)
{
    if (g_inHook || !HooksEnabled() || g_originalRoGetApartmentIdentifier == nullptr)
    {
        if (g_originalRoGetApartmentIdentifier == nullptr)
        {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        return g_originalRoGetApartmentIdentifier(apartmentIdentifier);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const HRESULT result = g_originalRoGetApartmentIdentifier(apartmentIdentifier);
    const DWORD lastError = GetLastError();
    QueryPerformanceCounter(&end);

    const DWORD eventError = FAILED(result) ? static_cast<DWORD>(result) : 0;
    if (HooksEnabled())
    {
        EmitRoGetApartmentIdentifierEvent(result, eventError, start, end, apartmentIdentifier);
    }

    SetLastError(lastError);
    return result;
}

RPC_STATUS RPC_ENTRY HookedRpcStringBindingComposeW(RPC_WSTR objUuid, RPC_WSTR protSeq, RPC_WSTR networkAddr, RPC_WSTR endpoint, RPC_WSTR options, RPC_WSTR* stringBinding)
{
    if (g_inHook || !HooksEnabled() || g_originalRpcStringBindingComposeW == nullptr)
    {
        if (g_originalRpcStringBindingComposeW == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalRpcStringBindingComposeW(objUuid, protSeq, networkAddr, endpoint, options, stringBinding);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalRpcStringBindingComposeW(objUuid, protSeq, networkAddr, endpoint, options, stringBinding);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRpcStringBindingComposeWEvent(result, start, end, objUuid, protSeq, networkAddr, endpoint, options, stringBinding);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedRpcBindingFromStringBindingW(RPC_WSTR stringBinding, RPC_BINDING_HANDLE* binding)
{
    if (g_inHook || !HooksEnabled() || g_originalRpcBindingFromStringBindingW == nullptr)
    {
        if (g_originalRpcBindingFromStringBindingW == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalRpcBindingFromStringBindingW(stringBinding, binding);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalRpcBindingFromStringBindingW(stringBinding, binding);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitRpcBindingFromStringBindingWEvent(result, start, end, stringBinding, binding);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedRpcStringFreeW(RPC_WSTR* string)
{
    if (g_inHook || !HooksEnabled() || g_originalRpcStringFreeW == nullptr)
    {
        if (g_originalRpcStringFreeW == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalRpcStringFreeW(string);
    }

    HookReentryGuard guard;
    RPC_WSTR preString = nullptr;
    char preStringText[knmon::KnMonTransportText0Bytes] = {};
    std::uint32_t preStringTextStatus = static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::Decoded);

    if (ReadCurrentProcessValue(string, &preString))
    {
        preStringTextStatus = CopyRpcWideStringText(preStringText, nullptr, sizeof(preStringText), preString);
    }
    else
    {
        preStringTextStatus = string == nullptr ?
            static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::InvalidPointer) :
            static_cast<std::uint32_t>(knmon::KnMonDecodeStatus::UnreadableMemory);
    }

    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalRpcStringFreeW(string);
    QueryPerformanceCounter(&end);

    RPC_WSTR postString = nullptr;
    ReadCurrentProcessValue(string, &postString);

    if (HooksEnabled())
    {
        EmitRpcStringFreeWEvent(result, start, end, string, preString, postString, preStringText, preStringTextStatus);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedRpcBindingFree(RPC_BINDING_HANDLE* binding)
{
    if (g_inHook || !HooksEnabled() || g_originalRpcBindingFree == nullptr)
    {
        if (g_originalRpcBindingFree == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalRpcBindingFree(binding);
    }

    HookReentryGuard guard;
    RPC_BINDING_HANDLE preBinding = nullptr;
    ReadCurrentProcessValue(binding, &preBinding);

    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalRpcBindingFree(binding);
    QueryPerformanceCounter(&end);

    RPC_BINDING_HANDLE postBinding = nullptr;
    ReadCurrentProcessValue(binding, &postBinding);

    if (HooksEnabled())
    {
        EmitRpcBindingFreeEvent(result, start, end, binding, preBinding, postBinding);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedUuidCreate(UUID* uuid)
{
    if (g_inHook || !HooksEnabled() || g_originalUuidCreate == nullptr)
    {
        if (g_originalUuidCreate == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalUuidCreate(uuid);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalUuidCreate(uuid);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitUuidCreateEvent(result, start, end, uuid);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedUuidToStringW(UUID* uuid, RPC_WSTR* stringUuid)
{
    if (g_inHook || !HooksEnabled() || g_originalUuidToStringW == nullptr)
    {
        if (g_originalUuidToStringW == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalUuidToStringW(uuid, stringUuid);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalUuidToStringW(uuid, stringUuid);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitUuidToStringWEvent(result, start, end, uuid, stringUuid);
    }

    return result;
}

RPC_STATUS RPC_ENTRY HookedUuidFromStringW(RPC_WSTR stringUuid, UUID* uuid)
{
    if (g_inHook || !HooksEnabled() || g_originalUuidFromStringW == nullptr)
    {
        if (g_originalUuidFromStringW == nullptr)
        {
            return RPC_S_CALL_FAILED;
        }

        return g_originalUuidFromStringW(stringUuid, uuid);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const RPC_STATUS result = g_originalUuidFromStringW(stringUuid, uuid);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitUuidFromStringWEvent(result, start, end, stringUuid, uuid);
    }

    return result;
}

int WINAPI HookedWSAStartup(WORD versionRequested, LPWSADATA data)
{
    if (g_inHook || !HooksEnabled() || g_originalWSAStartup == nullptr)
    {
        if (g_originalWSAStartup == nullptr)
        {
            return WSASYSNOTREADY;
        }

        return g_originalWSAStartup(versionRequested, data);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalWSAStartup(versionRequested, data);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitWSAStartupEvent(result, start, end, versionRequested, data);
    }

    return result;
}

int WINAPI HookedWSACleanup()
{
    if (g_inHook || !HooksEnabled() || g_originalWSACleanup == nullptr)
    {
        if (g_originalWSACleanup == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_originalWSACleanup();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalWSACleanup();
    const DWORD errorCode = result == SOCKET_ERROR && g_originalWSAGetLastError != nullptr ? static_cast<DWORD>(g_originalWSAGetLastError()) : 0;
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitWSACleanupEvent(result, errorCode, start, end);
    }

    return result;
}

SOCKET WINAPI HookedSocket(int af, int type, int protocol)
{
    if (g_inHook || !HooksEnabled() || g_originalSocket == nullptr)
    {
        if (g_originalSocket == nullptr)
        {
            return INVALID_SOCKET;
        }

        return g_originalSocket(af, type, protocol);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const SOCKET result = g_originalSocket(af, type, protocol);
    const DWORD errorCode = result == INVALID_SOCKET && g_originalWSAGetLastError != nullptr ? static_cast<DWORD>(g_originalWSAGetLastError()) : 0;
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitSocketEvent(result, errorCode, start, end, af, type, protocol);
    }

    return result;
}

int WINAPI HookedClosesocket(SOCKET socketValue)
{
    if (g_inHook || !HooksEnabled() || g_originalClosesocket == nullptr)
    {
        if (g_originalClosesocket == nullptr)
        {
            return SOCKET_ERROR;
        }

        return g_originalClosesocket(socketValue);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalClosesocket(socketValue);
    const DWORD errorCode = result == SOCKET_ERROR && g_originalWSAGetLastError != nullptr ? static_cast<DWORD>(g_originalWSAGetLastError()) : 0;
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitClosesocketEvent(result, errorCode, start, end, socketValue);
    }

    return result;
}

int WINAPI HookedGetAddrInfo(PCSTR nodeName, PCSTR serviceName, const ADDRINFOA* hints, PADDRINFOA* resultValue)
{
    if (g_inHook || !HooksEnabled() || g_originalGetAddrInfo == nullptr)
    {
        if (g_originalGetAddrInfo == nullptr)
        {
            return EAI_FAIL;
        }

        return g_originalGetAddrInfo(nodeName, serviceName, hints, resultValue);
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalGetAddrInfo(nodeName, serviceName, hints, resultValue);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitGetAddrInfoEvent(result, start, end, nodeName, serviceName, hints, resultValue);
    }

    return result;
}

void WINAPI HookedFreeAddrInfo(PADDRINFOA addrInfo)
{
    if (g_inHook || !HooksEnabled() || g_originalFreeAddrInfo == nullptr)
    {
        if (g_originalFreeAddrInfo != nullptr)
        {
            g_originalFreeAddrInfo(addrInfo);
        }

        return;
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    g_originalFreeAddrInfo(addrInfo);
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitFreeAddrInfoEvent(start, end, addrInfo);
    }
}

int WINAPI HookedWSAGetLastError()
{
    if (g_inHook || !HooksEnabled() || g_originalWSAGetLastError == nullptr)
    {
        if (g_originalWSAGetLastError == nullptr)
        {
            return 0;
        }

        return g_originalWSAGetLastError();
    }

    HookReentryGuard guard;
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};
    QueryPerformanceCounter(&start);
    const int result = g_originalWSAGetLastError();
    QueryPerformanceCounter(&end);

    if (HooksEnabled())
    {
        EmitWSAGetLastErrorEvent(result, start, end);
    }

    return result;
}

bool InstallHooks()
{
    const bool allInstalled = SweepLoadedModules("initial", true, nullptr);

    if (allInstalled)
    {
        SetLifecycleState(AgentLifecycleState::Running);
        InterlockedExchange(&g_hooksEnabled, 1);
    }

    return allInstalled;
}

void CloseAgentPipe()
{
    AcquireSRWLockExclusive(&g_pipeLock);
    if (g_pipeHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_pipeHandle);
        g_pipeHandle = INVALID_HANDLE_VALUE;
    }
    ReleaseSRWLockExclusive(&g_pipeLock);
}

void ShutdownAgent(const char* reason, AgentLifecycleState finalState)
{
    const AgentLifecycleState previousState = GetLifecycleState();
    if (previousState == AgentLifecycleState::Stopping || previousState == AgentLifecycleState::Disabled || previousState == AgentLifecycleState::Failed)
    {
        return;
    }

    SetLifecycleState(AgentLifecycleState::Stopping);
    HookLifecycleCounts counts = UninstallHooks();
    SetLifecycleState(finalState);
    SendAgentShutdown(reason, counts);
    CloseTransport();
    CloseAgentPipe();
}

bool DisabledAgentCanReinitialize(const HookLifecycleCounts& counts)
{
    return counts.FailedHooks == 0 && counts.InstalledHooks == counts.RestoredHooks;
}

bool ResetDisabledAgentForReinitialize()
{
    bool reset = false;

    do
    {
        if (GetLifecycleState() != AgentLifecycleState::Disabled)
        {
            break;
        }

        const HookLifecycleCounts counts = SnapshotHookCounts();
        if (!DisabledAgentCanReinitialize(counts))
        {
            break;
        }

        CloseTransport();
        CloseAgentPipe();

        AcquireSRWLockExclusive(&g_hookLock);
        for (HookRecord& record : g_hookRecords)
        {
            record = {};
        }
        g_hookRecordCount = 0;
        ReleaseSRWLockExclusive(&g_hookLock);

        InterlockedExchange(&g_failedHooks, 0);
        InterlockedExchange(&g_hooksEnabled, 0);
        InterlockedExchange64(&g_droppedEvents, 0);
        InterlockedExchange64(&g_sequence, 0);
        g_operationId.clear();
        InterlockedExchange(&g_workerStarted, 0);
        SetLifecycleState(AgentLifecycleState::Starting);
        reset = true;
    }
    while (false);

    return reset;
}

DWORD WINAPI AgentWorker(void* context)
{
    auto* suppliedConfig = reinterpret_cast<AgentWorkerConfig*>(context);
    AgentWorkerConfig runtimeConfig;

    if (suppliedConfig != nullptr)
    {
        runtimeConfig = *suppliedConfig;
        delete suppliedConfig;
        suppliedConfig = nullptr;
    }
    else
    {
        runtimeConfig.PipeName = ReadEnv(L"KNMON_AGENT_PIPE");
        runtimeConfig.TransportName = ReadEnv(L"KNMON_TRANSPORT_NAME");
        runtimeConfig.OperationId = ReadEnv(L"KNMON_OPERATION_ID");
        runtimeConfig.TransportRequired = EnvEnabled(L"KNMON_TRANSPORT_REQUIRED");
    }

    g_operationId = runtimeConfig.OperationId;

    do
    {
        if (runtimeConfig.PipeName.empty())
        {
            break;
        }

        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 50; ++attempt)
        {
            pipeHandle = CreateFileW(
                runtimeConfig.PipeName.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (pipeHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            if (GetLastError() != ERROR_PIPE_BUSY)
            {
                Sleep(50);
            }
            else
            {
                WaitNamedPipeW(runtimeConfig.PipeName.c_str(), 100);
            }
        }

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        AcquireSRWLockExclusive(&g_pipeLock);
        g_pipeHandle = pipeHandle;
        ReleaseSRWLockExclusive(&g_pipeLock);

        SendHello();

        if (runtimeConfig.TransportRequired && !OpenTransport(runtimeConfig.TransportName))
        {
            SendHookStatus("knmon-transport", "shared_memory", false, "Required shared-memory transport could not be opened by the agent.");
            SendDroppedEvents();
            ShutdownAgent("transport_open_failed", AgentLifecycleState::Failed);
            break;
        }

        if (!InstallHooks())
        {
            SendDroppedEvents();
            ShutdownAgent("hook_install_failed", AgentLifecycleState::Failed);
            break;
        }

        SendDroppedEvents();
    }
    while (false);

    return 0;
}

knmon::KnMonAgentControlStatus StartAgentWorker(AgentWorkerConfig* config)
{
    knmon::KnMonAgentControlStatus status = knmon::KnMonAgentControlStatus::WorkerStartFailed;

    do
    {
        const AgentLifecycleState state = GetLifecycleState();
        if (state == AgentLifecycleState::Disabled)
        {
            if (!ResetDisabledAgentForReinitialize())
            {
                status = knmon::KnMonAgentControlStatus::InvalidState;
                break;
            }
        }
        else if (state == AgentLifecycleState::Running || state == AgentLifecycleState::Stopping)
        {
            status = knmon::KnMonAgentControlStatus::AlreadyRunning;
            break;
        }
        else if (state == AgentLifecycleState::Failed)
        {
            status = knmon::KnMonAgentControlStatus::InvalidState;
            break;
        }

        if (InterlockedCompareExchange(&g_workerStarted, 1, 0) != 0)
        {
            status = knmon::KnMonAgentControlStatus::AlreadyRunning;
            break;
        }

        HANDLE threadHandle = CreateThread(nullptr, 0, AgentWorker, config, 0, nullptr);
        if (threadHandle == nullptr)
        {
            InterlockedExchange(&g_workerStarted, 0);
            SetLifecycleState(AgentLifecycleState::Failed);
            status = knmon::KnMonAgentControlStatus::WorkerStartFailed;
            break;
        }

        CloseHandle(threadHandle);
        status = knmon::KnMonAgentControlStatus::Success;
    }
    while (false);

    if (status != knmon::KnMonAgentControlStatus::Success)
    {
        delete config;
    }

    return status;
}

bool LaunchEnvironmentConfigured()
{
    wchar_t value[2] = {};
    const DWORD length = GetEnvironmentVariableW(L"KNMON_AGENT_PIPE", value, static_cast<DWORD>(std::size(value)));
    return length > 0;
}

void CopyCurrentOperationId(wchar_t* destination, std::size_t capacity)
{
    if (destination == nullptr || capacity == 0)
    {
        return;
    }

    const std::size_t count = std::min(capacity - 1, g_operationId.size());
    for (std::size_t index = 0; index < count; ++index)
    {
        destination[index] = g_operationId[index];
    }
    destination[count] = L'\0';
}

void FillAgentState(knmon::KnMonAgentStateV1* state)
{
    if (state == nullptr)
    {
        return;
    }

    const AgentLifecycleState lifecycle = GetLifecycleState();
    const HookLifecycleCounts counts = SnapshotHookCounts();
    const LONG workerStarted = InterlockedCompareExchange(&g_workerStarted, 0, 0);
    const LONG hooksEnabled = InterlockedCompareExchange(&g_hooksEnabled, 0, 0);

    knmon::KnMonAgentStateV1 output;
    output.StructSize = static_cast<std::uint16_t>(sizeof(output));
    output.LifecycleState = PublicLifecycleState(lifecycle);
    output.WorkerStarted = workerStarted != 0 ? 1 : 0;
    output.HooksEnabled = hooksEnabled != 0 ? 1 : 0;
    output.AgentVersion = AgentVersionPacked;
    output.InstalledHooks = static_cast<std::uint32_t>(std::max(counts.InstalledHooks, 0));
    output.RestoredHooks = static_cast<std::uint32_t>(std::max(counts.RestoredHooks, 0));
    output.FailedHooks = static_cast<std::uint32_t>(std::max(counts.FailedHooks, 0));
    output.DroppedEvents = static_cast<std::uint64_t>(std::max<LONG64>(InterlockedCompareExchange64(&g_droppedEvents, 0, 0), 0));

    if (lifecycle == AgentLifecycleState::Disabled && DisabledAgentCanReinitialize(counts))
    {
        output.Flags |= knmon::KnMonAgentStateFlagResettable;
    }

    if (lifecycle == AgentLifecycleState::Running || hooksEnabled != 0)
    {
        output.Flags |= knmon::KnMonAgentStateFlagActive;
    }

    if (
        lifecycle == AgentLifecycleState::Starting ||
        lifecycle == AgentLifecycleState::Stopping ||
        (workerStarted != 0 && lifecycle != AgentLifecycleState::Disabled))
    {
        output.Flags |= knmon::KnMonAgentStateFlagBusy;
    }

    CopyCurrentOperationId(output.OperationId, std::size(output.OperationId));
    *state = output;
}
}

extern "C" __declspec(dllexport) DWORD KnMonAgentVersion()
{
    return AgentVersionPacked;
}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:KnMonAgentInitialize=_KnMonAgentInitialize@4")
#pragma comment(linker, "/EXPORT:KnMonAgentStop=_KnMonAgentStop@0")
#pragma comment(linker, "/EXPORT:KnMonAgentQueryState=_KnMonAgentQueryState@4")
#endif

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentQueryState(knmon::KnMonAgentStateV1* state)
{
    knmon::KnMonAgentControlStatus status = knmon::KnMonAgentControlStatus::InvalidConfig;

    do
    {
        if (state == nullptr)
        {
            break;
        }

        if (state->Magic != knmon::KnMonAgentStateMagic)
        {
            break;
        }

        if (state->AbiVersion != knmon::KnMonAgentStateAbiVersion || state->StructSize < sizeof(knmon::KnMonAgentStateV1))
        {
            status = knmon::KnMonAgentControlStatus::UnsupportedAbi;
            break;
        }

        FillAgentState(state);
        status = knmon::KnMonAgentControlStatus::Success;
    }
    while (false);

    return static_cast<DWORD>(status);
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentInitialize(const knmon::KnMonAttachConfigV1* config)
{
    AgentWorkerConfig workerConfig;
    knmon::KnMonAgentControlStatus status = CopyAttachConfig(config, &workerConfig);

    if (status == knmon::KnMonAgentControlStatus::Success)
    {
        auto* heapConfig = new (std::nothrow) AgentWorkerConfig(workerConfig);
        if (heapConfig == nullptr)
        {
            status = knmon::KnMonAgentControlStatus::WorkerStartFailed;
        }
        else
        {
            status = StartAgentWorker(heapConfig);
        }
    }

    return static_cast<DWORD>(status);
}

extern "C" __declspec(dllexport) DWORD WINAPI KnMonAgentStop()
{
    knmon::KnMonAgentControlStatus status = knmon::KnMonAgentControlStatus::Success;
    const AgentLifecycleState state = GetLifecycleState();

    if (state == AgentLifecycleState::Starting && InterlockedCompareExchange(&g_workerStarted, 0, 0) == 0)
    {
        status = knmon::KnMonAgentControlStatus::NotRunning;
    }
    else if (state == AgentLifecycleState::Disabled || state == AgentLifecycleState::Failed)
    {
        status = knmon::KnMonAgentControlStatus::NotRunning;
    }
    else
    {
        ShutdownAgent("self_disable", AgentLifecycleState::Disabled);
    }

    return static_cast<DWORD>(status);
}

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH)
    {
        g_agentModule = moduleHandle;
        DisableThreadLibraryCalls(moduleHandle);
        if (LaunchEnvironmentConfigured())
        {
            (void)StartAgentWorker(nullptr);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        ShutdownAgent("process_detach", AgentLifecycleState::Disabled);
    }

    return TRUE;
}
