#pragma once

#include <knmon/common/GeneratedApiMetadata.h>
#include <knmon/common/Protocol.h>
#include <string_view>

namespace knmon
{
struct ApiResult
{
    std::string_view Domain = "none";
    std::string_view Outcome = "unknown";
    std::string_view ErrorValidity = "not_applicable";
    std::string_view Predicate = "unspecified";
    std::uint32_t Code = 0;
    bool HasError = false;
};

inline ApiResult ClassifyApiResult(const KnMonGeneratedApiMetadata* metadata, const KnMonTransportRecord& record)
{
    ApiResult result;
    if (metadata != nullptr)
    {
        const auto name = metadata->Name;
        const auto value = record.RawReturnValue;
        const auto low = static_cast<std::uint32_t>(value);
        const auto signedLow = static_cast<std::int32_t>(low);
        if (metadata->ReturnType == "NTSTATUS" || metadata->ErrorSource == "return_ntstatus")
        {
            result = {"ntstatus", signedLow < 0 ? "failure" : (low == 0x103 ? "pending" : "success"),
                "valid", "NT_SUCCESS(return)", low, signedLow < 0};
        }
        else if (metadata->ReturnType == "HRESULT" || metadata->ErrorSource == "HRESULT" || metadata->ReturnType == "SECURITY_STATUS")
        {
            result = {"hresult", signedLow < 0 ? "failure" : "success", "valid", "SUCCEEDED(return)", low, signedLow < 0};
        }
        else if ((metadata->ModuleName == "ws2_32.dll" || name == "WSARevertImpersonation") && name != "freeaddrinfo" && name != "WSAGetLastError")
        {
            const bool direct = name == "WSAStartup" || name == "getaddrinfo";
            const bool failed = direct ? low != 0 : (name == "socket" ?
                value == (record.RawReturnBits == 32 ? 0xffffffffULL : 0xffffffffffffffffULL) : low == 0xffffffff);
            result = {"winsock", failed ? "failure" : "success", direct || record.HasWinsockError != 0 ? "valid" : "unavailable",
                direct ? "return == 0" : (name == "socket" ? "return != INVALID_SOCKET" : "return != SOCKET_ERROR"),
                direct ? low : record.RawWinsockErrorCode, failed && (direct || record.HasWinsockError != 0)};
        }
        else if (metadata->ReturnType == "LSTATUS" || metadata->ReturnType == "RPC_STATUS" ||
            metadata->ReturnType == "NETIO_STATUS" || name == "GetAdaptersAddresses" || name == "GetIpStatistics")
        {
            const bool success = low == 0 || (name == "UuidCreate" && low == 1824);
            result = {"win32", success ? "success" : "failure", "valid",
                name == "UuidCreate" ? "return in {RPC_S_OK,RPC_S_UUID_LOCAL_ONLY}" : "return == 0", low, !success};
        }
        else if (metadata->ErrorSource == "GetLastError")
        {
            result.Domain = "win32";
            result.ErrorValidity = "unspecified";
            result.Code = record.RawLastErrorCode;
            const auto failure = metadata->FailureJson;
            bool known = true;
            bool failed = false;
            if (name == "GetClipboardOwner" || name == "GetClipboardViewer" || name == "GetOpenClipboardWindow" ||
                name == "CountClipboardFormats" || name == "GetFileType")
            {
                // Null/zero can be a valid result. Preserve raw error without inventing failure.
                result.Predicate = "zero may be a valid result";
                result.Outcome = value != 0 ? "success" : "unknown";
                known = false;
            }
            else if (name == "WinHttpCheckPlatform")
            {
                result = {"none", "success", "not_applicable", "platform capability boolean", 0, false};
                known = false;
            }
            else if (failure == "{\"returnEqual\":\"INVALID_HANDLE_VALUE\"}")
            {
                failed = value == (record.RawReturnBits == 32 ? 0xffffffffULL : 0xffffffffffffffffULL);
                result.Predicate = "return != INVALID_HANDLE_VALUE";
            }
            else if (failure == "{\"returnEqual\":\"0xFFFFFFFF\"}" || name == "TlsAlloc")
            {
                failed = low == 0xffffffff;
                result.Predicate = "return != 0xFFFFFFFF";
            }
            else if (failure == "{\"returnEqual\":\"NULL\"}" || failure == "{\"returnEqual\":\"FALSE\"}" ||
                failure == "{\"returnEqual\":0}" || failure == "{\"returnEqual\":\"0\"}" ||
                name == "GetCursorPos" || name == "SetupDiClassNameFromGuidW" || name == "CreateThreadpoolCleanupGroup" ||
                name == "CreateTimerQueue" || name == "GetConsoleCP" || name == "GetConsoleOutputCP" ||
                name == "GetLogicalDrives" || name == "GetProcessHeap" || name == "RevertToSelf" ||
                name == "CloseClipboard" || name == "CreateMenu" || name == "CreatePopupMenu" ||
                name == "GetCaretBlinkTime" || name == "GetProcessWindowStation" || name == "CM_Get_Version")
            {
                failed = value == 0;
                result.Predicate = "return != 0";
            }
            else
            {
                known = false;
            }
            if (known)
            {
                const bool pending = failed && record.RawLastErrorCode == 997 && (name == "ReadFile" || name == "WriteFile");
                result.Outcome = pending ? "pending" : (failed ? "failure" : "success");
                result.ErrorValidity = failed ? "valid" : "not_applicable";
                result.HasError = failed && !pending;
            }
        }
        else if (metadata->ReturnType == "void" || metadata->SuccessJson == "{\"always\":true}" ||
            name == "GetCurrentProcess" || name == "GetCurrentThread" || name == "GetCurrentProcessId" || name == "GetCurrentThreadId")
        {
            result.Outcome = "success";
            result.Predicate = "no failure return";
        }
    }
    return result;
}
}
