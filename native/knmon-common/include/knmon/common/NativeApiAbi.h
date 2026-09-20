// Generated from pinned PHNT prototypes by tools/def-validator/generate-sdk-abi.mjs.
#pragma once
#include <Windows.h>
#include <winternl.h>

namespace knmon::native_abi
{
using LdrLoadDll = NTSTATUS(NTAPI*)(PCWSTR, PULONG, const UNICODE_STRING*, PVOID *);
using LdrGetProcedureAddress = NTSTATUS(NTAPI*)(PVOID, const ANSI_STRING*, ULONG, PVOID *);
}
