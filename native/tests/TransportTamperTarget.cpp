#include <knmon/common/Protocol.h>

#include <Windows.h>

int main()
{
    int result = 1;
    HANDLE mapping = nullptr;
    knmon::KnMonTransportHeader* header = nullptr;
    do
    {
        wchar_t name[512] = {};
        const DWORD length = GetEnvironmentVariableW(L"KNMON_TRANSPORT_NAME", name, 512);
        if (length == 0 || length >= 512)
        {
            break;
        }
        mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
        if (mapping == nullptr)
        {
            break;
        }
        header = static_cast<knmon::KnMonTransportHeader*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(*header)));
        if (header == nullptr)
        {
            break;
        }
        Sleep(100);
        InterlockedExchange(reinterpret_cast<volatile LONG*>(&header->Capacity), 0x7fffffff);
        Sleep(250);
        result = 0;
    }
    while (false);
    if (header != nullptr)
    {
        UnmapViewOfFile(header);
    }
    if (mapping != nullptr)
    {
        CloseHandle(mapping);
    }
    return result;
}
