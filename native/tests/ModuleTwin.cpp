#include <Windows.h>

extern "C" DWORD WINAPI timeGetTime()
{
    return KNMON_TWIN_VALUE;
}
