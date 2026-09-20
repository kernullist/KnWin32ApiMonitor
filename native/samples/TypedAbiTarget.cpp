#include <Windows.h>
#include <OleAuto.h>
#include <d2d1_1.h>
#include <array>
#include <cstdint>
#include <cstring>

struct Report
{
    std::array<unsigned char, 256> Bytes = {};
    std::size_t Size = 0;
    template <typename T>
    void Add(const T& value)
    {
        std::memcpy(Bytes.data() + Size, &value, sizeof(value));
        Size += sizeof(value);
    }
};

struct CallbackState
{
    std::uint32_t Count = 0;
    std::uint32_t IdSum = 0;
    bool NestedResult = true;
};

BOOL CALLBACK Enumerate(HWND window, LPARAM parameter)
{
    auto& state = *reinterpret_cast<CallbackState*>(parameter);
    ++state.Count;
    state.IdSum += static_cast<std::uint32_t>(GetDlgCtrlID(window));
    double output = 0;
    state.NestedResult = state.NestedResult && VarR8FromR4(1.25f, &output) == S_OK && output == 1.25;
    SetLastError(9876);
    return TRUE;
}

int wmain(int argc, wchar_t** argv)
{
    int exitCode = 1;
    HWND parent = nullptr;
    HANDLE file = INVALID_HANDLE_VALUE;
    do
    {
        if (argc != 2)
        {
            break;
        }
        Report report;
        double output64 = 0;
        SetLastError(1234);
        const auto result64 = VarR8FromR4(1.25f, &output64);
        const DWORD error64 = GetLastError();
        report.Add(result64);
        report.Add(error64);
        report.Add(output64);
        float output32 = -99.0f;
        SetLastError(2345);
        const auto result32 = VarR4FromR8(1.0e300, &output32);
        const DWORD error32 = GetLastError();
        report.Add(result32);
        report.Add(error32);
        report.Add(output32);
        D2D1_MATRIX_3X2_F matrix = {};
        SetLastError(3456);
        D2D1MakeRotateMatrix(27.25f, D2D1_POINT_2F{1.25f, -3.75f}, &matrix);
        const DWORD matrixError = GetLastError();
        report.Add(matrix);
        report.Add(matrixError);
        const D2D1_COLOR_F color{0.125f, 0.5f, 0.875f, 0.75f};
        SetLastError(4567);
        const auto converted = D2D1ConvertColorSpace(D2D1_COLOR_SPACE_SRGB, D2D1_COLOR_SPACE_SCRGB, &color);
        const DWORD colorError = GetLastError();
        report.Add(converted);
        report.Add(colorError);
        SetLastError(5678);
        const float length = D2D1Vec3Length(3.0f, 4.0f, 0.0f);
        const DWORD lengthError = GetLastError();
        report.Add(length);
        report.Add(lengthError);
        parent = CreateWindowExW(0, L"STATIC", L"", WS_OVERLAPPED, 0, 0, 1, 1, nullptr, nullptr, nullptr, nullptr);
        if (parent == nullptr || CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 0, 0, 1, 1, parent,
            reinterpret_cast<HMENU>(101), nullptr, nullptr) == nullptr)
        {
            break;
        }
        CallbackState state;
        SetLastError(6789);
        const BOOL enumeration = EnumChildWindows(parent, Enumerate, reinterpret_cast<LPARAM>(&state));
        const DWORD enumerationError = GetLastError();
        report.Add(enumeration);
        report.Add(enumerationError);
        report.Add(state.Count);
        report.Add(state.IdSum);
        if (result64 != S_OK || output64 != 1.25 || result32 != DISP_E_OVERFLOW || length != 5.0f ||
            !state.NestedResult || state.Count != 1 || state.IdSum != 101)
        {
            break;
        }
        file = CreateFileW(argv[1], GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        if (file == INVALID_HANDLE_VALUE || !WriteFile(file, report.Bytes.data(), static_cast<DWORD>(report.Size), &written, nullptr) ||
            written != report.Size || !FlushFileBuffers(file))
        {
            break;
        }
        exitCode = 0;
    }
    while (false);
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (parent != nullptr)
    {
        DestroyWindow(parent);
    }
    return exitCode;
}
