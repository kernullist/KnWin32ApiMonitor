#include <knmon/common/RuntimeSupport.h>
#include <knmon/core/Controller.h>

#include <iostream>
#include <string>

int main()
{
    int failures = 0;
    std::string rejected;
    for (const std::string selection : {"", "kernel32.dll!CreateFileW", "KERNEL32.DLL!*", "kernel32.dll", "kernel32.dll!ReadFile;kernel32.dll!WriteFile", "kernel32.dll!ReadFile   "})
    {
        if (!knmon::ValidateRuntimeApiSelection(selection, rejected))
        {
            std::cerr << "Supported selection rejected: " << selection << "\n";
            ++failures;
        }
    }
    for (const std::string selection : {"user32.dll!wsprintfW", "d2d1.dll!D2D1SinCos", "oleaut32.dll!VarI4FromR8", "unknown.dll!*", "kernel32.dll!ReadFile;user32.dll!wsprintfW", " ; ", "kernel32.dll!!*"})
    {
        if (knmon::ValidateRuntimeApiSelection(selection, rejected) || rejected.empty())
        {
            std::cerr << "Unsafe selection accepted: " << selection << "\n";
            ++failures;
        }
    }
    if (knmon::RuntimeApiSupported("user32.dll", "wsprintfW") ||
        !knmon::RuntimeApiSupported("kernel32.dll", "CreateFileW") ||
        knmon::ValidateRuntimeApiSelection(std::string(knmon::KnMonAttachConfigSelectedApisChars, 'a'), rejected))
    {
        std::cerr << "Runtime boundary validation failed.\n";
        ++failures;
    }

    const knmon::Controller controller;
    knmon::KnMonLaunchRequest launch;
    launch.ApiSelection = "user32.dll!wsprintfW";
    knmon::KnMonAttachRequest attach;
    attach.ApiSelection = launch.ApiSelection;
    const auto checkRejection = [&failures](const auto& result)
    {
        if (result.Success || result.Operation != "unsupported_api_selection" ||
            result.TargetProcessId != 0 || result.Win32ErrorCode != 50)
        {
            std::cerr << "Controller did not reject unsupported selection before target access.\n";
            ++failures;
        }
    };
    checkRejection(controller.LaunchWithEarlyBirdApc(launch));
    checkRejection(controller.LaunchCapture(launch));
    checkRejection(controller.CaptureSampleFileIo(launch));
    checkRejection(controller.AttachCapture(attach));
    return failures == 0 ? 0 : 1;
}
