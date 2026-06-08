#include <knmon/core/Controller.h>

#include <iostream>

int main()
{
    knmon::Controller controller;
    knmon::KnMonError error;
    const auto targets = controller.EnumerateTargets(&error);

    std::cout << "knmon-collector protocol "
              << knmon::KnMonProtocolMajor << "."
              << knmon::KnMonProtocolMinor << "."
              << knmon::KnMonProtocolPatch << "\n";

    if (error.Code != 0)
    {
        std::cout << "enumerate error: " << error.Message << "\n";
    }
    else
    {
        std::cout << "targets: " << targets.size() << "\n";
    }

    std::cout << "capture backend: mock-only safe MVP\n";
    return error.Code == 0 ? 0 : 1;
}
