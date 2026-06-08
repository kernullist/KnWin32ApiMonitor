#pragma once

#include <knmon/common/Protocol.h>

#include <vector>

namespace knmon
{
class Controller
{
public:
    std::vector<KnMonTargetProcess> EnumerateTargets(KnMonError* error) const;
    KnMonLaunchResult LaunchWithEarlyBirdApc(const KnMonLaunchRequest& request) const;

    KnMonError LaunchTarget(const std::string& imagePath) const;
    KnMonError AttachToTarget(std::uint32_t processId) const;
    KnMonError DetachFromTarget(std::uint32_t processId) const;
    KnMonError StartCapture(std::uint32_t processId) const;
    KnMonError StopCapture(std::uint32_t processId) const;
};
}
