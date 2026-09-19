#include <knmon/common/TransportWriter.h>

namespace knmon
{
TransportWriteOutcome InvokeTransportCallbackCpp(void* context, TransportWriteCallback callback,
    KnMonTransportRecord* record) noexcept
{
    TransportWriteOutcome outcome = TransportWriteOutcome::Completed;
    try
    {
        callback(context, record);
    }
    catch (...)
    {
        outcome = TransportWriteOutcome::CppException;
    }
    return outcome;
}

int TransportFaultFilter(DWORD code) noexcept
{
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
        code == EXCEPTION_DATATYPE_MISALIGNMENT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

// Keep SEH outside C++ object lifetimes. This boundary only contains telemetry.
__declspec(noinline) TransportWriteOutcome InvokeTransportCallback(void* context,
    TransportWriteCallback callback, TransportReservation* reservation) noexcept
{
    TransportWriteOutcome outcome = TransportWriteOutcome::Completed;
    __try
    {
        __try
        {
            outcome = InvokeTransportCallbackCpp(context, callback, reservation->Get());
        }
        __except (TransportFaultFilter(GetExceptionCode()))
        {
            outcome = TransportWriteOutcome::MemoryFault;
        }
    }
    __finally
    {
        // Unhandled SEH still releases sequence ownership during unwind.
        if (AbnormalTermination())
        {
            reservation->Abort(TransportWriteOutcome::Abandoned);
        }
    }
    return outcome;
}

}
