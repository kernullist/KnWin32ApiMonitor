import type { StackObservation } from "./types";

export function describeStackObservation(event: StackObservation)
{
  const source = event.stackSource === undefined ? "legacy_unverified" : event.stackSource;
  const context = event.hookContext;
  const capture = event.stackCapture;
  const native = source === "native_backtrace";
  const validCapture = native ? capture !== null && typeof capture === "object" && !Array.isArray(capture) &&
    capture.method === "rtl_capture_stack_back_trace" && capture.phase === "post_call" &&
    (capture.addressBits === 32 || capture.addressBits === 64) &&
    Number.isInteger(capture.requestedFrames) && capture.requestedFrames >= 1 && capture.requestedFrames <= 32 &&
    Array.isArray(event.stack) && event.stack.length <= capture.requestedFrames &&
    ["captured", "empty", "memory_fault", "cpp_exception", "unavailable", "invalid_result"].includes(capture.status) &&
    ((capture.status === "captured") === (event.stack.length > 0)) &&
    capture.limitReached === (event.stack.length === capture.requestedFrames) &&
    (capture.status === "memory_fault" ? [0xc0000005, 0xc0000006, 0x80000002].includes(capture.exceptionCode) : capture.exceptionCode === 0) &&
    event.stack.every((address) => typeof address === "string" &&
      new RegExp(`^0x[0-9a-f]{${capture.addressBits / 4}}$`, "u").test(address) && /[1-9a-f]/u.test(address.slice(2)))
    : capture === undefined;
  const valid = Array.isArray(event.stack) && event.stack.every((entry) => typeof entry === "string") &&
    (source === "not_captured" || source === "legacy_unverified" || native) && validCapture &&
    (source !== "not_captured" || event.stack.length === 0) &&
    (context === undefined || (context !== null && typeof context === "object" && !Array.isArray(context) &&
      typeof context.agent === "string" && context.agent.length > 0 &&
      (context.resolvedHostModule === undefined || (typeof context.resolvedHostModule === "string" && context.resolvedHostModule.length > 0))));

  return {
    source: valid ? source : "invalid",
    message: !valid ? "Invalid stack observation metadata."
      : source === "not_captured" ? "Call stack was not captured."
      : native ? capture!.status === "captured"
        ? `Raw post-call backtrace (${capture!.addressBits}-bit). Agent frames may be included.${capture!.limitReached ? " Frame limit reached; trace may be incomplete." : " Unwind completeness is not established."}`
        : `Post-call stack capture returned no frames: ${capture!.status}.`
      : "Legacy stack entries have no verified capture provenance.",
    entries: valid && source !== "not_captured" ? event.stack : [],
    hookContext: valid ? context : undefined
  };
}
