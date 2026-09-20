import type { AgentApiCallEvent, TraceEvent } from "./types";

export function createTraceEventFromAgentApiCall(event: AgentApiCallEvent, eventId: number, contextTags: string[]): TraceEvent
{
  const hasTiming = event.timeSource === "qpc" && event.timing !== undefined &&
    typeof event.relativeTimeMs === "number" && Number.isFinite(event.relativeTimeMs) && event.relativeTimeMs >= 0;
  const relativeTimeMs = hasTiming ? event.relativeTimeMs! : 0;

  return {
    schemaVersion: event.schemaVersion,
    eventId,
    recordSequence: event.recordSequence,
    observation: event.observation,
    relativeTimeMs,
    timeSource: hasTiming ? "qpc" : "unavailable",
    timing: hasTiming ? event.timing : undefined,
    timestampUtc: hasTiming ? event.timestampUtc : undefined,
    collectedAtUtc: event.collectedAtUtc,
    pid: event.pid,
    tid: event.tid,
    process: event.process,
    module: event.module,
    api: event.api,
    arguments: event.arguments,
    returnValue: event.returnValue,
    rawReturnValue: event.rawReturnValue,
    rawReturnBytes: event.rawReturnBytes,
    rawReturnEncoding: event.rawReturnEncoding,
    callId: event.callId,
    parentCallId: event.parentCallId,
    callDepth: event.callDepth,
    rawReturnBits: event.rawReturnBits,
    rawLastErrorCode: event.rawLastErrorCode,
    rawWinsockErrorCode: event.rawWinsockErrorCode,
    winsockErrorSampled: event.winsockErrorSampled,
    errorDomain: event.errorDomain,
    outcome: event.outcome,
    errorValidity: event.errorValidity,
    successPredicate: event.successPredicate,
    error: !(event.hasError ?? event.lastErrorCode !== 0) || event.errorDomain === "none"
      ? null
      : {
          kind: event.errorDomain ?? "win32",
          code: `0x${event.lastErrorCode.toString(16).padStart(8, "0")}`,
          message: event.lastErrorMessage
        },
    durationUs: event.durationUs,
    tags: Array.from(new Set([...event.tags, ...contextTags])),
    stack: event.stack,
    bufferPreview: event.bufferPreview || undefined
  };
}
