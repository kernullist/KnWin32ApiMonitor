import type { AgentApiCallEvent, TraceEvent } from "./types";

export function describeCaptureDetail(event: Pick<TraceEvent, "captureDetail" | "arguments" | "bufferPreview">)
{
  const detail = event.captureDetail;
  const valid = detail === undefined ||
    ((detail === "metadata" || detail === "arguments" || detail === "preview") &&
     Array.isArray(event.arguments) && typeof event.bufferPreview === "string" &&
     (detail !== "metadata" || event.arguments.length === 0) &&
     (detail === "preview" || event.bufferPreview === ""));
  return {
    detail: valid ? detail ?? "unspecified" : "invalid",
    message: !valid ? "Invalid capture detail payload."
      : detail === "metadata" ? "Metadata only. Arguments and buffers were not captured."
      : detail === "arguments" ? "Arguments captured. Byte-buffer previews were disabled."
      : detail === "preview" ? "Arguments and byte-buffer previews enabled. Availability depends on the API and call result."
      : "Capture detail was not recorded in this legacy event."
  };
}

export function createTraceEventFromAgentApiCall(event: AgentApiCallEvent, eventId: number, contextTags: string[]): TraceEvent
{
  if (describeCaptureDetail(event).detail === "invalid")
  {
    throw new Error("Inconsistent capture detail payload.");
  }
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
    captureDetail: event.captureDetail,
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
    stackSource: event.stackSource === undefined ? "legacy_unverified" : event.stackSource,
    stackCapture: event.stackCapture,
    hookContext: event.hookContext,
    bufferPreview: event.captureDetail === undefined ? event.bufferPreview || undefined : event.bufferPreview
  };
}
