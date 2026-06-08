import type { TraceEvent } from "./types";

export function buildJsonl(events: TraceEvent[]): string {
  return events
    .map((event) => JSON.stringify({
      schemaVersion: event.schemaVersion,
      eventId: event.eventId,
      relativeTimeMs: event.relativeTimeMs,
      pid: event.pid,
      tid: event.tid,
      process: event.process,
      module: event.module,
      api: event.api,
      arguments: event.arguments,
      returnValue: event.returnValue,
      error: event.error,
      durationUs: event.durationUs,
      tags: event.tags,
      stack: event.stack,
      bufferPreview: event.bufferPreview ?? null
    }))
    .join("\n");
}

export function estimateSessionBytes(events: TraceEvent[]): number {
  return new TextEncoder().encode(buildJsonl(events)).length;
}

export function downloadJsonl(events: TraceEvent[]): void {
  const jsonl = `${buildJsonl(events)}\n`;
  const blob = new Blob([jsonl], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  anchor.href = url;
  anchor.download = `knmon-session-${stamp}.jsonl`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
