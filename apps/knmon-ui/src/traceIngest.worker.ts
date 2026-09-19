import type { AgentApiCallEvent, NativeTraceBatch, TraceEvent } from "./types";
import { createTraceEventFromAgentApiCall } from "./traceConversion";
import { traceDisplayEventLimit } from "./traceIngestConfig";

type CapturedEventChunk = {
  events: AgentApiCallEvent[];
  contextTags: string[];
};

type TraceIngestCommand =
  | { type: "reset" }
  | { type: "replace"; events: TraceEvent[]; selectedEventId?: number }
  | { type: "enqueue-events"; chunks: CapturedEventChunk[] }
  | { type: "enqueue-batches"; batches: NativeTraceBatch[] };

type TraceIngestSnapshot = {
  type: "snapshot";
  events: TraceEvent[];
  totalCapturedEvents: number;
  selectedEventId: number;
  processedEvents: number;
  estimatedSessionBytes: number;
};

let displayEvents: TraceEvent[] = [];
let displayEventBytes: number[] = [];
let displayBytesEstimate = 0;
let totalCapturedEvents = 0;
let nextEventId = 1;

// Batching multiple enqueues into one publish keeps the main thread from paying
// a full-array structured clone per small chunk during streaming.
const publishIntervalMs = 250;
let publishTimer: ReturnType<typeof setTimeout> | null = null;
let pendingSelectedEventId = 0;
let pendingProcessedEvents = 0;
let snapshotSeq = 0;

function estimateEventBytes(event: TraceEvent): number {
  return JSON.stringify(event).length;
}

function nextTraceEventId(events: TraceEvent[]): number {
  return events.reduce((maximum, event) => Math.max(maximum, event.eventId), 0) + 1;
}

function publishSnapshot(selectedEventId: number, processedEvents: number) {
  const snapshot: TraceIngestSnapshot = {
    type: "snapshot",
    events: displayEvents,
    totalCapturedEvents,
    selectedEventId,
    processedEvents,
    estimatedSessionBytes: displayBytesEstimate
  };

  self.postMessage(snapshot);
}

function scheduleSnapshotPublish(selectedEventId: number, processedEvents: number) {
  pendingSelectedEventId = selectedEventId;
  pendingProcessedEvents += processedEvents;
  if (publishTimer !== null) {
    return;
  }

  publishTimer = setTimeout(() => {
    publishTimer = null;
    publishSnapshot(pendingSelectedEventId, pendingProcessedEvents);
    pendingSelectedEventId = 0;
    pendingProcessedEvents = 0;
  }, publishIntervalMs);
}

function resolveSelectedEventId(candidate?: number): number {
  if (candidate !== undefined && displayEvents.some((event) => event.eventId === candidate)) {
    return candidate;
  }

  return displayEvents[displayEvents.length - 1]?.eventId ?? 0;
}

function recomputeDisplayBytes() {
  displayBytesEstimate = displayEvents.reduce((total, event) => total + estimateEventBytes(event), 0);
}

function replaceEvents(events: TraceEvent[], selectedEventId?: number) {
  displayEvents = events.slice(-traceDisplayEventLimit);
  displayEventBytes = displayEvents.map(estimateEventBytes);
  recomputeDisplayBytes();
  totalCapturedEvents = events.length;
  nextEventId = nextTraceEventId(events);
  publishSnapshot(resolveSelectedEventId(selectedEventId), events.length);
}

function enqueueChunks(chunks: CapturedEventChunk[]) {
  const incomingCount = chunks.reduce((count, chunk) => count + chunk.events.length, 0);
  if (incomingCount === 0) {
    return;
  }

  const retainFromIncoming = Math.max(0, incomingCount - traceDisplayEventLimit);
  let incomingIndex = 0;
  const traceEvents: TraceEvent[] = [];

  chunks.forEach((chunk) => {
    chunk.events.forEach((event) => {
      const eventId = nextEventId + incomingIndex;
      incomingIndex += 1;

      if (incomingIndex <= retainFromIncoming) {
        return;
      }

      traceEvents.push(createTraceEventFromAgentApiCall(event, eventId, chunk.contextTags));
    });
  });

  nextEventId += incomingCount;
  totalCapturedEvents += incomingCount;

  if (traceEvents.length > 0) {
    const appended = [...displayEvents, ...traceEvents];
    const evictedCount = Math.max(0, appended.length - traceDisplayEventLimit);
    const kept = appended.slice(-traceDisplayEventLimit);

    let evictedBytes = 0;
    for (let index = 0; index < evictedCount; index += 1) {
      evictedBytes += estimateEventBytes(appended[index]);
    }
    const appendedBytes = traceEvents.reduce((total, event) => total + estimateEventBytes(event), 0);

    displayEvents = kept;
    displayEventBytes = kept.map(estimateEventBytes);
    displayBytesEstimate = Math.max(0, displayBytesEstimate - evictedBytes) + appendedBytes;
    scheduleSnapshotPublish(traceEvents[traceEvents.length - 1].eventId, incomingCount);
  }
  else {
    scheduleSnapshotPublish(displayEvents[displayEvents.length - 1]?.eventId ?? 0, incomingCount);
  }
}

function enqueueBatches(batches: NativeTraceBatch[]) {
  enqueueChunks(batches.map((batch) => ({
    events: batch.events,
    contextTags: ["ui-stream", `session:${batch.sessionId}`, `batch:${batch.batchSequence}`]
  })));
}

self.onmessage = (event: MessageEvent<TraceIngestCommand>) => {
  switch (event.data.type) {
    case "reset":
    {
      displayEvents = [];
      displayEventBytes = [];
      displayBytesEstimate = 0;
      totalCapturedEvents = 0;
      nextEventId = 1;
      if (publishTimer !== null) {
        clearTimeout(publishTimer);
        publishTimer = null;
        pendingSelectedEventId = 0;
        pendingProcessedEvents = 0;
      }
      publishSnapshot(0, 0);
      break;
    }
    case "replace":
    {
      replaceEvents(event.data.events, event.data.selectedEventId);
      break;
    }
    case "enqueue-events":
    {
      enqueueChunks(event.data.chunks);
      break;
    }
    case "enqueue-batches":
    {
      enqueueBatches(event.data.batches);
      break;
    }
  }
};

export {};
