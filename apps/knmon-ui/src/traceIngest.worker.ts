import type { AgentApiCallEvent, NativeTraceBatch, TraceEvent } from "./types";
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
};

let displayEvents: TraceEvent[] = [];
let totalCapturedEvents = 0;
let nextEventId = 1;

function nextTraceEventId(events: TraceEvent[]): number {
  return events.reduce((maximum, event) => Math.max(maximum, event.eventId), 0) + 1;
}

function createTraceEventFromAgentApiCall(event: AgentApiCallEvent, eventId: number, contextTags: string[]): TraceEvent {
  return {
    schemaVersion: event.schemaVersion,
    eventId,
    relativeTimeMs: event.sequence * 10,
    pid: event.pid,
    tid: event.tid,
    process: event.process,
    module: event.module,
    api: event.api,
    arguments: event.arguments,
    returnValue: event.returnValue,
    error: event.lastErrorCode === 0
      ? null
      : {
          kind: "win32",
          code: `0x${event.lastErrorCode.toString(16).padStart(8, "0")}`,
          message: event.lastErrorMessage
        },
    durationUs: event.durationUs,
    tags: Array.from(new Set([...event.tags, ...contextTags])),
    stack: event.stack,
    bufferPreview: event.bufferPreview || undefined
  };
}

function publishSnapshot(selectedEventId: number, processedEvents: number) {
  const snapshot: TraceIngestSnapshot = {
    type: "snapshot",
    events: displayEvents,
    totalCapturedEvents,
    selectedEventId,
    processedEvents
  };

  self.postMessage(snapshot);
}

function resolveSelectedEventId(candidate?: number): number {
  if (candidate !== undefined && displayEvents.some((event) => event.eventId === candidate)) {
    return candidate;
  }

  return displayEvents[displayEvents.length - 1]?.eventId ?? 0;
}

function replaceEvents(events: TraceEvent[], selectedEventId?: number) {
  displayEvents = events.slice(-traceDisplayEventLimit);
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
    displayEvents = [...displayEvents, ...traceEvents].slice(-traceDisplayEventLimit);
    publishSnapshot(traceEvents[traceEvents.length - 1].eventId, incomingCount);
  }
  else {
    publishSnapshot(displayEvents[displayEvents.length - 1]?.eventId ?? 0, incomingCount);
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
      totalCapturedEvents = 0;
      nextEventId = 1;
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
