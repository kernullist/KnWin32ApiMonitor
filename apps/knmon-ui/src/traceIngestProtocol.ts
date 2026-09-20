import type { AgentApiCallEvent, NativeTraceBatch, TraceEvent } from "./types";
import { createTraceEventFromAgentApiCall } from "./traceConversion";
import { traceDisplayEventLimit } from "./traceIngestConfig";

export type CapturedEventChunk = { events: AgentApiCallEvent[]; contextTags: string[] };
export type TraceIngestCommand =
  | { type: "reset" }
  | { type: "replace"; events: TraceEvent[]; selectedEventId?: number; totalCapturedEvents?: number }
  | { type: "enqueue-events"; chunks: CapturedEventChunk[] }
  | { type: "enqueue-batches"; batches: NativeTraceBatch[] };
export type TraceIngestRequest = { epoch: number; sequence: number; command: TraceIngestCommand };
export type TraceIngestDelta = {
  type: "delta"; epoch: number; sequence: number; replace: boolean; evictCount: number;
  events: TraceEvent[]; totalCapturedEvents: number; selectedEventId: number; estimatedSessionBytes: number;
};
export const traceDisplayByteLimit = 16 * 1024 * 1024;

export class TraceIngestState
{
  private epoch = -1;
  private sequence = 0;
  private retained: { eventId: number; bytes: number }[] = [];
  private bytes = 0;
  private total = 0;
  private nextId = 1;
  private encoder = new TextEncoder();

  apply(request: TraceIngestRequest): TraceIngestDelta | null
  {
    const { epoch, sequence, command } = request;
    if (!Number.isSafeInteger(epoch) || !Number.isSafeInteger(sequence) || epoch < this.epoch)
    {
      return null;
    }
    const replace = command.type === "reset" || command.type === "replace";
    if (epoch > this.epoch)
    {
      if (!replace || sequence !== 1)
      {
        return null;
      }
      this.epoch = epoch;
      this.sequence = 0;
      this.retained = [];
      this.bytes = 0;
      this.total = 0;
      this.nextId = 1;
    }
    if (sequence !== this.sequence + 1 || (replace && sequence !== 1))
    {
      return null;
    }
    this.sequence = sequence;
    const previousCount = this.retained.length;
    let appended: TraceEvent[] = [];
    let selected = 0;
    if (command.type === "replace")
    {
      appended = command.events.slice(-traceDisplayEventLimit);
      this.total = Math.max(command.totalCapturedEvents ?? command.events.length, command.events.length);
      this.nextId = command.events.reduce((maximum, event) => Math.max(maximum, event.eventId), 0) + 1;
      selected = command.selectedEventId ?? 0;
    }
    else if (command.type === "enqueue-events" || command.type === "enqueue-batches")
    {
      const chunks = command.type === "enqueue-events" ? command.chunks : command.batches.map((batch) => ({
        events: batch.events, contextTags: ["ui-stream", `session:${batch.sessionId}`, `batch:${batch.batchSequence}`]
      }));
      const count = chunks.reduce((sum, chunk) => sum + chunk.events.length, 0);
      const skip = Math.max(0, count - traceDisplayEventLimit);
      let index = 0;
      for (const chunk of chunks)
      {
        for (const event of chunk.events)
        {
          if (index >= skip)
          {
            appended.push(createTraceEventFromAgentApiCall(event, this.nextId + index, chunk.contextTags));
          }
          index += 1;
        }
      }
      this.nextId += count;
      this.total += count;
    }
    for (const event of appended)
    {
      const bytes = this.encoder.encode(JSON.stringify(event)).byteLength;
      this.retained.push({ eventId: event.eventId, bytes });
      this.bytes += bytes;
    }
    let removed = 0;
    while (this.retained.length - removed > traceDisplayEventLimit || this.bytes > traceDisplayByteLimit)
    {
      this.bytes -= this.retained[removed].bytes;
      removed += 1;
    }
    this.retained = this.retained.slice(removed);
    appended = appended.slice(Math.max(0, removed - previousCount));
    if (!this.retained.some((event) => event.eventId === selected))
    {
      selected = this.retained[this.retained.length - 1]?.eventId ?? 0;
    }
    return { type: "delta", epoch, sequence, replace, evictCount: Math.min(removed, previousCount),
      events: appended, totalCapturedEvents: this.total, selectedEventId: selected, estimatedSessionBytes: this.bytes };
  }
}

type Pending = { sequence: number; resolve: (accepted: boolean) => void; timer: ReturnType<typeof setTimeout> };
export class TraceIngestClient
{
  epoch = 0;
  private sequence = 0;
  private pending: Pending | null = null;
  private wire: TraceIngestRequest | null = null;
  private queued: TraceIngestRequest | null = null;
  private closed = false;
  constructor(private send: (request: TraceIngestRequest) => void,
    private apply: (delta: TraceIngestDelta) => void, private fail: (message: string) => void) {}

  get busy(): boolean
  {
    return this.pending !== null || this.closed;
  }

  submit(command: TraceIngestCommand, expectedEpoch = this.epoch): Promise<boolean>
  {
    if (this.closed || expectedEpoch !== this.epoch)
    {
      return Promise.resolve(false);
    }
    const replace = command.type === "reset" || command.type === "replace";
    if (replace)
    {
      this.finish(false);
      this.epoch += 1;
      this.sequence = 0;
    }
    else if (this.pending)
    {
      return Promise.resolve(false);
    }
    const sequence = ++this.sequence;
    return new Promise((resolve) => {
      const timer = setTimeout(() => this.abort("Trace ingest acknowledgement timed out."), 15000);
      this.pending = { sequence, resolve, timer };
      try
      {
        const request = { epoch: this.epoch, sequence, command };
        if (this.wire)
        {
          this.queued = request;
        }
        else
        {
          this.wire = request;
          this.send(request);
        }
      }
      catch (error)
      {
        this.abort(String(error));
      }
    });
  }

  receive(delta: TraceIngestDelta): void
  {
    if (this.closed || delta.type !== "delta" || delta.epoch !== this.wire?.epoch || delta.sequence !== this.wire?.sequence)
    {
      return;
    }
    try
    {
      this.wire = null;
      if (delta.epoch === this.epoch && delta.sequence === this.pending?.sequence)
      {
        this.apply(delta);
        this.finish(true);
      }
      if (this.queued)
      {
        const request = this.queued;
        this.queued = null;
        this.wire = request;
        this.send(request);
      }
    }
    catch (error)
    {
      this.abort(String(error));
    }
  }

  private finish(accepted: boolean): void
  {
    if (this.pending)
    {
      clearTimeout(this.pending.timer);
      this.pending.resolve(accepted);
      this.pending = null;
    }
  }

  abort(message?: string): void
  {
    this.closed = true;
    this.queued = null;
    this.wire = null;
    this.finish(false);
    if (message)
    {
      this.fail(message);
    }
  }
}
