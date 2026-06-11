import type { TraceQueryClause } from "./traceQuery";
import type { TraceEvent } from "./types";

export interface TraceViewSample {
  eventId: number;
  relativeTimeMs: number;
  module: string;
  api: string;
  message: string;
}

export interface TraceViewTopValue {
  value: string;
  count: number;
}

export interface TraceThreadGroup {
  id: string;
  pid: number;
  tid: number;
  process: string;
  threadLabel: string;
  eventCount: number;
  firstRelativeTimeMs: number;
  lastRelativeTimeMs: number;
  spanMs: number;
  errorCount: number;
  decodeFailureCount: number;
  slowCallCount: number;
  topModules: TraceViewTopValue[];
  topApis: TraceViewTopValue[];
  eventIds: number[];
  samples: TraceViewSample[];
  clauses: Array<Omit<TraceQueryClause, "id">>;
}

export interface TraceTimelineBucket {
  id: string;
  bucketIndex: number;
  startRelativeTimeMs: number;
  endRelativeTimeMs: number;
  eventCount: number;
  errorCount: number;
  decodeFailureCount: number;
  slowCallCount: number;
  dominantModule: string;
  dominantApi: string;
  eventIds: number[];
  samples: TraceViewSample[];
  clauses: Array<Omit<TraceQueryClause, "id">>;
}

export interface TraceTimelineView {
  bucketSizeMs: number;
  startRelativeTimeMs: number;
  endRelativeTimeMs: number;
  buckets: TraceTimelineBucket[];
}

function hasDecodeFailure(event: TraceEvent): boolean {
  return event.arguments.some((argument) => argument.decodeStatus !== "decoded");
}

function sampleForEvent(event: TraceEvent): TraceViewSample {
  return {
    eventId: event.eventId,
    relativeTimeMs: event.relativeTimeMs,
    module: event.module,
    api: event.api,
    message: event.error?.message ?? event.returnValue
  };
}

function incrementCounter(counter: Map<string, number>, value: string) {
  counter.set(value, (counter.get(value) ?? 0) + 1);
}

function topValues(counter: Map<string, number>, limit: number): TraceViewTopValue[] {
  return Array.from(counter.entries())
    .map(([value, count]) => ({
      value,
      count
    }))
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }

      return left.value.localeCompare(right.value);
    })
    .slice(0, limit);
}

function normalizedDurationThreshold(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

export function buildTraceThreadGroups(events: TraceEvent[], durationThresholdUs: number): TraceThreadGroup[] {
  const threshold = normalizedDurationThreshold(durationThresholdUs);
  const groups = new Map<string, {
    pid: number;
    tid: number;
    process: string;
    firstRelativeTimeMs: number;
    lastRelativeTimeMs: number;
    errorCount: number;
    decodeFailureCount: number;
    slowCallCount: number;
    eventIds: number[];
    samples: TraceViewSample[];
    modules: Map<string, number>;
    apis: Map<string, number>;
  }>();

  for (const event of events) {
    const id = `${event.pid}:${event.tid}:${event.process}`;
    const current = groups.get(id);
    const group = current ?? {
      pid: event.pid,
      tid: event.tid,
      process: event.process,
      firstRelativeTimeMs: event.relativeTimeMs,
      lastRelativeTimeMs: event.relativeTimeMs,
      errorCount: 0,
      decodeFailureCount: 0,
      slowCallCount: 0,
      eventIds: [],
      samples: [],
      modules: new Map<string, number>(),
      apis: new Map<string, number>()
    };

    group.firstRelativeTimeMs = Math.min(group.firstRelativeTimeMs, event.relativeTimeMs);
    group.lastRelativeTimeMs = Math.max(group.lastRelativeTimeMs, event.relativeTimeMs);
    group.eventIds.push(event.eventId);
    if (event.error) {
      group.errorCount += 1;
    }
    if (hasDecodeFailure(event)) {
      group.decodeFailureCount += 1;
    }
    if (threshold > 0 && event.durationUs >= threshold) {
      group.slowCallCount += 1;
    }
    if (group.samples.length < 3) {
      group.samples.push(sampleForEvent(event));
    }
    incrementCounter(group.modules, event.module);
    incrementCounter(group.apis, event.api);
    groups.set(id, group);
  }

  return Array.from(groups.entries())
    .map(([id, group]) => ({
      id,
      pid: group.pid,
      tid: group.tid,
      process: group.process,
      threadLabel: `${group.process} / ${group.pid}:${group.tid}`,
      eventCount: group.eventIds.length,
      firstRelativeTimeMs: group.firstRelativeTimeMs,
      lastRelativeTimeMs: group.lastRelativeTimeMs,
      spanMs: Math.max(0, group.lastRelativeTimeMs - group.firstRelativeTimeMs),
      errorCount: group.errorCount,
      decodeFailureCount: group.decodeFailureCount,
      slowCallCount: group.slowCallCount,
      topModules: topValues(group.modules, 3),
      topApis: topValues(group.apis, 3),
      eventIds: group.eventIds,
      samples: group.samples,
      clauses: [
        { field: "process", operator: "equals", value: group.process },
        { field: "pid", operator: "equals", value: String(group.pid) },
        { field: "tid", operator: "equals", value: String(group.tid) }
      ] satisfies Array<Omit<TraceQueryClause, "id">>
    }))
    .sort((left, right) => {
      if (right.eventCount !== left.eventCount) {
        return right.eventCount - left.eventCount;
      }

      if (left.firstRelativeTimeMs !== right.firstRelativeTimeMs) {
        return left.firstRelativeTimeMs - right.firstRelativeTimeMs;
      }

      return left.threadLabel.localeCompare(right.threadLabel);
    });
}

export function chooseTimelineBucketSizeMs(spanMs: number, targetBucketCount = 36): number {
  const safeSpan = Number.isFinite(spanMs) ? Math.max(0, spanMs) : 0;
  const safeTarget = Math.max(1, Math.trunc(targetBucketCount));
  const rawSize = safeSpan <= 0 ? 1 : safeSpan / safeTarget;
  const niceSizes = [
    1,
    2,
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    30000,
    60000,
    300000,
    600000
  ];

  return niceSizes.find((size) => size >= rawSize) ?? niceSizes[niceSizes.length - 1];
}

export function buildTraceTimeline(events: TraceEvent[], durationThresholdUs: number, targetBucketCount = 36): TraceTimelineView {
  if (events.length === 0) {
    return {
      bucketSizeMs: 1,
      startRelativeTimeMs: 0,
      endRelativeTimeMs: 0,
      buckets: []
    };
  }

  const threshold = normalizedDurationThreshold(durationThresholdUs);
  const startRelativeTimeMs = Math.min(...events.map((event) => event.relativeTimeMs));
  const endRelativeTimeMs = Math.max(...events.map((event) => event.relativeTimeMs));
  const bucketSizeMs = chooseTimelineBucketSizeMs(endRelativeTimeMs - startRelativeTimeMs, targetBucketCount);
  const buckets = new Map<number, {
    startRelativeTimeMs: number;
    endRelativeTimeMs: number;
    errorCount: number;
    decodeFailureCount: number;
    slowCallCount: number;
    eventIds: number[];
    samples: TraceViewSample[];
    modules: Map<string, number>;
    apis: Map<string, number>;
  }>();

  for (const event of events) {
    const bucketIndex = Math.max(0, Math.floor((event.relativeTimeMs - startRelativeTimeMs) / bucketSizeMs));
    const bucketStart = startRelativeTimeMs + bucketIndex * bucketSizeMs;
    const current = buckets.get(bucketIndex);
    const bucket = current ?? {
      startRelativeTimeMs: bucketStart,
      endRelativeTimeMs: bucketStart + bucketSizeMs,
      errorCount: 0,
      decodeFailureCount: 0,
      slowCallCount: 0,
      eventIds: [],
      samples: [],
      modules: new Map<string, number>(),
      apis: new Map<string, number>()
    };

    bucket.eventIds.push(event.eventId);
    if (event.error) {
      bucket.errorCount += 1;
    }
    if (hasDecodeFailure(event)) {
      bucket.decodeFailureCount += 1;
    }
    if (threshold > 0 && event.durationUs >= threshold) {
      bucket.slowCallCount += 1;
    }
    if (bucket.samples.length < 3) {
      bucket.samples.push(sampleForEvent(event));
    }
    incrementCounter(bucket.modules, event.module);
    incrementCounter(bucket.apis, event.api);
    buckets.set(bucketIndex, bucket);
  }

  return {
    bucketSizeMs,
    startRelativeTimeMs,
    endRelativeTimeMs,
    buckets: Array.from(buckets.entries())
      .map(([bucketIndex, bucket]) => {
        const dominantModule = topValues(bucket.modules, 1)[0]?.value ?? "";
        const dominantApi = topValues(bucket.apis, 1)[0]?.value ?? "";

        return {
          id: `bucket:${bucketIndex}:${bucket.startRelativeTimeMs}`,
          bucketIndex,
          startRelativeTimeMs: bucket.startRelativeTimeMs,
          endRelativeTimeMs: bucket.endRelativeTimeMs,
          eventCount: bucket.eventIds.length,
          errorCount: bucket.errorCount,
          decodeFailureCount: bucket.decodeFailureCount,
          slowCallCount: bucket.slowCallCount,
          dominantModule,
          dominantApi,
          eventIds: bucket.eventIds,
          samples: bucket.samples,
          clauses: [
            { field: "relativeTimeMs", operator: "greater_than", value: String(bucket.startRelativeTimeMs - 0.001) },
            { field: "relativeTimeMs", operator: "less_than", value: String(bucket.endRelativeTimeMs) }
          ] satisfies Array<Omit<TraceQueryClause, "id">>
        };
      })
      .sort((left, right) => left.bucketIndex - right.bucketIndex)
  };
}
