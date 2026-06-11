import type { TraceEvent } from "./types";

export type TraceQueryField =
  | "api"
  | "module"
  | "process"
  | "pid"
  | "tid"
  | "tag"
  | "returnValue"
  | "error"
  | "argument"
  | "durationUs"
  | "decodeStatus";

export type TraceQueryOperator =
  | "contains"
  | "equals"
  | "not_equals"
  | "starts_with"
  | "exists"
  | "missing"
  | "greater_than"
  | "less_than";

export type TraceQueryMatchMode = "all" | "any";

export interface TraceQueryClause {
  id: string;
  field: TraceQueryField;
  operator: TraceQueryOperator;
  value: string;
}

export interface TraceQueryOption<T extends string> {
  id: T;
  label: string;
}

export interface InvalidTraceQueryClause {
  id: string;
  reason: string;
}

export interface CompiledTraceQuery {
  activeClauseCount: number;
  invalidClauses: InvalidTraceQueryClause[];
  matches: (event: TraceEvent) => boolean;
}

export interface TraceIssueSample {
  eventId: number;
  module: string;
  api: string;
  message: string;
}

export interface TraceIssueGroup {
  id: string;
  kind: "error" | "decode" | "duration" | "module_api";
  label: string;
  detail: string;
  count: number;
  eventIds: number[];
  samples: TraceIssueSample[];
  clauses: Array<Omit<TraceQueryClause, "id">>;
}

export const traceQueryFieldOptions: Array<TraceQueryOption<TraceQueryField>> = [
  { id: "api", label: "API" },
  { id: "module", label: "Module" },
  { id: "process", label: "Process" },
  { id: "pid", label: "PID" },
  { id: "tid", label: "TID" },
  { id: "tag", label: "Tag" },
  { id: "returnValue", label: "Return" },
  { id: "error", label: "Error" },
  { id: "argument", label: "Argument" },
  { id: "durationUs", label: "Duration" },
  { id: "decodeStatus", label: "Decode" }
];

export const traceQueryOperatorOptions: Array<TraceQueryOption<TraceQueryOperator>> = [
  { id: "contains", label: "contains" },
  { id: "equals", label: "equals" },
  { id: "not_equals", label: "not equals" },
  { id: "starts_with", label: "starts with" },
  { id: "exists", label: "exists" },
  { id: "missing", label: "missing" },
  { id: "greater_than", label: "greater than" },
  { id: "less_than", label: "less than" }
];

const valueLessOperators = new Set<TraceQueryOperator>(["exists", "missing"]);
const numericFields = new Set<TraceQueryField>(["pid", "tid", "durationUs"]);

export function operatorNeedsValue(operator: TraceQueryOperator): boolean {
  return !valueLessOperators.has(operator);
}

export function isNumericTraceQueryField(field: TraceQueryField): boolean {
  return numericFields.has(field);
}

export function makeTraceEventSearchText(event: TraceEvent): string {
  return [
    event.api,
    event.module,
    event.process,
    event.returnValue,
    event.error?.code ?? "",
    event.error?.message ?? "",
    event.tags.join(" "),
    event.arguments.map((argument) => [
      argument.type,
      argument.name,
      argument.preCallValue,
      argument.postCallValue,
      argument.rawValue,
      argument.decodedValue,
      argument.decodeStatus
    ].join(" ")).join(" ")
  ].join(" ").toLowerCase();
}

export function matchesFreeTextFilter(event: TraceEvent, filter: string): boolean {
  const normalized = filter.trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  return makeTraceEventSearchText(event).includes(normalized);
}

function getStringValues(event: TraceEvent, field: TraceQueryField): string[] {
  switch (field) {
    case "api":
      return [event.api];
    case "module":
      return [event.module];
    case "process":
      return [event.process];
    case "pid":
      return [String(event.pid)];
    case "tid":
      return [String(event.tid)];
    case "tag":
      return event.tags;
    case "returnValue":
      return [event.returnValue];
    case "error":
      return event.error ? [event.error.kind, event.error.code, event.error.message] : [];
    case "argument":
      return event.arguments.flatMap((argument) => [
        argument.type,
        argument.name,
        argument.preCallValue,
        argument.postCallValue,
        argument.rawValue,
        argument.decodedValue
      ]);
    case "durationUs":
      return [String(event.durationUs)];
    case "decodeStatus":
      return event.arguments.map((argument) => argument.decodeStatus);
    default:
      return [];
  }
}

function getNumericValue(event: TraceEvent, field: TraceQueryField): number | null {
  switch (field) {
    case "pid":
      return event.pid;
    case "tid":
      return event.tid;
    case "durationUs":
      return event.durationUs;
    default:
      return null;
  }
}

function validateClause(clause: TraceQueryClause): string | null {
  if (operatorNeedsValue(clause.operator) && !clause.value.trim()) {
    return "value required";
  }

  if ((clause.operator === "greater_than" || clause.operator === "less_than") && !isNumericTraceQueryField(clause.field)) {
    return "numeric operator requires pid, tid, or duration";
  }

  if ((clause.operator === "greater_than" || clause.operator === "less_than") && !Number.isFinite(Number(clause.value))) {
    return "numeric value required";
  }

  return null;
}

function matchClause(event: TraceEvent, clause: TraceQueryClause): boolean {
  const values = getStringValues(event, clause.field);
  const normalizedValue = clause.value.trim().toLowerCase();

  if (clause.operator === "exists") {
    return values.some((value) => value.trim().length > 0);
  }

  if (clause.operator === "missing") {
    return values.every((value) => value.trim().length === 0);
  }

  if (clause.operator === "greater_than" || clause.operator === "less_than") {
    const numericValue = getNumericValue(event, clause.field);
    const expectedValue = Number(clause.value);
    if (numericValue === null || !Number.isFinite(expectedValue)) {
      return false;
    }

    return clause.operator === "greater_than"
      ? numericValue > expectedValue
      : numericValue < expectedValue;
  }

  const normalizedValues = values.map((value) => value.toLowerCase());
  if (clause.operator === "contains") {
    return normalizedValues.some((value) => value.includes(normalizedValue));
  }

  if (clause.operator === "equals") {
    return normalizedValues.some((value) => value === normalizedValue);
  }

  if (clause.operator === "not_equals") {
    return normalizedValues.every((value) => value !== normalizedValue);
  }

  if (clause.operator === "starts_with") {
    return normalizedValues.some((value) => value.startsWith(normalizedValue));
  }

  return true;
}

export function compileTraceQuery(clauses: TraceQueryClause[], matchMode: TraceQueryMatchMode): CompiledTraceQuery {
  const invalidClauses: InvalidTraceQueryClause[] = [];
  const validClauses = clauses.filter((clause) => {
    const reason = validateClause(clause);
    if (reason) {
      invalidClauses.push({
        id: clause.id,
        reason
      });
      return false;
    }

    return true;
  });

  return {
    activeClauseCount: validClauses.length,
    invalidClauses,
    matches(event: TraceEvent): boolean {
      if (validClauses.length === 0) {
        return true;
      }

      if (matchMode === "any") {
        return validClauses.some((clause) => matchClause(event, clause));
      }

      return validClauses.every((clause) => matchClause(event, clause));
    }
  };
}

function sampleForEvent(event: TraceEvent): TraceIssueSample {
  return {
    eventId: event.eventId,
    module: event.module,
    api: event.api,
    message: event.error?.message ?? `${event.durationUs} us`
  };
}

function upsertIssueGroup(
  groups: Map<string, TraceIssueGroup>,
  group: Omit<TraceIssueGroup, "count" | "eventIds" | "samples">,
  event: TraceEvent
) {
  const current = groups.get(group.id);
  if (current) {
    current.count += 1;
    current.eventIds.push(event.eventId);
    if (current.samples.length < 3) {
      current.samples.push(sampleForEvent(event));
    }
    return;
  }

  groups.set(group.id, {
    ...group,
    count: 1,
    eventIds: [event.eventId],
    samples: [sampleForEvent(event)]
  });
}

export function buildTraceIssueGroups(events: TraceEvent[], durationThresholdUs: number): TraceIssueGroup[] {
  const groups = new Map<string, TraceIssueGroup>();
  const threshold = Number.isFinite(durationThresholdUs) ? Math.max(0, Math.trunc(durationThresholdUs)) : 0;

  for (const event of events) {
    if (event.error) {
      upsertIssueGroup(
        groups,
        {
          id: `error:${event.error.code}:${event.error.message}`,
          kind: "error",
          label: `${event.error.code} ${event.error.message}`,
          detail: "Error code and message",
          clauses: [
            { field: "error", operator: "contains", value: event.error.code },
            { field: "error", operator: "contains", value: event.error.message }
          ]
        },
        event
      );

      upsertIssueGroup(
        groups,
        {
          id: `module-api:${event.module}:${event.api}`,
          kind: "module_api",
          label: `${event.module}!${event.api}`,
          detail: "Erroring module/API pair",
          clauses: [
            { field: "module", operator: "equals", value: event.module },
            { field: "api", operator: "equals", value: event.api },
            { field: "error", operator: "exists", value: "" }
          ]
        },
        event
      );
    }

    for (const argument of event.arguments) {
      if (argument.decodeStatus !== "decoded") {
        upsertIssueGroup(
          groups,
          {
            id: `decode:${argument.decodeStatus}`,
            kind: "decode",
            label: argument.decodeStatus,
            detail: "Argument decode status",
            clauses: [
              { field: "decodeStatus", operator: "equals", value: argument.decodeStatus }
            ]
          },
          event
        );
      }
    }

    if (event.durationUs >= threshold && threshold > 0) {
      upsertIssueGroup(
        groups,
        {
          id: `duration:${threshold}:${event.api}`,
          kind: "duration",
          label: `${event.api} >= ${threshold} us`,
          detail: "High-duration API calls",
          clauses: [
            { field: "api", operator: "equals", value: event.api },
            { field: "durationUs", operator: "greater_than", value: String(Math.max(0, threshold - 1)) }
          ]
        },
        event
      );
    }
  }

  return Array.from(groups.values()).sort((left, right) => {
    if (right.count !== left.count) {
      return right.count - left.count;
    }

    return left.label.localeCompare(right.label);
  });
}
