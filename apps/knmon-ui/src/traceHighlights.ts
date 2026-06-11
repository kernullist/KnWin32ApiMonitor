import type { TraceQueryClause, TraceQueryMatchMode } from "./traceQuery";
import type { TraceEvent } from "./types";

export type TraceHighlightSeverity = "critical" | "warning" | "info" | "muted";

export interface TraceHighlightSample {
  eventId: number;
  module: string;
  api: string;
  reason: string;
}

export interface TraceHighlightMatch {
  ruleId: string;
  label: string;
  severity: TraceHighlightSeverity;
  detail: string;
  reason: string;
}

export interface TraceEventHighlight {
  eventId: number;
  highestSeverity: TraceHighlightSeverity;
  matches: TraceHighlightMatch[];
}

export interface TraceHighlightSummary {
  id: string;
  label: string;
  severity: TraceHighlightSeverity;
  detail: string;
  count: number;
  eventIds: number[];
  samples: TraceHighlightSample[];
  matchMode: TraceQueryMatchMode;
  clauses: Array<Omit<TraceQueryClause, "id">>;
}

export interface TraceHighlightState {
  eventHighlights: TraceEventHighlight[];
  eventHighlightsById: Map<number, TraceEventHighlight>;
  summaries: TraceHighlightSummary[];
}

interface TraceHighlightContext {
  durationThresholdUs: number;
}

interface TraceHighlightRule {
  id: string;
  label: string;
  severity: TraceHighlightSeverity;
  detail: string;
  match: (event: TraceEvent, context: TraceHighlightContext) => string | null;
  buildClauses: (events: TraceEvent[], context: TraceHighlightContext) => {
    matchMode: TraceQueryMatchMode;
    clauses: Array<Omit<TraceQueryClause, "id">>;
  };
}

const severityRank: Record<TraceHighlightSeverity, number> = {
  critical: 4,
  warning: 3,
  info: 2,
  muted: 1
};

const unknownTextValues = new Set(["unknown", "(unknown)", "<unknown>", "n/a", "na", "none", "-"]);

function normalizedDurationThreshold(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

function normalizedText(value: string): string {
  return value.trim().toLowerCase();
}

function isMissingOrUnknown(value: string): boolean {
  const normalized = normalizedText(value);

  return normalized.length === 0 || unknownTextValues.has(normalized);
}

function decodeFailureStatuses(event: TraceEvent): string[] {
  return Array.from(new Set(event.arguments
    .map((argument) => argument.decodeStatus)
    .filter((status) => status !== "decoded")))
    .sort((left, right) => left.localeCompare(right));
}

function highSignalApiReason(event: TraceEvent): string | null {
  const api = event.api.trim();
  const apiLower = api.toLowerCase();
  const moduleLower = event.module.trim().toLowerCase();

  if (api.startsWith("Nt") || moduleLower === "ntdll.dll") {
    return "Native NT API boundary";
  }

  if (api.startsWith("Reg")) {
    return "Registry API family";
  }

  if (api === "OpenProcessToken" || api === "LookupPrivilegeValueW") {
    return "Security token or privilege API family";
  }

  if (api.startsWith("BCrypt")) {
    return "CNG crypto provider/RNG API family";
  }

  if (api.startsWith("Crypt") || api.startsWith("Cert")) {
    return "Certificate or crypto message API family";
  }

  if (api.startsWith("WinHttp") || api.startsWith("Internet")) {
    return "HTTP client session API family";
  }

  if (api.startsWith("Rpc")) {
    return "RPC binding API family";
  }

  if (["socket", "connect", "send", "recv", "sendto", "recvfrom", "getaddrinfo"].includes(apiLower)) {
    return "Winsock networking API family";
  }

  return null;
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
    .sort((left, right) => left.localeCompare(right));
}

function clausesForDecodeFailures(events: TraceEvent[]): Array<Omit<TraceQueryClause, "id">> {
  return uniqueSorted(events.flatMap((event) => decodeFailureStatuses(event)))
    .map((status) => ({
      field: "decodeStatus",
      operator: "equals",
      value: status
    }));
}

function clausesForMissingMetadata(events: TraceEvent[]): Array<Omit<TraceQueryClause, "id">> {
  const clauses: Array<Omit<TraceQueryClause, "id">> = [];
  const unknownModules = uniqueSorted(events
    .map((event) => event.module.trim())
    .filter((value) => value.length > 0 && isMissingOrUnknown(value)));
  const unknownApis = uniqueSorted(events
    .map((event) => event.api.trim())
    .filter((value) => value.length > 0 && isMissingOrUnknown(value)));

  if (events.some((event) => event.module.trim().length === 0)) {
    clauses.push({ field: "module", operator: "missing", value: "" });
  }
  if (events.some((event) => event.api.trim().length === 0)) {
    clauses.push({ field: "api", operator: "missing", value: "" });
  }

  unknownModules.forEach((value) => {
    clauses.push({ field: "module", operator: "equals", value });
  });
  unknownApis.forEach((value) => {
    clauses.push({ field: "api", operator: "equals", value });
  });

  return clauses;
}

function coverageHintClauses(): Array<Omit<TraceQueryClause, "id">> {
  return [
    { field: "api", operator: "starts_with", value: "Nt" },
    { field: "module", operator: "equals", value: "ntdll.dll" },
    { field: "api", operator: "starts_with", value: "Reg" },
    { field: "api", operator: "equals", value: "OpenProcessToken" },
    { field: "api", operator: "equals", value: "LookupPrivilegeValueW" },
    { field: "api", operator: "starts_with", value: "BCrypt" },
    { field: "api", operator: "starts_with", value: "Crypt" },
    { field: "api", operator: "starts_with", value: "Cert" },
    { field: "api", operator: "starts_with", value: "WinHttp" },
    { field: "api", operator: "starts_with", value: "Internet" },
    { field: "api", operator: "starts_with", value: "Rpc" },
    { field: "api", operator: "equals", value: "socket" },
    { field: "api", operator: "equals", value: "connect" },
    { field: "api", operator: "equals", value: "send" },
    { field: "api", operator: "equals", value: "recv" },
    { field: "api", operator: "equals", value: "getaddrinfo" }
  ];
}

export const builtinTraceHighlightRules: TraceHighlightRule[] = [
  {
    id: "error-return",
    label: "Error return",
    severity: "critical",
    detail: "Error field is present on the API event.",
    match(event) {
      if (!event.error) {
        return null;
      }

      return `${event.error.kind} ${event.error.code}: ${event.error.message}`;
    },
    buildClauses() {
      return {
        matchMode: "all",
        clauses: [
          { field: "error", operator: "exists", value: "" }
        ]
      };
    }
  },
  {
    id: "decode-failure",
    label: "Decode failure",
    severity: "warning",
    detail: "One or more arguments were not fully decoded.",
    match(event) {
      const statuses = decodeFailureStatuses(event);
      if (statuses.length === 0) {
        return null;
      }

      return `decode=${statuses.join(",")}`;
    },
    buildClauses(events) {
      return {
        matchMode: "any",
        clauses: clausesForDecodeFailures(events)
      };
    }
  },
  {
    id: "slow-call",
    label: "Slow call",
    severity: "warning",
    detail: "Duration is at or above the current slow-call threshold.",
    match(event, context) {
      if (context.durationThresholdUs <= 0 || event.durationUs < context.durationThresholdUs) {
        return null;
      }

      return `${event.durationUs} us >= ${context.durationThresholdUs} us`;
    },
    buildClauses(_events, context) {
      return {
        matchMode: "all",
        clauses: [
          { field: "durationUs", operator: "greater_than", value: String(Math.max(0, context.durationThresholdUs - 1)) }
        ]
      };
    }
  },
  {
    id: "coverage-hint",
    label: "Coverage hint",
    severity: "info",
    detail: "API family is useful for security-oriented trace triage.",
    match(event) {
      return highSignalApiReason(event);
    },
    buildClauses() {
      return {
        matchMode: "any",
        clauses: coverageHintClauses()
      };
    }
  },
  {
    id: "metadata-quality",
    label: "Metadata quality",
    severity: "muted",
    detail: "Module or API identity is missing or unknown.",
    match(event) {
      const missing: string[] = [];
      if (isMissingOrUnknown(event.module)) {
        missing.push("module");
      }
      if (isMissingOrUnknown(event.api)) {
        missing.push("api");
      }
      if (missing.length === 0) {
        return null;
      }

      return `missing=${missing.join(",")}`;
    },
    buildClauses(events) {
      return {
        matchMode: "any",
        clauses: clausesForMissingMetadata(events)
      };
    }
  }
];

function sampleForMatch(event: TraceEvent, match: TraceHighlightMatch): TraceHighlightSample {
  return {
    eventId: event.eventId,
    module: event.module,
    api: event.api,
    reason: match.reason
  };
}

export function compareTraceHighlightSeverity(left: TraceHighlightSeverity, right: TraceHighlightSeverity): number {
  return severityRank[right] - severityRank[left];
}

export function buildTraceHighlightState(events: TraceEvent[], durationThresholdUs: number): TraceHighlightState {
  const context = {
    durationThresholdUs: normalizedDurationThreshold(durationThresholdUs)
  };
  const summaryState = new Map<string, {
    rule: TraceHighlightRule;
    eventIds: number[];
    samples: TraceHighlightSample[];
    events: TraceEvent[];
  }>();
  const eventHighlights: TraceEventHighlight[] = [];
  const eventHighlightsById = new Map<number, TraceEventHighlight>();

  builtinTraceHighlightRules.forEach((rule) => {
    summaryState.set(rule.id, {
      rule,
      eventIds: [],
      samples: [],
      events: []
    });
  });

  events.forEach((event) => {
    const matches = builtinTraceHighlightRules.flatMap((rule) => {
      const reason = rule.match(event, context);
      if (!reason) {
        return [];
      }

      return [{
        ruleId: rule.id,
        label: rule.label,
        severity: rule.severity,
        detail: rule.detail,
        reason
      }];
    }).sort((left, right) => {
      const severityCompare = compareTraceHighlightSeverity(left.severity, right.severity);
      if (severityCompare !== 0) {
        return severityCompare;
      }

      return left.label.localeCompare(right.label);
    });

    if (matches.length === 0) {
      return;
    }

    matches.forEach((match) => {
      const summary = summaryState.get(match.ruleId);
      if (!summary) {
        return;
      }

      summary.eventIds.push(event.eventId);
      summary.events.push(event);
      if (summary.samples.length < 3) {
        summary.samples.push(sampleForMatch(event, match));
      }
    });

    const eventHighlight = {
      eventId: event.eventId,
      highestSeverity: matches[0].severity,
      matches
    };
    eventHighlights.push(eventHighlight);
    eventHighlightsById.set(event.eventId, eventHighlight);
  });

  const summaries = builtinTraceHighlightRules.map((rule) => {
    const state = summaryState.get(rule.id);
    const matchedEvents = state?.events ?? [];
    const query = rule.buildClauses(matchedEvents, context);

    return {
      id: rule.id,
      label: rule.label,
      severity: rule.severity,
      detail: rule.detail,
      count: state?.eventIds.length ?? 0,
      eventIds: state?.eventIds ?? [],
      samples: state?.samples ?? [],
      matchMode: query.matchMode,
      clauses: query.clauses
    };
  }).sort((left, right) => {
    const severityCompare = compareTraceHighlightSeverity(left.severity, right.severity);
    if (severityCompare !== 0) {
      return severityCompare;
    }

    return left.label.localeCompare(right.label);
  });

  return {
    eventHighlights,
    eventHighlightsById,
    summaries
  };
}
