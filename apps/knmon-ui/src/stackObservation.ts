import type { StackObservation } from "./types";

export function describeStackObservation(event: StackObservation)
{
  const source = event.stackSource === undefined ? "legacy_unverified" : event.stackSource;
  const context = event.hookContext;
  const valid = Array.isArray(event.stack) && event.stack.every((entry) => typeof entry === "string") &&
    (source === "not_captured" || source === "legacy_unverified") &&
    (source !== "not_captured" || event.stack.length === 0) &&
    (context === undefined || (context !== null && typeof context === "object" && !Array.isArray(context) &&
      typeof context.agent === "string" && context.agent.length > 0 &&
      (context.resolvedHostModule === undefined || (typeof context.resolvedHostModule === "string" && context.resolvedHostModule.length > 0))));

  return {
    source: valid ? source : "invalid",
    message: !valid ? "Invalid stack observation metadata."
      : source === "not_captured" ? "Call stack was not captured."
      : "Legacy stack entries have no verified capture provenance.",
    entries: valid && source === "legacy_unverified" ? event.stack : [],
    hookContext: valid ? context : undefined
  };
}
