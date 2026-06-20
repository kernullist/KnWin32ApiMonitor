import fs from "node:fs";
import path from "node:path";

import {
  apiKey,
  collectApiRecords,
  normalizeModuleName,
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

export const generatedDllBatchPromotionPlanPath = path.join(repoRoot, "generated", "dll-batch-promotion-plan.json");

const validClassifications = new Set([
  "already_live",
  "auto_promotable",
  "manual_decoder_required",
  "blocked_by_payload_policy",
  "unsupported"
]);

const liveStatuses = new Set(["hooked", "smoke_verified"]);
const liveHookPolicies = new Set(["iat"]);
const autoRisks = new Set(["low", "medium"]);
const safeAliasKinds = new Set(["count", "enum", "flags", "handle", "pointer"]);
const payloadAliasKinds = new Set(["buffer", "string"]);
const manualAliasKinds = new Set(["object", "unknown"]);
const lifecycleNamePattern = /^(Close|Cleanup|Delete|Destroy|Free|Release|Revert|RoUninitialize|Unmap|Unregister)|Cleanup$|Close$/i;
const queryNamePattern = /^(Get|Open|Query|Enum|Find|Lookup|Uuid|SymCleanup|SymInitialize)/i;
const payloadTermPattern = /(authdata|authentication|password|secret|privatekey|private_key|credentialblob|secbuffer|tokenprivileges|plaintext|ciphertext|payload|cookie|header|requestbody|responsebody|certificateblob|cert_context|crypt_blob|bufferpreview|rawbuffer|filecontent|file_content)/i;
const stringPayloadTermPattern = /(string|path|url|uri|commandline|environment|principal|package|targetname|servername|username|domain|folder|filename|file_name|modulepath|searchpath|bstr|hstring)/i;
const manualFamilyPattern = /^(trust|symbols|shell|module|resource|profile|network-management|network-metadata)$/i;

export function loadDllBatchPromotionPlan()
{
  if (!fs.existsSync(generatedDllBatchPromotionPlanPath))
  {
    return null;
  }

  return JSON.parse(fs.readFileSync(generatedDllBatchPromotionPlanPath, "utf8"));
}

export function writeDllBatchPromotionPlan(plan)
{
  writeStableJson(generatedDllBatchPromotionPlanPath, plan);
}

export function buildDllBatchPromotionPlan(apiDocuments, metadataIndex)
{
  const records = collectApiRecords(apiDocuments, metadataIndex);
  const grouped = new Map();

  for (const record of records)
  {
    const moduleName = normalizeModuleName(record.api.module);
    if (!grouped.has(moduleName))
    {
      grouped.set(moduleName, []);
    }

    grouped.get(moduleName).push(buildApiBatchEntry(record, metadataIndex));
  }

  const dlls = Array.from(grouped.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([moduleName, apis]) => buildDllEntry(moduleName, apis));
  const summary = summarizeDllEntries(dlls);

  return {
    schemaVersion: "0.1.0",
    source: {
      definitions: "definitions/win32",
      metadata: "definitions/metadata",
      generatedFrom: [
        "definitions/**/*.json",
        "definitions/metadata/**/*.json"
      ]
    },
    policy: {
      installMode: "dll_batch_review",
      autoPromotionBoundary: "pointer_scalar_or_existing_pointer_only_metadata",
      generatedRuntimeHooksEnabledByDefault: false,
      payloadCaptureDefault: "disabled",
      batchRule: "Promote all auto-promotable APIs in the same DLL together, document manual decoders, and block sensitive payload APIs explicitly.",
      x86Requirement: "Every auto-promotable API still needs ABI-class compatible wrappers before runtime promotion."
    },
    summary,
    dlls
  };
}

export function validateDllBatchPromotionPlan(plan = loadDllBatchPromotionPlan(), apiDocuments, metadataIndex)
{
  const errors = [];

  if (plan === null)
  {
    return [`${relativePath(generatedDllBatchPromotionPlanPath)} is missing; run npm run defs:dll-batch-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`DLL batch promotion plan has unsupported schema version ${plan.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedDllBatchPromotionPlanPath) ? fs.readFileSync(generatedDllBatchPromotionPlanPath, "utf8") : "";
  if (apiDocuments && metadataIndex)
  {
    const expectedText = stableStringify(buildDllBatchPromotionPlan(apiDocuments, metadataIndex));
    if (actualText !== expectedText)
    {
      errors.push(`${relativePath(generatedDllBatchPromotionPlanPath)} is stale; run npm run defs:dll-batch-plan:generate`);
    }
  }

  const dlls = plan.dlls ?? [];
  const seenDlls = new Set();
  const seenApis = new Set();
  const counted = {
    totalApis: 0,
    alreadyLive: 0,
    autoPromotable: 0,
    manualDecoderRequired: 0,
    blockedByPayloadPolicy: 0,
    unsupported: 0
  };

  for (const dll of dlls)
  {
    if (!dll.module || seenDlls.has(dll.module))
    {
      errors.push(`DLL batch promotion plan has duplicate or missing DLL entry ${dll.module}`);
    }
    seenDlls.add(dll.module);

    const apis = dll.apis ?? [];
    const dllCounts = countClassifications(apis);
    if (dll.totalApis !== apis.length)
    {
      errors.push(`DLL ${dll.module} totalApis mismatch: total=${dll.totalApis} apis=${apis.length}`);
    }

    for (const [field, value] of Object.entries(dllCounts))
    {
      if (dll[field] !== value)
      {
        errors.push(`DLL ${dll.module} ${field} mismatch: summary=${dll[field]} actual=${value}`);
      }
    }

    for (const api of apis)
    {
      const key = api.key ?? apiKey(api.module, api.apiName);
      if (seenApis.has(key))
      {
        errors.push(`DLL batch promotion plan has duplicate API entry ${key}`);
      }
      seenApis.add(key);

      if (!validClassifications.has(api.classification))
      {
        errors.push(`DLL batch promotion plan has invalid classification for ${key}: ${api.classification}`);
      }

      if (api.classification === "auto_promotable" && (api.risk === "high" || api.risk === "critical"))
      {
        errors.push(`High-risk API cannot be auto-promotable: ${key}`);
      }

      if (api.classification === "auto_promotable" && (api.reasons ?? []).some((reason) => reason.startsWith("payload_")))
      {
        errors.push(`Auto-promotable API has payload block reason: ${key}`);
      }
    }

    counted.totalApis += apis.length;
    counted.alreadyLive += dllCounts.alreadyLive;
    counted.autoPromotable += dllCounts.autoPromotable;
    counted.manualDecoderRequired += dllCounts.manualDecoderRequired;
    counted.blockedByPayloadPolicy += dllCounts.blockedByPayloadPolicy;
    counted.unsupported += dllCounts.unsupported;
  }

  const summary = plan.summary ?? {};
  if (summary.totalDlls !== dlls.length)
  {
    errors.push(`DLL batch promotion totalDlls mismatch: summary=${summary.totalDlls} dlls=${dlls.length}`);
  }

  for (const [field, value] of Object.entries(counted))
  {
    if (summary[field] !== value)
    {
      errors.push(`DLL batch promotion ${field} mismatch: summary=${summary[field]} actual=${value}`);
    }
  }

  return errors;
}

export function dllBatchPromotionPlanToMarkdown(plan)
{
  if (plan === null)
  {
    return "# DLL Batch Promotion Plan\n\nNot generated. Run `npm run defs:dll-batch-plan:generate`.\n";
  }

  const lines = [
    "# DLL Batch Promotion Plan",
    "",
    `Total DLLs: ${plan.summary.totalDlls}`,
    `Total APIs: ${plan.summary.totalApis}`,
    `Already live: ${plan.summary.alreadyLive}`,
    `Auto-promotable: ${plan.summary.autoPromotable}`,
    `Manual decoder required: ${plan.summary.manualDecoderRequired}`,
    `Blocked by payload policy: ${plan.summary.blockedByPayloadPolicy}`,
    `Unsupported: ${plan.summary.unsupported}`,
    "",
    "## DLLs With Auto-Promotable APIs",
    ""
  ];

  const dlls = (plan.dlls ?? []).filter((dll) => dll.autoPromotable > 0);
  for (const dll of dlls)
  {
    const names = dll.apis
      .filter((api) => api.classification === "auto_promotable")
      .map((api) => api.apiName)
      .join(", ");
    lines.push(`- ${dll.module}: ${dll.autoPromotable} (${names})`);
  }

  if (dlls.length === 0)
  {
    lines.push("- none");
  }

  lines.push("");
  return lines.join("\n");
}

function buildApiBatchEntry(record, metadataIndex)
{
  const api = record.api;
  const key = record.key;
  const parameterAnalyses = (api.parameters ?? []).map((parameter) => analyzeParameter(parameter, metadataIndex));
  const classification = classifyApi(api, parameterAnalyses);

  return {
    id: record.assignment?.id ?? null,
    key,
    module: normalizeModuleName(api.module),
    apiName: api.name,
    family: api.family ?? "uncategorized",
    category: api.category ?? "uncategorized",
    risk: api.risk ?? "medium",
    hookPolicy: api.hookPolicy ?? "definition_only",
    coverageStatus: api.coverageStatus ?? "definition_only",
    callingConvention: api.callingConvention ?? "winapi",
    returnType: api.returnType ?? "void",
    errorSource: api.errorSource ?? "none",
    parameterCount: parameterAnalyses.length,
    classification: classification.classification,
    recommendation: classification.recommendation,
    reasons: classification.reasons,
    pointerOnlyParameters: parameterAnalyses
      .filter((parameter) => parameter.pointerOnlyCandidate)
      .map((parameter) => parameter.name),
    payloadSensitiveParameters: parameterAnalyses
      .filter((parameter) => parameter.payloadSensitive)
      .map((parameter) => parameter.name),
    sourceFile: relativePath(record.filePath)
  };
}

function buildDllEntry(moduleName, apis)
{
  const sortedApis = [...apis].sort((left, right) => {
    if ((left.id ?? Number.MAX_SAFE_INTEGER) !== (right.id ?? Number.MAX_SAFE_INTEGER))
    {
      return (left.id ?? Number.MAX_SAFE_INTEGER) - (right.id ?? Number.MAX_SAFE_INTEGER);
    }

    return left.apiName.localeCompare(right.apiName);
  });
  const counts = countClassifications(sortedApis);
  const sourceFiles = Array.from(new Set(sortedApis.map((api) => api.sourceFile))).sort();

  return {
    module: moduleName,
    sourceFiles,
    totalApis: sortedApis.length,
    ...counts,
    recommendation: recommendationForDll(counts),
    apis: sortedApis
  };
}

function summarizeDllEntries(dlls)
{
  const summary = {
    totalDlls: dlls.length,
    totalApis: 0,
    alreadyLive: 0,
    autoPromotable: 0,
    manualDecoderRequired: 0,
    blockedByPayloadPolicy: 0,
    unsupported: 0,
    dllsWithAutoPromotableApis: 0,
    dllsFullyTriaged: 0
  };

  for (const dll of dlls)
  {
    summary.totalApis += dll.totalApis;
    summary.alreadyLive += dll.alreadyLive;
    summary.autoPromotable += dll.autoPromotable;
    summary.manualDecoderRequired += dll.manualDecoderRequired;
    summary.blockedByPayloadPolicy += dll.blockedByPayloadPolicy;
    summary.unsupported += dll.unsupported;
    if (dll.autoPromotable > 0)
    {
      summary.dllsWithAutoPromotableApis += 1;
    }

    if (dll.autoPromotable === 0 && dll.manualDecoderRequired === 0)
    {
      summary.dllsFullyTriaged += 1;
    }
  }

  return summary;
}

function countClassifications(apis)
{
  return {
    alreadyLive: apis.filter((api) => api.classification === "already_live").length,
    autoPromotable: apis.filter((api) => api.classification === "auto_promotable").length,
    manualDecoderRequired: apis.filter((api) => api.classification === "manual_decoder_required").length,
    blockedByPayloadPolicy: apis.filter((api) => api.classification === "blocked_by_payload_policy").length,
    unsupported: apis.filter((api) => api.classification === "unsupported").length
  };
}

function recommendationForDll(counts)
{
  if (counts.autoPromotable > 0)
  {
    return "promote_auto_batch_before_single_api_work";
  }

  if (counts.manualDecoderRequired > 0)
  {
    return "design_manual_decoder_batch";
  }

  if (counts.blockedByPayloadPolicy > 0)
  {
    return "document_payload_boundary_only";
  }

  return "fully_triaged";
}

function classifyApi(api, parameterAnalyses)
{
  const reasons = [];

  if (liveHookPolicies.has(api.hookPolicy) && liveStatuses.has(api.coverageStatus))
  {
    return {
      classification: "already_live",
      recommendation: "keep_in_dll_batch_smoke",
      reasons: ["already_live_iat_coverage"]
    };
  }

  if (api.hookPolicy === "unsupported" || api.coverageStatus === "unsupported")
  {
    return {
      classification: "unsupported",
      recommendation: "leave_unsupported",
      reasons: ["unsupported_policy"]
    };
  }

  if (api.hookPolicy === "inline_review_required" || api.hookPolicy === "deferred")
  {
    return {
      classification: "manual_decoder_required",
      recommendation: "review_non_iat_hook_strategy",
      reasons: ["non_iat_or_deferred_policy"]
    };
  }

  if (!autoRisks.has(api.risk))
  {
    reasons.push("payload_risk_policy");
  }

  const text = searchableApiText(api);
  if (payloadTermPattern.test(text))
  {
    reasons.push("payload_sensitive_name_or_type");
  }

  if (parameterAnalyses.some((parameter) => parameter.payloadSensitive))
  {
    reasons.push("payload_sensitive_parameter");
  }

  if (parameterAnalyses.some((parameter) => payloadAliasKinds.has(parameter.aliasKind)))
  {
    reasons.push("payload_string_or_buffer_decoder");
  }

  if (reasons.length > 0)
  {
    return {
      classification: "blocked_by_payload_policy",
      recommendation: "keep_definition_only_until_payload_policy_review",
      reasons: Array.from(new Set(reasons)).sort()
    };
  }

  const manualReasons = [];
  if (parameterAnalyses.some((parameter) => manualAliasKinds.has(parameter.aliasKind)))
  {
    manualReasons.push("manual_object_or_unknown_decoder");
  }

  if (manualFamilyPattern.test(api.family ?? "") || manualFamilyPattern.test(api.category ?? ""))
  {
    manualReasons.push("manual_family_boundary_review");
  }

  if (!isBatchFriendlyName(api.name) && parameterAnalyses.some((parameter) => parameter.direction !== "in"))
  {
    manualReasons.push("manual_output_boundary_review");
  }

  if (!lifecycleNamePattern.test(api.name) && parameterAnalyses.some((parameter) => parameter.readsTargetMemory && parameter.direction !== "in"))
  {
    manualReasons.push("manual_output_pointer_memory_boundary");
  }

  if (parameterAnalyses.some((parameter) => !parameter.pointerOrScalarCapturable))
  {
    manualReasons.push("manual_unsupported_parameter_shape");
  }

  if (manualReasons.length > 0)
  {
    return {
      classification: "manual_decoder_required",
      recommendation: "design_dll_batch_decoder_before_runtime_promotion",
      reasons: Array.from(new Set(manualReasons)).sort()
    };
  }

  return {
    classification: "auto_promotable",
    recommendation: "promote_with_same_dll_pointer_scalar_batch",
    reasons: ["pointer_scalar_or_pointer_only_parameters"]
  };
}

function analyzeParameter(parameter, metadataIndex)
{
  const alias = metadataIndex.aliasByName.get(parameter.decode) ?? null;
  const aliasKind = alias?.kind ?? "unknown";
  const text = searchableParameterText(parameter, alias);
  const stringLike = aliasKind === "string" || stringPayloadTermPattern.test(text);
  const payloadSensitive = payloadAliasKinds.has(aliasKind) || payloadTermPattern.test(text) || stringLike;
  const pointerOrScalarCapturable = safeAliasKinds.has(aliasKind);
  const pointerOnlyCandidate = aliasKind === "pointer" || (aliasKind === "handle" && parameter.type.includes("*"));

  return {
    name: parameter.name,
    direction: parameter.direction,
    type: parameter.type,
    decode: parameter.decode,
    aliasKind,
    readsTargetMemory: alias?.readsTargetMemory === true,
    pointerOrScalarCapturable,
    pointerOnlyCandidate,
    payloadSensitive
  };
}

function searchableApiText(api)
{
  return [
    api.module,
    api.name,
    api.family,
    api.category,
    api.returnType,
    ...(api.parameters ?? []).flatMap((parameter) => [
      parameter.name,
      parameter.type,
      parameter.decode
    ])
  ].join(" ");
}

function searchableParameterText(parameter, alias)
{
  return [
    parameter.name,
    parameter.type,
    parameter.decode,
    alias?.name,
    alias?.kind,
    alias?.preview
  ].join(" ");
}

function isBatchFriendlyName(name)
{
  return lifecycleNamePattern.test(name) || queryNamePattern.test(name);
}
