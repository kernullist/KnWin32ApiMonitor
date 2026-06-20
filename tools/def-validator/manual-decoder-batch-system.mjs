import fs from "node:fs";
import path from "node:path";

import {
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

export const generatedManualDecoderBatchPlanPath = path.join(repoRoot, "generated", "manual-decoder-batch-plan.json");

const requiredEvidence = [
  "x64_native_smoke",
  "x86_native_smoke",
  "zero_healthy_path_drops",
  "payload_absence_assertions",
  "hook_overhead_gate",
  "same_dll_batch_review"
];

const defaultForbiddenEvidence = [
  "target_memory_bulk_copy",
  "strings_or_buffer_payloads",
  "credentials_or_secret_material",
  "byte_previews",
  "stack_or_injection_payloads"
];

const manualApiBoundaries = new Map([
  [
    "rpcrt4.dll!RpcMgmtEpEltInqDone",
    {
      allowedEvidence: [
        "RPC_EP_INQ_HANDLE pointer address",
        "pre/post RPC_EP_INQ_HANDLE value only",
        "RPC_STATUS return value",
        "duration and hook lifecycle metadata"
      ],
      forbiddenEvidence: [
        "endpoint annotation strings",
        "RPC binding vectors or string bindings",
        "object UUID payload expansion",
        "endpoint mapper inventory",
        "RPC auth data or network payloads"
      ],
      reviewNotes: [
        "Only the cleanup call is a possible low-payload candidate; begin/next remain payload-policy blocked.",
        "A runtime hook must not infer endpoint inventory from the inquiry handle."
      ]
    }
  ],
  [
    "wintrust.dll!WTHelperProvDataFromStateData",
    {
      allowedEvidence: [
        "state-data HANDLE value",
        "returned CRYPT_PROVIDER_DATA pointer value",
        "NULL/non-NULL return classification",
        "duration and hook lifecycle metadata"
      ],
      forbiddenEvidence: [
        "CRYPT_PROVIDER_DATA structure dereference",
        "signer, certificate, chain, or catalog structure traversal",
        "file path or subject/issuer string capture",
        "hash, signature, or policy payload capture",
        "WinVerifyTrust state mutation"
      ],
      reviewNotes: [
        "This helper exposes a provider-data pointer; any dereference requires a separate trust payload design.",
        "Do not promote it as a standalone hook without reviewing the paired WinVerifyTrust state lifecycle."
      ]
    }
  ]
]);

export function loadManualDecoderBatchPlan()
{
  if (!fs.existsSync(generatedManualDecoderBatchPlanPath))
  {
    return null;
  }

  return JSON.parse(fs.readFileSync(generatedManualDecoderBatchPlanPath, "utf8"));
}

export function writeManualDecoderBatchPlan(plan)
{
  writeStableJson(generatedManualDecoderBatchPlanPath, plan);
}

export function buildManualDecoderBatchPlan(dllBatchPromotionPlan)
{
  const dlls = (dllBatchPromotionPlan?.dlls ?? [])
    .filter((dll) => dll.manualDecoderRequired > 0)
    .map((dll) => buildManualDllEntry(dll));
  const summary = summarizeManualDlls(dlls);

  return {
    schemaVersion: "0.1.0",
    source: {
      generatedFrom: "generated/dll-batch-promotion-plan.json",
      policyInput: "classification == manual_decoder_required"
    },
    policy: {
      installMode: "blocked_by_default",
      runtimeHooksEnabledByDefault: false,
      promotionRule: "Manual-decoder APIs require same-DLL design review, explicit payload boundary, x64/x86 smoke evidence, and hook-overhead evidence before runtime promotion.",
      payloadCaptureDefault: "disabled"
    },
    summary,
    dlls
  };
}

export function validateManualDecoderBatchPlan(plan = loadManualDecoderBatchPlan(), dllBatchPromotionPlan)
{
  const errors = [];

  if (plan === null)
  {
    return [`${relativePath(generatedManualDecoderBatchPlanPath)} is missing; run npm run defs:manual-decoder-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`Manual decoder batch plan has unsupported schema version ${plan.schemaVersion}`);
  }

  if (dllBatchPromotionPlan)
  {
    const actualText = fs.existsSync(generatedManualDecoderBatchPlanPath) ? fs.readFileSync(generatedManualDecoderBatchPlanPath, "utf8") : "";
    const expectedText = stableStringify(buildManualDecoderBatchPlan(dllBatchPromotionPlan));
    if (actualText !== expectedText)
    {
      errors.push(`${relativePath(generatedManualDecoderBatchPlanPath)} is stale; run npm run defs:manual-decoder-plan:generate`);
    }
  }

  const sourceManualKeys = new Set();
  for (const dll of (dllBatchPromotionPlan?.dlls ?? []))
  {
    for (const api of (dll.apis ?? []))
    {
      if (api.classification === "manual_decoder_required")
      {
        sourceManualKeys.add(api.key);
      }
    }
  }

  const dlls = plan.dlls ?? [];
  const seenDlls = new Set();
  const seenApis = new Set();
  const counted = {
    totalApis: 0,
    totalDlls: dlls.length,
    manualDecoderRequired: 0,
    payloadBlockedInManualDlls: 0,
    runtimeHooksEnabledByDefault: 0
  };

  for (const dll of dlls)
  {
    if (!dll.module || seenDlls.has(dll.module))
    {
      errors.push(`Manual decoder batch plan has duplicate or missing DLL entry ${dll.module}`);
    }
    seenDlls.add(dll.module);

    const apis = dll.apis ?? [];
    const payloadBlockedApis = dll.payloadBlockedApis ?? [];
    if (dll.totalApis !== apis.length)
    {
      errors.push(`Manual decoder DLL ${dll.module} totalApis mismatch: total=${dll.totalApis} apis=${apis.length}`);
    }

    if (dll.manualDecoderRequired !== apis.length)
    {
      errors.push(`Manual decoder DLL ${dll.module} manualDecoderRequired mismatch: summary=${dll.manualDecoderRequired} apis=${apis.length}`);
    }

    if (dll.payloadBlockedInSameDll !== payloadBlockedApis.length)
    {
      errors.push(`Manual decoder DLL ${dll.module} payloadBlockedInSameDll mismatch: summary=${dll.payloadBlockedInSameDll} apis=${payloadBlockedApis.length}`);
    }

    if (dll.runtimeHooksEnabledByDefault !== false)
    {
      errors.push(`Manual decoder DLL ${dll.module} must keep runtimeHooksEnabledByDefault=false`);
    }

    for (const api of apis)
    {
      if (seenApis.has(api.key))
      {
        errors.push(`Manual decoder batch plan has duplicate API entry ${api.key}`);
      }
      seenApis.add(api.key);

      if (dllBatchPromotionPlan && !sourceManualKeys.has(api.key))
      {
        errors.push(`Manual decoder batch plan includes non-manual API ${api.key}`);
      }

      if (api.classification !== "manual_decoder_required")
      {
        errors.push(`Manual decoder API ${api.key} has invalid classification ${api.classification}`);
      }

      if (api.runtimeHookPolicy !== "blocked_by_default")
      {
        errors.push(`Manual decoder API ${api.key} must be blocked_by_default`);
      }

      if (api.designStatus !== "review_required")
      {
        errors.push(`Manual decoder API ${api.key} must require review`);
      }

      if (!Array.isArray(api.allowedEvidence) || api.allowedEvidence.length === 0)
      {
        errors.push(`Manual decoder API ${api.key} is missing allowed evidence boundaries`);
      }

      if (!Array.isArray(api.forbiddenEvidence) || api.forbiddenEvidence.length === 0)
      {
        errors.push(`Manual decoder API ${api.key} is missing forbidden evidence boundaries`);
      }

      if (!Array.isArray(api.requiredEvidence) || stableStringify(api.requiredEvidence) !== stableStringify(requiredEvidence))
      {
        errors.push(`Manual decoder API ${api.key} is missing required smoke/evidence gates`);
      }
    }

    counted.totalApis += apis.length;
    counted.manualDecoderRequired += apis.length;
    counted.payloadBlockedInManualDlls += payloadBlockedApis.length;
  }

  if (dllBatchPromotionPlan)
  {
    for (const key of sourceManualKeys)
    {
      if (!seenApis.has(key))
      {
        errors.push(`Manual decoder batch plan is missing ${key}`);
      }
    }
  }

  const summary = plan.summary ?? {};
  for (const [field, value] of Object.entries(counted))
  {
    if (summary[field] !== value)
    {
      errors.push(`Manual decoder batch summary ${field} mismatch: summary=${summary[field]} actual=${value}`);
    }
  }

  return errors;
}

export function manualDecoderBatchPlanToMarkdown(plan)
{
  if (plan === null)
  {
    return "# Manual Decoder Batch Plan\n\nNot generated. Run `npm run defs:manual-decoder-plan:generate`.\n";
  }

  const lines = [
    "# Manual Decoder Batch Plan",
    "",
    `Total DLLs: ${plan.summary.totalDlls}`,
    `Manual decoder APIs: ${plan.summary.manualDecoderRequired}`,
    `Payload-blocked APIs in those DLLs: ${plan.summary.payloadBlockedInManualDlls}`,
    `Runtime hooks enabled by default: ${plan.summary.runtimeHooksEnabledByDefault}`,
    "",
    "## DLLs Requiring Manual Decoder Review",
    ""
  ];

  for (const dll of (plan.dlls ?? []))
  {
    const names = dll.apis.map((api) => api.apiName).join(", ");
    lines.push(`- ${dll.module}: ${dll.manualDecoderRequired} (${names})`);
  }

  if ((plan.dlls ?? []).length === 0)
  {
    lines.push("- none");
  }

  lines.push("");
  return lines.join("\n");
}

function buildManualDllEntry(dll)
{
  const manualApis = (dll.apis ?? [])
    .filter((api) => api.classification === "manual_decoder_required")
    .map((api) => buildManualApiEntry(api));
  const payloadBlockedApis = (dll.apis ?? [])
    .filter((api) => api.classification === "blocked_by_payload_policy")
    .map((api) => ({
      apiName: api.apiName,
      category: api.category,
      family: api.family,
      id: api.id,
      key: api.key,
      reasons: api.reasons,
      risk: api.risk
    }));

  return {
    module: dll.module,
    sourceFiles: dll.sourceFiles,
    totalApis: manualApis.length,
    manualDecoderRequired: manualApis.length,
    payloadBlockedInSameDll: payloadBlockedApis.length,
    runtimeHooksEnabledByDefault: false,
    recommendation: "design_manual_decoder_batch_before_runtime_promotion",
    payloadBlockedApis,
    apis: manualApis
  };
}

function buildManualApiEntry(api)
{
  const boundary = manualApiBoundaries.get(api.key) ?? defaultBoundary(api);

  return {
    id: api.id,
    key: api.key,
    module: api.module,
    apiName: api.apiName,
    family: api.family,
    category: api.category,
    risk: api.risk,
    returnType: api.returnType,
    callingConvention: api.callingConvention,
    parameterCount: api.parameterCount,
    classification: api.classification,
    originalRecommendation: api.recommendation,
    reasons: api.reasons,
    pointerOnlyParameters: api.pointerOnlyParameters,
    payloadSensitiveParameters: api.payloadSensitiveParameters,
    designStatus: "review_required",
    runtimeHookPolicy: "blocked_by_default",
    allowedEvidence: boundary.allowedEvidence,
    forbiddenEvidence: boundary.forbiddenEvidence,
    requiredEvidence,
    reviewNotes: boundary.reviewNotes
  };
}

function defaultBoundary(api)
{
  return {
    allowedEvidence: [
      `${api.apiName} scalar arguments`,
      `${api.apiName} pointer or handle values`,
      `${api.apiName} return value`,
      "duration and hook lifecycle metadata"
    ],
    forbiddenEvidence: defaultForbiddenEvidence,
    reviewNotes: [
      "A concrete family-specific boundary must be added before runtime promotion."
    ]
  };
}

function summarizeManualDlls(dlls)
{
  return {
    totalDlls: dlls.length,
    totalApis: dlls.reduce((sum, dll) => sum + dll.totalApis, 0),
    manualDecoderRequired: dlls.reduce((sum, dll) => sum + dll.manualDecoderRequired, 0),
    payloadBlockedInManualDlls: dlls.reduce((sum, dll) => sum + dll.payloadBlockedInSameDll, 0),
    runtimeHooksEnabledByDefault: 0
  };
}
