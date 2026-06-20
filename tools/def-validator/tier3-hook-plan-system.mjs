import fs from "node:fs";
import path from "node:path";

import {
  apiKey,
  normalizeModuleName,
  readJson,
  relativePath,
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";
import {
  generatedApiInventoryPath,
  loadApiInventory
} from "./api-inventory-system.mjs";

export const generatedTier3HookPlanPath = path.join(repoRoot, "generated", "tier3-hook-plan.json");

const validClassifications = new Set([
  "callback_registration",
  "callback_invocation_boundary",
  "com_interface_or_vtable",
  "winrt_activation_or_hstring",
  "window_message_or_hook_proc",
  "varargs_or_unsupported_abi",
  "buffer_or_payload_heavy",
  "remote_process_or_injection_sensitive",
  "security_descriptor_or_credential_sensitive",
  "manual_strategy_required"
]);

const validDefaultRuntimeStates = new Set([
  "blocked_by_default"
]);

const validRisks = new Set(["low", "medium", "high", "critical"]);

const globalForbiddenEvidence = [
  "arbitrary_pointer_memory",
  "callback_argument_payloads",
  "com_object_payloads",
  "credentials",
  "raw_buffer_contents",
  "remote_memory_bytes",
  "ui_text_or_pixels",
  "vtable_contents"
];

export function loadTier3HookPlan()
{
  if (!fs.existsSync(generatedTier3HookPlanPath))
  {
    return null;
  }

  return readJson(generatedTier3HookPlanPath);
}

export function writeTier3HookPlan(plan)
{
  writeStableJson(generatedTier3HookPlanPath, plan);
}

export function buildTier3HookPlan(inventory = loadApiInventory())
{
  if (inventory === null)
  {
    throw new Error(`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory.`);
  }

  const tier3Apis = (inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier === 3)
    .sort(comparePlanEntries);
  const apis = tier3Apis.map((entry, index) => buildPlanEntry(entry, index + 1));
  const summary = summarizePlanEntries(apis, inventory);

  return {
    schemaVersion: "0.1.0",
    source: {
      inventory: relativePath(generatedApiInventoryPath),
      inventorySchemaVersion: inventory.schemaVersion ?? null,
      microsoftSourceVersion: inventory.sources?.win32Metadata?.version ?? null
    },
    policy: {
      defaultTier3HookCount: 0,
      installMode: "blocked_by_default",
      broadCoverageRequiresDesignReview: true,
      runtimeEnablementPolicy: "explicit_allowlist_and_design_review_required",
      defaultRuntimeState: "blocked_by_default",
      genericIatHookPolicy: "disabled",
      rawPayloadCapture: "disabled",
      supportedClassifications: Array.from(validClassifications).sort()
    },
    summary,
    apis
  };
}

export function validateTier3HookPlan(plan = loadTier3HookPlan(), inventory = loadApiInventory())
{
  const errors = [];

  if (inventory === null)
  {
    return [`${relativePath(generatedApiInventoryPath)} is missing; run npm run defs:inventory`];
  }

  if (plan === null)
  {
    return [`${relativePath(generatedTier3HookPlanPath)} is missing; run npm run defs:tier3-plan:generate`];
  }

  if (plan.schemaVersion !== "0.1.0")
  {
    errors.push(`tier 3 hook plan has unsupported schema version ${plan.schemaVersion}`);
  }

  const actualText = fs.existsSync(generatedTier3HookPlanPath) ? fs.readFileSync(generatedTier3HookPlanPath, "utf8") : "";
  const expectedText = stableStringify(plan);
  if (actualText !== expectedText)
  {
    errors.push(`${relativePath(generatedTier3HookPlanPath)} is not stable-sorted; run npm run defs:tier3-plan:generate`);
  }

  const tier3Entries = (inventory.apis ?? []).filter((entry) => entry.hookability?.tier === 3);
  const expectedTier3Keys = new Set(tier3Entries.map((entry) => apiKey(entry.module, entry.name)));
  const nonTier3Keys = new Set((inventory.apis ?? [])
    .filter((entry) => entry.hookability?.tier !== 3)
    .map((entry) => apiKey(entry.module, entry.name)));
  const planEntries = plan.apis ?? [];
  const planKeys = new Set();

  if (plan.policy?.defaultTier3HookCount !== 0)
  {
    errors.push("tier 3 hook plan policy must keep defaultTier3HookCount at 0");
  }

  if (plan.policy?.installMode !== "blocked_by_default")
  {
    errors.push(`tier 3 hook plan invalid install mode: ${plan.policy?.installMode}`);
  }

  if (plan.summary?.tier3Total !== tier3Entries.length)
  {
    errors.push(`tier 3 hook plan total mismatch: summary=${plan.summary?.tier3Total} inventory=${tier3Entries.length}`);
  }

  if (plan.summary?.planned !== planEntries.length)
  {
    errors.push(`tier 3 hook plan planned mismatch: summary=${plan.summary?.planned} apis=${planEntries.length}`);
  }

  if ((plan.summary?.defaultInstallable ?? -1) !== 0)
  {
    errors.push("tier 3 hook plan must not make any API installable by default");
  }

  for (const entry of planEntries)
  {
    const key = apiKey(entry.module, entry.apiName);
    if (planKeys.has(key))
    {
      errors.push(`tier 3 hook plan duplicate API row ${key}`);
    }
    planKeys.add(key);

    if (!expectedTier3Keys.has(key))
    {
      errors.push(`tier 3 hook plan contains non-tier3 API ${key}`);
    }

    if (nonTier3Keys.has(key))
    {
      errors.push(`tier 3 hook plan accidentally includes non-tier3 API ${key}`);
    }

    if (!entry.planId || !/^tier3-\d{5}$/.test(entry.planId))
    {
      errors.push(`tier 3 hook plan invalid planId for ${key}`);
    }

    if (entry.inventoryKey !== key)
    {
      errors.push(`tier 3 hook plan inventoryKey mismatch for ${key}: ${entry.inventoryKey}`);
    }

    if (!validClassifications.has(entry.classification))
    {
      errors.push(`tier 3 hook plan invalid classification for ${key}: ${entry.classification}`);
    }

    if (!validDefaultRuntimeStates.has(entry.defaultRuntimeState))
    {
      errors.push(`tier 3 hook plan invalid default runtime state for ${key}: ${entry.defaultRuntimeState}`);
    }

    if (entry.defaultInstallable !== false)
    {
      errors.push(`tier 3 hook plan default-installable API is not allowed: ${key}`);
    }

    if (entry.enabledByDefault !== false)
    {
      errors.push(`tier 3 hook plan default-enabled API is not allowed: ${key}`);
    }

    if (entry.installPolicy !== "not_installable_by_default")
    {
      errors.push(`tier 3 hook plan invalid install policy for ${key}: ${entry.installPolicy}`);
    }

    if (entry.hookStrategy !== "blocked")
    {
      errors.push(`tier 3 hook plan must keep hook strategy blocked for ${key}: ${entry.hookStrategy}`);
    }

    if (entry.requiredDesignReview !== true)
    {
      errors.push(`tier 3 hook plan must require design review for ${key}`);
    }

    if (!validRisks.has(entry.risk))
    {
      errors.push(`tier 3 hook plan invalid risk for ${key}: ${entry.risk}`);
    }

    if (typeof entry.reason !== "string" || entry.reason.length === 0)
    {
      errors.push(`tier 3 hook plan missing reason for ${key}`);
    }

    if (!Array.isArray(entry.allowedEvidence) || entry.allowedEvidence.length === 0)
    {
      errors.push(`tier 3 hook plan missing allowed evidence list for ${key}`);
    }

    if (!Array.isArray(entry.forbiddenEvidence) || entry.forbiddenEvidence.length === 0)
    {
      errors.push(`tier 3 hook plan missing forbidden evidence list for ${key}`);
    }

    if (!Array.isArray(entry.parameters) || entry.parameters.length !== entry.parameterCount)
    {
      errors.push(`tier 3 hook plan parameter count mismatch for ${key}`);
    }
  }

  for (const expectedKey of expectedTier3Keys)
  {
    if (!planKeys.has(expectedKey))
    {
      errors.push(`tier 3 hook plan missing API ${expectedKey}`);
    }
  }

  return errors;
}

export function selectTier3HookPlan(plan, options = {})
{
  const allowlist = new Set((options.allowlist ?? []).map(normalizeAllowlistKey));
  const modules = new Set((options.modules ?? []).map(normalizeModuleName));
  const families = new Set(options.families ?? []);
  const risks = new Set(options.risks ?? []);
  const classifications = new Set(options.classifications ?? []);
  const limit = options.limit ?? 0;
  const hooks = [];

  for (const entry of plan.apis ?? [])
  {
    const key = normalizeAllowlistKey(entry.inventoryKey);
    let selected = true;

    if (allowlist.size > 0 && !allowlist.has(key))
    {
      selected = false;
    }

    if (selected && modules.size > 0 && !modules.has(normalizeModuleName(entry.module)))
    {
      selected = false;
    }

    if (selected && families.size > 0 && !families.has(entry.family))
    {
      selected = false;
    }

    if (selected && risks.size > 0 && !risks.has(entry.risk))
    {
      selected = false;
    }

    if (selected && classifications.size > 0 && !classifications.has(entry.classification))
    {
      selected = false;
    }

    if (!selected)
    {
      continue;
    }

    hooks.push({
      inventoryKey: entry.inventoryKey,
      module: entry.module,
      apiName: entry.apiName,
      entryPoint: entry.entryPoint,
      family: entry.family,
      risk: entry.risk,
      classification: entry.classification,
      defaultRuntimeState: entry.defaultRuntimeState,
      installable: false,
      blockedReasons: [
        "tier3_design_review_required",
        "default_runtime_blocked"
      ]
    });

    if (limit > 0 && hooks.length >= limit)
    {
      break;
    }
  }

  return {
    schemaVersion: "0.1.0",
    selection: {
      modules: Array.from(modules).sort(),
      families: Array.from(families).sort(),
      risks: Array.from(risks).sort(),
      classifications: Array.from(classifications).sort(),
      allowlist: Array.from(allowlist).sort(),
      limit
    },
    summary: {
      selected: hooks.length,
      installable: 0,
      blocked: hooks.length,
      defaultRuntimeEnablement: "blocked"
    },
    groupedCounts: {
      byClassification: countBy(hooks, (hook) => hook.classification),
      byFamily: countBy(hooks, (hook) => hook.family),
      byModule: countBy(hooks, (hook) => hook.module),
      byRisk: countBy(hooks, (hook) => hook.risk)
    },
    hooks
  };
}

export function tier3HookPlanToMarkdown(plan)
{
  if (plan === null)
  {
    return "# Tier 3 Hook Plan\n\nNot generated. Run `npm run defs:tier3-plan:generate`.\n";
  }

  const lines = [
    "# Tier 3 Hook Plan",
    "",
    `Tier 3 total: ${plan.summary.tier3Total}`,
    `Tier 3 planned: ${plan.summary.planned}`,
    `Tier 3 default installable: ${plan.summary.defaultInstallable}`,
    `Tier 3 design-review required: ${plan.summary.requiredDesignReview}`,
    "",
    "## Classifications",
    ""
  ];

  for (const [classification, count] of Object.entries(plan.summary.byClassification ?? {}))
  {
    lines.push(`- ${classification}: ${count}`);
  }

  lines.push("", "## Runtime Policy", "");
  lines.push(`- installMode: ${plan.policy?.installMode ?? "unknown"}`);
  lines.push(`- runtimeEnablementPolicy: ${plan.policy?.runtimeEnablementPolicy ?? "unknown"}`);
  lines.push(`- rawPayloadCapture: ${plan.policy?.rawPayloadCapture ?? "unknown"}`);
  lines.push("");
  return lines.join("\n");
}

function buildPlanEntry(entry, ordinal)
{
  const key = apiKey(entry.module, entry.name);
  const classification = classificationForEntry(entry);
  const parameters = (entry.parameters ?? []).map((parameter, index) => ({
    index,
    name: parameter.name,
    type: parameter.type,
    direction: parameter.direction,
    decodeHint: parameter.decodeHint,
    capturePolicy: capturePolicyForParameter(parameter, classification)
  }));

  return {
    planId: `tier3-${String(ordinal).padStart(5, "0")}`,
    inventoryKey: key,
    module: normalizeModuleName(entry.module),
    apiName: entry.name,
    entryPoint: entry.entryPoint ?? entry.name,
    header: entry.header ?? null,
    family: entry.family ?? "uncategorized",
    category: entry.category ?? "uncategorized",
    callingConvention: entry.callingConvention ?? "winapi",
    returnType: entry.returnType ?? "void",
    returnCapturePolicy: capturePolicyForReturn(entry.returnType),
    errorSource: entry.errorSource ?? "none",
    parameterCount: parameters.length,
    parameters,
    characterSet: entry.characterSet ?? { variant: "neutral", aliasBase: null, counterpart: null },
    risk: entry.risk,
    riskSignals: entry.riskSignals ?? [],
    hookabilityReason: entry.hookability?.reason ?? null,
    classification,
    defaultRuntimeState: "blocked_by_default",
    defaultInstallable: false,
    enabledByDefault: false,
    installPolicy: "not_installable_by_default",
    hookStrategy: "blocked",
    runtimeStatus: "design_review_required",
    requiredDesignReview: true,
    reason: reasonForEntry(entry, classification),
    allowedEvidence: allowedEvidenceForClassification(classification),
    forbiddenEvidence: forbiddenEvidenceForClassification(classification),
    futureRuntimeGate: {
      explicitAllowlistRequired: true,
      designReviewRequired: true,
      smokeRequired: true,
      overheadReviewRequired: true,
      defaultProfileEligible: false
    }
  };
}

function classificationForEntry(entry)
{
  const reason = String(entry.hookability?.reason ?? "");
  const text = textForEntry(entry);

  if (/message|window-hook/i.test(reason) || /\b(MSG|HHOOK|WNDPROC|HOOKPROC|TIMERPROC|CallNextHookEx|SetWindowsHook)\b/i.test(text))
  {
    return "window_message_or_hook_proc";
  }

  if (/\b(HSTRING|IInspectable|IActivationFactory|RoActivate|RoGetActivationFactory|RuntimeClass|restricted-error|winrt)\b/i.test(text))
  {
    return "winrt_activation_or_hstring";
  }

  if (isRemoteProcessSensitive(entry, text))
  {
    return "remote_process_or_injection_sensitive";
  }

  if (isSecurityDescriptorOrCredentialSensitive(entry, text))
  {
    return "security_descriptor_or_credential_sensitive";
  }

  if (/callback|function-pointer/i.test(reason) || /\b(function_pointer|PFN[A-Za-z0-9_]*|CALLBACK|APC_ROUTINE|COMPLETION_ROUTINE|LPFN[A-Za-z0-9_]*)\b/i.test(text))
  {
    return isCallbackRegistration(entry, text) ? "callback_registration" : "callback_invocation_boundary";
  }

  if (isPayloadHeavy(entry, text))
  {
    return "buffer_or_payload_heavy";
  }

  if (/\.\.\.|va_list|VARARGS|CDECL/i.test(text))
  {
    return "varargs_or_unsupported_abi";
  }

  if (/COM interface|object strategy/i.test(reason) || hasComInterfaceShape(entry))
  {
    return "com_interface_or_vtable";
  }

  return "manual_strategy_required";
}

function isCallbackRegistration(entry, text)
{
  if (/(Register|Unregister|Set|Add|Advise|Subscribe|Initialize|Create|Open|Start|Install|Enable|Hook)/i.test(entry.name))
  {
    return true;
  }

  if (/\b(register|registration|notify|event|listener|sink|callbackcontext|callback_context)\b/i.test(text))
  {
    return true;
  }

  return false;
}

function isRemoteProcessSensitive(entry, text)
{
  if (/\b(ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|VirtualFreeEx|VirtualProtectEx|CreateRemoteThread|QueueUserAPC|NtQueueApcThread|SetThreadContext|GetThreadContext|DebugActiveProcess|MiniDumpWriteDump)\b/i.test(entry.name))
  {
    return true;
  }

  return /\b(PROCESS_VM_|THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|PAPCFUNC|APC_ROUTINE|remote process|remote thread)\b/i.test(text);
}

function isSecurityDescriptorOrCredentialSensitive(entry, text)
{
  if (entry.family !== "security" && entry.risk !== "critical")
  {
    return false;
  }

  return /\b(SECURITY_DESCRIPTOR|SECURITY_INFORMATION|OBJECT_SECURITY_INFORMATION|ACL|PACL|ACE|SID|TOKEN|CREDENTIAL|CRED|AUTHZ|PASSWORD|TRUSTEE|INHERITED_FROM|GENERIC_MAPPING)\b/i.test(text);
}

function isPayloadHeavy(entry, text)
{
  if (/\b(byte|buffer|blob|stream|payload|bitmap|dib|sample|shader|memory|pData|pvData|lpBuffer|pSrcData|pSDPStream)\b/i.test(text))
  {
    return true;
  }

  return (entry.parameters ?? []).some((parameter) => {
    const type = String(parameter.type ?? "");
    const name = String(parameter.name ?? "");
    return parameter.decodeHint === "raw" && /[*]/.test(type) && /\b(data|buffer|stream|memory|bytes|blob)\b/i.test(`${name} ${type}`);
  });
}

function hasComInterfaceShape(entry)
{
  return (entry.parameters ?? []).some((parameter) => {
    const bareType = String(parameter.type ?? "").replace(/[&*]+$/g, "");
    return /^I[A-Z][A-Za-z0-9_]*$/.test(bareType);
  });
}

function reasonForEntry(entry, classification)
{
  const inventoryReason = entry.hookability?.reason ?? "Tier 3 API requires manual strategy before hook installation";
  const classReason = {
    callback_registration: "callback registration stores code pointers and context pointers that need reentrancy and lifetime review",
    callback_invocation_boundary: "callback invocation boundaries can expose callback arguments and caller-owned payloads",
    com_interface_or_vtable: "COM interface and vtable payloads require object-lifetime and method-boundary design",
    winrt_activation_or_hstring: "WinRT activation and HSTRING handling require object and string-lifetime design",
    window_message_or_hook_proc: "window messages and hook procedures can expose UI/input payloads and reentrancy hazards",
    varargs_or_unsupported_abi: "variable argument or unsupported ABI shapes cannot use the generic fixed-slot decoder",
    buffer_or_payload_heavy: "buffer-heavy APIs require explicit payload and overhead policy before capture",
    remote_process_or_injection_sensitive: "remote-process sensitive APIs require explicit non-bypass and no-memory-copy design",
    security_descriptor_or_credential_sensitive: "security descriptor or credential-sensitive APIs require explicit no-secret capture policy",
    manual_strategy_required: "manual instrumentation design is required before runtime hook installation"
  }[classification];

  return `${inventoryReason}; ${classReason}`;
}

function allowedEvidenceForClassification(classification)
{
  const base = [
    "api_name",
    "call_duration",
    "last_error_or_status",
    "module_name",
    "pointer_or_handle_values",
    "return_scalar_or_status",
    "thread_id",
    "timestamp"
  ];

  const additions = {
    callback_registration: [
      "callback_context_pointer_value",
      "callback_pointer_value",
      "registration_handle_value"
    ],
    callback_invocation_boundary: [
      "callback_pointer_value",
      "invocation_count"
    ],
    com_interface_or_vtable: [
      "hresult_value",
      "iid_guid_value",
      "interface_pointer_value"
    ],
    winrt_activation_or_hstring: [
      "activation_hresult",
      "hstring_handle_value",
      "winrt_object_pointer_value"
    ],
    window_message_or_hook_proc: [
      "hook_handle_value",
      "hwnd_value",
      "message_id_numeric",
      "wparam_lparam_scalar"
    ],
    varargs_or_unsupported_abi: [
      "fixed_argument_scalar_values"
    ],
    buffer_or_payload_heavy: [
      "buffer_pointer_value",
      "buffer_size_value"
    ],
    remote_process_or_injection_sensitive: [
      "target_handle_value",
      "target_process_id_when_explicitly_available"
    ],
    security_descriptor_or_credential_sensitive: [
      "access_mask_value",
      "security_descriptor_pointer_value"
    ],
    manual_strategy_required: [
      "argument_pointer_values",
      "scalar_argument_values"
    ]
  };

  return Array.from(new Set([...base, ...(additions[classification] ?? [])])).sort();
}

function forbiddenEvidenceForClassification(classification)
{
  const additions = {
    callback_registration: [
      "callback_context_memory",
      "callback_target_code_bytes"
    ],
    callback_invocation_boundary: [
      "callback_argument_payloads",
      "callback_stack_or_register_dump"
    ],
    com_interface_or_vtable: [
      "com_object_internals",
      "interface_method_arguments",
      "marshaled_stream_payload"
    ],
    winrt_activation_or_hstring: [
      "hstring_text",
      "restricted_error_info_payload",
      "runtime_class_payload"
    ],
    window_message_or_hook_proc: [
      "keyboard_mouse_payload",
      "message_buffer_contents",
      "window_text"
    ],
    varargs_or_unsupported_abi: [
      "varargs_stack_contents"
    ],
    buffer_or_payload_heavy: [
      "buffer_preview_bytes",
      "decoded_payload_contents"
    ],
    remote_process_or_injection_sensitive: [
      "remote_context_registers",
      "remote_memory_bytes",
      "remote_stack_bytes"
    ],
    security_descriptor_or_credential_sensitive: [
      "acl_entries",
      "credential_material",
      "sid_values",
      "token_group_or_privilege_arrays"
    ],
    manual_strategy_required: [
      "unreviewed_struct_decode"
    ]
  };

  return Array.from(new Set([...globalForbiddenEvidence, ...(additions[classification] ?? [])])).sort();
}

function capturePolicyForParameter(parameter, classification)
{
  if (classification === "buffer_or_payload_heavy")
  {
    return "pointer_and_size_only_no_payload";
  }

  if (parameter.decodeHint === "raw" || parameter.decodeHint === "handle")
  {
    return "scalar_or_handle_only";
  }

  if (parameter.decodeHint === "string")
  {
    return "pointer_only_no_string_capture";
  }

  if (parameter.decodeHint === "object")
  {
    return "object_pointer_only_no_payload";
  }

  return "pointer_value_only";
}

function capturePolicyForReturn(returnType)
{
  const value = String(returnType ?? "void");
  if (value === "void")
  {
    return "void";
  }

  if (value.endsWith("*") || value.includes("HANDLE") || /^H[A-Z0-9_]+$/.test(value))
  {
    return "pointer_or_handle_value_only";
  }

  return "scalar_or_status_only";
}

function summarizePlanEntries(entries, inventory)
{
  return {
    inventoryTotal: inventory.summary?.totalApis ?? 0,
    tier3Total: entries.length,
    planned: entries.length,
    defaultInstallable: entries.filter((entry) => entry.defaultInstallable).length,
    enabledByDefault: entries.filter((entry) => entry.enabledByDefault).length,
    requiredDesignReview: entries.filter((entry) => entry.requiredDesignReview).length,
    byClassification: countBy(entries, (entry) => entry.classification),
    byDefaultRuntimeState: countBy(entries, (entry) => entry.defaultRuntimeState),
    byFamily: countBy(entries, (entry) => entry.family),
    byModule: countBy(entries, (entry) => entry.module),
    byRisk: countBy(entries, (entry) => entry.risk),
    byRuntimeStatus: countBy(entries, (entry) => entry.runtimeStatus)
  };
}

function comparePlanEntries(left, right)
{
  const moduleCompare = normalizeModuleName(left.module).localeCompare(normalizeModuleName(right.module));
  if (moduleCompare !== 0)
  {
    return moduleCompare;
  }

  return String(left.name).localeCompare(String(right.name));
}

function countBy(entries, selector)
{
  const counts = {};
  for (const entry of entries)
  {
    const key = selector(entry);
    counts[key] = (counts[key] ?? 0) + 1;
  }

  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeAllowlistKey(value)
{
  const text = String(value ?? "");
  const parts = text.split("!");
  if (parts.length !== 2)
  {
    return text;
  }

  return `${normalizeModuleName(parts[0])}!${parts[1]}`;
}

function textForEntry(entry)
{
  return [
    entry.name,
    entry.namespace ?? "",
    entry.module,
    entry.family,
    entry.category,
    entry.returnType,
    entry.hookability?.reason ?? "",
    ...(entry.parameters ?? []).flatMap((parameter) => [
      parameter.name,
      parameter.type,
      parameter.decodeHint,
      parameter.direction
    ])
  ].join(" ");
}
