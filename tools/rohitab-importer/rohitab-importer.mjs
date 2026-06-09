import { stableStringify } from "../def-validator/definition-system.mjs";

function decodeXmlEntity(value) {
  return value
    .replaceAll("&quot;", "\"")
    .replaceAll("&apos;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

function parseAttributes(text) {
  const attributes = {};
  const regex = /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*"([^"]*)"/g;
  let match = regex.exec(text);

  while (match !== null) {
    attributes[match[1]] = decodeXmlEntity(match[2]);
    match = regex.exec(text);
  }

  return attributes;
}

function normalizeCallingConvention(value) {
  const normalized = String(value ?? "stdcall").trim().toLowerCase();

  if (normalized === "__stdcall" || normalized === "winapi") {
    return "stdcall";
  }

  if (normalized === "ntapi") {
    return "ntapi";
  }

  if (normalized === "__cdecl") {
    return "cdecl";
  }

  return normalized;
}

function defaultDecodeForType(type) {
  const normalized = String(type ?? "").trim().toUpperCase();

  if (normalized === "LPCWSTR" || normalized === "PCWSTR" || normalized === "PWSTR") {
    return "utf16_string";
  }

  if (normalized === "LPCSTR" || normalized === "PCSTR" || normalized === "PSTR") {
    return "ansi_string";
  }

  if (normalized === "HANDLE") {
    return "handle";
  }

  if (normalized === "HMODULE") {
    return "module_handle";
  }

  if (normalized === "DWORD" || normalized === "ULONG" || normalized === "SIZE_T") {
    return "byte_count";
  }

  return "unresolved";
}

function normalizeDirection(value) {
  const normalized = String(value ?? "in").trim().toLowerCase();

  if (normalized === "in" || normalized === "out" || normalized === "inout" || normalized === "return") {
    return normalized;
  }

  return "in";
}

export function importRohitabXml(xmlText) {
  const apis = [];
  const moduleRegex = /<module\b([^>]*)>([\s\S]*?)<\/module>/gi;
  let moduleMatch = moduleRegex.exec(xmlText);

  while (moduleMatch !== null) {
    const moduleAttributes = parseAttributes(moduleMatch[1]);
    const moduleName = moduleAttributes.name ?? moduleAttributes.dll ?? "unknown.dll";
    const moduleBody = moduleMatch[2];
    const apiRegex = /<api\b([^>]*)>([\s\S]*?)<\/api>/gi;
    let apiMatch = apiRegex.exec(moduleBody);

    while (apiMatch !== null) {
      const apiAttributes = parseAttributes(apiMatch[1]);
      const apiBody = apiMatch[2];
      const parameters = [];
      const paramRegex = /<param\b([^>]*)\/?>/gi;
      let paramMatch = paramRegex.exec(apiBody);

      while (paramMatch !== null) {
        const paramAttributes = parseAttributes(paramMatch[1]);
        const type = paramAttributes.type ?? "PVOID";
        parameters.push({
          name: paramAttributes.name ?? `Param${parameters.length}`,
          type,
          direction: normalizeDirection(paramAttributes.direction),
          decode: paramAttributes.decode ?? defaultDecodeForType(type)
        });
        paramMatch = paramRegex.exec(apiBody);
      }

      apis.push({
        module: moduleName,
        name: apiAttributes.name ?? "UnknownApi",
        family: apiAttributes.family ?? "imported",
        category: apiAttributes.category ?? "imported",
        risk: apiAttributes.risk ?? "medium",
        hookPolicy: "definition_only",
        coverageStatus: "definition_only",
        callingConvention: normalizeCallingConvention(apiAttributes.callingConvention),
        returnType: apiAttributes.returnType ?? apiAttributes.returns ?? "NTSTATUS",
        errorSource: apiAttributes.errorSource ?? "none",
        parameters
      });

      apiMatch = apiRegex.exec(moduleBody);
    }

    moduleMatch = moduleRegex.exec(xmlText);
  }

  apis.sort((left, right) => `${left.module}!${left.name}`.localeCompare(`${right.module}!${right.name}`));

  return {
    schemaVersion: "0.1.0",
    module: "rohitab-import",
    description: "Draft API definitions imported from a Rohitab-style XML fixture.",
    apis
  };
}

export function stringifyImportedDefinition(document) {
  return stableStringify(document);
}
