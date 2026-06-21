import fs from "node:fs";
import path from "node:path";

import {
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const write = args.has("--write");
const outputPath = path.join(repoRoot, "generated", "ntdll-supplemental-spec-index.json");

const sources = [
  {
    id: "wine",
    name: "Wine",
    repository: "https://github.com/wine-mirror/wine.git",
    commit: argumentValue("--wine-commit", "ff95854f8cc48de0301c5e03096ad9bd7c990227"),
    file: "dlls/ntdll/ntdll.spec",
    path: argumentValue("--wine-spec", process.env.WINE_NTDLL_SPEC ?? "")
  },
  {
    id: "reactos",
    name: "ReactOS",
    repository: "https://github.com/reactos/reactos.git",
    commit: argumentValue("--reactos-commit", "33e9970b78b95cb9ccee930f48e6c3b76055bef8"),
    file: "dll/ntdll/def/ntdll.spec",
    path: argumentValue("--reactos-spec", process.env.REACTOS_NTDLL_SPEC ?? "")
  }
].filter((source) => source.path.length > 0);

if (sources.length === 0)
{
  throw new Error("Provide --wine-spec/--reactos-spec or WINE_NTDLL_SPEC/REACTOS_NTDLL_SPEC");
}

const prototypes = new Map();
for (const source of sources)
{
  const sourcePrototypes = parseSpecSource(source);
  for (const prototype of sourcePrototypes)
  {
    const existing = prototypes.get(prototype.name);
    if (!existing || sourcePriority(prototype.source.id) < sourcePriority(existing.source.id))
    {
      prototypes.set(prototype.name, prototype);
    }
  }
}

const document = {
  schemaVersion: "0.1.0",
  source: {
    note: "Supplemental ntdll ABI hints parsed from Wine and ReactOS spec files. Used only when PHNT has no prototype.",
    inputs: sources.map((source) => ({
      id: source.id,
      name: source.name,
      repository: source.repository,
      commit: source.commit,
      file: source.file
    }))
  },
  prototypes: [...prototypes.values()].sort((left, right) => left.name.localeCompare(right.name))
};

if (write)
{
  writeStableJson(outputPath, document);
  console.log(`Generated supplemental ntdll spec index: prototypes=${document.prototypes.length}`);
}
else
{
  console.log(stableStringify({
    write: false,
    prototypes: document.prototypes.length,
    output: path.relative(repoRoot, outputPath).replaceAll("\\", "/")
  }));
}

function argumentValue(name, fallback)
{
  const prefix = `${name}=`;
  for (const arg of process.argv.slice(2))
  {
    if (arg.startsWith(prefix))
    {
      return arg.slice(prefix.length);
    }
  }

  return fallback;
}

function sourcePriority(sourceId)
{
  if (sourceId === "wine")
  {
    return 0;
  }

  return 1;
}

function parseSpecSource(source)
{
  const text = fs.readFileSync(source.path, "utf8");
  const prototypes = [];
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; ++index)
  {
    const prototype = parseSpecLine(lines[index], index + 1, source);
    if (prototype)
    {
      prototypes.push(prototype);
    }
  }

  return prototypes;
}

function parseSpecLine(line, lineNumber, source)
{
  const trimmed = line.trim();
  if (trimmed.length === 0 || trimmed.startsWith("#") || trimmed.startsWith(";"))
  {
    return null;
  }

  const body = trimmed.replace(/\s*#.*$/, "").trim();
  const dataExport = parseDataOrStubExport(body, lineNumber, source);
  if (dataExport)
  {
    return dataExport;
  }

  const match = /^@?\s*(?<tokens>.*?)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?<args>[^)]*)\)/.exec(body);
  if (!match)
  {
    return null;
  }

  const tokens = match.groups.tokens.split(/\s+/).filter(Boolean);
  const kind = tokens.find((token) => ["cdecl", "stdcall", "fastcall", "thiscall", "varargs", "stub", "extern"].includes(token));
  if (!kind || kind === "extern")
  {
    return null;
  }

  const name = match.groups.name;
  const args = match.groups.args.trim();
  const variadic = kind === "varargs" || tokens.includes("varargs") || /\.\.\.|varargs/i.test(args);
  const parameters = args.length === 0
    ? []
    : args.split(/\s+/).filter(Boolean).map((arg, index) => parameterFromSpecToken(arg, index));
  if (variadic && parameters.length === 0)
  {
    parameters.push({
      name: "arg0",
      type: "ULONG_PTR",
      direction: "in",
      variadic: true
    });
  }
  else if (variadic)
  {
    parameters[parameters.length - 1].variadic = true;
  }

  return {
    name,
    callingConvention: kind === "stub" ? callingConventionFromName(name) : normalizeCallingConvention(kind),
    returnType: returnTypeFromSpecName(name, parameters, kind),
    parameters,
    stub: kind === "stub" || tokens.includes("stub"),
    dataExport: false,
    source: {
      id: source.id,
      name: source.name,
      repository: source.repository,
      commit: source.commit,
      file: source.file,
      line: lineNumber,
      signature: body
    }
  };
}

function parseDataOrStubExport(body, lineNumber, source)
{
  const match = /^@\s+(?<kind>extern|stub)(?<tail>(?:\s+[^()]+)?)$/.exec(body);
  if (!match)
  {
    return null;
  }

  const tokens = match.groups.tail.split(/\s+/).filter(Boolean);
  const name = [...tokens].reverse().find((token) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(token));
  if (!name)
  {
    return null;
  }

  return {
    name,
    callingConvention: callingConventionFromName(name),
    returnType: match.groups.kind === "extern" ? "PVOID" : returnTypeFromName(name),
    parameters: [],
    stub: match.groups.kind === "stub",
    dataExport: match.groups.kind === "extern",
    source: {
      id: source.id,
      name: source.name,
      repository: source.repository,
      commit: source.commit,
      file: source.file,
      line: lineNumber,
      signature: body
    }
  };
}

function parameterFromSpecToken(token, index)
{
  const type = typeFromSpecToken(token);
  return {
    name: `arg${index}`,
    type,
    direction: "in",
    nullable: type.includes("*") || type === "PVOID" || type === "PCSTR" || type === "PCWSTR"
  };
}

function typeFromSpecToken(token)
{
  const normalized = token.toLowerCase();
  if (normalized === "ptr")
  {
    return "PVOID";
  }

  if (normalized === "str")
  {
    return "PCSTR";
  }

  if (normalized === "wstr")
  {
    return "PCWSTR";
  }

  if (normalized === "long")
  {
    return "ULONG";
  }

  if (normalized === "int")
  {
    return "INT";
  }

  if (normalized === "int64" || normalized === "longlong")
  {
    return "ULONGLONG";
  }

  if (normalized === "double")
  {
    return "double";
  }

  if (normalized === "float")
  {
    return "float";
  }

  return "ULONG_PTR";
}

function normalizeCallingConvention(kind)
{
  if (kind === "cdecl" || kind === "stdcall" || kind === "fastcall" || kind === "thiscall")
  {
    return kind;
  }

  return "winapi";
}

function callingConventionFromName(name)
{
  if (/^(Nt|Zw|Rtl|Ldr|Csr|Dbg|Etw|Tp|Tpp|ApiSet)/.test(name))
  {
    return "ntapi";
  }

  return "cdecl";
}

function returnTypeFromSpecName(name, parameters, kind)
{
  if (kind === "stub")
  {
    return returnTypeFromName(name);
  }

  if (/^(atan|atan2|ceil|cos|fabs|floor|log|pow|sin|sqrt|tan)$/.test(name))
  {
    return "double";
  }

  if (/^(memcpy|memmove|memchr|memset|strcat|strchr|strcpy|strncpy|strpbrk|strrchr|strstr|wcscat|wcschr|wcscpy|wcsncpy|wcspbrk|wcsrchr|wcsstr)/.test(name))
  {
    return "PVOID";
  }

  if (/^(strlen|strnlen|wcslen|wcsnlen|mbstowcs|wcstombs|_vscprintf|_vscwprintf)$/.test(name))
  {
    return "SIZE_T";
  }

  if (/^(Nt|Zw|Csr|Etw|Ldr)/.test(name))
  {
    return "NTSTATUS";
  }

  if (/^(Rtl).*(Status|Security|Unicode|String|Activation|Resource|Sid|Acl|Wnf|Feature|Boot|RXact|Timer|Ums)/.test(name))
  {
    return "NTSTATUS";
  }

  return returnTypeFromName(name);
}

function returnTypeFromName(name)
{
  if (/^(Nt|Zw|Csr|Etw)/.test(name))
  {
    return "NTSTATUS";
  }

  if (/^(Ldr|Rtl).*(Status|String|Unicode|Ansi|Integer|Security|Activation|Resource|Condition|Sid|Acl)/.test(name))
  {
    return "NTSTATUS";
  }

  return "ULONG_PTR";
}
