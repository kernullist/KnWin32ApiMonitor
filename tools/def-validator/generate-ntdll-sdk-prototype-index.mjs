import fs from "node:fs";
import path from "node:path";

import {
  repoRoot,
  stableStringify,
  writeStableJson
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const write = args.has("--write");
const includeRoot = path.resolve(argumentValue("--include-root", process.env.WINDOWS_SDK_INCLUDE_ROOT ?? latestSdkIncludeRoot()));
const exportBaselinePath = path.join(repoRoot, "generated", "ntdll-win11-export-baseline.json");
const outputPath = path.join(repoRoot, "generated", "ntdll-sdk-prototype-index.json");
const headerFiles = [
  path.join("shared", "ip2string.h"),
  path.join("shared", "mstcpip.h"),
  path.join("um", "winnt.h"),
  path.join("km", "ntddk.h"),
  path.join("km", "crt", "stdio.h"),
  path.join("km", "crt", "string.h"),
  path.join("km", "crt", "wchar.h")
];

if (!includeRoot || includeRoot === path.parse(includeRoot).root || !fs.existsSync(includeRoot))
{
  throw new Error("Provide a Windows SDK include root with --include-root=<path> or WINDOWS_SDK_INCLUDE_ROOT.");
}

const exportBaseline = JSON.parse(fs.readFileSync(exportBaselinePath, "utf8"));
const exportNames = new Set((exportBaseline.exports ?? []).map((entry) => entry.name));
const prototypes = buildPrototypeIndex(includeRoot, exportNames);
const document = {
  schemaVersion: "0.1.0",
  source: {
    name: "Windows SDK headers",
    includeRoot,
    note: "Generated from installed Windows SDK headers for ntdll export prototype enrichment."
  },
  baseline: {
    file: "generated/ntdll-win11-export-baseline.json",
    exportCount: exportNames.size
  },
  prototypes
};

if (write)
{
  writeStableJson(outputPath, document);
}

console.log(`Generated Windows SDK ntdll prototype index. exports=${exportNames.size} prototypes=${prototypes.length}`);

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

function latestSdkIncludeRoot()
{
  const base = "C:/Program Files (x86)/Windows Kits/10/Include";
  if (!fs.existsSync(base))
  {
    return "";
  }

  const versions = fs.readdirSync(base)
    .filter((entry) => /^\d+\.\d+\.\d+\.\d+$/.test(entry))
    .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));
  if (versions.length === 0)
  {
    return "";
  }

  return path.join(base, versions[versions.length - 1]);
}

function buildPrototypeIndex(root, exportNames)
{
  const entries = new Map();
  for (const relative of headerFiles)
  {
    const filePath = path.join(root, relative);
    if (!fs.existsSync(filePath))
    {
      continue;
    }

    const text = fs.readFileSync(filePath, "utf8");
    for (const statement of prototypeStatements(text))
    {
      const parsed = parsePrototypeStatement(statement, relative.replaceAll("\\", "/"));
      if (parsed === null || !exportNames.has(parsed.name) || entries.has(parsed.name))
      {
        continue;
      }

      entries.set(parsed.name, parsed);
    }
  }

  return [...entries.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function stripComments(text)
{
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/.*$/gm, " ");
}

function prototypeStatements(text)
{
  const clean = stripComments(text)
    .replace(/^\s*#.*$/gm, " ")
    .replace(/extern\s+"C"\s*\{/g, " ")
    .replace(/^\s*\}\s*$/gm, " ");
  const statements = [];
  let current = "";

  for (let index = 0; index < clean.length; ++index)
  {
    const ch = clean[index];

    current += ch;
    if (ch === ";")
    {
      const statement = current.trim();
      if (
        /\b(?:NTSYSAPI|NTSYSCALLAPI|WINBASEAPI|DECLSPEC_IMPORT|__cdecl|__CRTDECL|__ALTDECL|_CRTIMP|_CRTIMP_ALT|_CRT_STDIO_IMP|_CRT_STDIO_IMP_ALT)\b/.test(statement) &&
        statement.includes("(") &&
        !/\btypedef\b/.test(statement))
      {
        statements.push(statement);
      }
      current = "";
    }
  }

  return statements;
}

function parsePrototypeStatement(statement, fileName)
{
  let result = null;

  do
  {
    const trimmed = statement.replace(/;$/, "").trim();
    const closeIndex = trimmed.lastIndexOf(")");
    if (closeIndex !== trimmed.length - 1)
    {
      break;
    }

    const openIndex = matchingOpenParen(trimmed, closeIndex);
    if (openIndex < 0)
    {
      break;
    }

    const before = trimmed.slice(0, openIndex).trim();
    const argsText = trimmed.slice(openIndex + 1, closeIndex).trim();
    const nameMatch = /([A-Za-z_][A-Za-z0-9_]*)$/.exec(before);
    if (nameMatch === null)
    {
      break;
    }

    const name = nameMatch[1];
    result = {
      name,
      returnType: normalizeReturnType(before.slice(0, nameMatch.index)) || "ULONG_PTR",
      callingConvention: callingConventionFromPrototype(before),
      parameters: parseParameters(argsText),
      source: {
        file: fileName
      }
    };
  }
  while (false);

  return result;
}

function matchingOpenParen(text, closeIndex)
{
  let depth = 0;
  for (let index = closeIndex; index >= 0; --index)
  {
    const ch = text[index];
    if (ch === ")")
    {
      ++depth;
    }
    else if (ch === "(")
    {
      --depth;
      if (depth === 0)
      {
        return index;
      }
    }
  }

  return -1;
}

function normalizeReturnType(text)
{
  return stripPrototypeNoise(text)
    .replace(/\b(?:NTSYSAPI|NTSYSCALLAPI|WINBASEAPI|DECLSPEC_IMPORT|NTAPI|WINAPI|APIENTRY|STDAPIVCALLTYPE|STDAPI|CDECL|__cdecl|__CRTDECL|__ALTDECL|DECLSPEC_NORETURN|NORETURN|FORCEINLINE|EXTERN_C|CONST|_CRTIMP|_CRTIMP_ALT|_ACRTIMP|_CRT_STDIO_IMP|_CRT_STDIO_IMP_ALT)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function callingConventionFromPrototype(text)
{
  if (/\bSTDAPIVCALLTYPE\b|\b__cdecl\b|\b__CRTDECL\b|\b__ALTDECL\b|\bCDECL\b/.test(text))
  {
    return "cdecl";
  }

  if (/\bNTAPI\b/.test(text))
  {
    return "ntapi";
  }

  return "winapi";
}

function parseParameters(text)
{
  const trimmed = text.trim();
  if (trimmed === "" || /^VOID$/i.test(trimmed))
  {
    return [];
  }

  return splitParameterList(trimmed).map((parameter, index) => parseParameter(parameter, index));
}

function splitParameterList(text)
{
  const parts = [];
  let current = "";
  let depth = 0;

  for (let index = 0; index < text.length; ++index)
  {
    const ch = text[index];
    if (ch === "(" || ch === "[" || ch === "<")
    {
      ++depth;
    }
    else if ((ch === ")" || ch === "]" || ch === ">") && depth > 0)
    {
      --depth;
    }

    if (ch === "," && depth === 0)
    {
      parts.push(current.trim());
      current = "";
      continue;
    }

    current += ch;
  }

  if (current.trim().length > 0)
  {
    parts.push(current.trim());
  }

  return parts;
}

function parseParameter(text, index)
{
  if (text === "...")
  {
    return {
      name: "varargs",
      type: "...",
      direction: "in",
      variadic: true
    };
  }

  const direction = directionFromAnnotations(text);
  const nullable = /_opt_|OPTIONAL\b/i.test(text);
  const withoutAnnotations = stripPrototypeNoise(text)
    .replace(/\b(?:CONST|const)\b/g, "const")
    .replace(/\bOPTIONAL\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const cleaned = withoutAnnotations.replace(/\[[^\]]*\]/g, "").trim();
  const nameMatch = /([A-Za-z_][A-Za-z0-9_]*)$/.exec(cleaned);
  let name = `arg${index}`;
  let type = cleaned;

  if (nameMatch !== null)
  {
    name = nameMatch[1];
    type = cleaned.slice(0, nameMatch.index).trim();
    if (type === "")
    {
      type = cleaned;
      name = `arg${index}`;
    }
  }

  if (type === "")
  {
    type = "ULONG_PTR";
  }

  const parameter = {
    name,
    type,
    direction
  };

  if (nullable)
  {
    parameter.nullable = true;
  }

  return parameter;
}

function stripPrototypeNoise(text)
{
  let result = text;
  let previous = "";

  while (previous !== result)
  {
    previous = result;
    result = result
      .replace(/(?<![A-Za-z0-9])_[A-Za-z0-9_]+_(?![A-Za-z0-9])\([^()]*\)/g, " ")
      .replace(/(?<![A-Za-z0-9])_[A-Za-z0-9_]+_(?![A-Za-z0-9])/g, " ")
      .replace(/\b(?:_IRQL_requires_max_|_When_|_At_|_Analysis_assume_|_Success_)\([^()]*\)/g, " ");
  }

  return result.replace(/\s+/g, " ").trim();
}

function directionFromAnnotations(text)
{
  if (/_Inout_|_Inout\b|_Inout_/i.test(text))
  {
    return "inout";
  }

  if (/_Out_|_Out\b|_Out_/i.test(text))
  {
    return "out";
  }

  return "in";
}
