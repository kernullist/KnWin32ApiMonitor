import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  repoRoot,
  writeStableJson
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const write = args.has("--write");
const pePath = path.resolve(argumentValue("--pe", process.env.NTDLL_LATEST_PE ?? ""));
const baselinePath = path.join(repoRoot, "generated", "ntdll-win11-export-baseline.json");
const outputPath = path.join(repoRoot, "generated", "ntdll-win11-latest-export-overlay.json");

if (!pePath || pePath === path.parse(pePath).root || !fs.existsSync(pePath))
{
  throw new Error("Provide a latest ntdll.dll PE with --pe=<path> or NTDLL_LATEST_PE.");
}

const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
const baselineNames = new Set((baseline.exports ?? []).map((entry) => entry.name));
const latest = readPeExports(pePath);
const addedExports = latest.namedExports
  .filter((entry) => !baselineNames.has(entry.name))
  .sort((left, right) => left.name.localeCompare(right.name));

const document = {
  schemaVersion: "0.1.0",
  source: {
    name: argumentValue("--source-name", "Windows 11 latest ntdll.dll"),
    url: argumentValue("--source-url", null),
    update: argumentValue("--source-update", null),
    version: argumentValue("--source-version", latest.fileVersion),
    sha256: argumentValue("--source-sha256", null),
    path: pePath,
    fileVersion: latest.fileVersion,
    productVersion: latest.productVersion,
    size: latest.size,
    machine: latest.machine,
    note: "Overlay exports absent from the local 24H2 baseline but present in a newer Windows 11 ntdll binary."
  },
  baseline: {
    file: "generated/ntdll-win11-export-baseline.json",
    numberOfNames: baseline.summary?.numberOfNames ?? (baseline.exports ?? []).length
  },
  latest: {
    numberOfFunctions: latest.numberOfFunctions,
    numberOfNames: latest.numberOfNames,
    ordinalOnlyCount: latest.ordinalOnlyCount
  },
  addedExports
};

if (write)
{
  writeStableJson(outputPath, document);
}

console.log(`Generated latest ntdll export overlay. latest=${latest.numberOfNames} baseline=${baselineNames.size} added=${addedExports.length}`);

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

function readPeExports(filePath)
{
  const buffer = fs.readFileSync(filePath);
  const stat = fs.statSync(filePath);
  const version = fileVersion(filePath);
  const u16 = (offset) => buffer.readUInt16LE(offset);
  const u32 = (offset) => buffer.readUInt32LE(offset);
  const peOffset = u32(0x3c);
  const machine = u16(peOffset + 4);
  const sectionCount = u16(peOffset + 6);
  const optionalHeaderSize = u16(peOffset + 20);
  const optionalHeaderOffset = peOffset + 24;
  const magic = u16(optionalHeaderOffset);
  const dataDirectoryOffset = magic === 0x20b ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
  const exportRva = u32(dataDirectoryOffset);
  const exportSize = u32(dataDirectoryOffset + 4);
  const sectionOffset = optionalHeaderOffset + optionalHeaderSize;
  const sections = [];

  for (let index = 0; index < sectionCount; ++index)
  {
    const offset = sectionOffset + index * 40;
    sections.push({
      name: buffer.slice(offset, offset + 8).toString("ascii").replace(/\0.*$/, ""),
      virtualSize: u32(offset + 8),
      virtualAddress: u32(offset + 12),
      rawSize: u32(offset + 16),
      rawAddress: u32(offset + 20),
      characteristics: u32(offset + 36)
    });
  }

  const rvaToSection = (rva) => {
    for (const section of sections)
    {
      const size = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + size)
      {
        return section;
      }
    }

    return null;
  };
  const rvaToOffset = (rva) => {
    const section = rvaToSection(rva);
    if (section)
    {
      return section.rawAddress + (rva - section.virtualAddress);
    }

    throw new Error(`unmapped PE RVA 0x${rva.toString(16)}`);
  };
  const readString = (rva) => {
    const offset = rvaToOffset(rva);
    let end = offset;
    while (end < buffer.length && buffer[end] !== 0)
    {
      ++end;
    }

    return buffer.slice(offset, end).toString("ascii");
  };

  const exportDirectoryOffset = rvaToOffset(exportRva);
  const ordinalBase = u32(exportDirectoryOffset + 16);
  const numberOfFunctions = u32(exportDirectoryOffset + 20);
  const numberOfNames = u32(exportDirectoryOffset + 24);
  const functionsRva = u32(exportDirectoryOffset + 28);
  const namesRva = u32(exportDirectoryOffset + 32);
  const ordinalsRva = u32(exportDirectoryOffset + 36);
  const namedExports = [];

  for (let index = 0; index < numberOfNames; ++index)
  {
    const nameRva = u32(rvaToOffset(namesRva) + index * 4);
    const ordinalIndex = u16(rvaToOffset(ordinalsRva) + index * 2);
    const functionRva = u32(rvaToOffset(functionsRva) + ordinalIndex * 4);
    const section = rvaToSection(functionRva);
    namedExports.push({
      name: readString(nameRva),
      ordinal: ordinalBase + ordinalIndex,
      rva: `0x${functionRva.toString(16).padStart(8, "0")}`,
      sectionName: section?.name ?? null,
      executable: Boolean((section?.characteristics ?? 0) & 0x20000000),
      forwarder: functionRva >= exportRva && functionRva < exportRva + exportSize ? readString(functionRva) : null
    });
  }

  namedExports.sort((left, right) => left.name.localeCompare(right.name));
  return {
    path: filePath,
    fileVersion: version.fileVersion,
    productVersion: version.productVersion,
    size: stat.size,
    machine: `0x${machine.toString(16)}`,
    numberOfFunctions,
    numberOfNames,
    ordinalOnlyCount: numberOfFunctions - numberOfNames,
    namedExports
  };
}

function fileVersion(filePath)
{
  if (process.platform !== "win32")
  {
    return {
      fileVersion: null,
      productVersion: null
    };
  }

  const command = [
    "$item = Get-Item -LiteralPath ",
    powerShellString(filePath),
    "; [pscustomobject]@{ fileVersion = $item.VersionInfo.FileVersion; productVersion = $item.VersionInfo.ProductVersion } | ConvertTo-Json -Compress"
  ].join("");
  const output = childProcess.execFileSync(
    "powershell",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
    {
      encoding: "utf8",
      maxBuffer: 1024 * 1024
    });

  return JSON.parse(output);
}

function powerShellString(value)
{
  return `'${String(value).replaceAll("'", "''")}'`;
}
