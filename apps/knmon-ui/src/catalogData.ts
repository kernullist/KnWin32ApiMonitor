import decoderTables from "../../../generated/definition-decoder-tables.json";
import type { ApiCatalogEntry, ApiNode, CaptureProfile } from "./types";

type DecoderApiRow = {
  module?: string;
  name?: string;
  family?: string;
  category?: string;
  risk?: string;
  hookPolicy?: string;
  coverageStatus?: string;
};

type DecoderTables = {
  apis?: DecoderApiRow[];
};

function normalizeText(value: string | undefined, fallback: string): string {
  const text = (value ?? "").trim();
  return text.length > 0 ? text : fallback;
}

function compareText(left: string, right: string): number {
  return left.localeCompare(right, undefined, { sensitivity: "base" });
}

function titleFromToken(value: string): string {
  return value
    .split(/[-_/]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function createSelectionKey(module: string, api: string): string {
  return `${module.toLowerCase()}!${api}`;
}

function createApiCatalogEntries(): ApiCatalogEntry[] {
  const rows = (decoderTables as DecoderTables).apis ?? [];
  const entries = rows
    .map((row): ApiCatalogEntry | null => {
      const module = normalizeText(row.module, "");
      const api = normalizeText(row.name, "");

      if (module.length === 0 || api.length === 0) {
        return null;
      }

      return {
        selectionKey: createSelectionKey(module, api),
        module,
        api,
        family: normalizeText(row.family, "other"),
        category: normalizeText(row.category, "uncategorized"),
        risk: normalizeText(row.risk, "unknown"),
        hookPolicy: normalizeText(row.hookPolicy, "iat"),
        coverageStatus: normalizeText(row.coverageStatus, "available")
      };
    })
    .filter((entry): entry is ApiCatalogEntry => entry !== null);

  const uniqueEntries = new Map<string, ApiCatalogEntry>();
  for (const entry of entries) {
    uniqueEntries.set(entry.selectionKey, entry);
  }

  return [...uniqueEntries.values()].sort((left, right) =>
    compareText(left.family, right.family) ||
    compareText(left.module, right.module) ||
    compareText(left.api, right.api)
  );
}

export const apiCatalogEntries: ApiCatalogEntry[] = createApiCatalogEntries();

function buildApiTree(entries: ApiCatalogEntry[]): ApiNode[] {
  const familyMap = new Map<string, Map<string, ApiCatalogEntry[]>>();

  for (const entry of entries) {
    let moduleMap = familyMap.get(entry.family);
    if (!moduleMap) {
      moduleMap = new Map<string, ApiCatalogEntry[]>();
      familyMap.set(entry.family, moduleMap);
    }

    const moduleEntries = moduleMap.get(entry.module) ?? [];
    moduleEntries.push(entry);
    moduleMap.set(entry.module, moduleEntries);
  }

  return [...familyMap.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([family, moduleMap]) => {
      const moduleNodes = [...moduleMap.entries()]
        .sort(([left], [right]) => compareText(left, right))
        .map(([module, moduleEntries]) => {
          const children = [...moduleEntries]
            .sort((left, right) => compareText(left.api, right.api))
            .map((entry): ApiNode => ({
              id: `api:${entry.selectionKey}`,
              label: entry.api,
              checked: true,
              selectionKey: entry.selectionKey,
              module: entry.module,
              api: entry.api,
              family: entry.family,
              category: entry.category,
              risk: entry.risk,
              hookPolicy: entry.hookPolicy,
              coverageStatus: entry.coverageStatus,
              count: 1
            }));

          return {
            id: `module:${family}:${module.toLowerCase()}`,
            label: module,
            checked: true,
            module,
            family,
            count: children.length,
            children
          };
        });

      return {
        id: `family:${family}`,
        label: titleFromToken(family),
        checked: true,
        family,
        count: moduleNodes.reduce((total, node) => total + (node.count ?? 0), 0),
        children: moduleNodes
      };
    });
}

export const apiTree: ApiNode[] = buildApiTree(apiCatalogEntries);

export const captureProfiles: CaptureProfile[] = [
  {
    id: "all-current",
    name: "All current hooks",
    description: "Enable every API currently represented in the generated decoder catalog.",
    enabledApis: apiCatalogEntries.map((entry) => entry.selectionKey)
  },
  {
    id: "file-io",
    name: "File I/O",
    description: "Create/open/read/write/close and native file open coverage.",
    enabledApis: apiCatalogEntries
      .filter((entry) => entry.family === "file-io")
      .map((entry) => entry.selectionKey)
  },
  {
    id: "process-memory",
    name: "Process and memory",
    description: "Process, thread, module, memory, and handle inspection boundaries.",
    enabledApis: apiCatalogEntries
      .filter((entry) => /process|thread|memory|module|handle/i.test(`${entry.family}/${entry.category}`))
      .map((entry) => entry.selectionKey)
  },
  {
    id: "network-security",
    name: "Network and security",
    description: "Winsock, WinHTTP, WinINet, RPC, crypto, certificate, token, and registry APIs.",
    enabledApis: apiCatalogEntries
      .filter((entry) => /network|rpc|crypto|certificate|security|registry|service/i.test(`${entry.family}/${entry.category}`))
      .map((entry) => entry.selectionKey)
  }
];
