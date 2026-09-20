import compactCatalog from "../../../generated/ui-catalog.json";
import runtimeSupport from "../../../generated/runtime-support.json";
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

const supportedApiKeys = new Set(runtimeSupport.supportedKeys);

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
  const rows: DecoderApiRow[] = compactCatalog.rows.map((row) => ({
    name: row[0] as string,
    module: compactCatalog.strings[row[1] as number],
    family: compactCatalog.strings[row[2] as number],
    category: compactCatalog.strings[row[3] as number],
    risk: compactCatalog.strings[row[4] as number],
    hookPolicy: compactCatalog.strings[row[5] as number],
    coverageStatus: compactCatalog.strings[row[6] as number]
  }));
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
        coverageStatus: normalizeText(row.coverageStatus, "available"),
        runtimeSupported: supportedApiKeys.has(createSelectionKey(module, api).toLowerCase()),
        runtimeBlockedReason: supportedApiKeys.has(createSelectionKey(module, api).toLowerCase())
          ? "" : runtimeSupport.defaultBlockedReason
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
              runtimeSupported: entry.runtimeSupported,
              runtimeBlockedReason: entry.runtimeBlockedReason,
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
const runtimeApiEntries = apiCatalogEntries.filter((entry) => entry.runtimeSupported);

export function compactRuntimeApiSelection(selectedKeys: ReadonlySet<string>): string[]
{
  const modules = new Map<string, ApiCatalogEntry[]>();
  for (const entry of runtimeApiEntries)
  {
    const entries = modules.get(entry.module) ?? [];
    entries.push(entry);
    modules.set(entry.module, entries);
  }
  const tokens: string[] = [];
  for (const [module, entries] of modules)
  {
    const selected = entries.filter((entry) => selectedKeys.has(entry.selectionKey));
    if (selected.length === entries.length)
    {
      tokens.push(`${module}!*`);
    }
    else
    {
      tokens.push(...selected.map((entry) => entry.selectionKey));
    }
  }
  return tokens.sort();
}

export const captureProfiles: CaptureProfile[] = [
  {
    id: "all-current",
    name: "All current hooks",
    description: "Enable the compiled manual hook subset. Differential verification is tracked separately.",
    enabledApis: runtimeApiEntries.map((entry) => entry.selectionKey)
  },
  {
    id: "file-io",
    name: "File I/O",
    description: "Create/open/read/write/close and native file open coverage.",
    enabledApis: runtimeApiEntries
      .filter((entry) => entry.family === "file-io")
      .map((entry) => entry.selectionKey)
  },
  {
    id: "process-memory",
    name: "Process and memory",
    description: "Process, thread, module, memory, and handle inspection boundaries.",
    enabledApis: runtimeApiEntries
      .filter((entry) => /process|thread|memory|module|handle/i.test(`${entry.family}/${entry.category}`))
      .map((entry) => entry.selectionKey)
  },
  {
    id: "network-security",
    name: "Network and security",
    description: "Winsock, WinHTTP, WinINet, RPC, crypto, certificate, token, and registry APIs.",
    enabledApis: runtimeApiEntries
      .filter((entry) => /network|rpc|crypto|certificate|security|registry|service/i.test(`${entry.family}/${entry.category}`))
      .map((entry) => entry.selectionKey)
  }
];
