import { visit, parseTree } from "jsonc-parser";

export const defaultJsonLimits = Object.freeze({
    documentBytes: 8 * 1024 * 1024,
    stringBytes: 256 * 1024,
    depth: 32,
    containerItems: 65536,
    values: 250000
});

// This independent Microsoft parser preserves duplicate keys and numeric tokens.
export function inspectStrictJson(input, overrides = {})
{
    const limits = { ...defaultJsonLimits, ...overrides };
    const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
    if (bytes.length === 0 || bytes.length > limits.documentBytes ||
        bytes.includes(0) || bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])))
    {
        throw new Error("JSON document byte limit or encoding violation.");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const frames = [];
    let values = 0;
    function checkString(value)
    {
        if (!value.isWellFormed() || value.includes("\0") || Buffer.byteLength(value) > limits.stringBytes)
        {
            throw new Error("JSON string limit or Unicode violation.");
        }
    }
    function countValue()
    {
        if (++values > limits.values || (frames.length > 0 && ++frames.at(-1).items > limits.containerItems))
        {
            throw new Error("JSON value or container limit exceeded.");
        }
    }
    function begin()
    {
        countValue();
        if (frames.length >= limits.depth)
        {
            throw new Error("JSON depth limit exceeded.");
        }
        frames.push({ keys: new Set(), items: 0 });
    }
    visit(text, {
        onObjectBegin: begin,
        onArrayBegin: begin,
        onObjectEnd()
        {
            frames.pop();
        },
        onArrayEnd()
        {
            frames.pop();
        },
        onObjectProperty(key)
        {
            checkString(key);
            const keys = frames.at(-1).keys;
            if (keys.has(key))
            {
                throw new Error("Duplicate JSON object key.");
            }
            keys.add(key);
        },
        onLiteralValue(value)
        {
            countValue();
            if (typeof value === "string")
            {
                checkString(value);
            }
            else if (typeof value === "number" && !Number.isFinite(value))
            {
                throw new Error("Non-finite JSON number.");
            }
        },
        onError()
        {
            throw new Error("Malformed JSON syntax.");
        }
    }, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
    const document = JSON.parse(text);
    const errors = [];
    const root = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false });
    if (errors.length > 0)
    {
        throw new Error("Malformed JSON tree.");
    }
    return { document, root, text };
}

export function parseStrictJson(input, overrides = {})
{
    return inspectStrictJson(input, overrides).document;
}

export function typedJsonValue(parsed, key, kind, required = false)
{
    const { document, root, text } = parsed;
    if (root.type !== "object")
    {
        throw new Error("JSON object required.");
    }
    const property = root.children.find((entry) => entry.children[0].value === key);
    if (!property)
    {
        if (required)
        {
            throw new Error("Required field missing.");
        }
        return { string: "", bool: "false", u64: "0", u32: "0", object: "{}", array: "[]", objects: "0" }[kind] ?? "";
    }
    const node = property.children[1];
    const value = document[key];
    if (kind === "string" && node.type === "string")
    {
        return value;
    }
    if (kind === "bool" && node.type === "boolean")
    {
        return value ? "true" : "false";
    }
    if ((kind === "u64" || kind === "u32") && node.type === "number")
    {
        const token = text.slice(node.offset, node.offset + node.length);
        if (/^(0|[1-9][0-9]*)$/u.test(token))
        {
            const integer = BigInt(token);
            const maximum = kind === "u64" ? 18446744073709551615n : 4294967295n;
            if (integer <= maximum)
            {
                return integer.toString();
            }
        }
    }
    if (kind === "object" && node.type === "object")
    {
        return JSON.stringify(value);
    }
    if (kind === "array" && node.type === "array")
    {
        return JSON.stringify(value);
    }
    if (kind === "objects" && node.type === "array" && node.children.every((child) => child.type === "object"))
    {
        return String(node.children.length);
    }
    throw new Error("JSON field type or integer range mismatch.");
}

export function validateAgentJson(parsed)
{
    function field(key, kind, required = true)
    {
        return typedJsonValue(parsed, key, kind, required);
    }
    const type = field("messageType", "string");
    if (field("schemaVersion", "string") !== "0.1.0" || !type ||
        !field("operationId", "string") || field("pid", "u32") === "0")
    {
        throw new Error("Invalid agent envelope.");
    }
    field("tid", "u32");
    field("timestampUtc", "string");
    field("sequence", "u64");
    if (type === "agent_hello")
    {
        if (!["x86", "x64"].includes(field("architecture", "string")) || !field("agentVersion", "string"))
        {
            throw new Error("Invalid agent HELLO.");
        }
    }
    else if (type === "agent_shutdown")
    {
        field("reason", "string");
        for (const key of ["installedHooks", "restoredHooks", "failedHooks", "droppedCount"])
        {
            field(key, "u64");
        }
    }
    else if (type === "dropped_events")
    {
        field("droppedCount", "u64");
    }
    else if (type === "api_call")
    {
        for (const key of ["module", "api", "process", "returnValue", "lastErrorMessage", "bufferPreview"])
        {
            field(key, "string");
        }
        field("lastErrorCode", "u32");
        field("durationUs", "u64");
        field("arguments", "objects");
        const argumentsNode = parsed.root.children.find((entry) => entry.children[0].value === "arguments").children[1];
        for (const [index, argument] of parsed.document.arguments.entries())
        {
            typedJsonValue({ document: argument, root: argumentsNode.children[index], text: parsed.text }, "index", "u32", true);
            for (const key of ["name", "type", "direction", "rawValue", "preCallValue", "postCallValue", "decodedValue", "decodeStatus"])
            {
                if (typeof argument[key] !== "string")
                {
                    throw new Error("Invalid argument field.");
                }
            }
        }
        for (const key of ["tags", "stack"])
        {
            field(key, "array");
            if (parsed.document[key].some((item) => typeof item !== "string"))
            {
                throw new Error("Invalid string array.");
            }
        }
    }
    else if (["resolver_pointer_instrumented", "resolver_pointer_candidate", "resolver_pointer_unsupported"].includes(type))
    {
        for (const key of ["resolverApi", "classification", "reason", "requestedModule", "requestedName", "lookupKind",
            "targetModule", "targetRvaHex", "definitionName", "replacementPointer", "instrumentationReason"])
        {
            field(key, "string", false);
        }
        field("definitionApiId", "u32", false);
        field("requestedOrdinal", "u32", false);
        field("instrumented", "bool", false);
    }
}
