import process from "node:process";

import {
  buildGeneratedDecoderTables,
  validateRepositoryDefinitions
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const maxTransportArguments = 16;
const maxPreviewSlots = 16;

function lower(value) {
  return String(value ?? "").toLowerCase();
}

function contains(value, token) {
  return value.includes(token);
}

function isRuntimeHookable(api) {
  return api.hookPolicy !== "definition_only" &&
    api.hookPolicy !== "unsupported" &&
    api.coverageStatus !== "unsupported";
}

function typeLooksBool(type) {
  const value = lower(type);
  return value === "bool" || value === "boolean" || value === "winbool";
}

function typeLooksHandleValue(type) {
  const value = lower(type);

  if (
    value === "handle" ||
    value === "hwnd" ||
    value === "hdc" ||
    value === "hkey" ||
    value === "hmenu" ||
    value === "hcursor" ||
    value === "hicon" ||
    value === "hinstance" ||
    value === "hmodule" ||
    value === "hmonitor" ||
    value === "socket" ||
    value === "sc_handle"
  ) {
    return true;
  }

  if (contains(value, "_handle") || contains(value, "handle_t")) {
    return true;
  }

  if (value.length > 1 && value[0] === "h" && !contains(value, "*")) {
    return value !== "hresult" &&
      !value.startsWith("http") &&
      !value.startsWith("hyper");
  }

  return false;
}

function typeLooksPointer(type) {
  const value = lower(type);

  return contains(value, "*") ||
    contains(value, "handle") ||
    value === "socket" ||
    value === "hmodule" ||
    value === "hwnd" ||
    value === "hkey" ||
    value === "hmenu" ||
    value === "hcursor" ||
    value === "hicon" ||
    value === "hdc" ||
    value === "bstr" ||
    value === "hstring" ||
    value.startsWith("p");
}

function typeLooksStringLike(type) {
  return typeLooksUtf16StringLike(type) ||
    typeLooksAnsiStringLike(type) ||
    contains(lower(type), "tchar");
}

function typeLooksUtf16StringLike(type) {
  const value = lower(type);

  return contains(value, "unicode_string") ||
    (contains(value, "ws_string") && !contains(value, "ws_xml_string")) ||
    contains(value, "wstr") ||
    contains(value, "pwsz") ||
    contains(value, "pcwsz") ||
    contains(value, "pwstr") ||
    contains(value, "pcwstr") ||
    contains(value, "lpwstr") ||
    contains(value, "lpcwstr") ||
    contains(value, "wchar") ||
    contains(value, "olechar") ||
    contains(value, "bstr") ||
    contains(value, "hstring");
}

function typeLooksAnsiStringLike(type) {
  const value = lower(type);

  return contains(value, "ansi_string") ||
    contains(value, "oem_string") ||
    contains(value, "utf8_string") ||
    contains(value, "lsa_string") ||
    contains(value, "ws_xml_string") ||
    contains(value, "pstr") ||
    contains(value, "pcstr") ||
    contains(value, "pcsz") ||
    contains(value, "lpstr") ||
    contains(value, "lpcstr") ||
    contains(value, "char*");
}

function typeLooksBufferLike(type, name) {
  const value = lower(type);
  const parameterName = lower(name);
  if (parameterNameLooksOpaquePointer(parameterName)) {
    return false;
  }

  const rawByteBufferType =
    contains(value, "byte*") ||
    contains(value, "uchar*") ||
    contains(value, "u_char*") ||
    contains(value, "pbyte") ||
    contains(value, "puchar") ||
    contains(value, "lpbyte") ||
    (contains(value, "blob") && !contains(value, "id3dblob"));
  const rawVoidBufferType =
    contains(value, "void*") ||
    contains(value, "lpvoid") ||
    contains(value, "pvoid");
  const bufferNameHint =
    contains(parameterName, "buffer") ||
    contains(parameterName, "bytes") ||
    contains(parameterName, "data");

  return rawByteBufferType ||
    (bufferNameHint && rawVoidBufferType);
}

function parameterNameLooksOpaquePointer(name) {
  const value = lower(name);
  return contains(value, "callbackdata") ||
    contains(value, "callbackcontext") ||
    contains(value, "callerdata") ||
    contains(value, "callercontext") ||
    contains(value, "userdata") ||
    contains(value, "usercontext") ||
    contains(value, "completioncontext") ||
    contains(value, "flsdata") ||
    contains(value, "tlsdata") ||
    contains(value, "contextdata");
}

function typeLooksGuidLike(type) {
  const value = lower(type);

  if (contains(value, "**")) {
    return false;
  }

  return contains(value, "guid") ||
    contains(value, "uuid");
}

function typeLooksScalarPointerLike(type) {
  const value = lower(type);

  if (contains(value, "**")) {
    return false;
  }

  return contains(value, "boolean*") ||
    contains(value, "pboolean") ||
    contains(value, "ushort*") ||
    contains(value, "pushort") ||
    contains(value, "short*") ||
    contains(value, "pshort") ||
    contains(value, "uint16*") ||
    contains(value, "int16*") ||
    contains(value, "word*") ||
    contains(value, "lpword") ||
    contains(value, "uint64*") ||
    contains(value, "uint64_t*") ||
    contains(value, "int64*") ||
    contains(value, "int64_t*") ||
    contains(value, "pint64") ||
    contains(value, "ulong64*") ||
    contains(value, "dword64*") ||
    contains(value, "longlong*") ||
    contains(value, "size_t*") ||
    contains(value, "ssize_t*") ||
    contains(value, "psize_t") ||
    contains(value, "pssize_t") ||
    contains(value, "uint_ptr*") ||
    contains(value, "int_ptr*") ||
    contains(value, "ulong_ptr*") ||
    contains(value, "long_ptr*") ||
    contains(value, "dword_ptr*") ||
    contains(value, "puint_ptr") ||
    contains(value, "pint_ptr") ||
    contains(value, "pulong_ptr") ||
    contains(value, "plong_ptr") ||
    contains(value, "pdword_ptr") ||
    contains(value, "reghandle*") ||
    contains(value, "handle*") ||
    contains(value, "phandle") ||
    contains(value, "uint*") ||
    contains(value, "puint") ||
    contains(value, "ulong*") ||
    contains(value, "pulong") ||
    contains(value, "dword*") ||
    contains(value, "lpdword") ||
    contains(value, "uint32*") ||
    contains(value, "int32*") ||
    contains(value, "int*") ||
    contains(value, "pint") ||
    contains(value, "long*") ||
    contains(value, "plong") ||
    contains(value, "bool*") ||
    contains(value, "pbool") ||
    contains(value, "float*") ||
    contains(value, "pfloat") ||
    contains(value, "double*") ||
    contains(value, "pdouble") ||
    contains(value, "uerrorcode*");
}

function typeLooksPointerSizedScalar(type) {
  const value = lower(type);
  return value === "intptr" ||
    value === "uintptr" ||
    value === "int_ptr" ||
    value === "uint_ptr" ||
    value === "long_ptr" ||
    value === "ulong_ptr" ||
    value === "dword_ptr" ||
    value === "size_t" ||
    value === "ssize_t" ||
    value === "intptr_t" ||
    value === "uintptr_t";
}

function smallStructDecodeClass(type) {
  const value = lower(type);

  if (contains(value, "large_integer")) {
    return "large_integer";
  }

  if (contains(value, "luid") && !contains(value, "fluid")) {
    return "luid";
  }

  if (contains(value, "filetime")) {
    return "filetime";
  }

  if (contains(value, "systemtime")) {
    return "systemtime";
  }

  if (contains(value, "point*") || contains(value, "ppoint") || contains(value, "lppoint")) {
    return "point";
  }

  if (contains(value, "rect*") || contains(value, "prect") || contains(value, "lprect")) {
    return "rect";
  }

  return "";
}

function typeLooksPointerIndirect(type, decode, name = "") {
  const value = lower(type);
  const alias = lower(decode);
  const parameterName = lower(name);
  const nameLooksPointerPointer =
    parameterName.startsWith("pp") &&
    !contains(value, "**") &&
    (contains(value, "*") || contains(value, "id3dblob"));

  return contains(alias, "pointer_pointer") ||
    contains(alias, "function_pointer_pointer") ||
    contains(alias, "handle_pointer") ||
    contains(alias, "rpc_string_pointer") ||
    contains(value, "**") ||
    contains(value, "* *") ||
    contains(value, "pvoid*") ||
    contains(value, "pvoid *") ||
    contains(value, "lpvoid*") ||
    contains(value, "lpvoid *") ||
    contains(value, "lpcvoid*") ||
    contains(value, "lpcvoid *") ||
    contains(value, "pbyte*") ||
    contains(value, "pbyte *") ||
    contains(value, "puchar*") ||
    contains(value, "puchar *") ||
    contains(value, "lpbyte*") ||
    contains(value, "lpbyte *") ||
    contains(value, "pwstr*") ||
    contains(value, "pwstr *") ||
    contains(value, "pcwstr*") ||
    contains(value, "pcwstr *") ||
    contains(value, "pstr*") ||
    contains(value, "pstr *") ||
    contains(value, "pcstr*") ||
    contains(value, "pcstr *") ||
    contains(value, "rpc_wstr*") ||
    contains(value, "rpc_wstr *") ||
    contains(value, "rpc_cstr*") ||
    contains(value, "rpc_cstr *") ||
    contains(value, "bstr*") ||
    contains(value, "bstr *") ||
    contains(value, "hstring*") ||
    contains(value, "hstring *") ||
    contains(value, "psid*") ||
    contains(value, "psid *") ||
    contains(value, "psecurity_descriptor*") ||
    contains(value, "psecurity_descriptor *") ||
    nameLooksPointerPointer;
}

function typeLooksBstrString(type) {
  const value = lower(type);

  return contains(value, "bstr") &&
    !contains(value, "bstr*") &&
    !contains(value, "bstr *") &&
    !contains(value, "**");
}

function typeLooksHstring(type) {
  const value = lower(type);

  return contains(value, "hstring") &&
    !contains(value, "hstring*") &&
    !contains(value, "hstring *") &&
    !contains(value, "**");
}

function typeLooksWsStringStruct(type) {
  const value = lower(type);

  return contains(value, "ws_string") &&
    !contains(value, "ws_xml_string") &&
    !contains(value, "**");
}

function typeLooksWsXmlStringStruct(type) {
  const value = lower(type);

  return contains(value, "ws_xml_string") &&
    !contains(value, "**");
}

function typeLooksCryptoBlobStruct(type) {
  const value = lower(type);

  if (contains(value, "**") || contains(value, "ual_data_blob")) {
    return false;
  }

  return contains(value, "cryptoapi_blob") ||
    contains(value, "crypt_integer_blob") ||
    contains(value, "crypt_uint_blob") ||
    contains(value, "crypt_objid_blob") ||
    contains(value, "crypt_data_blob") ||
    contains(value, "crypt_hash_blob") ||
    contains(value, "crypt_digest_blob") ||
    contains(value, "crypt_der_blob") ||
    contains(value, "cert_blob") ||
    contains(value, "cert_name_blob") ||
    contains(value, "cert_rdn_value_blob") ||
    contains(value, "crl_blob") ||
    contains(value, "ctl_blob") ||
    contains(value, "crypt_xml_blob") ||
    contains(value, "crypt_xml_data_blob") ||
    value === "blob*" ||
    value === "blob *" ||
    contains(value, "data_blob*") ||
    contains(value, "data_blob *");
}

function typeLooksObjectAttributesStruct(type, decode) {
  const value = lower(type);
  const alias = lower(decode);

  if (contains(value, "**")) {
    return false;
  }

  return contains(value, "object_attributes") ||
    contains(alias, "object_attributes");
}

function typeLooksSockaddrStruct(type, decode) {
  const value = lower(type);
  const alias = lower(decode);

  if (contains(value, "**")) {
    return false;
  }

  return contains(value, "sockaddr") ||
    contains(alias, "sockaddr");
}

function fixedRawBytePreviewLength(parameter, api) {
  const type = lower(parameter.type);
  const name = lower(parameter.name);
  const apiName = lower(api?.name);

  if (contains(type, "**")) {
    return 0;
  }

  const rawBytePointer = contains(type, "byte*") ||
    contains(type, "uchar*") ||
    contains(type, "u_char*") ||
    contains(type, "pbyte") ||
    contains(type, "puchar") ||
    contains(type, "lpbyte");

  const rawVoidPointer = contains(type, "void*") ||
    contains(type, "lpvoid") ||
    contains(type, "pvoid") ||
    contains(type, "lpcvoid");

  if (contains(type, "ual_data_blob")) {
    return 16;
  }

  if (contains(lower(parameter.decode), "version_info_buffer_pointer")) {
    return 16;
  }

  if (!rawBytePointer && !rawVoidPointer) {
    return 0;
  }

  if (rawBytePointer && rawByteScalarPreviewLength(name) !== 0) {
    return rawByteScalarPreviewLength(name);
  }

  if (rawBytePointer && (contains(name, "pformat") || contains(name, "formatstring"))) {
    return 16;
  }

  if (rawBytePointer && contains(name, "lpkeystate")) {
    return 256;
  }

  if (rawBytePointer && (
    contains(name, "rmcontrol") ||
    contains(name, "nodenumber") ||
    contains(name, "pbalpha") ||
    contains(name, "seed") ||
    contains(name, "wireid")
  )) {
    return 1;
  }

  if (
    rawBytePointer &&
    name === "param1" &&
    (contains(apiName, "_usermarshal") || contains(apiName, "_userunmarshal"))
  ) {
    return 16;
  }

  if (rawBytePointer && name === "pmemory" && apiName.startsWith("ndr")) {
    return 16;
  }

  if (typeLooksBufferLike(type, name)) {
    return 16;
  }

  return 0;
}

function rawByteScalarPreviewLength(name) {
  const value = lower(name);
  if (
    contains(value, "enabled") ||
    contains(value, "istoken") ||
    contains(value, "masklength") ||
    contains(value, "prefixlength") ||
    contains(value, "majorversion") ||
    contains(value, "minorversion") ||
    contains(value, "recordtype") ||
    contains(value, "scsistatus") ||
    contains(value, "packettype") ||
    contains(value, "optionlen")
  ) {
    return 1;
  }

  return 0;
}

function aliasLooksSid(alias) {
  const value = lower(alias);

  return value === "sid" ||
    value === "psid" ||
    value === "sid_pointer" ||
    value === "sid_optional" ||
    value.endsWith("_sid") ||
    contains(value, "security_identifier");
}

function parameterNameSuffix(parameter) {
  const original = String(parameter.name ?? "");
  let suffix = lower(original);

  if (suffix.startsWith("lp")) {
    suffix = suffix.slice(2);
  }

  if (suffix.startsWith("pb") || suffix.startsWith("pv")) {
    suffix = suffix.slice(2);
  } else if (suffix.startsWith("p")) {
    const second = original.length > 1 ? original[1] : "";
    const pointerStyle =
      (second >= "A" && second <= "Z") ||
      suffix.startsWith("pbuffer") ||
      suffix.startsWith("pbuf") ||
      suffix.startsWith("pdata") ||
      suffix.startsWith("pbytes") ||
      suffix.startsWith("pmemory") ||
      suffix.startsWith("pformat");
    if (pointerStyle) {
      suffix = suffix.slice(1);
    }
  }

  return suffix;
}

function lengthParameterLooksScalar(parameter) {
  if (!parameter) {
    return false;
  }

  const type = lower(parameter.type);
  const name = lower(parameter.name);
  const decode = lower(parameter.decode);
  if (contains(type, "*") ||
    contains(type, "handle") ||
    contains(type, "str") ||
    contains(type, "wchar") ||
    contains(type, "char") ||
    type.startsWith("p")) {
    return false;
  }

  return contains(decode, "byte_count") ||
    contains(decode, "size") ||
    contains(decode, "length") ||
    contains(decode, "count") ||
    name === "cb" ||
    name.startsWith("cb") ||
    contains(name, "size") ||
    contains(name, "length") ||
    contains(name, "len") ||
    contains(name, "bytes") ||
    contains(name, "numberofbytesto") ||
    contains(name, "numberofcharsto");
}

function lengthParameterLooksScalarPointer(parameter) {
  if (!parameter || !typeLooksScalarPointerLike(parameter.type)) {
    return false;
  }

  const name = lower(parameter.name);
  const decode = lower(parameter.decode);
  return contains(decode, "byte_count") ||
    contains(decode, "size") ||
    contains(decode, "length") ||
    contains(decode, "count") ||
    name === "pcb" ||
    name.startsWith("pcb") ||
    name.startsWith("lpcb") ||
    name.startsWith("pdw") ||
    name.startsWith("lpdw") ||
    contains(name, "size") ||
    contains(name, "length") ||
    contains(name, "len") ||
    contains(name, "bytes");
}

function lengthParameterLooksUsable(parameter) {
  return lengthParameterLooksScalar(parameter) || lengthParameterLooksScalarPointer(parameter);
}

function lengthParameterMatchScore(bufferParameter, lengthParameter, suffix) {
  if (!bufferParameter || !lengthParameter || !suffix || !lengthParameterLooksUsable(lengthParameter)) {
    return 0;
  }

  const name = lower(lengthParameter.name);
  const bufferName = lower(bufferParameter.name);
  if (name === `cb${suffix}` ||
    name === `pcb${suffix}` ||
    name === `lpcb${suffix}` ||
    name === `pcb${suffix}len` ||
    name === `lpcb${suffix}len` ||
    name === `dw${suffix}len` ||
    name === `dw${suffix}length` ||
    name === `dw${suffix}size` ||
    name === `pdw${suffix}len` ||
    name === `pdw${suffix}length` ||
    name === `pdw${suffix}size` ||
    name === `lpdw${suffix}len` ||
    name === `lpdw${suffix}length` ||
    name === `lpdw${suffix}size` ||
    name === `p${suffix}len` ||
    name === `p${suffix}length` ||
    name === `p${suffix}size` ||
    name === `cch${suffix}` ||
    name === `pcch${suffix}` ||
    name === `n${suffix}size` ||
    name === `${suffix}len` ||
    name === `${suffix}length` ||
    name === `${suffix}bytes` ||
    name === `${suffix}size`) {
    return 100;
  }

  if (suffix.endsWith("data")) {
    const base = suffix.slice(0, -4);
    if (
      base &&
      (name === `${base}len` ||
        name === `${base}length` ||
        name === `${base}size` ||
        name === `dw${base}len` ||
        name === `dw${base}length` ||
        name === `dw${base}size` ||
        name === `p${base}len` ||
        name === `p${base}length` ||
        name === `p${base}size`)
    ) {
      return 95;
    }
  }

  if (
    contains(bufferName, "signature") &&
    (name === "dwsiglen" || name === "pdwsiglen" || name === "lpdwsiglen" || name === "siglen")
  ) {
    return 95;
  }

  if (contains(bufferName, "inbuffer") && (name === "ninbuffersize" || name === "inbuffersize" || name === "cbinbuffer")) {
    return 95;
  }

  if (contains(bufferName, "outbuffer") && (name === "noutbuffersize" || name === "outbuffersize" || name === "cboutbuffer")) {
    return 95;
  }

  if ((suffix === "buffer" || contains(bufferName, "buffer")) &&
    (name === "buffersize" || name === "bufferlength" || name === "nbuffersize" || name === "cbbuffer" || name === "cbbufsize" ||
      name === "pcbbuffer" || name === "lpcbbuffer" || name === "pdwbufferlength" || name === "lpdwbufferlength" ||
      name === "pdwbuffersize" || name === "lpdwbuffersize")) {
    return 90;
  }

  if ((suffix === "data" || contains(bufferName, "data")) &&
    (name === "datasize" || name === "datalength" || name === "cbdata" || name === "pcbdata" || name === "lpcbdata" ||
      name === "dwdata" || name === "datalen" || name === "pdwdatalen" || name === "pdwdatalength" ||
      name === "lpdwdatalen" || name === "lpdwdatalength")) {
    return 90;
  }

  if ((contains(bufferName, "buffer") || contains(bufferName, "data") || contains(bufferName, "bytes")) &&
    (contains(name, "numberofbytesto") || contains(name, "numberofcharsto"))) {
    return 90;
  }

  if (name === "nsize" ||
    name === "dwsize" ||
    name === "cbsize" ||
    name === "pcbsize" ||
    name === "lpcbsize" ||
    name === "pdwsize" ||
    name === "lpdwsize" ||
    name === "size" ||
    name === "psize" ||
    name === "length" ||
    name === "plength" ||
    name === "pullength" ||
    name === "pullen" ||
    name === "pulsize" ||
    name === "dwlen" ||
    name === "nlen" ||
    name === "pdwlength" ||
    name === "pdwlen" ||
    name === "lpdwlength" ||
    name === "lpdwlen" ||
    name === "cch" ||
    name === "pcch" ||
    name === "len" ||
    name === "bytes" ||
    name === "ubytes" ||
    name === "lbytes") {
    if (Math.abs(bufferParameter.index - lengthParameter.index) <= 2) {
      return 70;
    }
  }

  if (contains(lower(lengthParameter.decode), "byte_count") && Math.abs(bufferParameter.index - lengthParameter.index) <= 2) {
    return 50;
  }

  return 0;
}

function hasResolvedBufferLength(parameter, parameters) {
  if (Number.isInteger(parameter.lengthFromIndex) && parameter.lengthFromIndex >= 0 && parameter.lengthFromIndex < parameters.length) {
    return true;
  }

  const suffix = parameterNameSuffix(parameter);
  let bestScore = 0;
  for (const candidate of parameters) {
    if (candidate.index === parameter.index) {
      continue;
    }

    bestScore = Math.max(bestScore, lengthParameterMatchScore(parameter, candidate, suffix));
  }

  return bestScore !== 0;
}

function valueKind(parameter) {
  const alias = lower(parameter.decode);
  const type = lower(parameter.type);
  const name = lower(parameter.name);

  if (parameter.flags) {
    return "flags";
  }

  if (parameter.enum) {
    return "enum";
  }

  if (alias === "bool" || alias === "bool_value" || typeLooksBool(type)) {
    return "bool";
  }

  if (typeLooksPointerSizedScalar(type)) {
    return "scalar";
  }

  if (contains(alias, "string") || typeLooksStringLike(type)) {
    return "string";
  }

  if (contains(alias, "buffer") || contains(alias, "bytes") || typeLooksBufferLike(type, name)) {
    return "buffer";
  }

  if (contains(alias, "guid") || contains(alias, "uuid") || typeLooksGuidLike(type)) {
    return "object";
  }

  if (smallStructDecodeClass(type)) {
    return "object";
  }

  if (typeLooksScalarPointerLike(type)) {
    return "pointer";
  }

  if (contains(alias, "handle") || typeLooksHandleValue(type)) {
    return "handle";
  }

  if (
    contains(alias, "object") ||
    contains(alias, "struct") ||
    contains(alias, "guid") ||
    aliasLooksSid(alias) ||
    contains(alias, "sockaddr") ||
    contains(alias, "descriptor")
  ) {
    return "object";
  }

  if (typeLooksPointer(type) || alias === "pointer") {
    return "pointer";
  }

  if (contains(alias, "status") || contains(alias, "error")) {
    return "status";
  }

  return "scalar";
}

function decodeClass(parameter) {
  if (parameter.flags) {
    return `flags:${parameter.flags}`;
  }

  if (parameter.enum) {
    return `enum:${parameter.enum}`;
  }

  if (typeLooksUtf16StringLike(parameter.type)) {
    return "utf16_string";
  }

  if (typeLooksAnsiStringLike(parameter.type)) {
    return "ansi_string";
  }

  if (contains(lower(parameter.decode), "utf16") || contains(lower(parameter.decode), "wide")) {
    return "utf16_string";
  }

  if (contains(lower(parameter.decode), "ansi")) {
    return "ansi_string";
  }

  if (contains(lower(parameter.decode), "guid") || contains(lower(parameter.decode), "uuid") || typeLooksGuidLike(parameter.type)) {
    return "guid";
  }

  const structDecodeClass = smallStructDecodeClass(parameter.type);
  if (structDecodeClass) {
    return structDecodeClass;
  }

  if (valueKind(parameter) === "pointer" && typeLooksScalarPointerLike(parameter.type)) {
    return "scalar_pointer";
  }

  if (parameter.decode) {
    return parameter.decode;
  }

  return valueKind(parameter);
}

function decodeAliasLooksTargetMemory(parameter) {
  const alias = lower(parameter.decode);
  const type = lower(parameter.type);
  const name = lower(parameter.name);

  if (!alias) {
    return typeLooksStringLike(type) ||
      typeLooksBufferLike(type, name) ||
      typeLooksGuidLike(type) ||
      typeLooksScalarPointerLike(type) ||
      typeLooksPointerIndirect(type, alias, name) ||
      Boolean(smallStructDecodeClass(type));
  }

  return typeLooksStringLike(type) ||
    typeLooksBufferLike(type, name) ||
    typeLooksGuidLike(type) ||
    typeLooksScalarPointerLike(type) ||
    typeLooksPointerIndirect(type, alias, name) ||
    Boolean(smallStructDecodeClass(type)) ||
    contains(alias, "string") ||
    contains(alias, "buffer") ||
    contains(alias, "bytes") ||
    contains(alias, "blob") ||
    contains(alias, "object") ||
    contains(alias, "struct") ||
    contains(alias, "descriptor") ||
    contains(alias, "guid") ||
    aliasLooksSid(alias) ||
    contains(alias, "sockaddr") ||
    contains(alias, "path") ||
    contains(alias, "pointer_pointer") ||
    contains(alias, "function_pointer_pointer") ||
    contains(alias, "handle_pointer") ||
    contains(alias, "rpc_string_pointer");
}

function parameterAllowsPreview(parameter, kind) {
  const direction = lower(parameter.direction);
  const timing = lower(parameter.captureTiming);
  return !(contains(direction, "out") && !contains(direction, "inout") && !contains(timing, "post") && kind !== "pointer_indirect");
}

function previewPriority(kind) {
  if (kind === "buffer") {
    return 100;
  }

  if (kind === "pointer_indirect") {
    return 95;
  }

  if (kind === "guid" ||
    kind === "utf16_string_struct" ||
    kind === "ansi_string_struct" ||
    kind === "large_integer" ||
    kind === "filetime" ||
    kind === "systemtime" ||
    kind === "point" ||
    kind === "rect") {
    return 90;
  }

  if (kind === "utf16_string" || kind === "ansi_string" || kind === "bstr" || kind === "hstring") {
    return 80;
  }

  if (kind === "scalar_pointer") {
    return 70;
  }

  return 0;
}

function previewKind(parameter, parameters, api) {
  const type = lower(parameter.type);
  const alias = lower(parameter.decode);
  const name = lower(parameter.name);

  if (contains(type, "unicode_string")) {
    return "utf16_string_struct";
  }

  if (contains(type, "ansi_string")) {
    return "ansi_string_struct";
  }

  if (
    contains(type, "oem_string") ||
    contains(type, "utf8_string") ||
    contains(type, "lsa_string")
  ) {
    return "ansi_string_struct";
  }

  if (typeLooksWsStringStruct(type)) {
    return "utf16_string_struct";
  }

  if (typeLooksWsXmlStringStruct(type)) {
    return "ansi_string_struct";
  }

  if (typeLooksObjectAttributesStruct(type, alias)) {
    return "utf16_string_struct";
  }

  if (typeLooksSockaddrStruct(type, alias) && hasResolvedBufferLength(parameter, parameters)) {
    return "ansi_string";
  }

  if (typeLooksCryptoBlobStruct(type)) {
    return "buffer";
  }

  const structPreviewKind = smallStructDecodeClass(type);
  if (structPreviewKind) {
    if (structPreviewKind === "luid") {
      return "large_integer";
    }

    return structPreviewKind;
  }

  if (typeLooksBstrString(type)) {
    return "bstr";
  }

  if (typeLooksHstring(type)) {
    return "hstring";
  }

  if (typeLooksPointerIndirect(type, alias, name)) {
    return "pointer_indirect";
  }

  if (
    contains(type, "wstr") ||
    contains(type, "pwsz") ||
    contains(type, "pcwsz") ||
    contains(type, "pwstr") ||
    contains(type, "pcwstr") ||
    contains(type, "lpwstr") ||
    contains(type, "lpcwstr") ||
    contains(type, "wchar") ||
    contains(alias, "utf16") ||
    contains(alias, "wide")
  ) {
    return "utf16_string";
  }

  if (
    contains(type, "pstr") ||
    contains(type, "pcstr") ||
    contains(type, "pcsz") ||
    contains(type, "lpstr") ||
    contains(type, "lpcstr") ||
    contains(type, "char*") ||
    contains(alias, "ansi")
  ) {
    return "ansi_string";
  }

  if (
    (contains(alias, "buffer") || contains(alias, "bytes") || typeLooksBufferLike(type, name)) &&
    hasResolvedBufferLength(parameter, parameters)
  ) {
    return "buffer";
  }

  if (fixedRawBytePreviewLength(parameter, api) !== 0) {
    return "buffer";
  }

  if (contains(alias, "guid") || contains(alias, "uuid") || typeLooksGuidLike(type)) {
    return "guid";
  }

  if (typeLooksScalarPointerLike(type)) {
    return "scalar_pointer";
  }

  return "";
}

function payloadPolicy(kind, hasPreviewSlot, targetMemoryCapable) {
  if (hasPreviewSlot) {
    return "target_memory";
  }

  if (targetMemoryCapable && (kind === "pointer" || kind === "string" || kind === "buffer" || kind === "object")) {
    return "pointer_value_only";
  }

  return "value";
}

const result = validateRepositoryDefinitions();
const errors = [...result.errors];
const decoder = errors.length === 0 ? buildGeneratedDecoderTables(result.apiDocuments, result.metadataIndex) : null;

if (decoder !== null) {
  const parametersByApi = new Map();
  for (const parameter of decoder.parameters) {
    const list = parametersByApi.get(parameter.apiId) ?? [];
    list.push(parameter);
    parametersByApi.set(parameter.apiId, list);
  }

  const summary = {
    runtimeHookableApis: 0,
    runtimeHookableParameters: 0,
    capturedGenericParameters: 0,
    returnOnlyApis: 0,
    truncatedByTransportLimit: 0,
    byValueKind: {},
    byPayloadPolicy: {},
    previewEligibleParameters: 0,
    previewCoveredApis: 0,
    previewCoveredParameters: 0,
    byPreviewKind: {}
  };
  const pointerValueOnlyParameters = [];

  for (const api of decoder.apis) {
    if (!isRuntimeHookable(api)) {
      continue;
    }

    summary.runtimeHookableApis += 1;
    const parameters = parametersByApi.get(api.id) ?? [];
    if (parameters.length !== api.parameterCount) {
      errors.push(`${api.module}!${api.name}: generated parameter count mismatch: expected ${api.parameterCount}, got ${parameters.length}`);
      continue;
    }

    if (parameters.length === 0) {
      summary.returnOnlyApis += 1;
      continue;
    }

    summary.runtimeHookableParameters += parameters.length;
    if (parameters.length > maxTransportArguments) {
      summary.truncatedByTransportLimit += 1;
    }

    const capturedParameters = parameters.slice(0, maxTransportArguments);
    const previewIndexes = capturedParameters
      .map((parameter, index) => {
        const kind = previewKind(parameter, capturedParameters, api);
        return { parameter, index, kind: kind && parameterAllowsPreview(parameter, kind) ? kind : "" };
      })
      .filter((entry) => entry.kind)
      .sort((left, right) => {
        const priorityDelta = previewPriority(right.kind) - previewPriority(left.kind);
        if (priorityDelta !== 0) {
          return priorityDelta;
        }

        return left.index - right.index;
      })
      .slice(0, maxPreviewSlots);
    const previewIndexSet = new Set(previewIndexes.map((entry) => entry.index));
    if (previewIndexes.length > 0) {
      summary.previewCoveredApis += 1;
      summary.previewCoveredParameters += previewIndexes.length;
    }

    for (const [index, parameter] of capturedParameters.entries()) {
      const kind = valueKind(parameter);
      const klass = decodeClass(parameter);
      const previewCandidateKind = previewKind(parameter, capturedParameters, api);
      const kindForPreview = previewCandidateKind && parameterAllowsPreview(parameter, previewCandidateKind) ? previewCandidateKind : "";
      const hasPreviewSlot = previewIndexSet.has(index);
      const targetMemoryCapable = decodeAliasLooksTargetMemory(parameter);
      const policy = payloadPolicy(kind, hasPreviewSlot, targetMemoryCapable);
      summary.capturedGenericParameters += 1;
      summary.byValueKind[kind] = (summary.byValueKind[kind] ?? 0) + 1;
      summary.byPayloadPolicy[policy] = (summary.byPayloadPolicy[policy] ?? 0) + 1;
      if (kindForPreview) {
        summary.previewEligibleParameters += 1;
        summary.byPreviewKind[kindForPreview] = (summary.byPreviewKind[kindForPreview] ?? 0) + 1;
      }

      if (!kind || !klass || !policy) {
        errors.push(`${api.module}!${api.name}.${parameter.name}: missing generic rich semantic classification`);
      }

      if (targetMemoryCapable && (kind === "pointer" || kind === "string" || kind === "buffer" || kind === "object") && policy !== "pointer_value_only" && policy !== "target_memory") {
        errors.push(`${api.module}!${api.name}.${parameter.name}: pointer-like generic argument must use pointer_value_only or target_memory policy`);
      }

      if (policy === "target_memory" && kind !== "string" && kind !== "buffer" && kind !== "object" && kind !== "pointer" && kind !== "handle") {
        errors.push(`${api.module}!${api.name}.${parameter.name}: generated preview target_memory policy is currently only supported for string, buffer, object, pointer, and handle arguments`);
      }

      if (policy === "pointer_value_only") {
        pointerValueOnlyParameters.push({
          module: api.module,
          api: api.name,
          family: api.family,
          category: api.category,
          risk: api.risk,
          parameter: parameter.name,
          index: parameter.index,
          type: parameter.type,
          direction: parameter.direction,
          decode: parameter.decode,
          captureTiming: parameter.captureTiming,
          nullable: parameter.nullable,
          maxBytes: parameter.maxBytes,
          lengthFrom: parameter.lengthFrom,
          lengthFromIndex: parameter.lengthFromIndex,
          lengthExpression: parameter.lengthExpression,
          valueKind: kind,
          decodeClass: klass,
          previewCandidateKind,
          previewAllowed: Boolean(kindForPreview),
          hasPreviewSlot
        });
      }
    }
  }

  if (summary.runtimeHookableApis === 0) {
    errors.push("generic rich decoder readiness did not find runtime hookable APIs");
  }

  if (errors.length === 0) {
    if (args.has("--json")) {
      process.stdout.write(`${JSON.stringify({
        summary,
        pointerValueOnlyParameters
      }, null, 2)}\n`);
    } else {
      console.log(
        `Generic rich decoder readiness passed. runtimeHookableApis=${summary.runtimeHookableApis} capturedGenericParameters=${summary.capturedGenericParameters} returnOnlyApis=${summary.returnOnlyApis} truncatedByTransportLimit=${summary.truncatedByTransportLimit}`
      );
      console.log(`Value kinds: ${JSON.stringify(summary.byValueKind)}`);
      console.log(`Payload policies: ${JSON.stringify(summary.byPayloadPolicy)}`);
      console.log(
        `Preview slots: eligibleParameters=${summary.previewEligibleParameters} coveredParameters=${summary.previewCoveredParameters} coveredApis=${summary.previewCoveredApis} maxPerApi=${maxPreviewSlots} kinds=${JSON.stringify(summary.byPreviewKind)}`
      );
    }
  }
}

if (errors.length > 0) {
  console.error("Generic rich decoder readiness failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}
