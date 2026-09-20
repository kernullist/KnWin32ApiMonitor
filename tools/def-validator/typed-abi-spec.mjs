// Every type is checked against the SDK declaration by the native compiler.
const parameter = (type, name, kind, direction = "in") => ({ type, name, kind, direction });
export const typedAbiSpecs = [
  { module: "oleaut32.dll", name: "VarR8FromR4", ordinal: 81, returnType: "HRESULT", returnKind: "Signed32",
    parameters: [parameter("FLOAT", "fltIn", "Float32"), parameter("DOUBLE*", "pdblOut", "Pointer", "out")] },
  { module: "oleaut32.dll", name: "VarR4FromR8", ordinal: 71, returnType: "HRESULT", returnKind: "Signed32",
    parameters: [parameter("DOUBLE", "dblIn", "Float64"), parameter("FLOAT*", "pfltOut", "Pointer", "out")] },
  { module: "d2d1.dll", name: "D2D1ConvertColorSpace", ordinal: 6, returnType: "D2D1_COLOR_F", returnKind: "Color4F",
    parameters: [parameter("D2D1_COLOR_SPACE", "sourceColorSpace", "Unsigned32"),
      parameter("D2D1_COLOR_SPACE", "destinationColorSpace", "Unsigned32"), parameter("const D2D1_COLOR_F*", "color", "Pointer")] },
  { module: "d2d1.dll", name: "D2D1MakeRotateMatrix", ordinal: 2, returnType: "void", returnKind: "Void",
    parameters: [parameter("FLOAT", "angle", "Float32"), parameter("D2D1_POINT_2F", "center", "Point2F"),
      parameter("D2D1_MATRIX_3X2_F*", "matrix", "Pointer", "out")] },
  { module: "d2d1.dll", name: "D2D1Vec3Length", ordinal: 11, returnType: "FLOAT", returnKind: "Float32",
    parameters: [parameter("FLOAT", "x", "Float32"), parameter("FLOAT", "y", "Float32"), parameter("FLOAT", "z", "Float32")] },
  { module: "user32.dll", name: "EnumChildWindows", returnType: "BOOL", returnKind: "Signed32",
    parameters: [parameter("HWND", "hWndParent", "Pointer"), parameter("WNDENUMPROC", "lpEnumFunc", "Pointer"),
      parameter("LPARAM", "lParam", "SignedPointer")] }
];

export function validateTypedAbiSpec(spec)
{
  const known = typedAbiSpecs.find((entry) => entry.module === spec.module && entry.name === spec.name);
  if (spec.variadic || spec.callingConvention && spec.callingConvention !== "winapi" ||
      !known || JSON.stringify(spec.parameters) !== JSON.stringify(known.parameters) ||
      spec.returnType !== known.returnType || spec.returnKind !== known.returnKind || spec.ordinal !== known.ordinal)
  {
    throw new Error("A typed ABI requires an exact reviewed SDK contract; variadic and unknown types are refused.");
  }
}
