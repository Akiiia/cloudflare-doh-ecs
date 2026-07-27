export function readU16(data: Uint8Array, offset: number): number {
  if (offset < 0 || offset + 2 > data.length) {
    throw new RangeError("u16_out_of_bounds");
  }
  return ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
}

export function readU32(data: Uint8Array, offset: number): number {
  if (offset < 0 || offset + 4 > data.length) {
    throw new RangeError("u32_out_of_bounds");
  }
  return (
    ((data[offset] ?? 0) * 0x1000000) +
    ((data[offset + 1] ?? 0) << 16) +
    ((data[offset + 2] ?? 0) << 8) +
    (data[offset + 3] ?? 0)
  );
}

export function writeU16(data: Uint8Array, offset: number, value: number): void {
  if (offset < 0 || offset + 2 > data.length) {
    throw new RangeError("u16_out_of_bounds");
  }
  data[offset] = (value >>> 8) & 0xff;
  data[offset + 1] = value & 0xff;
}

export function writeU32(data: Uint8Array, offset: number, value: number): void {
  if (offset < 0 || offset + 4 > data.length) {
    throw new RangeError("u32_out_of_bounds");
  }
  data[offset] = (value >>> 24) & 0xff;
  data[offset + 1] = (value >>> 16) & 0xff;
  data[offset + 2] = (value >>> 8) & 0xff;
  data[offset + 3] = value & 0xff;
}

export function equalBytes(
  left: Uint8Array,
  right: Uint8Array,
  caseInsensitiveAscii = false
): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    let a = left[i] ?? 0;
    let b = right[i] ?? 0;
    if (caseInsensitiveAscii) {
      if (a >= 65 && a <= 90) a += 32;
      if (b >= 65 && b <= 90) b += 32;
    }
    if (a !== b) return false;
  }
  return true;
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return copy.buffer;
}
