export interface ParsedIp {
  family: 1 | 2;
  bytes: Uint8Array;
}

export interface EcsSubnet extends ParsedIp {
  prefixLength: number;
  network: Uint8Array;
}

function parseIpv4(value: string): Uint8Array | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const part = parts[i];
    if (part === undefined || !/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const number = Number(part);
    if (number > 255) return null;
    bytes[i] = number;
  }
  return bytes;
}

function parseHextet(part: string): number | null {
  if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
  return Number.parseInt(part, 16);
}

function parseIpv6(value: string): Uint8Array | null {
  if (value.length === 0 || value.includes("%")) return null;
  let address = value;
  let ipv4Tail: Uint8Array | null = null;
  const lastColon = address.lastIndexOf(":");
  const lastPart = lastColon >= 0 ? address.slice(lastColon + 1) : address;
  if (lastPart.includes(".")) {
    ipv4Tail = parseIpv4(lastPart);
    if (ipv4Tail === null) return null;
    address = `${address.slice(0, lastColon)}:ipv4`;
  }

  if ((address.match(/::/g) ?? []).length > 1) return null;
  const halves = address.split("::");
  const leftParts = halves[0] === "" ? [] : (halves[0] ?? "").split(":");
  const rightParts =
    halves.length === 1 || halves[1] === "" ? [] : (halves[1] ?? "").split(":");

  const parseParts = (parts: string[]): number[] | null => {
    const result: number[] = [];
    for (const part of parts) {
      if (part === "ipv4") {
        if (ipv4Tail === null) return null;
        result.push(
          ((ipv4Tail[0] ?? 0) << 8) | (ipv4Tail[1] ?? 0),
          ((ipv4Tail[2] ?? 0) << 8) | (ipv4Tail[3] ?? 0)
        );
      } else {
        const parsed = parseHextet(part);
        if (parsed === null) return null;
        result.push(parsed);
      }
    }
    return result;
  };

  const left = parseParts(leftParts);
  const right = parseParts(rightParts);
  if (left === null || right === null) return null;
  const hasCompression = halves.length === 2;
  const missing = 8 - left.length - right.length;
  if ((!hasCompression && missing !== 0) || (hasCompression && missing < 1)) return null;
  const words = [...left, ...new Array<number>(missing).fill(0), ...right];
  if (words.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i] ?? 0;
    bytes[i * 2] = word >>> 8;
    bytes[i * 2 + 1] = word & 0xff;
  }
  return bytes;
}

export function parseIp(value: string): ParsedIp | null {
  const ipv4 = parseIpv4(value);
  if (ipv4 !== null) return { family: 1, bytes: ipv4 };
  const ipv6 = parseIpv6(value);
  if (ipv6 === null) return null;

  let mapped = true;
  for (let i = 0; i < 10; i += 1) {
    if ((ipv6[i] ?? 0) !== 0) mapped = false;
  }
  if (mapped && ipv6[10] === 0xff && ipv6[11] === 0xff) {
    return { family: 1, bytes: ipv6.slice(12) };
  }
  return { family: 2, bytes: ipv6 };
}

export function isGlobalUnicast(ip: ParsedIp): boolean {
  const b = ip.bytes;
  if (ip.family === 1) {
    const a = b[0] ?? 0;
    const second = b[1] ?? 0;
    const third = b[2] ?? 0;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && second >= 64 && second <= 127) return false;
    if (a === 169 && second === 254) return false;
    if (a === 172 && second >= 16 && second <= 31) return false;
    if (a === 192 && second === 168) return false;
    if (a === 192 && second === 0 && third === 0) return false;
    if (a === 192 && second === 0 && third === 2) return false;
    if (a === 192 && second === 88 && third === 99) return false;
    if (a === 198 && (second === 18 || second === 19)) return false;
    if (a === 198 && second === 51 && third === 100) return false;
    if (a === 203 && second === 0 && third === 113) return false;
    return true;
  }

  if (((b[0] ?? 0) & 0xe0) !== 0x20) return false;
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) {
    return false;
  }
  if (
    b[0] === 0x20 &&
    b[1] === 0x01 &&
    b[2] === 0x00 &&
    ((b[3] ?? 0) & 0xf0) === 0x10
  ) {
    return false;
  }
  if (
    b[0] === 0x20 &&
    b[1] === 0x01 &&
    b[2] === 0x00 &&
    b[3] === 0x02 &&
    b[4] === 0 &&
    b[5] === 0
  ) {
    return false;
  }
  return true;
}

function stripForwardedPort(token: string): string {
  let value = token.trim();
  if (value.startsWith("\"") && value.endsWith("\"") && value.length >= 2) {
    value = value.slice(1, -1).trim();
  }
  if (value.startsWith("[")) {
    const closing = value.indexOf("]");
    if (closing > 0) {
      const suffix = value.slice(closing + 1);
      if (suffix === "" || /^:[0-9]{1,5}$/.test(suffix)) {
        return value.slice(1, closing);
      }
    }
    return value;
  }
  const colonCount = (value.match(/:/g) ?? []).length;
  if (colonCount === 1) {
    const colon = value.lastIndexOf(":");
    const host = value.slice(0, colon);
    const port = value.slice(colon + 1);
    if (host.includes(".") && /^[0-9]{1,5}$/.test(port)) return host;
  }
  return value;
}

export function clientIpFromXff(header: string | null): ParsedIp | null {
  if (header === null || header.length > 4096) return null;
  const values = header.split(",");
  for (let i = 0; i < values.length; i += 1) {
    const item = values[i];
    if (item === undefined) continue;
    const parsed = parseIp(stripForwardedPort(item));
    if (parsed !== null && isGlobalUnicast(parsed)) return parsed;
  }
  return null;
}

export function clientIpFromSingleHeader(header: string | null): ParsedIp | null {
  if (header === null || header.length > 64) return null;
  const parsed = parseIp(header.trim());
  return parsed !== null && isGlobalUnicast(parsed) ? parsed : null;
}

export function subnetForEcs(
  ip: ParsedIp | null,
  ipv4Prefix: number,
  ipv6Prefix: number
): EcsSubnet | null {
  if (ip === null || !isGlobalUnicast(ip)) return null;
  const prefixLength = ip.family === 1 ? ipv4Prefix : ipv6Prefix;
  const network = ip.bytes.slice();
  const wholeBytes = Math.floor(prefixLength / 8);
  const remainingBits = prefixLength % 8;
  if (remainingBits !== 0) {
    network[wholeBytes] = (network[wholeBytes] ?? 0) & (0xff << (8 - remainingBits));
  }
  const clearFrom = wholeBytes + (remainingBits === 0 ? 0 : 1);
  network.fill(0, clearFrom);
  return { ...ip, prefixLength, network };
}
