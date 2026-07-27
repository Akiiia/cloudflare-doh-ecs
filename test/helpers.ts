import { toArrayBuffer, writeU16, writeU32 } from "../src/binary";
import type { Env, RuleManifest } from "../src/types";

export function encodeName(name: string): Uint8Array {
  const labels = name.split(".");
  let length = 1;
  for (const label of labels) length += 1 + label.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const label of labels) {
    output[offset] = label.length;
    offset += 1;
    for (let i = 0; i < label.length; i += 1) {
      output[offset + i] = label.charCodeAt(i);
    }
    offset += label.length;
  }
  output[offset] = 0;
  return output;
}

export function makeQuery(
  name = "www.qq.com",
  type = 1,
  options?: {
    id?: number;
    optOptions?: Uint8Array;
    udpSize?: number;
    optTtl?: number;
  }
): Uint8Array {
  const qname = encodeName(name);
  const optOptions = options?.optOptions;
  const optLength = optOptions === undefined ? 0 : 11 + optOptions.length;
  const output = new Uint8Array(12 + qname.length + 4 + optLength);
  writeU16(output, 0, options?.id ?? 0x1234);
  writeU16(output, 2, 0x0110);
  writeU16(output, 4, 1);
  writeU16(output, 10, optOptions === undefined ? 0 : 1);
  let offset = 12;
  output.set(qname, offset);
  offset += qname.length;
  writeU16(output, offset, type);
  writeU16(output, offset + 2, 1);
  offset += 4;
  if (optOptions !== undefined) {
    output[offset] = 0;
    writeU16(output, offset + 1, 41);
    writeU16(output, offset + 3, options?.udpSize ?? 1232);
    writeU32(output, offset + 5, options?.optTtl ?? 0);
    writeU16(output, offset + 9, optOptions.length);
    output.set(optOptions, offset + 11);
  }
  return output;
}

export function makeResponseFromQuery(query: Uint8Array): Uint8Array {
  const output = query.slice();
  output[2] = (output[2] ?? 0) | 0x80;
  output[3] = (output[3] ?? 0) | 0x80;
  return output;
}

export function makeRuleBytes(newline = "\n", finalNewline = false): Uint8Array {
  const lines = [
    "0.zone",
    "a.cn",
    "qq.com",
    "z-last.cn",
    "full:exact.qq.net",
    "full:only.example",
    "regexp:^ignored\\.example$"
  ];
  return new TextEncoder().encode(lines.join(newline) + (finalNewline ? newline : ""));
}

export class MemoryKv {
  readonly values = new Map<string, ArrayBuffer | string>();
  failReadback = false;

  async get(
    key: string,
    type?: "text" | "json" | "arrayBuffer"
  ): Promise<unknown> {
    if (this.failReadback && key.startsWith("rules:data:")) return null;
    const value = this.values.get(key);
    if (value === undefined) return null;
    if (type === "arrayBuffer") {
      if (typeof value === "string") return new TextEncoder().encode(value).buffer;
      return value.slice(0);
    }
    const text =
      typeof value === "string" ? value : new TextDecoder().decode(new Uint8Array(value));
    if (type === "json") return JSON.parse(text) as unknown;
    return text;
  }

  async put(key: string, value: string | ArrayBuffer | ArrayBufferView): Promise<void> {
    if (typeof value === "string") {
      this.values.set(key, value);
      return;
    }
    if (ArrayBuffer.isView(value)) {
      this.values.set(
        key,
        value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
      );
      return;
    }
    this.values.set(key, value.slice(0));
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }

  asBinding(): KVNamespace {
    return this as unknown as KVNamespace;
  }
}

export async function envWithRules(
  rules = makeRuleBytes()
): Promise<{ env: Env; kv: MemoryKv; version: string }> {
  const kv = new MemoryKv();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(rules)));
  let hash = "";
  for (const byte of digest) hash += byte.toString(16).padStart(2, "0");
  const version = `rules:data:${hash}`;
  const stored = rules.buffer.slice(
    rules.byteOffset,
    rules.byteOffset + rules.byteLength
  ) as ArrayBuffer;
  await kv.put(version, stored);
  const manifest: RuleManifest = {
    active: version,
    previous: null,
    sha256: hash,
    size: rules.byteLength,
    updatedAt: new Date(0).toISOString()
  };
  await kv.put("rules:active", JSON.stringify(manifest));
  return {
    env: {
      RULES_KV: kv.asBinding()
    },
    kv,
    version
  };
}
