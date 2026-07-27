import { readU16, readU32, writeU16, writeU32 } from "../src/binary";
import { parseDnsMessage } from "../src/dns";
import { rewriteEcs } from "../src/ecs";
import { parseIp, subnetForEcs } from "../src/ip";
import { makeQuery } from "./helpers";

function option(code: number, data: number[]): Uint8Array {
  const output = new Uint8Array(4 + data.length);
  writeU16(output, 0, code);
  writeU16(output, 2, data.length);
  output.set(data, 4);
  return output;
}

describe("EDNS Client Subnet rewriting", () => {
  it("adds an OPT with an IPv4 /24 ECS", () => {
    const query = makeQuery();
    const subnet = subnetForEcs(parseIp("8.8.4.123"), 24, 56);
    const output = rewriteEcs(query, parseDnsMessage(query), subnet);
    const parsed = parseDnsMessage(output);
    expect(parsed.additionalCount).toBe(1);
    expect(parsed.opt?.class).toBe(1232);
    expect(parsed.opt?.ttl).toBe(0);
    const start = parsed.opt?.rdataStart ?? 0;
    expect(Array.from(output.slice(start, start + 11))).toEqual([
      0, 8, 0, 7, 0, 1, 24, 0, 8, 8, 4
    ]);
  });

  it("encodes IPv6 with a non-octet prefix and scope zero", () => {
    const query = makeQuery();
    const subnet = subnetForEcs(parseIp("2001:4860:1234:56ff::1"), 24, 57);
    const output = rewriteEcs(query, parseDnsMessage(query), subnet);
    const opt = parseDnsMessage(output).opt;
    const start = opt?.rdataStart ?? 0;
    expect(readU16(output, start)).toBe(8);
    expect(readU16(output, start + 2)).toBe(12);
    expect(readU16(output, start + 4)).toBe(2);
    expect(output[start + 6]).toBe(57);
    expect(output[start + 7]).toBe(0);
    expect(Array.from(output.slice(start + 8, start + 16))).toEqual([
      0x20, 0x01, 0x48, 0x60, 0x12, 0x34, 0x56, 0x80
    ]);
  });

  it("replaces old ECS while preserving other options, UDP size and DO", () => {
    const padding = option(12, [1, 2, 3]);
    const oldEcs = option(8, [0, 1, 32, 0, 9, 9, 9, 9]);
    const options = new Uint8Array(padding.length + oldEcs.length);
    options.set(padding);
    options.set(oldEcs, padding.length);
    const query = makeQuery("qq.com", 1, {
      optOptions: options,
      udpSize: 4096,
      optTtl: 0x8000
    });
    const subnet = subnetForEcs(parseIp("1.1.1.129"), 25, 56);
    const output = rewriteEcs(query, parseDnsMessage(query), subnet);
    const parsed = parseDnsMessage(output);
    expect(parsed.opt?.class).toBe(4096);
    expect((parsed.opt?.ttl ?? 0) & 0x8000).toBe(0x8000);
    const start = parsed.opt?.rdataStart ?? 0;
    expect(readU16(output, start)).toBe(12);
    const ecsStart = start + padding.length;
    expect(readU16(output, ecsStart)).toBe(8);
    expect(Array.from(output.slice(ecsStart + 8, ecsStart + 12))).toEqual([1, 1, 1, 128]);
  });

  it("removes client-provided ECS when no trusted public IP exists", () => {
    const oldEcs = option(8, [0, 1, 24, 0, 9, 9, 9]);
    const query = makeQuery("qq.com", 1, { optOptions: oldEcs });
    const output = rewriteEcs(query, parseDnsMessage(query), null);
    const parsed = parseDnsMessage(output);
    expect(parsed.opt?.rdataStart).toBe(parsed.opt?.rdataEnd);
    expect(readU16(output, (parsed.opt?.rdataStart ?? 2) - 2)).toBe(0);
  });

  it("rejects truncated EDNS options", () => {
    const bad = Uint8Array.of(0, 8, 0, 10, 1);
    const query = makeQuery("qq.com", 1, { optOptions: bad });
    expect(() =>
      rewriteEcs(
        query,
        parseDnsMessage(query),
        subnetForEcs(parseIp("8.8.8.8"), 24, 56)
      )
    ).toThrowError("truncated_edns_option_data");
  });

  it("rejects an OPT that is not the final additional record", () => {
    const query = makeQuery("qq.com", 1, { optOptions: new Uint8Array() });
    const extra = new Uint8Array(15);
    extra[0] = 0;
    writeU16(extra, 1, 1);
    writeU16(extra, 3, 1);
    writeU32(extra, 5, 0);
    writeU16(extra, 9, 4);
    extra.set([1, 2, 3, 4], 11);
    const combined = new Uint8Array(query.length + extra.length);
    combined.set(query);
    combined.set(extra, query.length);
    writeU16(combined, 10, 2);
    const parsed = parseDnsMessage(combined);
    expect(readU32(combined, (parsed.opt?.rdataStart ?? 10) - 6)).toBe(0);
    expect(() =>
      rewriteEcs(
        combined,
        parsed,
        subnetForEcs(parseIp("8.8.8.8"), 24, 56)
      )
    ).toThrowError("opt_must_be_last_additional");
  });
});
