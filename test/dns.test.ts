import { readU16, writeU16 } from "../src/binary";
import {
  buildDnsError,
  DnsFormatError,
  parseDnsMessage,
  parseName,
  validateUpstreamResponse
} from "../src/dns";
import { encodeName, makeQuery, makeResponseFromQuery } from "./helpers";

describe("DNS wire parser", () => {
  it("parses and lowercases a normal question", () => {
    const parsed = parseDnsMessage(makeQuery("WWW.QQ.COM", 65));
    expect(parsed.question.name.ruleName).toBe("www.qq.com");
    expect(parsed.question.type).toBe(65);
    expect(parsed.question.class).toBe(1);
  });

  it("supports a valid compression pointer", () => {
    const base = encodeName("qq.com");
    const data = new Uint8Array(base.length + 2);
    data.set(base);
    data[base.length] = 0xc0;
    data[base.length + 1] = 0;
    const name = parseName(data, base.length);
    expect(name.ruleName).toBe("qq.com");
    expect(name.nextOffset).toBe(base.length + 2);
  });

  it.each([
    ["pointer loop", Uint8Array.of(0xc0, 0x00), "pointer_loop"],
    ["out of bounds", Uint8Array.of(0xc0, 0x20), "pointer_out_of_bounds"],
    ["reserved label type", Uint8Array.of(0x40, 0), "invalid_label_type"],
    ["truncated label", Uint8Array.of(3, 97), "invalid_label_length"]
  ])("rejects %s", (_name, bytes, code) => {
    expect(() => parseName(bytes, 0)).toThrowError(code);
  });

  it("rejects multiple questions and trailing bytes", () => {
    const multiple = makeQuery();
    writeU16(multiple, 4, 2);
    expect(() => parseDnsMessage(multiple)).toThrow(DnsFormatError);

    const valid = makeQuery();
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    expect(() => parseDnsMessage(trailing)).toThrowError("trailing_bytes");
  });

  it("validates upstream identity and question", () => {
    const query = makeQuery();
    const parsed = parseDnsMessage(query);
    const response = makeResponseFromQuery(query);
    expect(validateUpstreamResponse(response, parsed).id).toBe(0x1234);

    const wrongId = response.slice();
    writeU16(wrongId, 0, 7);
    expect(() => validateUpstreamResponse(wrongId, parsed)).toThrowError(
      "transaction_id_mismatch"
    );

    const notResponse = query.slice();
    expect(() => validateUpstreamResponse(notResponse, parsed)).toThrowError(
      "upstream_not_a_response"
    );
  });

  it("builds canonical FORMERR and SERVFAIL responses", () => {
    const query = makeQuery("www.qq.com", 28);
    const parsed = parseDnsMessage(query);
    const formerr = buildDnsError(query, 1, parsed.question);
    const failure = buildDnsError(query, 2);
    expect(readU16(formerr, 0)).toBe(0x1234);
    expect(readU16(formerr, 2) & 0x800f).toBe(0x8001);
    expect(readU16(formerr, 4)).toBe(1);
    expect(readU16(failure, 2) & 0x000f).toBe(2);
    expect(readU16(failure, 4)).toBe(0);
  });
});
