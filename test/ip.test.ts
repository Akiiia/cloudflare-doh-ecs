import {
  clientIpFromSingleHeader,
  clientIpFromXff,
  isGlobalUnicast,
  parseIp,
  subnetForEcs
} from "../src/ip";

describe("IP and X-Forwarded-For handling", () => {
  it("parses IPv4, IPv6, embedded IPv4 and ports", () => {
    expect(parseIp("203.1.2.3")?.family).toBe(1);
    expect(parseIp("2001:4860:4860::8888")?.bytes).toHaveLength(16);
    expect(parseIp("::ffff:8.8.8.8")).toEqual({
      family: 1,
      bytes: Uint8Array.of(8, 8, 8, 8)
    });
    expect(clientIpFromXff("1.1.1.1, 203.1.2.3:443")?.bytes).toEqual(
      Uint8Array.of(1, 1, 1, 1)
    );
    expect(clientIpFromXff("bad, [2001:4860:4860::8888]:443")?.family).toBe(2);
  });

  it("uses the leftmost globally routable XFF address", () => {
    expect(clientIpFromXff("1.1.1.1, invalid, 8.8.4.4")?.bytes).toEqual(
      Uint8Array.of(1, 1, 1, 1)
    );
    expect(clientIpFromXff("10.0.0.1, 8.8.4.4")?.bytes).toEqual(
      Uint8Array.of(8, 8, 4, 4)
    );
    expect(clientIpFromXff("unknown, bad")).toBeNull();
    expect(clientIpFromXff(null)).toBeNull();
    expect(clientIpFromXff("x".repeat(4097))).toBeNull();
  });

  it("reads one globally routable IP from a direct client header", () => {
    expect(clientIpFromSingleHeader(" 8.8.4.123 ")?.bytes).toEqual(
      Uint8Array.of(8, 8, 4, 123)
    );
    expect(clientIpFromSingleHeader("2001:4860:4860::8888")?.family).toBe(2);
    expect(clientIpFromSingleHeader("10.0.0.1")).toBeNull();
    expect(clientIpFromSingleHeader("1.1.1.1, 8.8.4.4")).toBeNull();
    expect(clientIpFromSingleHeader(null)).toBeNull();
  });

  it.each([
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.168.1.1",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "ff02::1"
  ])("rejects non-global address %s", (value) => {
    const parsed = parseIp(value);
    expect(parsed === null || isGlobalUnicast(parsed)).toBe(false);
  });

  it("masks IPv4 and IPv6 host bits", () => {
    const ipv4 = subnetForEcs(parseIp("8.8.4.123"), 24, 56);
    expect(ipv4?.network).toEqual(Uint8Array.of(8, 8, 4, 0));
    const ipv6 = subnetForEcs(parseIp("2001:4860:1234:56ff::1"), 24, 57);
    expect(ipv6?.prefixLength).toBe(57);
    expect(ipv6?.network.slice(0, 8)).toEqual(
      Uint8Array.of(0x20, 0x01, 0x48, 0x60, 0x12, 0x34, 0x56, 0x80)
    );
    expect(subnetForEcs(parseIp("10.0.0.1"), 24, 56)).toBeNull();
  });

  it("rejects malformed IP strings", () => {
    expect(parseIp("01.2.3.4")).toBeNull();
    expect(parseIp("256.2.3.4")).toBeNull();
    expect(parseIp("2001::1::2")).toBeNull();
    expect(parseIp("2001:db8:1")).toBeNull();
    expect(parseIp("fe80::1%eth0")).toBeNull();
  });
});
