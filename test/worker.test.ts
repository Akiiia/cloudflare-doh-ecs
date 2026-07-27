import { readU16, toArrayBuffer } from "../src/binary";
import { parseDnsMessage } from "../src/dns";
import { handleRequest } from "../src/index";
import { resetRuleCacheForTest } from "../src/rules";
import { envWithRules, makeQuery, makeResponseFromQuery, MemoryKv } from "./helpers";

function base64Url(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("DoH worker", () => {
  beforeEach(() => {
    resetRuleCacheForTest();
    vi.restoreAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  it("routes domestic POST to AliDNS and injects ECS", async () => {
    const { env } = await envWithRules();
    let destination = "";
    let forwarded = new Uint8Array();
    let redirect: RequestRedirect | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destination = String(input);
        forwarded = new Uint8Array(init?.body as ArrayBuffer);
        redirect = init?.redirect;
        return new Response(toArrayBuffer(makeResponseFromQuery(forwarded)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("www.qq.com", 1);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "198.51.100.1, 8.8.4.123"
        },
        body: toArrayBuffer(query)
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(destination).toBe("https://dns.alidns.com/dns-query");
    expect(redirect).toBe("manual");
    expect(parseDnsMessage(forwarded).opt).not.toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("routes foreign GET to Google and supports base64url", async () => {
    const { env } = await envWithRules();
    const destinations: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destinations.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 65);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: { "x-forwarded-for": "2001:4860:4860::8888" }
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(destinations).toEqual(["https://dns.google/dns-query"]);
  });

  it("falls back to CF-Connecting-IP when XFF has no public address", async () => {
    const { env } = await envWithRules();
    let forwarded = new Uint8Array();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        forwarded = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(forwarded)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 66);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: {
          "x-forwarded-for": "10.0.0.1, 192.168.1.1",
          "cf-connecting-ip": "8.8.4.123"
        }
      }),
      env
    );
    const opt = parseDnsMessage(forwarded).opt;
    const start = opt?.rdataStart ?? 0;
    expect(response.status).toBe(200);
    expect(Array.from(forwarded.slice(start, start + 11))).toEqual([
      0, 8, 0, 7, 0, 1, 24, 0, 8, 8, 4
    ]);
  });

  it("returns DNS SERVFAIL after exhausting the domestic group", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        calls.push(String(input));
        throw new TypeError("request to https://private.example/secret failed");
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0x000f).toBe(2);
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenNthCalledWith(1, "doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "network_error",
      detail: "TypeError: request to [url] failed"
    });
  });

  it("falls back from Google to Cloudflare without crossing groups", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        if (calls.length === 1) return new Response(null, { status: 503 });
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "global",
      role: "primary",
      reason: "http_status_503"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("falls back from AliDNS when it returns DNS SERVFAIL", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        const dnsBody = makeResponseFromQuery(body);
        if (calls.length === 1) dnsBody[3] = ((dnsBody[3] ?? 0) & 0xf0) | 2;
        return new Response(toArrayBuffer(dnsBody), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "dns_servfail"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("returns FORMERR for malformed DNS and empty HTTP errors for bad transport", async () => {
    const { env } = await envWithRules();
    const malformed = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(Uint8Array.of(1, 2, 3))
      }),
      env
    );
    expect(malformed.headers.get("content-type")).toBe("application/dns-message");
    expect(readU16(new Uint8Array(await malformed.arrayBuffer()), 2) & 0xf).toBe(1);

    const badGet = await handleRequest(
      new Request("https://worker.example/doh?dns=***"),
      env
    );
    expect(badGet.status).toBe(400);
    expect(await badGet.text()).toBe("");

    const wrongPath = await handleRequest(new Request("https://worker.example/"), env);
    expect(wrongPath.status).toBe(404);
    expect(await wrongPath.text()).toBe("");

    const wrongType = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}"
      }),
      env
    );
    expect(wrongType.status).toBe(415);
  });

  it("rejects invalid upstream response identity", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const body = makeResponseFromQuery(new Uint8Array(init?.body as ArrayBuffer));
        body[0] = 0;
        body[1] = 1;
        return new Response(toArrayBuffer(body), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0xf).toBe(2);
  });

  it("returns SERVFAIL without leaking invalid environment configuration", async () => {
    const env = {
      RULES_KV: new MemoryKv().asBinding(),
      GLOBAL_DOH_URL: "http://127.0.0.1/dns-query"
    };
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(2);
  });
});
