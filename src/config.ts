import { isGlobalUnicast, parseIp } from "./ip";
import type { Env } from "./types";

const DEFAULT_DOMESTIC = "https://dns.alidns.com/dns-query";
const DEFAULT_DOMESTIC_FALLBACK = "https://doh.pub/dns-query";
const DEFAULT_GLOBAL = "https://dns.google/dns-query";
const DEFAULT_GLOBAL_FALLBACK = "https://cloudflare-dns.com/dns-query";
const DEFAULT_PATH = "/doh";

export interface WorkerConfig {
  path: string;
  domesticUrls: readonly [string, string];
  globalUrls: readonly [string, string];
}


function validatePath(value: string | undefined): string {
  const path = value ?? DEFAULT_PATH;
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("?") ||
    path.includes("#") ||
    path.includes("\\") ||
    path.length > 256
  ) {
    throw new Error("invalid_doh_path");
  }
  return path;
}

function validateUpstream(value: string | undefined, fallback: string): string {
  let url: URL;
  try {
    url = new URL(value ?? fallback);
  } catch {
    throw new Error("invalid_upstream_url");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.search !== ""
  ) {
    throw new Error("invalid_upstream_url");
  }

  let hostname = url.hostname;
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  const literal = parseIp(hostname);
  if (literal !== null && !isGlobalUnicast(literal)) {
    throw new Error("private_upstream_literal");
  }
  return url.toString();
}

export function readConfig(env: Env): WorkerConfig {
  return {
    path: validatePath(env.DOH_PATH),
    domesticUrls: [
      validateUpstream(env.DOMESTIC_DOH_URL, DEFAULT_DOMESTIC),
      validateUpstream(env.DOMESTIC_FALLBACK_DOH_URL, DEFAULT_DOMESTIC_FALLBACK)
    ],
    globalUrls: [
      validateUpstream(env.GLOBAL_DOH_URL, DEFAULT_GLOBAL),
      validateUpstream(env.GLOBAL_FALLBACK_DOH_URL, DEFAULT_GLOBAL_FALLBACK)
    ]
  };
}
