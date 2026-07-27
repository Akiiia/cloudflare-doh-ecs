import type { Env, RuleManifest } from "./types";

export const RULES_URL =
  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt";
export const ACTIVE_MANIFEST_KEY = "rules:active";
export const MAX_RULE_BYTES = 8 * 1024 * 1024;
const MIN_RULE_BYTES = 32;
const CACHE_RECHECK_MS = 15 * 60 * 1000;
const encoder = new TextEncoder();

export interface RuleIndex {
  plainStart: number;
  plainEnd: number;
  fullStart: number;
  fullEnd: number;
  regexpStart: number;
}

export interface LoadedRules {
  version: string;
  data: Uint8Array;
  index: RuleIndex;
  checkedAt: number;
}

export type RuleUpdateResult = "updated" | "unchanged";

let cachedRules: LoadedRules | null = null;
let rulesLoadPromise: Promise<LoadedRules | null> | null = null;
let bootstrapPromise: Promise<RuleUpdateResult> | null = null;

function startsWithAscii(
  data: Uint8Array,
  start: number,
  end: number,
  text: string
): boolean {
  if (end - start < text.length) return false;
  for (let i = 0; i < text.length; i += 1) {
    if ((data[start + i] ?? -1) !== text.charCodeAt(i)) return false;
  }
  return true;
}

function compareRanges(
  data: Uint8Array,
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number
): number {
  const length = Math.min(leftEnd - leftStart, rightEnd - rightStart);
  for (let i = 0; i < length; i += 1) {
    const left = data[leftStart + i] ?? 0;
    const right = data[rightStart + i] ?? 0;
    if (left !== right) return left < right ? -1 : 1;
  }
  const leftLength = leftEnd - leftStart;
  const rightLength = rightEnd - rightStart;
  return leftLength === rightLength ? 0 : leftLength < rightLength ? -1 : 1;
}

function looksLikeHtml(data: Uint8Array): boolean {
  const limit = Math.min(data.length, 256);
  let text = "";
  for (let i = 0; i < limit; i += 1) {
    let value = data[i] ?? 0;
    if (value >= 65 && value <= 90) value += 32;
    text += String.fromCharCode(value);
  }
  const trimmed = text.trimStart();
  return trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html");
}

export function inspectRuleData(data: Uint8Array): RuleIndex {
  if (data.length < MIN_RULE_BYTES || data.length > MAX_RULE_BYTES) {
    throw new Error("rules_size_invalid");
  }
  if (looksLikeHtml(data)) throw new Error("rules_html_response");

  let plainEnd = data.length;
  let fullStart = data.length;
  let fullEnd = data.length;
  let regexpStart = data.length;
  let region = 0;
  let lineStart = 0;
  let previousStart = -1;
  let previousEnd = -1;
  let previousRegion = -1;
  let plainCount = 0;

  while (lineStart < data.length) {
    let rawEnd = lineStart;
    while (rawEnd < data.length && data[rawEnd] !== 10) rawEnd += 1;
    let lineEnd = rawEnd;
    if (lineEnd > lineStart && data[lineEnd - 1] === 13) lineEnd -= 1;
    if (lineEnd <= lineStart) throw new Error("rules_empty_line");

    for (let i = lineStart; i < lineEnd; i += 1) {
      const value = data[i] ?? 0;
      if (value === 0 || value < 0x20 || value > 0x7e) {
        throw new Error("rules_non_ascii");
      }
    }

    const isFull = startsWithAscii(data, lineStart, lineEnd, "full:");
    const isRegexp = startsWithAscii(data, lineStart, lineEnd, "regexp:");
    const lineRegion = isRegexp ? 2 : isFull ? 1 : 0;
    if (lineRegion < region) throw new Error("rules_region_order");

    if (lineRegion > region) {
      if (lineRegion === 1) {
        plainEnd = lineStart;
        fullStart = lineStart;
      } else {
        regexpStart = lineStart;
        if (region === 0) {
          plainEnd = lineStart;
          fullStart = lineStart;
        }
        fullEnd = lineStart;
      }
      region = lineRegion;
    }

    const prefixLength = lineRegion === 0 ? 0 : lineRegion === 1 ? 5 : 7;
    if (lineEnd - lineStart <= prefixLength) {
      throw new Error("rules_empty_pattern");
    }
    if (lineRegion < 2) {
      for (let i = lineStart + prefixLength; i < lineEnd; i += 1) {
        const value = data[i] ?? 0;
        if (value >= 65 && value <= 90) throw new Error("rules_uppercase_domain");
      }
      if (previousRegion === lineRegion && previousStart >= 0) {
        const comparison = compareRanges(
          data,
          previousStart + prefixLength,
          previousEnd,
          lineStart + prefixLength,
          lineEnd
        );
        if (comparison >= 0) throw new Error("rules_not_strictly_sorted");
      }
    }

    if (lineRegion === 0) plainCount += 1;
    previousStart = lineStart;
    previousEnd = lineEnd;
    previousRegion = lineRegion;
    lineStart = rawEnd < data.length ? rawEnd + 1 : data.length;
  }

  if (plainCount === 0) throw new Error("rules_missing_plain_region");
  if (region === 0) {
    plainEnd = data.length;
    fullStart = data.length;
    fullEnd = data.length;
  } else if (region === 1) {
    fullEnd = data.length;
  }

  return {
    plainStart: 0,
    plainEnd,
    fullStart,
    fullEnd,
    regexpStart
  };
}

function lineStartAt(data: Uint8Array, regionStart: number, position: number): number {
  let start = position;
  while (start > regionStart && data[start - 1] !== 10) start -= 1;
  return start;
}

function lineEndAt(data: Uint8Array, regionEnd: number, start: number): number {
  let end = start;
  while (end < regionEnd && data[end] !== 10) end += 1;
  if (end > start && data[end - 1] === 13) return end - 1;
  return end;
}

function nextLineAt(data: Uint8Array, regionEnd: number, logicalEnd: number): number {
  let next = logicalEnd;
  if (next < regionEnd && data[next] === 13) next += 1;
  if (next < regionEnd && data[next] === 10) next += 1;
  return next;
}

function compareLineWithTarget(
  data: Uint8Array,
  lineStart: number,
  lineEnd: number,
  prefixLength: number,
  target: Uint8Array,
  targetStart: number
): number {
  let left = lineStart + prefixLength;
  let right = targetStart;
  while (left < lineEnd && right < target.length) {
    const a = data[left] ?? 0;
    const b = target[right] ?? 0;
    if (a !== b) return a < b ? -1 : 1;
    left += 1;
    right += 1;
  }
  const leftRemaining = lineEnd - left;
  const rightRemaining = target.length - right;
  return leftRemaining === rightRemaining ? 0 : leftRemaining < rightRemaining ? -1 : 1;
}

function binarySearchRegion(
  data: Uint8Array,
  regionStart: number,
  regionEnd: number,
  prefixLength: number,
  target: Uint8Array,
  targetStart: number
): boolean {
  let low = regionStart;
  let high = regionEnd;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    const start = lineStartAt(data, regionStart, middle);
    const end = lineEndAt(data, regionEnd, start);
    const comparison = compareLineWithTarget(
      data,
      start,
      end,
      prefixLength,
      target,
      targetStart
    );
    if (comparison === 0) return true;
    if (comparison < 0) {
      const next = nextLineAt(data, regionEnd, end);
      if (next <= low) return false;
      low = next;
    } else {
      high = start;
    }
  }
  return false;
}

export function isDomesticDomain(
  rules: Pick<LoadedRules, "data" | "index">,
  qname: string
): boolean {
  const target = encoder.encode(qname);
  const { data, index } = rules;
  if (
    binarySearchRegion(
      data,
      index.fullStart,
      index.fullEnd,
      5,
      target,
      0
    )
  ) {
    return true;
  }

  let suffixStart = 0;
  while (suffixStart < target.length) {
    if (
      binarySearchRegion(
        data,
        index.plainStart,
        index.plainEnd,
        0,
        target,
        suffixStart
      )
    ) {
      return true;
    }
    let dot = suffixStart;
    while (dot < target.length && target[dot] !== 46) dot += 1;
    if (dot >= target.length) break;
    suffixStart = dot + 1;
  }
  return false;
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
  let hex = "";
  for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function readManifest(env: Env): Promise<RuleManifest | null> {
  const manifest = await env.RULES_KV.get<RuleManifest>(ACTIVE_MANIFEST_KEY, "json");
  if (
    manifest === null ||
    typeof manifest.active !== "string" ||
    (manifest.previous !== null && typeof manifest.previous !== "string") ||
    typeof manifest.sha256 !== "string" ||
    !Number.isInteger(manifest.size) ||
    manifest.size < MIN_RULE_BYTES ||
    manifest.size > MAX_RULE_BYTES
  ) {
    return null;
  }
  return manifest;
}

async function loadVersion(
  env: Env,
  version: string,
  expectedSize: number | null,
  now: number
): Promise<LoadedRules | null> {
  const buffer = await env.RULES_KV.get(version, "arrayBuffer");
  if (buffer === null || (expectedSize !== null && buffer.byteLength !== expectedSize)) {
    return null;
  }
  try {
    const data = new Uint8Array(buffer);
    const index = inspectRuleData(data);
    return { version, data, index, checkedAt: now };
  } catch {
    return null;
  }
}

async function refreshRules(env: Env, now: number, force: boolean): Promise<LoadedRules | null> {
  if (!force && cachedRules !== null && now - cachedRules.checkedAt < CACHE_RECHECK_MS) {
    return cachedRules;
  }
  try {
    const manifest = await readManifest(env);
    if (manifest === null) {
      if (cachedRules !== null) cachedRules.checkedAt = now;
      return cachedRules;
    }
    if (cachedRules !== null && cachedRules.version === manifest.active) {
      cachedRules.checkedAt = now;
      return cachedRules;
    }
    const active = await loadVersion(env, manifest.active, manifest.size, now);
    if (active !== null) {
      cachedRules = active;
      return active;
    }
    if (manifest.previous !== null) {
      const previous = await loadVersion(env, manifest.previous, null, now);
      if (previous !== null) {
        cachedRules = previous;
        return previous;
      }
    }
    return cachedRules;
  } catch {
    return cachedRules;
  }
}

export async function getRules(
  env: Env,
  now = Date.now(),
  force = false
): Promise<LoadedRules | null> {
  if (rulesLoadPromise !== null) return rulesLoadPromise;
  rulesLoadPromise = refreshRules(env, now, force).finally(() => {
    rulesLoadPromise = null;
  });
  return rulesLoadPromise;
}

export async function updateRules(
  env: Env,
  fetcher: typeof fetch = fetch
): Promise<RuleUpdateResult> {
  const response = await fetcher(RULES_URL, {
    method: "GET",
    redirect: "manual",
    headers: {
      Accept: "text/plain, application/octet-stream;q=0.9"
    }
  });
  if (!response.ok) throw new Error("rules_download_status");
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.includes("text/html")) throw new Error("rules_download_html");
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isFinite(parsedLength) || parsedLength > MAX_RULE_BYTES) {
      throw new Error("rules_download_too_large");
    }
  }

  const buffer = await response.arrayBuffer();
  const data = new Uint8Array(buffer);
  inspectRuleData(data);
  const sha256 = await sha256Hex(buffer);
  const version = `rules:data:${sha256}`;
  const oldManifest = await readManifest(env);
  if (
    oldManifest !== null &&
    oldManifest.active === version &&
    oldManifest.size === buffer.byteLength
  ) {
    return "unchanged";
  }

  await env.RULES_KV.put(version, buffer);
  const stored = await env.RULES_KV.get(version, "arrayBuffer");
  if (
    stored === null ||
    stored.byteLength !== buffer.byteLength ||
    (await sha256Hex(stored)) !== sha256
  ) {
    throw new Error("rules_kv_verification_failed");
  }

  const previous =
    oldManifest === null
      ? null
      : oldManifest.active === version
        ? oldManifest.previous
        : oldManifest.active;
  const manifest: RuleManifest = {
    active: version,
    previous,
    sha256,
    size: buffer.byteLength,
    updatedAt: new Date().toISOString()
  };
  await env.RULES_KV.put(ACTIVE_MANIFEST_KEY, JSON.stringify(manifest));

  const obsolete = oldManifest?.previous;
  if (obsolete !== undefined && obsolete !== null && obsolete !== version && obsolete !== previous) {
    try {
      await env.RULES_KV.delete(obsolete);
    } catch {
      // 旧版本清理失败不影响已经完成的原子切换。
    }
  }
  cachedRules = {
    version,
    data,
    index: inspectRuleData(data),
    checkedAt: Date.now()
  };
  return "updated";
}

export async function ensureRules(env: Env): Promise<LoadedRules | null> {
  const current = await getRules(env);
  if (current !== null) return current;
  if (bootstrapPromise === null) {
    bootstrapPromise = updateRules(env).finally(() => {
      bootstrapPromise = null;
    });
  }
  try {
    await bootstrapPromise;
  } catch {
    return null;
  }
  return getRules(env, Date.now(), true);
}

export function resetRuleCacheForTest(): void {
  cachedRules = null;
  rulesLoadPromise = null;
  bootstrapPromise = null;
}
