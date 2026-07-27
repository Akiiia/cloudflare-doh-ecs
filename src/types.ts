export interface Env {
  RULES_KV: KVNamespace;
  DOH_PATH?: string;
  DOMESTIC_DOH_URL?: string;
  DOMESTIC_FALLBACK_DOH_URL?: string;
  GLOBAL_DOH_URL?: string;
  GLOBAL_FALLBACK_DOH_URL?: string;
}

export interface RuleManifest {
  active: string;
  previous: string | null;
  sha256: string;
  size: number;
  updatedAt: string;
}
