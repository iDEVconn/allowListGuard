import { BlockList, isIP } from "node:net";

export type IpMatcher = (ip: string | undefined) => boolean;

export interface ParseOptions {
  /**
   * Always allow loopback (`127.0.0.0/8`, `::1`) once a list is set. Default `true`
   * (local dev, health probes). Set `false` when a reverse proxy runs on the SAME
   * host and `req.ip` may fall back to its loopback address — otherwise a proxy
   * without trust-proxy configured makes every client look like 127.0.0.1.
   */
  allowLoopback?: boolean;
}

const LOOPBACK = ["127.0.0.0/8", "::1"] as const;

/** `::ffff:1.2.3.4` (what a dual-stack socket reports for IPv4 peers) → `1.2.3.4`. */
export function normalizeIp(ip: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  return mapped?.[1] ?? ip;
}

function addEntry(list: BlockList, raw: string): void {
  const [addr = "", prefix, ...rest] = raw.split("/");
  const family = isIP(addr);
  // A zone id (`fe80::1%eth0`) is accepted by isIP but ignored by BlockList.check,
  // so `::1%x` would match loopback — never allow one in a list or as a client IP.
  if (!family || addr.includes("%") || rest.length > 0) {
    throw new Error(`invalid IP/CIDR "${raw}"`);
  }
  const type = family === 4 ? "ipv4" : "ipv6";
  if (prefix === undefined) {
    list.addAddress(addr, type);
    return;
  }
  const bits = Number(prefix);
  const max = family === 4 ? 32 : 128;
  if (!/^\d+$/.test(prefix) || bits > max) throw new Error(`invalid IP/CIDR "${raw}"`);
  list.addSubnet(addr, bits, type);
}

/**
 * Builds a matcher from a comma-separated string or an array of IPs/CIDRs
 * (IPv4 + IPv6). Returns `null` when the list is unset/blank (= not enforced).
 * Loopback is part of an enforced list by default (see `allowLoopback`). Throws on a malformed entry — a typo must not silently turn
 * into "everyone allowed" or "everyone blocked". `label` names the option in
 * the error message.
 */
export function parseIpAllowlist(
  value: string | readonly string[] | undefined,
  label = "allowlist",
  { allowLoopback = true }: ParseOptions = {},
): IpMatcher | null {
  const raw = typeof value === "string" ? value.split(",") : (value ?? []);
  const entries = raw.map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) return null;

  const list = new BlockList();
  for (const entry of [...(allowLoopback ? LOOPBACK : []), ...entries]) {
    try {
      addEntry(list, entry);
    } catch (err) {
      throw new Error(`${label}: ${(err as Error).message}`, { cause: err });
    }
  }
  return (ip) => {
    if (!ip || ip.includes("%")) return false;
    const addr = normalizeIp(ip);
    const family = isIP(addr);
    if (!family) return false;
    return list.check(addr, family === 4 ? "ipv4" : "ipv6");
  };
}
