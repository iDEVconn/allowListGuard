import { parseIpAllowlist } from "../ip-matcher.js";

describe("parseIpAllowlist", () => {
  it("returns null (not enforced) for unset or blank", () => {
    expect(parseIpAllowlist(undefined)).toBeNull();
    expect(parseIpAllowlist(" , ")).toBeNull();
    expect(parseIpAllowlist([])).toBeNull();
  });

  it("matches exact IPs and CIDRs, rejects others", () => {
    const m = parseIpAllowlist("203.0.113.5, 10.0.0.0/8, 2001:db8::/32")!;
    expect(m("203.0.113.5")).toBe(true);
    expect(m("10.4.5.6")).toBe(true);
    expect(m("2001:db8::1")).toBe(true);
    expect(m("203.0.113.6")).toBe(false);
    expect(m("2001:db9::1")).toBe(false);
    expect(m(undefined)).toBe(false);
    expect(m("not-an-ip")).toBe(false);
  });

  it("accepts an array", () => {
    const m = parseIpAllowlist(["203.0.113.5", "198.51.100.0/24"])!;
    expect(m("198.51.100.200")).toBe(true);
  });

  it("always allows loopback once a list is set", () => {
    const m = parseIpAllowlist("203.0.113.5")!;
    expect(m("127.0.0.1")).toBe(true);
    expect(m("::1")).toBe(true);
  });

  it("unwraps IPv4-mapped IPv6 addresses", () => {
    const m = parseIpAllowlist("203.0.113.0/24")!;
    expect(m("::ffff:203.0.113.9")).toBe(true);
    expect(m("::ffff:198.51.100.9")).toBe(false);
  });

  it("never matches via a %zone suffix, and rejects one in an entry", () => {
    const m = parseIpAllowlist("203.0.113.5")!;
    expect(m("::1%lo")).toBe(false);
    expect(m("fe80::1%eth0")).toBe(false);
    expect(() => parseIpAllowlist("fe80::1%eth0")).toThrow(/invalid IP\/CIDR/);
  });

  it("throws on a malformed entry, naming the option", () => {
    expect(() => parseIpAllowlist("1.2.3.4, banana", "protected")).toThrow(
      /protected: invalid IP\/CIDR "banana"/,
    );
    expect(() => parseIpAllowlist("1.2.3.0/33")).toThrow(/invalid/);
    expect(() => parseIpAllowlist("1.2.3.0/8/8")).toThrow(/invalid/);
    expect(() => parseIpAllowlist("1.2.3.4/")).toThrow(/invalid/);
  });
});
