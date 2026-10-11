import Fastify from "fastify";
import { buildTrustProxy, parseIpAllowlist, restrictRoutesToAllowlist } from "../fastify/index.js";

async function ipSeenBy(
  trusted: string | undefined,
  remoteAddress: string,
  xff: string,
): Promise<string> {
  const app = Fastify({ trustProxy: buildTrustProxy(trusted) });
  app.get("/ip", async (req) => req.ip);
  const res = await app.inject({ url: "/ip", remoteAddress, headers: { "x-forwarded-for": xff } });
  await app.close();
  return res.body;
}

describe("buildTrustProxy", () => {
  it("without trustedProxies trusts the immediate hop", async () => {
    expect(await ipSeenBy(undefined, "10.0.0.2", "8.8.8.8")).toBe("8.8.8.8");
  });

  it("honours X-Forwarded-For only from a listed proxy", async () => {
    expect(await ipSeenBy("10.0.0.0/24", "10.0.0.2", "8.8.8.8")).toBe("8.8.8.8");
  });

  it("ignores a forged header from a direct client", async () => {
    expect(await ipSeenBy("10.0.0.0/24", "198.51.100.9", "203.0.113.5")).toBe("198.51.100.9");
  });

  it("only ever trusts one hop", async () => {
    expect(await ipSeenBy("10.0.0.0/24", "10.0.0.2", "203.0.113.5, 8.8.8.8")).toBe("8.8.8.8");
  });
});

describe("restrictRoutesToAllowlist", () => {
  async function status(url: string, remoteAddress: string): Promise<number> {
    const app = Fastify();
    restrictRoutesToAllowlist(app, parseIpAllowlist("203.0.113.5")!, "/api/docs");
    app.get("/api/docs", async () => "docs");
    app.get("/api/docs/*", async () => "static");
    app.get("/api/other", async () => "other");
    const res = await app.inject({ url, remoteAddress });
    await app.close();
    return res.statusCode;
  }

  it("blocks non-allowlisted IPs, including percent-encoded and dot-segment paths", async () => {
    expect(await status("/api/docs", "8.8.8.8")).toBe(403);
    expect(await status("/api/docs/static/x.js", "8.8.8.8")).toBe(403);
    expect(await status("/api/%64ocs", "8.8.8.8")).toBe(403);
    expect(await status("/api/docs/../docs", "8.8.8.8")).toBe(403);
  });

  it("lets allowlisted IPs through and leaves other routes alone", async () => {
    expect(await status("/api/docs", "203.0.113.5")).toBe(200);
    expect(await status("/api/other", "8.8.8.8")).toBe(200);
  });

  it("denied rejects listed IPs even with no allowlist, and wins over allowed", async () => {
    async function st(url: string, ip: string, allowed: string | undefined, denied: string) {
      const app = Fastify();
      restrictRoutesToAllowlist(
        app,
        parseIpAllowlist(allowed),
        "/api/docs",
        parseIpAllowlist(denied, "deny", { allowLoopback: false }),
      );
      app.get("/api/docs", async () => "docs");
      app.get("/api/other", async () => "other");
      const res = await app.inject({ url, remoteAddress: ip });
      await app.close();
      return res.statusCode;
    }
    expect(await st("/api/docs", "198.51.100.9", undefined, "198.51.100.9")).toBe(403);
    expect(await st("/api/docs", "8.8.8.8", undefined, "198.51.100.9")).toBe(200);
    expect(await st("/api/docs", "203.0.113.5", "203.0.113.0/24", "203.0.113.5")).toBe(403);
    expect(await st("/api/other", "198.51.100.9", undefined, "198.51.100.9")).toBe(200);
  });
});
