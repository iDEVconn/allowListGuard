import { ForbiddenException, Logger, SetMetadata, type ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { IpAllowlistGuard } from "../ip-allowlist.guard.js";
import type { IpAllowlistOptions } from "../options.js";
import { SkipIpAllowlist } from "../skip-ip-allowlist.decorator.js";

const Public = () => SetMetadata("isPublic", true);

class ProtectedController {
  handler(): void {
    return undefined;
  }
}
class PublicController {
  @Public()
  handler(): void {
    return undefined;
  }
}
class WebhookController {
  @Public()
  @SkipIpAllowlist()
  handler(): void {
    return undefined;
  }
}

function ctx(
  cls: { new (): { handler: () => void } },
  ip: string | undefined,
  type = "http",
): ExecutionContext {
  return {
    getType: () => type,
    getHandler: () => cls.prototype.handler,
    getClass: () => cls,
    switchToHttp: () => ({ getRequest: () => ({ ip }) }),
  } as unknown as ExecutionContext;
}

const make = (options: IpAllowlistOptions = {}) => new IpAllowlistGuard(new Reflector(), options);

describe("IpAllowlistGuard", () => {
  it("allows everything when no list is configured", () => {
    const g = make();
    expect(g.canActivate(ctx(ProtectedController, "8.8.8.8"))).toBe(true);
    expect(g.canActivate(ctx(PublicController, "8.8.8.8"))).toBe(true);
  });

  it("enforces `protected` on non-public routes only", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(g.canActivate(ctx(ProtectedController, "203.0.113.5"))).toBe(true);
    expect(() => g.canActivate(ctx(ProtectedController, "8.8.8.8"))).toThrow(ForbiddenException);
    expect(g.canActivate(ctx(PublicController, "8.8.8.8"))).toBe(true);
  });

  it("enforces `public` on public routes only", () => {
    const g = make({ public: "198.51.100.0/24" });
    expect(g.canActivate(ctx(PublicController, "198.51.100.7"))).toBe(true);
    expect(() => g.canActivate(ctx(PublicController, "8.8.8.8"))).toThrow(ForbiddenException);
    expect(g.canActivate(ctx(ProtectedController, "8.8.8.8"))).toBe(true);
  });

  it("honours a custom publicMetadataKey", () => {
    class Custom {
      @SetMetadata("open", true)
      handler(): void {
        return undefined;
      }
    }
    const g = make({ public: "203.0.113.5", publicMetadataKey: "open" });
    expect(() => g.canActivate(ctx(Custom, "8.8.8.8"))).toThrow(ForbiddenException);
    // not the default key -> treated as protected, which has no list -> open
    expect(g.canActivate(ctx(PublicController, "8.8.8.8"))).toBe(true);
  });

  it("@SkipIpAllowlist exempts a route from both lists", () => {
    const g = make({ protected: "203.0.113.5", public: "203.0.113.5" });
    expect(g.canActivate(ctx(WebhookController, "8.8.8.8"))).toBe(true);
  });

  it("blocks a request with no resolvable IP when a list is enforced", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(() => g.canActivate(ctx(ProtectedController, undefined))).toThrow(ForbiddenException);
  });

  it("exempts only microservice (rpc) contexts", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(g.canActivate(ctx(ProtectedController, "8.8.8.8", "rpc"))).toBe(true);
  });

  it("fails closed for other non-http contexts (graphql, ws) when a list is enforced", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(() => g.canActivate(ctx(ProtectedController, "203.0.113.5", "graphql"))).toThrow(
      ForbiddenException,
    );
    expect(() => g.canActivate(ctx(ProtectedController, "203.0.113.5", "ws"))).toThrow(
      ForbiddenException,
    );
  });

  it("keeps public routes open when only `protected` is set (the two lists are independent)", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(g.canActivate(ctx(PublicController, "8.8.8.8"))).toBe(true);
  });

  it("allowLoopback: false stops loopback from bypassing the list", () => {
    expect(make({ protected: "203.0.113.5" }).canActivate(ctx(ProtectedController, "127.0.0.1"))).toBe(
      true,
    );
    const g = make({ protected: "203.0.113.5", allowLoopback: false });
    expect(() => g.canActivate(ctx(ProtectedController, "127.0.0.1"))).toThrow(ForbiddenException);
    expect(() => g.canActivate(ctx(ProtectedController, "::1"))).toThrow(ForbiddenException);
    expect(g.canActivate(ctx(ProtectedController, "203.0.113.5"))).toBe(true);
  });

  it("calls onBlocked for EVERY blocked request", () => {
    const seen: (string | undefined)[] = [];
    const g = make({ protected: "203.0.113.5", onBlocked: (ip) => seen.push(ip) });
    for (let i = 0; i < 3; i++) {
      expect(() => g.canActivate(ctx(ProtectedController, "8.8.8.8"))).toThrow();
    }
    expect(seen).toEqual(["8.8.8.8", "8.8.8.8", "8.8.8.8"]);
  });

  describe("default log line", () => {
    afterEach(() => {
      vi.restoreAllMocks();
      vi.useRealTimers();
    });

    it("is rate-limited per IP, and repeats after the window", () => {
      vi.useFakeTimers();
      const warn = vi.spyOn(Logger.prototype, "warn").mockImplementation(() => undefined);
      const g = make({ protected: "203.0.113.5" });
      const hit = (ip: string) => expect(() => g.canActivate(ctx(ProtectedController, ip))).toThrow();
      hit("8.8.8.8");
      hit("8.8.8.8");
      expect(warn).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(61_000);
      hit("8.8.8.8");
      expect(warn).toHaveBeenCalledTimes(2);
    });

    it("keeps logging after thousands of distinct IPs (an IP flood cannot mute it)", () => {
      const warn = vi.spyOn(Logger.prototype, "warn").mockImplementation(() => undefined);
      const g = make({ protected: "203.0.113.5" });
      for (let i = 0; i < 1500; i++) {
        const ip = `10.${(i >> 8) & 255}.${i & 255}.9`;
        expect(() => g.canActivate(ctx(ProtectedController, ip))).toThrow();
      }
      warn.mockClear();
      expect(() => g.canActivate(ctx(ProtectedController, "198.51.100.77"))).toThrow();
      expect(warn).toHaveBeenCalledTimes(1);
    });

    it("never echoes a malformed IP into the log", () => {
      const warn = vi.spyOn(Logger.prototype, "warn").mockImplementation(() => undefined);
      const g = make({ protected: "203.0.113.5" });
      expect(() => g.canActivate(ctx(ProtectedController, "evil\nINJECT"))).toThrow();
      expect(warn).toHaveBeenCalledWith("Blocked request from non-allowlisted IP invalid");
    });
  });

  it("fails at construction on a malformed list", () => {
    expect(() => make({ protected: "nope" })).toThrow(/protected/);
  });
});
