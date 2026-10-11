import { ForbiddenException, SetMetadata, type ExecutionContext } from "@nestjs/common";
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

  it("ignores non-http contexts", () => {
    const g = make({ protected: "203.0.113.5" });
    expect(g.canActivate(ctx(ProtectedController, "8.8.8.8", "rpc"))).toBe(true);
  });

  it("reports each distinct blocked IP once", () => {
    const seen: (string | undefined)[] = [];
    const g = make({ protected: "203.0.113.5", onBlocked: (ip) => seen.push(ip) });
    for (let i = 0; i < 3; i++) {
      expect(() => g.canActivate(ctx(ProtectedController, "8.8.8.8"))).toThrow();
    }
    expect(() => g.canActivate(ctx(ProtectedController, "1.1.1.1"))).toThrow();
    expect(seen).toEqual(["8.8.8.8", "1.1.1.1"]);
  });

  it("fails at construction on a malformed list", () => {
    expect(() => make({ protected: "nope" })).toThrow(/protected/);
  });
});
