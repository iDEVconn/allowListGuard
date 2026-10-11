import { Controller, Get, Injectable, Module, SetMetadata, type CanActivate } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { ExpressAdapter, type NestExpressApplication } from "@nestjs/platform-express";
import { FastifyAdapter, type NestFastifyApplication } from "@nestjs/platform-fastify";
import { Test } from "@nestjs/testing";
import { IpAllowlistModule } from "../ip-allowlist.module.js";
import { SkipIpAllowlist } from "../skip-ip-allowlist.decorator.js";

const calls: string[] = [];

@Injectable()
class LaterGuard implements CanActivate {
  canActivate(): boolean {
    calls.push("later");
    return true;
  }
}

@Controller()
class AppController {
  @Get("private")
  priv() {
    return { ok: true };
  }
  @SetMetadata("isPublic", true)
  @Get("open")
  open() {
    return { ok: true };
  }
  @SkipIpAllowlist()
  @Get("hook")
  hook() {
    return { ok: true };
  }
}

@Module({ providers: [{ provide: APP_GUARD, useClass: LaterGuard }] })
class LaterModule {}

// Mirrors a real app: IpAllowlistModule is imported before the module that owns the auth guard.
@Module({
  imports: [
    IpAllowlistModule.forRoot({ protected: "203.0.113.5", public: "198.51.100.0/24" }),
    LaterModule,
  ],
  controllers: [AppController],
})
class TestAppModule {}

beforeEach(() => {
  calls.length = 0;
});

describe("IpAllowlistModule on Fastify", () => {
  it("rejects before later global guards and honours public/skip", async () => {
    const mod = await Test.createTestingModule({ imports: [TestAppModule] }).compile();
    const app = mod.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    const get = (url: string, remoteAddress: string) =>
      app.inject({ method: "GET", url, remoteAddress }).then((r) => r.statusCode);

    expect(await get("/private", "8.8.8.8")).toBe(403);
    expect(calls).toEqual([]);
    expect(await get("/private", "203.0.113.5")).toBe(200);
    expect(calls).toEqual(["later"]);

    expect(await get("/open", "8.8.8.8")).toBe(403);
    expect(await get("/open", "198.51.100.9")).toBe(200);
    expect(await get("/hook", "8.8.8.8")).toBe(200);
    await app.close();
  });
});

describe("IpAllowlistModule on Express", () => {
  it("uses req.ip (behind trust proxy) over real HTTP", async () => {
    const mod = await Test.createTestingModule({ imports: [TestAppModule] }).compile();
    const app = mod.createNestApplication<NestExpressApplication>(new ExpressAdapter());
    app.set("trust proxy", true);
    await app.listen(0, "127.0.0.1");
    const base = await app.getUrl();
    const get = (path: string, xff: string) =>
      fetch(`${base}${path}`, { headers: { "x-forwarded-for": xff } }).then((r) => r.status);

    expect(await get("/private", "8.8.8.8")).toBe(403);
    expect(await get("/private", "203.0.113.5")).toBe(200);
    expect(await get("/open", "198.51.100.9")).toBe(200);
    expect(await get("/hook", "8.8.8.8")).toBe(200);
    await app.close();
  });
});
