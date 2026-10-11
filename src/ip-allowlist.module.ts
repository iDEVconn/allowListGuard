import { Module, type DynamicModule } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { IpAllowlistGuard } from "./ip-allowlist.guard.js";
import { IP_ALLOWLIST_OPTIONS, type IpAllowlistOptions } from "./options.js";

@Module({})
export class IpAllowlistModule {
  /**
   * Registers the guard globally (APP_GUARD). Import this module BEFORE the
   * module that registers your auth guard so a blocked IP is rejected before
   * any authentication work.
   */
  static forRoot(options: IpAllowlistOptions = {}): DynamicModule {
    return {
      module: IpAllowlistModule,
      providers: [
        { provide: IP_ALLOWLIST_OPTIONS, useValue: options },
        { provide: APP_GUARD, useClass: IpAllowlistGuard },
      ],
    };
  }
}
