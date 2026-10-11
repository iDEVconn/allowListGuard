export const IP_ALLOWLIST_OPTIONS = Symbol("IP_ALLOWLIST_OPTIONS");

export interface IpAllowlistOptions {
  /**
   * Allowlist for protected (non-public) routes: comma-separated string or
   * array of IPs/CIDRs. Unset/blank = not enforced.
   */
  protected?: string | readonly string[];
  /**
   * Allowlist for public ("open") routes, i.e. routes carrying the metadata key
   * below. Unset/blank = not enforced.
   */
  public?: string | readonly string[];
  /**
   * Metadata key that marks a route as public. Defaults to `'isPublic'`, the
   * key used by the common `@Public()` decorator (`SetMetadata('isPublic', true)`).
   */
  publicMetadataKey?: string;
  /** Called once per distinct blocked IP (bounded). Defaults to a Nest Logger warning. */
  onBlocked?: (ip: string | undefined) => void;
}
