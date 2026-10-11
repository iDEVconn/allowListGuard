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
  /**
   * Always allow loopback once a list is set. Default `true`. Set `false` if a
   * reverse proxy runs on the same host and `req.ip` could be its loopback address.
   */
  allowLoopback?: boolean;
  /**
   * Called on EVERY blocked request (feed your metrics/alerting from here).
   * The default Nest Logger warning is rate-limited per IP; this hook is not.
   */
  onBlocked?: (ip: string | undefined) => void;
}
