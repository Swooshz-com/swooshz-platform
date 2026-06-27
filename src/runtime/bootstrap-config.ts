export type PlatformNodeBootstrapErrorCode =
  | "invalid_config"
  | "database_client_failed"
  | "dependency_composition_failed"
  | "server_start_failed"
  | "server_stop_failed"
  | "already_started";

export class PlatformNodeBootstrapError extends Error {
  readonly code: PlatformNodeBootstrapErrorCode;
  readonly publicMessage = "Platform node bootstrap could not be completed.";

  constructor(code: PlatformNodeBootstrapErrorCode) {
    super("Platform node bootstrap could not be completed.");
    this.name = "PlatformNodeBootstrapError";
    this.code = code;
  }
}
