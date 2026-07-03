<?php
/** AUTO-GENERATED from config/api_paths.yaml — do not edit by hand. */
declare(strict_types=1);

final class PatcherlyApiPaths
{
    public const VERSION_PREFIX = "";
    public const APP_PREFIX = "/v1";
    public const AUTH_PREFIX = "/auth";

    public const NAMED_CONTEXT_UPLOAD = "/v1/context/upload";
    public const NAMED_ERRORS_INGEST = "/v1/errors/ingest";
    public const NAMED_ERRORS_INGEST_TEST = "/v1/errors/ingest-test";
    public const NAMED_ERRORS_LIST = "/v1/errors";
    public const NAMED_OAUTH_DEVICE = "/v1/oauth/device";
    public const NAMED_OAUTH_REVOKE = "/v1/oauth/revoke";
    public const NAMED_OAUTH_TOKEN = "/v1/oauth/token";
    public const NAMED_OAUTH_TOKEN_STATUS = "/v1/oauth/token/status";
    public const NAMED_PUBLIC_CONFIG = "/v1/public/config";
    public const NAMED_TARGETS_CONNECTOR_DISCONNECT = "/v1/targets/connector-disconnect";
    public const NAMED_TARGETS_CONNECTOR_STATUS = "/v1/targets/connector-status";
    public const CONNECTOR_CONTRACT_FILE_CONTENT = "/api/file-content";
    public const CONNECTOR_CONTRACT_RESCUE_POLL = "/api/rescue/poll";

    public static function appPath(string ...$segments): string
    {
        $base = rtrim(self::VERSION_PREFIX . self::APP_PREFIX, '/');
        $parts = array_values(array_filter(array_map(static fn ($s) => trim($s, '/'), $segments)));
        if ($parts === []) {
            return $base;
        }
        return $base . '/' . implode('/', $parts);
    }
}
