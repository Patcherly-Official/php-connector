#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * `patcherly` CLI — PHP connector OAuth onboarding (Phase-4).
 *
 * Subcommands:
 *   login        Run the device-authorization flow and save the token bundle.
 *   logout       Revoke the current token and delete the local credential file.
 *   status       Print tenant/target/scope/expiry of the current token.
 *   refresh      Force a refresh-token rotation.
 *   heartbeat    Cheap liveness ping: signed GET /v1/targets/connector-status. Wires
 *                into cron / systemd-timer so paired CLIs that don't run
 *                every day still keep their OAuth chain alive — the ping
 *                auto-rotates the access token (24h TTL) and refresh token
 *                (30-day TTL) on every call, and the server-side bearer
 *                validator bumps `targets.last_connected_at` so the dashboard
 *                "Connector is healthy" onboarding step stays green.
 *                Recommended cron:
 *                    0 6 * * *  /usr/bin/php /path/to/patcherly_cli.php heartbeat
 *                Exits 0 on success, 2 if not paired, 1 on HTTP / network
 *                failure (so cron emits the mail you want to see).
 *   send-test    Post a synthetic test event to /errors/ingest-test. To
 *                protect your real metrics and notifications, the API only
 *                accepts these synthetic events while the per-target **Test
 *                Mode** window is open. Open it in your Patcherly dashboard
 *                first (Targets → click your target → **Test Mode** toggle →
 *                a 30-minute window opens), then run `send-test` from this
 *                host. The CLI auto-preflights `/v1/targets/connector-status` and
 *                prints the dashboard URL if Test Mode is off, so a doomed
 *                POST is never sent. While Test Mode is on, the server
 *                stamps the event as ``is_test_sample=true`` so it never
 *                pollutes real metrics or fires customer notifications.
 *                Pass `--no-preflight` to skip the check (useful for tests).
 *
 * Configuration:
 *   --api-base / PATCHERLY_API_BASE   (default: https://api.patcherly.com)
 *   --client-id / PATCHERLY_CLIENT_ID (default: patcherly-connector-php)
 *
 * Run: `php patcherly_cli.php login`
 */

require_once __DIR__ . '/credential_store.php';
require_once __DIR__ . '/oauth_client.php';
require_once __DIR__ . '/lib/api_paths.php';
require_once __DIR__ . '/connector_version.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "patcherly_cli.php is meant to be run from the command line.\n");
    exit(1);
}

function patcherly_cli_parse_args(array $argv): array
{
    $cmd = 'help';
    $opts = [
        'api-base'     => getenv('PATCHERLY_API_BASE') ?: 'https://api.patcherly.com',
        'client-id'    => getenv('PATCHERLY_CLIENT_ID') ?: 'patcherly-connector-php',
        'json'         => false,
        // Skip the GET /v1/targets/connector-status preflight that gates send-test
        // on the per-target Test Mode window. Tests asserting the server-
        // side 403 test_window_closed contract pass --no-preflight to
        // bypass this check.
        'no-preflight' => false,
    ];
    for ($i = 1; $i < count($argv); $i++) {
        $a = $argv[$i];
        if (strpos($a, '--') === 0) {
            $eq = strpos($a, '=');
            if ($eq !== false) {
                $key = substr($a, 2, $eq - 2);
                $val = substr($a, $eq + 1);
                $opts[$key] = $val;
            } else {
                $key = substr($a, 2);
                if (isset($argv[$i + 1]) && strpos($argv[$i + 1], '--') !== 0) {
                    $opts[$key] = $argv[++$i];
                } else {
                    $opts[$key] = true;
                }
            }
        } elseif (in_array($a, ['login', 'logout', 'status', 'refresh', 'heartbeat', 'send-test', 'help'], true)) {
            $cmd = $a;
        }
    }
    $opts['cmd'] = $cmd;
    return $opts;
}

/**
 * @return list<string>
 */
function patcherly_cli_sign_headers(array $creds, string $method, string $path, string $body): array
{
    $ts = (string) time();
    $secret = (string) ($creds['hmac_secret'] ?? '');
    $sig = hash_hmac('sha256', strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $body, $secret);
    $headers = [
        'Authorization: Bearer ' . (string) ($creds['access_token'] ?? ''),
        'X-Patcherly-Timestamp: ' . $ts,
        'X-Patcherly-Signature: ' . $sig,
        'Content-Type: application/json',
    ];
    if (!empty($creds['hmac_secret_id'])) {
        $headers[] = 'X-Patcherly-Hmac-Kid: ' . (string) $creds['hmac_secret_id'];
    }
    return $headers;
}

function patcherly_cli_upload_context_after_pairing(array $opts, array $bundle): void
{
    if (empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
        return;
    }
    $contextData = [
        'runtime' => 'php',
        'version' => PHP_VERSION,
        'sapi' => PHP_SAPI,
        'platform' => PHP_OS,
        'cwd' => getcwd() ?: '',
        'framework' => ['detected' => 'none'],
        'collected_at' => gmdate('c'),
        'patcherly_connector_version' => PATCHERLY_CONNECTOR_VERSION,
    ];
    $payload = json_encode([
        'context_type' => 'php',
        'context_data' => $contextData,
        'server_context' => ['platform' => $contextData['platform'], 'runtime' => $contextData['runtime']],
    ]);
    if (!is_string($payload)) {
        return;
    }
    $path = PatcherlyApiPaths::NAMED_CONTEXT_UPLOAD;
    $url = rtrim((string) $opts['api-base'], '/') . $path;
    $ch = curl_init($url);
    if ($ch === false) {
        return;
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => array_merge(
            patcherly_cli_sign_headers($bundle, 'POST', $path, $payload),
            ['User-Agent: patcherly-connector-php/login']
        ),
        CURLOPT_TIMEOUT => 15,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

function patcherly_cli_login(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    fwrite(STDERR, "Requesting device code from {$opts['api-base']} ...\n");
    $dc = patcherly_oauth_request_device_code($opts['api-base'], $opts['client-id']);
    if ($opts['json']) {
        fwrite(STDOUT, json_encode($dc, JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(
            STDERR,
            "\nOpen this URL in your browser:\n  {$dc['verification_uri_complete']}\n\n" .
            "or visit {$dc['verification_uri']} and enter:\n  {$dc['user_code']}\n\n" .
            "Waiting for approval (this code expires in {$dc['expires_in']}s) ...\n"
        );
    }
    $bundle = patcherly_oauth_poll_for_token(
        $opts['api-base'],
        $opts['client-id'],
        $dc['device_code'],
        (int) ($dc['interval'] ?? 5),
        (int) ($dc['expires_in'] ?? 900)
    );
    $store->save($bundle);
    patcherly_cli_upload_context_after_pairing($opts, $bundle);
    if ($opts['json']) {
        $safe = $bundle;
        $safe['access_token'] = '<redacted>';
        $safe['refresh_token'] = isset($bundle['refresh_token']) ? '<redacted>' : null;
        $safe['hmac_secret'] = '<redacted>';
        fwrite(STDOUT, json_encode($safe, JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(
            STDERR,
            "\nLogin successful. Bound to target_id=" . ($bundle['target_id'] ?? 'unknown') .
            " tenant_id=" . ($bundle['tenant_id'] ?? 'unknown') . "\n" .
            'Credentials saved to ' . $store->getFilePath() . "\n"
        );
    }
}

function patcherly_cli_logout(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $creds = $store->load();
    if ($creds !== null && (!empty($creds['access_token']) || !empty($creds['refresh_token']))) {
        try {
            patcherly_oauth_revoke_token(
                $opts['api-base'],
                $opts['client-id'],
                (string) ($creds['refresh_token'] ?? $creds['access_token'])
            );
        } catch (Throwable $e) {
            fwrite(STDERR, 'Warning: revoke failed: ' . $e->getMessage() . "\n");
        }
    }
    $store->clear();
    fwrite(STDERR, "Logged out. Local credentials cleared.\n");
}

function patcherly_cli_status(): void
{
    $store = new PatcherlyCredentialStore();
    $creds = $store->load();
    if ($creds === null) {
        fwrite(STDERR, "Not logged in. Run `patcherly login` first.\n");
        exit(2);
    }
    $out = [
        'target_id'         => $creds['target_id'] ?? null,
        'tenant_id'         => $creds['tenant_id'] ?? null,
        'scope'             => $creds['scope'] ?? null,
        'expires_at'        => $creds['expires_at'] ?? null,
        'expired'           => $store->isExpired($creds, 0),
        'has_refresh_token' => !empty($creds['refresh_token']),
        'file'              => $store->getFilePath(),
    ];
    fwrite(STDOUT, json_encode($out, JSON_PRETTY_PRINT) . "\n");
}

function patcherly_cli_refresh(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $fresh = patcherly_oauth_ensure_fresh_token($opts['api-base'], $opts['client-id'], $store);
    fwrite(STDERR, "Refreshed. Now valid until " . ($fresh['expires_at'] ?? 'unknown') . "\n");
}

/**
 * Cheap liveness ping that keeps the OAuth chain and target alive.
 *
 * Performs a single signed `GET /v1/targets/connector-status` after running the
 * bundle through `patcherly_oauth_ensure_fresh_token`. That single call:
 *
 *   1. Rotates the access token when it's within the 30s refresh window
 *      (default 24h TTL on the access token, 30-day TTL on the refresh
 *      token). Because we call this regularly from cron, the refresh chain
 *      is rotated long before its 30-day TTL can age out, and the operator
 *      never has to manually re-pair.
 *   2. Bumps `targets.last_connected_at` via the server-side bearer
 *      validator, so the dashboard `connector_health_status` stays at
 *      `healthy` for the "Connector is healthy" onboarding step.
 *
 * Designed to be wired into a daily cron / systemd-timer so paired CLIs
 * that are otherwise quiet don't quietly age out. Exits 0 on success, 2
 * if no local bundle, 1 on HTTP / network failure.
 */
function patcherly_cli_heartbeat(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $creds = $store->load();
    if ($creds === null || empty($creds['access_token'])) {
        fwrite(STDERR, "patcherly: not paired. Run `patcherly login` first.\n");
        exit(2);
    }
    try {
        $fresh = patcherly_oauth_ensure_fresh_token($opts['api-base'], $opts['client-id'], $store);
    } catch (Throwable $e) {
        fwrite(STDERR, "patcherly: heartbeat could not refresh OAuth bundle: " . $e->getMessage() . "\n");
        fwrite(STDERR, "Run `patcherly login` to re-pair.\n");
        exit(1);
    }
    if (!is_array($fresh) || empty($fresh['access_token'])) {
        fwrite(STDERR, "patcherly: no access token after refresh; run `patcherly login`.\n");
        exit(2);
    }
    $url = rtrim((string) $opts['api-base'], '/') . PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_STATUS;
    $ch  = curl_init($url);
    if ($ch === false) {
        fwrite(STDERR, "patcherly: cURL init failed for $url\n");
        exit(1);
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPGET        => true,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . (string) $fresh['access_token'],
            'User-Agent: patcherly-connector-php/heartbeat',
        ],
        CURLOPT_TIMEOUT        => 10,
    ]);
    $body   = curl_exec($ch);
    $err    = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false) {
        fwrite(STDERR, "patcherly: heartbeat transport error: $err\n");
        exit(1);
    }
    if ($status !== 200) {
        fwrite(STDERR, "patcherly: heartbeat failed (HTTP $status): " . ((string) $body !== '' ? (string) $body : 'no body') . "\n");
        exit(1);
    }
    if (!empty($opts['json'])) {
        $payload = json_decode((string) $body, true);
        if (!is_array($payload)) {
            $payload = [];
        }
        fwrite(STDOUT, json_encode([
            'ok'                => true,
            'target_id'         => $payload['target_id']         ?? null,
            'tenant_id'         => $payload['tenant_id']         ?? null,
            'oauth_status'      => $payload['oauth_status']      ?? null,
            'last_connected_at' => $payload['last_connected_at'] ?? null,
        ], JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(STDERR, "patcherly: heartbeat OK - target alive.\n");
    }
}

/**
 * Read Test Mode state from GET /v1/targets/connector-status (Bearer-only, no HMAC).
 *
 * Returns an associative array:
 *   ['enabled' => bool, 'expires_at' => ?string, 'dashboard_url' => ?string,
 *    'reachable' => bool]
 *
 * `reachable=false` means the preflight itself failed (network error, 5xx,
 * malformed response); the caller falls back to attempting the POST and lets
 * the server's structured 403 handle the closed-window case. Mirrors the
 * WordPress plugin's Status panel pattern: read the per-target Test Mode flag
 * from the cheap status endpoint so the operator gets the dashboard URL
 * before any synthetic-traffic POST is attempted.
 */
function patcherly_cli_preflight_test_mode(string $apiBase, string $accessToken): array
{
    $url = rtrim($apiBase, '/') . PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_STATUS;
    $ch  = curl_init($url);
    if ($ch === false) {
        return ['enabled' => false, 'expires_at' => null, 'dashboard_url' => null, 'reachable' => false];
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPGET        => true,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $accessToken,
            'User-Agent: patcherly-connector-php/preflight-test-mode',
        ],
        CURLOPT_TIMEOUT        => 8,
    ]);
    $body   = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false || $status >= 400) {
        return ['enabled' => false, 'expires_at' => null, 'dashboard_url' => null, 'reachable' => false];
    }
    $data = json_decode((string) $body, true);
    if (!is_array($data)) {
        return ['enabled' => false, 'expires_at' => null, 'dashboard_url' => null, 'reachable' => false];
    }
    $expires   = $data['ingest_test_expires_at'] ?? null;
    $dashboard = $data['dashboard_url'] ?? null;
    return [
        'enabled'       => !empty($data['ingest_test_enabled']),
        'expires_at'    => is_string($expires) ? $expires : null,
        'dashboard_url' => is_string($dashboard) ? $dashboard : null,
        'reachable'     => true,
    ];
}

function patcherly_cli_emit_test_window_closed(array $opts, ?string $dashboardUrl, ?string $expiresHint): void
{
    $msg = 'Test mode window is not open for this target. Enable test mode from your '
        . 'Patcherly dashboard (Targets → Test Mode toggle), then retry.';
    if (!empty($opts['json'])) {
        $out = ['error' => 'test_window_closed', 'message' => $msg];
        if ($dashboardUrl !== null && $dashboardUrl !== '') {
            $out['dashboard_url'] = $dashboardUrl;
        }
        if ($expiresHint !== null && $expiresHint !== '') {
            $out['expires_at'] = $expiresHint;
        }
        fwrite(STDOUT, json_encode($out, JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(STDERR, $msg . "\n");
        if ($dashboardUrl !== null && $dashboardUrl !== '') {
            fwrite(STDERR, "Enable it at: $dashboardUrl\n");
        }
    }
}

/**
 * POST a synthetic test event to /errors/ingest-test using the stored OAuth bearer.
 *
 * Auto-preflights the per-target Test Mode window via
 * GET /v1/targets/connector-status (bearer-only, no HMAC) and short-circuits with the
 * dashboard URL when the window is closed, so a doomed POST is never sent.
 * Pass `--no-preflight` to skip and rely on the server's 403 fallback.
 */
function patcherly_cli_send_test(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $fresh = patcherly_oauth_ensure_fresh_token($opts['api-base'], $opts['client-id'], $store);
    if (!is_array($fresh) || empty($fresh['access_token'])) {
        fwrite(STDERR, "patcherly: no access token after refresh; run `patcherly login`.\n");
        exit(2);
    }
    if (empty($opts['no-preflight'])) {
        $pre = patcherly_cli_preflight_test_mode((string) $opts['api-base'], (string) $fresh['access_token']);
        if ($pre['reachable'] && !$pre['enabled']) {
            patcherly_cli_emit_test_window_closed($opts, $pre['dashboard_url'], $pre['expires_at']);
            exit(3);
        }
    }
    $url = rtrim((string) $opts['api-base'], '/') . PatcherlyApiPaths::NAMED_ERRORS_INGEST_TEST;
    $ch  = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('cURL init failed for ' . $url);
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => '',
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . (string) $fresh['access_token'],
            'Content-Type: application/json',
            'User-Agent: patcherly-connector-php/send-test',
        ],
        CURLOPT_TIMEOUT        => 15,
    ]);
    $body   = curl_exec($ch);
    $err    = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false) {
        fwrite(STDERR, "patcherly: send-test failed (transport): $err\n");
        exit(1);
    }
    $payload = json_decode((string) $body, true);
    if (!is_array($payload)) {
        $payload = ['raw' => (string) $body];
    }
    if ($status === 200 || $status === 201) {
        if (!empty($opts['json'])) {
            fwrite(STDOUT, json_encode($payload, JSON_PRETTY_PRINT) . "\n");
        } else {
            $id = $payload['id'] ?? null;
            fwrite(
                STDERR,
                'Test event accepted' . ($id ? " (id={$id})" : '') .
                ". Open your Patcherly dashboard → Errors to see it.\n"
            );
        }
        return;
    }
    $detail = $payload['detail'] ?? null;
    if ($status === 403 && is_array($detail) && ($detail['code'] ?? '') === 'test_window_closed') {
        $msg  = (string) ($detail['message'] ?? 'Test mode window is not open for this target.');
        $link = (string) ($detail['dashboard_url'] ?? '');
        if (!empty($opts['json'])) {
            fwrite(STDOUT, json_encode([
                'error'         => 'test_window_closed',
                'message'       => $msg,
                'dashboard_url' => $link,
            ], JSON_PRETTY_PRINT) . "\n");
        } else {
            fwrite(STDERR, $msg . "\n");
            if ($link !== '') {
                fwrite(STDERR, "Enable it at: $link\n");
            }
        }
        exit(3);
    }
    if (!empty($opts['json'])) {
        fwrite(STDOUT, json_encode([
            'error'  => 'http_error',
            'status' => $status,
            'detail' => $detail ?? $body,
        ], JSON_PRETTY_PRINT) . "\n");
    } else {
        $human = is_string($detail) ? $detail : (string) $body;
        fwrite(STDERR, "patcherly: send-test failed (HTTP $status): " . ($human !== '' ? $human : 'no body') . "\n");
    }
    exit(1);
}

$opts = patcherly_cli_parse_args($argv);
try {
    switch ($opts['cmd']) {
        case 'login':
            patcherly_cli_login($opts);
            break;
        case 'logout':
            patcherly_cli_logout($opts);
            break;
        case 'status':
            patcherly_cli_status();
            break;
        case 'refresh':
            patcherly_cli_refresh($opts);
            break;
        case 'heartbeat':
            patcherly_cli_heartbeat($opts);
            break;
        case 'send-test':
            patcherly_cli_send_test($opts);
            break;
        case 'help':
        default:
            fwrite(STDOUT, "Usage: php patcherly_cli.php <login|logout|status|refresh|heartbeat|send-test> [--api-base URL] [--client-id ID] [--json] [--no-preflight]\n");
    }
} catch (Throwable $e) {
    fwrite(STDERR, "patcherly: " . $e->getMessage() . "\n");
    exit(1);
}
