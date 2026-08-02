<?php
/**
 * OAuth 2.0 Device Authorization Grant client (RFC 8628) — PHP connector.
 *
 * Pairs with server/app/api/routers/oauth.py. Uses cURL (already a hard dep
 * of the PHP agent's API client) and matches the same request/response shape
 * as the Node.js / Python connectors.
 *
 * Public API:
 *   - patcherly_oauth_request_device_code($apiBase, $clientId, $scopes = [])
 *   - patcherly_oauth_poll_for_token($apiBase, $clientId, $deviceCode, $interval = 5, $maxWait = 900)
 *   - patcherly_oauth_refresh_token($apiBase, $clientId, $refreshToken)
 *   - patcherly_oauth_revoke_token($apiBase, $clientId, $token)
 *   - patcherly_oauth_ensure_fresh_token($apiBase, $clientId, $store)  // high-level
 */

declare(strict_types=1);

require_once __DIR__ . '/credential_store.php';
require_once __DIR__ . '/lib/api_paths.php';

if (!function_exists('patcherly_oauth_post_form')) {
    /**
     * @param array<string,string> $fields
     * @return array{0:int,1:array<string,mixed>}
     */
    function patcherly_oauth_post_form(string $apiBase, string $pathSuffix, array $fields): array
    {
        $url = rtrim($apiBase, '/') . $pathSuffix;
        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('cURL init failed for ' . $url);
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
                'User-Agent: patcherly-connector-php/1.46',
            ],
            CURLOPT_TIMEOUT => 30,
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($body === false) {
            throw new RuntimeException("cURL request failed: $err");
        }
        $parsed = json_decode((string) $body, true);
        if (!is_array($parsed)) {
            $parsed = ['raw' => (string) $body];
        }
        return [$status, $parsed];
    }
}

if (!function_exists('patcherly_oauth_add_expires_at')) {
    /** @param array<string,mixed> $bundle */
    function patcherly_oauth_add_expires_at(array $bundle): array
    {
        if (isset($bundle['expires_in']) && is_numeric($bundle['expires_in'])) {
            $bundle['expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + (int) $bundle['expires_in']);
        }
        return $bundle;
    }
}

if (!function_exists('patcherly_oauth_request_device_code')) {
    /** @param string[] $scopes */
    function patcherly_oauth_request_device_code(string $apiBase, string $clientId, array $scopes = []): array
    {
        if ($scopes === []) {
            $scopes = ['ingest', 'patch', 'audit', 'files'];
        }
        $fields = [
            'client_id' => $clientId,
            'scope'     => implode(' ', $scopes),
        ];
        [$status, $body] = patcherly_oauth_post_form($apiBase, PatcherlyApiPaths::NAMED_OAUTH_DEVICE, $fields);
        if ($status !== 200) {
            throw new RuntimeException("requestDeviceCode failed (HTTP $status): " . json_encode($body));
        }
        return $body;
    }
}

if (!function_exists('patcherly_oauth_poll_for_token')) {
    function patcherly_oauth_poll_for_token(
        string $apiBase,
        string $clientId,
        string $deviceCode,
        int $interval = 5,
        int $maxWaitSeconds = 900
    ): array {
        $interval = max(1, $interval);
        $start = time();
        while ((time() - $start) < $maxWaitSeconds) {
            $fields = [
                'grant_type'  => 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code' => $deviceCode,
                'client_id'   => $clientId,
            ];
            [$status, $body] = patcherly_oauth_post_form($apiBase, PatcherlyApiPaths::NAMED_OAUTH_TOKEN, $fields);
            if ($status === 200) {
                return patcherly_oauth_add_expires_at($body);
            }
            $detail = $body['detail'] ?? '';
            if ($detail === 'authorization_pending') {
                sleep($interval);
                continue;
            }
            if ($detail === 'slow_down') {
                $interval += 5;
                sleep($interval);
                continue;
            }
            throw new RuntimeException("Token exchange failed (HTTP $status): " . json_encode($body));
        }
        throw new RuntimeException('Device authorization timed out');
    }
}

if (!defined('PATCHERLY_OAUTH_LOCAL_REFRESH_RETRIES')) {
    // Keep in sync with settings_schema connector_local_refresh_retries default.
    define('PATCHERLY_OAUTH_LOCAL_REFRESH_RETRIES', 3);
}

if (!function_exists('patcherly_oauth_classify_refresh_failure')) {
    /** @param array<string,mixed>|null $body */
    function patcherly_oauth_classify_refresh_failure(?int $status = null, ?array $body = null, ?string $message = null): string
    {
        if ($status !== null) {
            $detail = '';
            if (is_array($body)) {
                $detail = strtolower((string) ($body['detail'] ?? $body['error'] ?? $body['error_description'] ?? ''));
            }
            if ($status === 400 || $status === 401 || strpos($detail, 'invalid_grant') !== false || strpos($detail, 'invalid_token') !== false || strpos($detail, 'revoked') !== false) {
                return 'auth_death';
            }
            if ($status >= 500 || $status === 0 || $status === 408 || $status === 429) {
                return 'transient';
            }
            if ($status >= 400 && $status < 500) {
                return 'auth_death';
            }
            return 'transient';
        }
        $msg = strtolower((string) $message);
        foreach (['timeout', 'timed out', 'curl', 'connection', 'network', 'refused', 'reset'] as $needle) {
            if (strpos($msg, $needle) !== false) {
                return 'transient';
            }
        }
        if (strpos($msg, 'invalid_grant') !== false || strpos($msg, 'invalid_token') !== false) {
            return 'auth_death';
        }
        if (preg_match('/http\s+(\d{3})/i', $msg, $m)) {
            return patcherly_oauth_classify_refresh_failure((int) $m[1], null, null);
        }
        return 'transient';
    }
}

if (!function_exists('patcherly_oauth_refresh_token')) {
    function patcherly_oauth_refresh_token(string $apiBase, string $clientId, string $refreshToken): array
    {
        $fields = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $clientId,
        ];
        try {
            [$status, $body] = patcherly_oauth_post_form($apiBase, PatcherlyApiPaths::NAMED_OAUTH_TOKEN, $fields);
        } catch (\Throwable $e) {
            $ex = new RuntimeException('Refresh failed (network): ' . $e->getMessage(), 0, $e);
            $ex->refreshClass = 'transient';
            throw $ex;
        }
        if ($status !== 200) {
            $ex = new RuntimeException('Refresh failed (HTTP ' . $status . '): ' . json_encode($body));
            $ex->refreshClass = patcherly_oauth_classify_refresh_failure($status, $body, null);
            throw $ex;
        }
        return patcherly_oauth_add_expires_at($body);
    }
}

if (!function_exists('patcherly_oauth_revoke_token')) {
    function patcherly_oauth_revoke_token(string $apiBase, string $clientId, string $token, ?string $trigger = null): void
    {
        $fields = ['token' => $token, 'client_id' => $clientId];
        if (is_string($trigger) && $trigger !== '') {
            $fields['trigger'] = $trigger;
        }
        patcherly_oauth_post_form($apiBase, PatcherlyApiPaths::NAMED_OAUTH_REVOKE, $fields);
    }
}

if (!function_exists('patcherly_oauth_signal_disconnect_best_effort')) {
    /**
     * Best-effort revoke. Default trigger=auth_failure; logout passes logout.
     */
    function patcherly_oauth_signal_disconnect_best_effort(
        string $apiBase,
        string $clientId,
        ?string $refreshToken = null,
        ?string $accessToken = null,
        string $trigger = 'auth_failure'
    ): void {
        $token = (is_string($refreshToken) && $refreshToken !== '')
            ? $refreshToken
            : ((is_string($accessToken) && $accessToken !== '') ? $accessToken : null);
        if ($token === null) {
            return;
        }
        try {
            patcherly_oauth_revoke_token($apiBase, $clientId, $token, $trigger);
        } catch (\Throwable $e) {
            // best effort
        }
    }
}

if (!function_exists('patcherly_oauth_signal_soft_hold_best_effort')) {
    function patcherly_oauth_signal_soft_hold_best_effort(
        string $apiBase,
        ?string $accessToken,
        ?string $hmacSecret,
        ?string $hmacKid = null
    ): void {
        patcherly_oauth_signal_reconnect_phase_best_effort(
            $apiBase,
            $accessToken,
            $hmacSecret,
            $hmacKid,
            'soft_hold',
            'transient'
        );
    }
}

if (!function_exists('patcherly_oauth_signal_reconnect_recovered_best_effort')) {
    function patcherly_oauth_signal_reconnect_recovered_best_effort(
        string $apiBase,
        ?string $accessToken,
        ?string $hmacSecret,
        ?string $hmacKid = null
    ): void {
        patcherly_oauth_signal_reconnect_phase_best_effort(
            $apiBase,
            $accessToken,
            $hmacSecret,
            $hmacKid,
            'recovered',
            null
        );
    }
}

if (!function_exists('patcherly_oauth_signal_reconnect_phase_best_effort')) {
    function patcherly_oauth_signal_reconnect_phase_best_effort(
        string $apiBase,
        ?string $accessToken,
        ?string $hmacSecret,
        ?string $hmacKid,
        string $phase,
        ?string $lastErrorClass
    ): void {
        if ($apiBase === '' || !is_string($accessToken) || $accessToken === '' || !is_string($hmacSecret) || $hmacSecret === '') {
            return;
        }
        try {
            $path = PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_RECONNECT_SIGNAL;
            $payload = ['phase' => $phase];
            if (is_string($lastErrorClass) && $lastErrorClass !== '') {
                $payload['last_error_class'] = $lastErrorClass;
            }
            $body = json_encode($payload);
            if ($body === false) {
                return;
            }
            $ts = (string) time();
            $canonical = "POST\n{$path}\n{$ts}\n" . $body;
            $sig = hash_hmac('sha256', $canonical, $hmacSecret);
            $url = rtrim($apiBase, '/') . $path;
            $ch = curl_init($url);
            if ($ch === false) {
                return;
            }
            $headers = [
                'Content-Type: application/json',
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken,
                'X-Patcherly-Timestamp: ' . $ts,
                'X-Patcherly-Signature: ' . $sig,
                'User-Agent: patcherly-connector-php/1.46',
            ];
            if (is_string($hmacKid) && $hmacKid !== '') {
                $headers[] = 'X-Patcherly-Hmac-Kid: ' . $hmacKid;
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_TIMEOUT => 15,
            ]);
            curl_exec($ch);
            curl_close($ch);
        } catch (\Throwable $e) {
            // best effort
        }
    }
}

if (!function_exists('patcherly_oauth_ensure_fresh_token')) {
    function patcherly_oauth_ensure_fresh_token(
        string $apiBase,
        string $clientId,
        PatcherlyCredentialStore $store
    ): array {
        $creds = $store->load();
        if ($creds === null) {
            throw new RuntimeException('No credentials. Run `patcherly login` to authorize this connector.');
        }
        if (!$store->isExpired($creds)) {
            return $creds;
        }
        $refresh = $creds['refresh_token'] ?? null;
        if (!is_string($refresh) || $refresh === '') {
            patcherly_oauth_signal_disconnect_best_effort(
                $apiBase,
                $clientId,
                null,
                is_string($creds['access_token'] ?? null) ? $creds['access_token'] : null,
                'auth_failure'
            );
            throw new RuntimeException('Access token expired and no refresh_token available.');
        }
        $last = null;
        $max = (int) PATCHERLY_OAUTH_LOCAL_REFRESH_RETRIES;
        for ($attempt = 1; $attempt <= $max; $attempt++) {
            try {
                $fresh = patcherly_oauth_refresh_token($apiBase, $clientId, $refresh);
                $store->save($fresh);
                return $fresh;
            } catch (\Throwable $e) {
                $last = $e;
                $klass = isset($e->refreshClass) && is_string($e->refreshClass)
                    ? $e->refreshClass
                    : patcherly_oauth_classify_refresh_failure(null, null, $e->getMessage());
                if ($klass === 'auth_death') {
                    patcherly_oauth_signal_disconnect_best_effort(
                        $apiBase,
                        $clientId,
                        $refresh,
                        is_string($creds['access_token'] ?? null) ? $creds['access_token'] : null,
                        'auth_failure'
                    );
                    throw $e;
                }
                if ($attempt < $max) {
                    usleep((int) (500000 * $attempt));
                }
            }
        }
        patcherly_oauth_signal_soft_hold_best_effort(
            $apiBase,
            is_string($creds['access_token'] ?? null) ? $creds['access_token'] : null,
            is_string($creds['hmac_secret'] ?? null) ? $creds['hmac_secret'] : null,
            is_string($creds['hmac_secret_id'] ?? null) ? $creds['hmac_secret_id'] : null
        );
        if ($last instanceof \Throwable) {
            throw $last;
        }
        throw new RuntimeException('Refresh failed after transient retries');
    }
}
