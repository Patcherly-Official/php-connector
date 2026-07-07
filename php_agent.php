<?php
/**
 * PHP Agent for resource-constrained environments
 * Monitors log files for errors, sends error context to a central server,
 * applies fixes and rolls back changes if necessary.
 * 
 * This script simulates the behavior similar to connectors/python_agent.py
 * using PHP. It's designed to run in a resource-constrained environment.
 * 
 * Usage: php php_agent.php [poll_interval_in_seconds]
 */

// Default API URL for auto-discovery fallback (production; proxy only for legacy shared-host)
define('DEFAULT_API_URL', 'https://api.patcherly.com');
require_once __DIR__ . '/lib/ingest_severity.php';
require_once __DIR__ . '/lib/api_paths.php';

/**
 * True when the operator pinned the API host via SERVER_URL or PATCHERLY_API_BASE.
 */
function patcherly_agent_is_explicit_server_url(): bool {
    $server = getenv('SERVER_URL');
    $apiBase = getenv('PATCHERLY_API_BASE');
    return (is_string($server) && $server !== '') || (is_string($apiBase) && $apiBase !== '');
}

/**
 * Canonical API base for outbound calls (data plane + OAuth refresh).
 */
function patcherly_agent_configured_server_url(): string {
    $raw = getenv('SERVER_URL') ?: getenv('PATCHERLY_API_BASE') ?: DEFAULT_API_URL;
    return rtrim($raw, '/');
}
/**
 * Bumped automatically by setup/git-hooks/bump_version_from_branch.py (pre-commit) and the
 * update-release-latest.yml workflow so the value baked into every released tarball matches
 * the GitHub release tag. Reported to the API on every context upload.
 */
require_once __DIR__ . '/connector_version.php';

// Load .env file if it exists
function loadEnvFile() {
    $envFiles = [
        __DIR__ . '/.env',
        dirname(__DIR__) . '/.env',
        getcwd() . '/.env'
    ];
    foreach ($envFiles as $envFile) {
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line && substr($line, 0, 1) !== '#' && strpos($line, '=') !== false) {
                    list($key, $value) = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value);
                    // Remove quotes if present
                    if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                        (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                        $value = substr($value, 1, -1);
                    }
                    if ($key && !getenv($key)) {
                        putenv("$key=$value");
                    }
                }
            }
            break; // Only load first found .env file
        }
    }
}
loadEnvFile();

class PHPAgent {
    /**
     * v1.47 log-path policy: connector-side allow-list of root prefixes.
     * Mirrors a strict subset of server/app/core/log_path_policy.py.
     */
    private const ALLOWED_LOG_PATH_ROOTS = [
        '/var/log/', '/srv/', '/opt/', '/home/', '/tmp/', '/app/',
        'logs/', 'log/', 'storage/logs/', 'app/logs/',
    ];

    /**
     * Strict log-path validator. Throws RuntimeException on rejection so the
     * caller can decide to skip vs warn vs abort startup.
     *
     * Site-root single-basename inputs ("debug.log", "/_error_log.log") are
     * accepted when they resolve safely under the connector's working
     * directory. Mirrors the server-side ``./`` SITE_ROOT_TOKEN sentinel in
     * ``server/app/core/log_path_policy.py`` for shared-hosting / WP Engine
     * deployments where the operator can only see paths starting at the
     * application root.
     */
    public static function validateLogPath($path): void {
        if (!is_string($path)) throw new \RuntimeException('path is not a string');
        $stripped = trim($path);
        if ($stripped === '') throw new \RuntimeException('empty path');
        if (strpos($stripped, "\0") !== false) throw new \RuntimeException('NUL byte in path');
        $segs = explode('/', str_replace('\\', '/', $stripped));
        if (in_array('..', $segs, true)) throw new \RuntimeException("traversal segment ('..')");
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $stripped)) throw new \RuntimeException('stream wrapper not allowed');
        $base = basename($stripped);
        if ($base !== '' && $base[0] === '.') throw new \RuntimeException('dot-prefixed basename is not allowed');

        // Site-root single-basename short-circuit. Strip a single leading slash
        // and resolve under getcwd(); if the candidate stays inside CWD it
        // cannot escape by construction (no internal separators were allowed).
        $norm_input = ltrim(str_replace('\\', '/', $stripped), '/');
        $is_site_root_basename = ($norm_input !== '' && strpos($norm_input, '/') === false);
        if ($is_site_root_basename) {
            $cwd = getcwd();
            if ($cwd !== false && $cwd !== '') {
                $cwd_real = realpath($cwd);
                if ($cwd_real === false) $cwd_real = $cwd;
                $candidate = rtrim($cwd_real, '/\\') . DIRECTORY_SEPARATOR . $norm_input;
                $candidate_real = realpath($candidate);
                if ($candidate_real === false) $candidate_real = $candidate;
                $candidate_norm = str_replace('\\', '/', $candidate_real);
                $cwd_norm = rtrim(str_replace('\\', '/', $cwd_real), '/');
                if ($candidate_norm === $cwd_norm || strpos($candidate_norm, $cwd_norm . '/') === 0) {
                    return;
                }
            }
        }

        $resolved = realpath($stripped);
        if ($resolved === false) {
            // File may not exist yet — fall back to a structural normalization.
            $resolved = $stripped;
        }
        $norm = str_replace('\\', '/', $resolved);
        $ok = false;
        foreach (self::ALLOWED_LOG_PATH_ROOTS as $root) {
            if (strpos($norm, $root) === 0 || strpos(ltrim($norm, '/'), ltrim($root, '/')) === 0) {
                $ok = true;
                break;
            }
        }
        if (!$ok) throw new \RuntimeException("resolved path '{$resolved}' is outside the allow-list");
    }

    private $serverUrl;
    private $logFile = 'logs/error.log';
    /** @var string[] All server-provided log paths (preset + custom). */
    private $serverLogPaths = [];
    private $idsPath;
    private $tenantId = null;
    private $targetId = null;
    private $queuePath;
    private $backupManager;
    private $patchApplicator;
    private $queueManager;
    // Cache for exclude_paths (update every 5 minutes)
    private $excludePaths = [];
    private $excludePathsCacheTime = 0;
    private $excludePathsCacheTtl = 300; // 5 minutes
    // Context upload throttle
    private $contextLastUpload = 0;
    private $contextUploadTtl = 300;
    /** @var array|null OAuth credential bundle (access_token, refresh_token, hmac_secret, ...). */
    private $oauthCreds = null;
    private $oauthCredFile = null;
    private $oauthClientId = 'patcherly-connector';
    private $oauthResolved = false;

    /**
     * Per-process set of error_ids for which post-apply steps already succeeded.
     * Mirrors the Python and Node connectors so a retried apply for the same
     * error never restarts twice in a single agent lifetime. Cleared at start.
     *
     * Implemented as a map<string,bool> for O(1) lookup.
     *
     * @var array<string,bool>
     */
    private $postApplySuccessErrorIds = [];

    public function __construct() {
        // Priority: env > default
        $this->serverUrl = patcherly_agent_configured_server_url();
        $this->idsPath = getenv('PATCHERLY_IDS_PATH') ?: 'patcherly_ids.json';
        $this->queuePath = getenv('PATCHERLY_QUEUE_PATH') ?: 'patcherly_queue.jsonl';
        $this->oauthClientId = getenv('PATCHERLY_OAUTH_CLIENT_ID') ?: 'patcherly-connector';
        $defaultCredFile = (getenv('HOME') ?: getenv('USERPROFILE') ?: sys_get_temp_dir()) . DIRECTORY_SEPARATOR . '.patcherly' . DIRECTORY_SEPARATOR . 'credentials.json';
        $this->oauthCredFile = getenv('PATCHERLY_CREDENTIAL_FILE') ?: $defaultCredFile;
        if (!file_exists('logs')) { mkdir('logs', 0777, true); }
        if (!file_exists($this->logFile)) { file_put_contents($this->logFile, ""); }
        
        // Initialize backup manager, patch applicator, and queue manager
        $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: '.patcherly_backups';
        require_once __DIR__ . '/backup_manager.php';
        require_once __DIR__ . '/patch_applicator.php';
        require_once __DIR__ . '/queue_manager.php';
        $this->backupManager = new AgentBackupManager($backupRoot);
        $this->patchApplicator = new PatchApplicator();
        $this->queueManager = new QueueManager($this->queuePath);
        
        $this->loadOrDiscoverIds();
        $this->fetchLogPathsFromServer();
        $this->reportDiscoveredLogPaths();
    }

    /**
     * Fetch enabled log paths from GET /api/targets/{target_id}/log-paths/connector.
     * Stores ALL returned paths in $serverLogPaths and sets $logFile to the first non-empty path.
     */
    private function fetchLogPathsFromServer() : void {
        if (!$this->targetId) {
            return;
        }
        try {
            $response = $this->sendSigned('GET', PatcherlyApiPaths::appPath('targets', (string) $this->targetId, 'log-paths', 'connector'));
            if ($response === false) {
                return;
            }
            $j = json_decode($response, true);
            $paths = (is_array($j) && isset($j['log_paths']) && is_array($j['log_paths']))
                ? array_values(array_filter($j['log_paths']))
                : [];
            if ($paths) {
                $this->serverLogPaths = $paths;
                $this->logFile = $paths[0];
                echo 'Using server-provided log paths: ' . implode(', ', $paths) . "\n";
            }
        } catch (\Throwable $e) {
            // Silently fail, keep default log file
        }
    }

    /**
     * POST discovered log path metadata (existence/readability) to the API for dashboard display.
     * Reports ALL server-provided paths — no hardcoded fallback lists.
     */
    private function reportDiscoveredLogPaths() : void {
        if (!$this->targetId) {
            return;
        }
        // Use all server-provided paths; fall back to primary logFile if not yet populated
        $paths = $this->serverLogPaths ?: [$this->logFile];
        $candidates = [];
        $seen = [];
        foreach ($paths as $path) {
            if (!$path || in_array($path, $seen, true)) continue;
            $seen[] = $path;
            $abs = (strpos((string)$path, '/') === 0) ? (string)$path : (getcwd() . '/' . ltrim((string)$path, '/'));
            $ex  = file_exists($abs);
            $rd  = $ex && is_readable($abs);
            $candidates[] = ['path' => $path, 'exists' => $ex, 'readable' => $rd, 'source_tier' => 'server'];
        }
        if (count($candidates) === 0) return;
        $payload = ['paths' => array_slice($candidates, 0, 200)];
        try {
            $this->sendSigned('POST', PatcherlyApiPaths::appPath('targets', (string) $this->targetId, 'log-paths', 'discovered'), $payload);
        } catch (\Throwable $e) {
            // Silently fail
        }
    }

    /**
     * Build a direct-API endpoint URL from a registry path (/v1/..., /auth/..., or legacy /api/...).
     */
    private function buildApiEndpoint($path) : string {
        if (is_string($path) && preg_match('#^https?://#i', $path)) {
            return $path;
        }
        $normalized = '/' . ltrim((string) $path, '/');
        return rtrim($this->serverUrl, '/') . $normalized;
    }

    private function discoverApiUrl() : void {
        /**Discover API URL from public config endpoint (skipped when SERVER_URL / PATCHERLY_API_BASE is set).*/
        if (!$this->serverUrl) {
            $this->serverUrl = rtrim(DEFAULT_API_URL, '/');
            return;
        }
        if (patcherly_agent_is_explicit_server_url()) {
            return;
        }
        
        try {
            $url = $this->buildApiEndpoint(PatcherlyApiPaths::NAMED_PUBLIC_CONFIG);
            $response = $this->sendGet($url, []);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if (is_array($data) && isset($data['api_base_url'])) {
                    $discoveredUrl = $data['api_base_url'];
                    if ($discoveredUrl) {
                        $this->serverUrl = rtrim($discoveredUrl, '/');
                        echo "Discovered API URL: {$this->serverUrl}\n";
                    }
                }
            }
        } catch (\Throwable $e) {
            // Silently fail, use current URL
        }
    }

    /**
     * Extract multi-line error events (stack traces, PHP Fatal, Node Error, etc.).
     * @param string[] $lines
     * @return string[]
     */
    private function extractErrorEvents(array $lines) : array {
        $events = [];
        $current = [];
        $startOrCont = '/^(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+Fatal|^\s+at\s+|\s*#\d+\s+)/i';
        $errorWord = '/\b(error|exception|traceback|fatal)\b/i';
        // Python exception type line (e.g. "ValueError: bad") — treat as continuation when in a block
        $pythonExceptionLine = '/^\w+(?:Error|Exception):\s/i';

        $flush = function () use (&$current, &$events) {
            if (count($current) > 0) {
                $events[] = implode('', $current);
                $current = [];
            }
        };

        foreach ($lines as $line) {
            $stripped = trim($line);
            $isContinuation = count($current) > 0 && ($stripped === '' || strpos($line, '  ') === 0 || strpos($line, "\t") === 0 || preg_match('/^\s+at\s+/', $line) || (strlen($stripped) > 0 && $stripped[0] === '#') || preg_match($pythonExceptionLine, $stripped));
            $isStart = (bool) preg_match($startOrCont, $line) || preg_match($errorWord, $stripped);
            if ($isContinuation) {
                $current[] = $line;
            } elseif ($isStart) {
                $flush();
                $current[] = $line;
            } elseif (count($current) > 0 && $stripped === '') {
                $flush();
            } elseif (count($current) > 0) {
                $flush();
            }
        }
        $flush();
        if (count($events) === 0) {
            $errorLines = array_filter($lines, function ($l) {
                return preg_match('/\b(error|exception|traceback|fatal|critical|failed|failure|rejection)\b/i', $l) === 1
                    || preg_match('/^\s*\w+(Error|Exception):/i', $l) === 1;
            });
            if (count($errorLines) > 0) {
                $events[] = implode('', $errorLines);
            }
        }
        return $events;
    }

    private const PROTECTION_MODE_SENTINEL = __DIR__ . '/.protection_mode_until';
    private const SUSPICIOUS_REFUSAL_MSG =
        'Connector refused to apply: server marked this patch as suspicious';

    private function clearExpiredProtectionMode(): void {
        $path = self::PROTECTION_MODE_SENTINEL;
        if (!is_file($path)) {
            return;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            error_log('Patcherly: failed to read protection mode sentinel');
            return;
        }
        $raw = trim($raw);
        if ($raw === '' || strcasecmp($raw, 'indefinite') === 0) {
            return;
        }
        try {
            $expiry = new \DateTimeImmutable($raw);
            if ($expiry <= new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
                @unlink($path);
            }
        } catch (\Throwable $e) {
            error_log('Patcherly: failed to evaluate protection mode sentinel: ' . $e->getMessage());
        }
    }

    private function isProtectionModeStandby(): bool {
        $this->clearExpiredProtectionMode();
        $path = self::PROTECTION_MODE_SENTINEL;
        if (!is_file($path)) {
            return false;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            error_log('Patcherly: failed to read protection mode sentinel');
            return true;
        }
        $raw = trim($raw);
        if ($raw === '' || strcasecmp($raw, 'indefinite') === 0) {
            return true;
        }
        try {
            $expiry = new \DateTimeImmutable($raw);
            return $expiry > new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        } catch (\Throwable $e) {
            error_log('Patcherly: invalid protection mode until in sentinel: ' . $e->getMessage());
            return true;
        }
    }

    private function enterProtectionModeStandby(?string $until): void {
        $value = ($until === null || trim($until) === '') ? 'indefinite' : trim($until);
        if (@file_put_contents(self::PROTECTION_MODE_SENTINEL, $value . "\n") === false) {
            error_log('Patcherly: failed to write protection mode sentinel');
        }
    }

    private function handleProtectionModeHttp(int $statusCode, string $bodyText): bool {
        if ($statusCode !== 423) {
            return false;
        }
        $matched = false;
        $until = null;
        try {
            $data = json_decode($bodyText, true);
            $detail = is_array($data) ? ($data['detail'] ?? null) : null;
            if (is_array($detail) && ($detail['code'] ?? '') === 'target_protection_mode_active') {
                $until = isset($detail['until']) ? (string) $detail['until'] : null;
                $matched = true;
            }
        } catch (\Throwable $e) {
            error_log('Patcherly: failed to parse protection-mode 423 body: ' . $e->getMessage());
            return false;
        }
        if (!$matched) {
            return false;
        }
        $this->enterProtectionModeStandby($until);
        error_log(
            'Patcherly: target entered protection mode standby until ' .
            ($until ?: 'manual release') . '; pausing ingest and fix polling.'
        );
        return true;
    }

    private function postRefusedApplyResult(string $errorId, string $message, string $label = ''): void {
        $applyPayload = [
            'success' => false,
            'fix_path' => $this->logFile,
            'message' => $message,
        ];
        try {
            [$respBody, $status] = $this->sendSignedWithStatus(
                'POST',
                PatcherlyApiPaths::appPath('errors', $errorId, 'fix', 'apply-result'),
                $applyPayload
            );
            if ($status === 409) {
                $detail = '';
                $decoded = is_string($respBody) ? json_decode($respBody, true) : null;
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $detail = (string) $decoded['detail'];
                }
                error_log(
                    "apply-result ({$label}) returned 409 for {$errorId}; " .
                    "server is canonical, not retrying. detail={$detail}"
                );
            } elseif ($status < 200 || $status >= 300) {
                error_log("apply-result ({$label}) failed: HTTP {$status}");
            }
        } catch (\Throwable $e) {
            error_log('apply-result (' . $label . ') failed: ' . $e->getMessage());
        }
    }

    public function monitorLogs() {
        // Try to discover API URL (non-blocking, uses current/default if fails)
        $this->discoverApiUrl();

        // v1.47 hardening: refuse to monitor a log path that fails the
        // connector-side policy (NUL, traversal, ``..``, stream wrapper,
        // out-of-allow-list). The server-side policy is the canonical one;
        // this is defence in depth in case a malicious dashboard tenant
        // crafts a path that survives a buggy server release.
        try {
            self::validateLogPath($this->logFile);
        } catch (\Throwable $e) {
            error_log("Patcherly: refusing to monitor invalid log path '{$this->logFile}': " . $e->getMessage());
            return;
        }

        $lastSize = file_exists($this->logFile) ? filesize($this->logFile) : 0;
        echo "Starting log monitoring on {$this->logFile}...\n";
        $this->collectAndUploadContext(true);
        $refreshCounter = 0;
        $idDiscoveryCounter = 0;
        while (true) {
            $this->clearExpiredProtectionMode();
            if (!$this->isProtectionModeStandby()) {
                clearstatcache();
                $currentSize = file_exists($this->logFile) ? filesize($this->logFile) : 0;
                if ($currentSize > $lastSize) {
                    $handle = @fopen($this->logFile, 'r');
                    if ($handle === false) {
                        error_log("Patcherly: fopen failed for {$this->logFile}; skipping iteration");
                        sleep(5);
                        continue;
                    }
                    fseek($handle, $lastSize);
                    $newLines = [];
                    while (($line = fgets($handle)) !== false) {
                        $newLines[] = $line;
                    }
                    fclose($handle);
                    $lastSize = $currentSize;
                    $events = $this->extractErrorEvents($newLines);
                    foreach ($events as $event) {
                        if (trim($event) !== '') {
                            echo "Error detected: " . substr(trim($event), 0, 100) . "...\n";
                            $this->processError($event);
                        }
                    }
                }
            }

            // Pick up dashboard-initiated manual rollbacks (status=rolling_back).
            // Without this, an operator clicking Rollback in the dashboard would
            // stall server-side because no connector ever notices the transition.
            try {
                $this->processRollingBackErrors();
            } catch (\Throwable $e) {
                error_log('Patcherly: processRollingBackErrors raised: ' . $e->getMessage());
            }

            // Refresh IDs, log paths, and API URL every 5 minutes (300s / 5s sleep = 60 iterations)
            $refreshCounter++;
            if ($refreshCounter >= 60) {
                $this->loadOrDiscoverIds();
                $this->fetchLogPathsFromServer();
                $this->reportDiscoveredLogPaths();
                $refreshCounter = 0;
            }
            
            // Aggressively retry ID discovery if IDs are missing (every 30 seconds = 6 iterations)
            // This ensures we connect as soon as the API comes back up
            if (!$this->tenantId || !$this->targetId) {
                $idDiscoveryCounter++;
                if ($idDiscoveryCounter >= 6) {
                    $this->loadOrDiscoverIds();
                    $idDiscoveryCounter = 0;
                }
            } else {
                $idDiscoveryCounter = 0; // Reset counter if we have IDs
            }
            
            sleep(5);
        }
    }

    private function collectAndUploadContext(bool $force = false) : void {
        if (!$this->ensureFreshOAuth()) return;
        $now = time();
        if (!$force && $now - $this->contextLastUpload < $this->contextUploadTtl) return;
        try {
            $contextData = [
                'runtime' => 'php',
                'version' => PHP_VERSION,
                'sapi' => PHP_SAPI,
                'platform' => PHP_OS,
                'cwd' => getcwd() ?: '',
                'framework' => ['detected' => $this->detectFrameworkForIngest() ?? 'none'],
                'collected_at' => date('c'),
                'patcherly_connector_version' => PATCHERLY_CONNECTOR_VERSION,
            ];
            $payload = [
                'context_type' => 'php',
                'context_data' => $contextData,
                'server_context' => ['platform' => $contextData['platform'], 'runtime' => $contextData['runtime']],
            ];
            $this->sendSigned('POST', PatcherlyApiPaths::NAMED_CONTEXT_UPLOAD, $payload);
            $this->contextLastUpload = $now;
        } catch (\Throwable $e) {
            // Non-critical
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Post-apply manifest support (C1)
    //
    // Mirrors `_get_post_apply_connector_json` / `_run_post_apply_steps` /
    // `_maybe_run_post_apply` in connectors/python/python_agent.py. PHP uses
    // proc_open with an argv array (PHP 7.4+) so we never invoke a shell, and
    // a hardcoded shell-token denylist rejects metacharacter abuse before exec.
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Fetch the signed post-apply manifest JSON for the current target.
     * Returns null on any transport/HMAC failure so callers omit `post_apply`.
     */
    private function getPostApplyConnectorJson() {
        if (!$this->targetId) return null;
        $tid = trim((string)$this->targetId);
        $path = PatcherlyApiPaths::appPath('targets', (string) $tid, 'post-apply-config', 'connector');
        $url = $this->buildApiEndpoint($path);
        $headers = $this->buildAuthHeaders('GET', $path, '');
        if (!isset($headers['Authorization'])) {
            return null;  // not authenticated; same as Python ensure_fresh_oauth fail
        }
        $respHeaders = [];
        $statusCode = 0;
        $body = $this->sendGet($url, $headers, $respHeaders, $statusCode);
        if ($body === false || $statusCode < 200 || $statusCode >= 300) {
            error_log('[patcherly] post-apply config fetch failed: status=' . $statusCode);
            return null;
        }
        $sig = $respHeaders['X-Patcherly-Signature'] ?? null;
        $ts = $respHeaders['X-Patcherly-Timestamp'] ?? null;
        if (!$this->verifyResponseHmac('GET', $path, $body, $sig, $ts)) {
            error_log('[patcherly] post-apply connector response HMAC failed — skipping post_apply');
            return null;
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) return null;
        return $decoded;
    }

    /**
     * Tokenize a shell-style command string into an argv array WITHOUT invoking
     * a shell. Supports single- and double-quoted arguments and simple
     * whitespace separation. Backslash escapes are honored only inside double
     * quotes (\\, \", \$, \`).
     *
     * Returns null if tokenization is ambiguous (unbalanced quotes) so the
     * caller can refuse to execute rather than guess at intent.
     *
     * @return string[]|null
     */
    private function tokenizeCommand(string $cmd) : ?array {
        $argv = [];
        $cur = '';
        $inSingle = false;
        $inDouble = false;
        $hasToken = false;
        $len = strlen($cmd);
        for ($i = 0; $i < $len; $i++) {
            $c = $cmd[$i];
            if ($inSingle) {
                if ($c === "'") { $inSingle = false; }
                else { $cur .= $c; }
                continue;
            }
            if ($inDouble) {
                if ($c === '"') { $inDouble = false; }
                elseif ($c === '\\' && $i + 1 < $len && strpos('\\"$`', $cmd[$i + 1]) !== false) {
                    $cur .= $cmd[$i + 1];
                    $i++;
                } else {
                    $cur .= $c;
                }
                continue;
            }
            if ($c === "'") { $inSingle = true; $hasToken = true; continue; }
            if ($c === '"') { $inDouble = true; $hasToken = true; continue; }
            if (ctype_space($c)) {
                if ($hasToken) { $argv[] = $cur; $cur = ''; $hasToken = false; }
                continue;
            }
            $cur .= $c;
            $hasToken = true;
        }
        if ($inSingle || $inDouble) return null;
        if ($hasToken) $argv[] = $cur;
        return $argv;
    }

    /**
     * Minimal YAML-subset parser for the post-apply manifest shape:
     *
     *   working_directory: /app
     *   dry_run: false
     *   when: on_fix_success_if_restart_required
     *   steps:
     *     - name: restart
     *       run: systemctl restart php-fpm
     *       timeout_seconds: 30
     *       ignore_failure: false
     *
     * Tries the PECL ``yaml`` extension first (``yaml_parse``); falls back to
     * the built-in parser if absent so connectors can run on shared hosts
     * without ext-yaml. Returns null on parse error.
     *
     * @return array|null
     */
    private function parseManifestYaml(string $raw) : ?array {
        $raw = (string)$raw;
        if (trim($raw) === '') return null;
        if (function_exists('yaml_parse')) {
            try {
                $parsed = @yaml_parse($raw);
                if (is_array($parsed)) return $parsed;
            } catch (\Throwable $e) {
                // fall through to built-in parser
            }
        }
        $out = ['steps' => []];
        $lines = preg_split('/\r?\n/', $raw);
        $i = 0;
        $stepsContext = false;
        $currentStep = null;
        $stepIndent = 0;
        $flush = function () use (&$out, &$currentStep) {
            if ($currentStep !== null) {
                $out['steps'][] = $currentStep;
                $currentStep = null;
            }
        };
        while ($i < count($lines)) {
            $raw_line = $lines[$i];
            $i++;
            // strip inline comments only if outside quotes (best-effort)
            $line = preg_replace('/(?<![\\\\])#.*$/', '', $raw_line);
            if (trim((string)$line) === '') continue;
            $indent = strlen($line) - strlen(ltrim($line));
            $trimmed = trim($line);

            // Top-level scalar key
            if ($indent === 0 && preg_match('/^([a-z_]+)\s*:\s*(.*)$/i', $trimmed, $m)) {
                $flush();
                $key = strtolower($m[1]);
                $val = trim($m[2]);
                if ($key === 'steps') {
                    $stepsContext = true;
                    continue;
                }
                $stepsContext = false;
                if ($val === '') continue;
                $out[$key] = $this->coerceYamlScalar($val);
                continue;
            }

            if (!$stepsContext) continue;

            // List item ("- name: ...") starts a new step
            if (preg_match('/^-\s*(.*)$/', $trimmed, $m)) {
                $flush();
                $currentStep = [];
                $stepIndent = $indent + 2;  // mappings under "- " expected at this indent
                $rest = trim($m[1]);
                if ($rest !== '' && preg_match('/^([a-z_]+)\s*:\s*(.*)$/i', $rest, $mm)) {
                    $currentStep[strtolower($mm[1])] = $this->coerceYamlScalar(trim($mm[2]));
                }
                continue;
            }

            // Step continuation field
            if ($currentStep !== null && preg_match('/^([a-z_]+)\s*:\s*(.*)$/i', $trimmed, $m)) {
                $currentStep[strtolower($m[1])] = $this->coerceYamlScalar(trim($m[2]));
                continue;
            }
        }
        $flush();
        return $out;
    }

    /** Coerce a YAML scalar text to bool / int / string. */
    private function coerceYamlScalar(string $val) {
        $stripped = $val;
        if ((strlen($stripped) >= 2)
            && (($stripped[0] === '"' && substr($stripped, -1) === '"')
                || ($stripped[0] === "'" && substr($stripped, -1) === "'"))) {
            return substr($stripped, 1, -1);
        }
        $low = strtolower($stripped);
        if ($low === 'true' || $low === 'yes' || $low === 'on') return true;
        if ($low === 'false' || $low === 'no' || $low === 'off') return false;
        if ($low === 'null' || $low === '~' || $low === '') return null;
        if (preg_match('/^-?\d+$/', $stripped)) return (int)$stripped;
        return $stripped;
    }

    /**
     * Execute manifest steps; returns telemetry dict matching the Python and
     * Node connectors. Honors `dry_run` and `ignore_failure`. Each step is run
     * via proc_open with an argv array (no shell), and any shell metacharacters
     * in a string-form `run:` are rejected as `unsafe_shell_tokens` before
     * tokenization.
     */
    private function runPostApplySteps(array $manifest, bool $dryRun) : array {
        $stepsIn = isset($manifest['steps']) && is_array($manifest['steps']) ? $manifest['steps'] : [];
        $wd = $manifest['working_directory'] ?? null;
        $rootCwd = $wd ? @realpath((string)$wd) : getcwd();
        if (!$rootCwd) $rootCwd = getcwd();
        $manifestDry = !empty($manifest['dry_run']);
        $effectiveDry = $dryRun || $manifestDry;

        $logs = [];
        $stepResults = [];

        foreach ($stepsIn as $i => $rawStep) {
            $step = is_array($rawStep) ? $rawStep : [];
            $name = (string)($step['name'] ?? ('step_' . ($i + 1)));
            $rawRun = $step['run'] ?? '';
            $cmd = is_array($rawRun) ? '' : trim((string)$rawRun);
            $timeoutS = max(1, (int)($step['timeout_seconds'] ?? 120));
            $ignoreFailure = !empty($step['ignore_failure']);

            if (!is_array($rawRun) && $cmd === '') {
                $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -1, 'error' => 'empty_run'];
                if (!$ignoreFailure) {
                    return [
                        'failed' => true, 'ran' => true, 'dry_run' => $effectiveDry,
                        'steps' => $stepResults, 'message' => "empty command in {$name}",
                    ];
                }
                continue;
            }

            if ($effectiveDry) {
                $logs[] = "[DRY-RUN] would execute ({$name}): " . ($cmd !== '' ? $cmd : implode(' ', array_map('strval', (array)$rawRun)));
                $stepResults[] = ['name' => $name, 'ok' => true, 'rc' => 0, 'dry_run' => true];
                continue;
            }

            try {
                if (is_array($rawRun)) {
                    $argv = array_values(array_filter(array_map(
                        function ($p) { return (string)$p; },
                        $rawRun
                    ), function ($p) { return trim($p) !== ''; }));
                } else {
                    // shell-token denylist (mirrors python_agent.py:1030).
                    $denylist = ['&&', '||', '|', ';', '`', '$(', '>', '<'];
                    foreach ($denylist as $tok) {
                        if (strpos($cmd, $tok) !== false) {
                            $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -4, 'error' => 'unsafe_shell_tokens'];
                            if (!$ignoreFailure) {
                                return [
                                    'failed' => true, 'ran' => true, 'dry_run' => false,
                                    'steps' => $stepResults, 'message' => "unsafe_command:{$name}",
                                    'log' => substr(implode("\n", $logs), -8000),
                                ];
                            }
                            continue 2;
                        }
                    }
                    $argv = $this->tokenizeCommand($cmd);
                    if ($argv === null) {
                        $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -5, 'error' => 'unbalanced_quotes'];
                        if (!$ignoreFailure) {
                            return [
                                'failed' => true, 'ran' => true, 'dry_run' => false,
                                'steps' => $stepResults, 'message' => "unsafe_command:{$name}",
                                'log' => substr(implode("\n", $logs), -8000),
                            ];
                        }
                        continue;
                    }
                }

                if (!$argv) {
                    $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -1, 'error' => 'empty_run'];
                    if (!$ignoreFailure) {
                        return [
                            'failed' => true, 'ran' => true, 'dry_run' => false,
                            'steps' => $stepResults, 'message' => "empty command in {$name}",
                        ];
                    }
                    continue;
                }

                $result = $this->execArgvWithTimeout($argv, $rootCwd, $timeoutS);
                $rc = $result['rc'];
                $ok = ($rc === 0);
                if (!empty($result['stdout'])) $logs[] = substr($result['stdout'], 0, 4000);
                if (!empty($result['stderr'])) $logs[] = substr($result['stderr'], 0, 4000);

                if ($result['timed_out']) {
                    $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -2, 'error' => 'timeout'];
                    if (!$ignoreFailure) {
                        return [
                            'failed' => true, 'ran' => true, 'dry_run' => false,
                            'steps' => $stepResults, 'message' => "step_timeout:{$name}",
                            'log' => substr(implode("\n", $logs), -8000),
                        ];
                    }
                    continue;
                }

                $stepResults[] = ['name' => $name, 'ok' => $ok, 'rc' => $rc];
                if (!$ok && !$ignoreFailure) {
                    return [
                        'failed' => true, 'ran' => true, 'dry_run' => false,
                        'steps' => $stepResults, 'message' => "step_failed:{$name}:rc={$rc}",
                        'log' => substr(implode("\n", $logs), -8000),
                    ];
                }
            } catch (\Throwable $e) {
                $stepResults[] = ['name' => $name, 'ok' => false, 'rc' => -3, 'error' => $e->getMessage()];
                if (!$ignoreFailure) {
                    return [
                        'failed' => true, 'ran' => true, 'dry_run' => false,
                        'steps' => $stepResults, 'message' => "step_error:{$name}:" . $e->getMessage(),
                        'log' => substr(implode("\n", $logs), -8000),
                    ];
                }
            }
        }

        return [
            'failed' => false, 'ran' => true, 'dry_run' => $effectiveDry,
            'steps' => $stepResults, 'log' => substr(implode("\n", $logs), -8000),
        ];
    }

    /**
     * Run an argv array with proc_open (no shell) and a wall-clock timeout.
     * Returns ['rc', 'stdout', 'stderr', 'timed_out'].
     *
     * proc_open accepts an array<int,string> as the first argument since PHP
     * 7.4 — under that signature PHP does NOT invoke /bin/sh, so shell
     * metacharacters in tokens are inert.
     */
    private function execArgvWithTimeout(array $argv, string $cwd, int $timeoutS) : array {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $env = null;  // inherit current env
        // Older PHP (<7.4) cannot take an array — degrade gracefully by
        // refusing to exec rather than dropping to shell mode.
        if (PHP_VERSION_ID < 70400) {
            return ['rc' => -3, 'stdout' => '', 'stderr' => 'php_version_below_7_4_unsupported', 'timed_out' => false];
        }
        // FP (semgrep): proc_open with argv array — no shell invocation (PHP 7.4+).
        // nosemgrep: php.lang.security.exec-use.exec-use
        $proc = @proc_open($argv, $descriptors, $pipes, $cwd, $env);
        if (!is_resource($proc)) {
            return ['rc' => -3, 'stdout' => '', 'stderr' => 'proc_open_failed', 'timed_out' => false];
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $stderr = '';
        $start = microtime(true);
        $timedOut = false;
        $maxBytes = 4 * 1024 * 1024;
        while (true) {
            $status = proc_get_status($proc);
            $chunkOut = stream_get_contents($pipes[1]);
            $chunkErr = stream_get_contents($pipes[2]);
            if ($chunkOut !== false) $stdout .= $chunkOut;
            if ($chunkErr !== false) $stderr .= $chunkErr;
            if (strlen($stdout) > $maxBytes) $stdout = substr($stdout, 0, $maxBytes);
            if (strlen($stderr) > $maxBytes) $stderr = substr($stderr, 0, $maxBytes);
            if (!$status['running']) break;
            if ((microtime(true) - $start) >= $timeoutS) {
                $timedOut = true;
                @proc_terminate($proc, 15);  // SIGTERM
                usleep(200000);  // grace
                $st2 = proc_get_status($proc);
                if ($st2['running']) {
                    @proc_terminate($proc, 9);  // SIGKILL
                }
                break;
            }
            usleep(50000);
        }
        // Drain remaining output after termination.
        $chunkOut = stream_get_contents($pipes[1]);
        $chunkErr = stream_get_contents($pipes[2]);
        if ($chunkOut !== false) $stdout .= $chunkOut;
        if ($chunkErr !== false) $stderr .= $chunkErr;
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($proc);
        if ($timedOut) $rc = -2;
        return [
            'rc' => (int)$rc,
            'stdout' => $stdout,
            'stderr' => $stderr,
            'timed_out' => $timedOut,
        ];
    }

    /**
     * After a successful apply_fix: optionally run the post-apply manifest.
     *
     * Returns:
     *   - null if the server didn't respond / HMAC failed (caller omits the
     *     `post_apply` field from apply-result for forward compatibility).
     *   - dict with `ran=false` + `skipped_reason` when the manifest decided
     *     to skip.
     *   - dict with telemetry when steps actually ran.
     *
     * @return array|null
     */
    private function maybeRunPostApply(string $errorId, array $fixJson) {
        $envDryRaw = strtolower((string)getenv('PATCHERLY_POST_APPLY_DRY_RUN'));
        $envDry = in_array($envDryRaw, ['1', 'true', 'yes', 'on'], true);

        $cfg = $this->getPostApplyConnectorJson();
        if ($cfg === null) return null;

        if (empty($cfg['enabled'])) {
            return [
                'ran' => false,
                'skipped_reason' => 'not_enabled',
                'reason' => $cfg['reason'] ?? null,
            ];
        }
        if (isset($cfg['restart_allowed']) && $cfg['restart_allowed'] === false) {
            return ['ran' => false, 'skipped_reason' => 'rate_limit'];
        }

        $eid = trim($errorId);
        if (isset($this->postApplySuccessErrorIds[$eid])) {
            return [
                'ran' => false,
                'skipped_reason' => 'already_restarted_for_error',
                'message' => 'already_restarted_for_error',
            ];
        }

        $rawYaml = $cfg['manifest_yaml'] ?? null;
        if (!$rawYaml || trim((string)$rawYaml) === '') {
            return ['ran' => false, 'skipped_reason' => 'no_manifest'];
        }
        $rawYaml = (string)$rawYaml;

        $expectedSha = strtolower(trim((string)($cfg['content_sha256'] ?? '')));
        if ($expectedSha !== '') {
            $actual = hash('sha256', $rawYaml);
            if ($actual !== $expectedSha) {
                error_log('[patcherly] post-apply manifest content_sha256 mismatch — refusing to run steps');
                return ['failed' => true, 'ran' => false, 'message' => 'content_sha256_mismatch'];
            }
        }

        $manifest = $this->parseManifestYaml($rawYaml);
        if (!is_array($manifest)) {
            return ['failed' => true, 'ran' => false, 'message' => 'manifest_parse_failed'];
        }

        $when = trim((string)($manifest['when'] ?? 'on_fix_success_if_restart_required'));
        $restartRequired = $fixJson['restart_required'] ?? null;
        if ($when === 'on_fix_success_if_restart_required' && $restartRequired === false) {
            return ['ran' => false, 'skipped_reason' => 'restart_not_required'];
        }

        $telemetry = $this->runPostApplySteps($manifest, $envDry);
        $telemetry['error_id'] = $errorId;
        if (empty($telemetry['failed']) && ($telemetry['ran'] ?? true) !== false) {
            $this->postApplySuccessErrorIds[$eid] = true;
        }
        return $telemetry;
    }

    /**
     * Detect a Composer-installed test runner under the agent's working
     * directory. Returns a [argv[], framework] pair or null if none found.
     *
     * We invoke the resolved binary via the current PHP_BINARY rather than
     * relying on a shebang so the path works on Windows hosts where
     * vendor/bin/phpunit is a `.bat` shim, and so we never accidentally
     * shell out. This mirrors the python_agent.py pattern of
     * `[sys.executable, '-m', 'pytest']` and node_agent.js's argv-form
     * `execFile('npm', ['test'])` — both rely on a known interpreter and
     * never go through /bin/sh.
     */
    private function detectPhpTestRunner() {
        $cwd = getcwd();
        if ($cwd === false) return null;
        $sep = DIRECTORY_SEPARATOR;
        $candidates = [
            ['vendor' . $sep . 'bin' . $sep . 'phpunit', 'phpunit'],
            ['vendor' . $sep . 'bin' . $sep . 'pest', 'pest'],
        ];
        foreach ($candidates as [$rel, $framework]) {
            $abs = $cwd . $sep . $rel;
            if (is_file($abs)) {
                return [[PHP_BINARY, $abs], $framework];
            }
        }
        return null;
    }

    /**
     * Build the test-result payload after the apply step. Tries to invoke
     * vendor/bin/phpunit (or vendor/bin/pest) so PHP matches the
     * Python (`pytest`) and Node.js (`npm test`) post-apply behaviour
     * advertised in help/connectors/overview.md. Falls back to a
     * synthetic `connector_smoke` row when no runner is installed or the
     * exec primitive fails.
     *
     * Pure helper exposed for unit tests in
     * connectors/php/tests/post_apply_steps_test.php — does NOT do any
     * network I/O. The networked POST happens in runTestsAndReport().
     *
     * @return array Payload ready for POST to /api/errors/{id}/test/results.
     */
    private function buildTestResultsPayload(string $errorId, bool $applySuccess) : array {
        $detected = $this->detectPhpTestRunner();
        if ($detected === null) {
            // No vendor/bin/phpunit or vendor/bin/pest on disk — mirror the
            // Node connector's behaviour when package.json has no test
            // script, so the dashboard can show "skipped" rather than a
            // misleading "passed".
            return [
                'error_id' => $errorId,
                'total_tests' => 1,
                'passed' => 0,
                'failed' => 0,
                'skipped' => 1,
                'execution_time' => 0,
                'results' => [[
                    'test_name' => 'phpunit_run',
                    'status' => 'skipped',
                    'duration' => 0,
                    'message' => 'vendor/bin/phpunit (or vendor/bin/pest) not found; tests not run',
                ]],
                'framework' => 'phpunit',
                'language' => 'php',
                'executed_by' => 'agent',
            ];
        }

        [$argv, $framework] = $detected;
        $cwd = getcwd();
        try {
            $start = microtime(true);
            $result = $this->execArgvWithTimeout($argv, $cwd ?: '.', 120);
            $elapsed = max(0.0, microtime(true) - $start);
            $rc = (int)($result['rc'] ?? -3);
            $timedOut = !empty($result['timed_out']);
            if ($rc === 0 && !$timedOut) {
                return [
                    'error_id' => $errorId,
                    'total_tests' => 1,
                    'passed' => 1,
                    'failed' => 0,
                    'skipped' => 0,
                    'execution_time' => $elapsed,
                    'results' => [[
                        'test_name' => $framework . '_run',
                        'status' => 'passed',
                        'duration' => $elapsed,
                        'message' => $framework . ' completed',
                    ]],
                    'framework' => $framework,
                    'language' => 'php',
                    'executed_by' => 'agent',
                ];
            }
            $tail = (string)($result['stderr'] ?? '');
            if ($tail === '') $tail = (string)($result['stdout'] ?? '');
            if ($tail === '') $tail = $timedOut ? 'timeout' : ('rc=' . $rc);
            return [
                'error_id' => $errorId,
                'total_tests' => 1,
                'passed' => 0,
                'failed' => 1,
                'skipped' => 0,
                'execution_time' => $elapsed,
                'results' => [[
                    'test_name' => $framework . '_run',
                    'status' => 'failed',
                    'duration' => $elapsed,
                    'error' => substr($tail, 0, 500),
                ]],
                'framework' => $framework,
                'language' => 'php',
                'executed_by' => 'agent',
            ];
        } catch (\Throwable $e) {
            // execArgvWithTimeout is defensive but PHP_BINARY could be
            // unavailable (e.g. embedded SAPI) — fall back to the synthetic
            // smoke row so the dashboard still gets something.
            return [
                'error_id' => $errorId,
                'total_tests' => 1,
                'passed' => $applySuccess ? 1 : 0,
                'failed' => $applySuccess ? 0 : 1,
                'skipped' => 0,
                'execution_time' => 0,
                'results' => [[
                    'test_name' => 'connector_smoke',
                    'status' => $applySuccess ? 'passed' : 'failed',
                    'duration' => 0,
                    'message' => $applySuccess ? 'Apply success' : 'Apply failed or rolled back',
                ]],
                'framework' => 'connector_smoke',
                'language' => 'php',
                'executed_by' => 'agent',
            ];
        }
    }

    private function runTestsAndReport(string $errorId, bool $applySuccess) : void {
        try {
            $payload = $this->buildTestResultsPayload($errorId, $applySuccess);
            $r = $this->sendSigned('POST', PatcherlyApiPaths::appPath('errors', (string) $errorId, 'test', 'results'), $payload);
            if ($r !== false && is_string($r)) {
                $dec = @json_decode($r, true);
                if (isset($dec['detail']) && strpos((string)$dec['detail'], 'entitlement') !== false) {
                    return; // 402 entitlement not enabled
                }
            }
        } catch (\Throwable $e) {
            echo "Run tests and report failed: " . $e->getMessage() . "\n";
        }
    }

    public function processError($errorContext) {
        echo "Processing error: $errorContext\n";
        
        if ($this->isProtectionModeStandby()) {
            echo "Protection mode standby active; skipping ingest/fix for this error.\n";
            return;
        }

        $this->loadOrDiscoverIds();
        $this->collectAndUploadContext();

        // Require OAuth credentials before making any API calls
        if (!$this->ensureFreshOAuth()) {
            echo "OAuth credentials not available. Run `patcherly login` to authenticate.\n";
            return;
        }

        // Update exclude_paths if cache is stale
        $this->updateExcludePaths();
        
        // PRIMARY FILTERING: Check if error path is excluded BEFORE sending to server
        $filePath = $this->extractFilePath($errorContext);
        if ($filePath && $this->isPathExcluded($filePath)) {
            echo "Error from excluded path skipped: $filePath\n";
            return; // Skip ingestion entirely - don't send to server
        }

        // ingest -> analyze -> get fix (include code_language/code_framework for AI template selection)
        require_once __DIR__ . '/sanitizer.php';
        $logLine = is_string($errorContext) ? $errorContext : (string) $errorContext;
        $logLine = \Patcherly\Connector\Sanitizer::sanitizeLogLineForIngest($logLine);
        if (patcherly_shared_should_skip_log_line_for_ingest($logLine)) {
            echo "Non-error log noise skipped.\n";
            return;
        }
        $severityFields = patcherly_shared_build_ingest_severity_fields($logLine);
        $payload = [
            'log_line' => $logLine,
            'error_type' => $severityFields['error_type'],
            'severity' => $severityFields['severity'],
            'source' => 'log_monitor',
        ];
        if ($this->tenantId && $this->targetId) {
            $payload['tenant_id'] = (string)$this->tenantId;
            $payload['target_id'] = (string)$this->targetId;
        }
        $payload['code_language'] = 'php';
        $fw = $this->detectFrameworkForIngest();
        if ($fw !== null) {
            $payload['code_framework'] = $fw;
        }
        [$r1Body, $r1Code] = $this->sendSignedWithStatus('POST', PatcherlyApiPaths::NAMED_ERRORS_INGEST, $payload);
        if ($r1Body === false && $r1Code === 0) {
            // Network error, enqueue for later
            $this->enqueue($payload);
            echo "Network issue: enqueued ingest for retry.\n";
            return;
        }
        if ($this->handleProtectionModeHttp((int) $r1Code, is_string($r1Body) ? $r1Body : '')) {
            return;
        }
        if ($r1Code === 409) {
            // Already processed idempotency key
            $item = ['id' => null];
        } elseif ($r1Code >= 200 && $r1Code < 300) {
            $item = is_string($r1Body) ? json_decode($r1Body, true) : [];
        } else {
            $item = is_string($r1Body) ? json_decode($r1Body, true) : [];
            if (!is_array($item)) {
                $item = [];
            }
            if ($r1Code === 429 || (isset($item['detail']) && stripos((string) $item['detail'], 'rate limit') !== false)) {
                $this->enqueue($payload);
                echo "Rate limited: enqueued ingest for retry.\n";
                return;
            }
            echo "Ingest failed: HTTP {$r1Code}\n";
            return;
        }
        if (!is_array($item)) {
            $item = [];
        }
        $id = $item['id'] ?? null;
        if (!$id) {
            // 429 rate limit: enqueue for retry (same as network error)
            if (isset($item['detail']) && stripos((string)$item['detail'], 'rate limit') !== false) {
                $this->enqueue($payload);
                echo "Rate limited: enqueued ingest for retry.\n";
                return;
            }
            echo "No id returned.\n";
            return;
        }

        // v1.49: auto_analyze and auto_apply are independent flags returned by the API.
        //   - auto_analyze=true,  auto_apply=true  -> full pipeline (analyze → approve → apply).
        //   - auto_analyze=true,  auto_apply=false -> analyze, then stop. Dashboard approves & applies.
        //   - auto_analyze=false                   -> stop after ingest. Dashboard runs everything.
        // Older API builds that don't return `auto_apply` default to false here, so the connector
        // stops after analyze rather than chain into auto-apply. The server-side approve gate
        // (409 auto_apply_not_enabled) is the authoritative safety net for any drift.
        $autoAnalyze = !empty($item['auto_analyze']);
        $autoApply = !empty($item['auto_apply']);
        $ingestedStatus = $item['status'] ?? 'pending';
        if (!$autoAnalyze || in_array($ingestedStatus, ['ignored', 'excluded', 'dismissed'], true)) {
            echo "Auto-analysis not enabled or error skipped (status={$ingestedStatus}); stopping after ingest.\n";
            return;
        }

        [$analyzeBody, $analyzeCode] = $this->sendSignedWithStatus(
            'POST',
            PatcherlyApiPaths::appPath('errors', (string) $id, 'analyze'),
            []
        );
        if ($this->handleProtectionModeHttp((int) $analyzeCode, is_string($analyzeBody) ? $analyzeBody : '')) {
            return;
        }
        if ($analyzeCode < 200 || $analyzeCode >= 300) {
            throw new \Exception("analyze failed: {$analyzeCode}");
        }

        // v1.49: only chain into approve+apply when autoApply is also true. Otherwise the
        // human approves & applies the analyzed fix from the dashboard.
        if (!$autoApply) {
            echo "Auto-apply not enabled for this target; stopping after analyze. "
                . "Review & approve from the dashboard.\n";
            return;
        }

        // Approve the fix before fetching it. The server returns 409 in two cases:
        //   - low_confidence_confirmation_required: stop the auto-pipeline; the dashboard
        //     surfaces the low-confidence prompt for manual approval.
        //   - auto_apply_not_enabled (v1.49): stop the auto-pipeline; the target opted out
        //     of auto-apply server-side or the entitlement was revoked between ingest and
        //     approve. The dashboard handles approval manually.
        $pathApprove = PatcherlyApiPaths::appPath('errors', (string) $id, 'approve');
        [$approveBody, $approveCode] = $this->sendSignedWithStatus('POST', $pathApprove, []);
        if ($this->handleProtectionModeHttp((int) $approveCode, is_string($approveBody) ? $approveBody : '')) {
            return;
        }
        if ($approveCode === 409) {
            $approveData = $approveBody ? json_decode($approveBody, true) : [];
            $code = $approveData['code'] ?? '';
            if ($code === 'low_confidence_confirmation_required') {
                $conf = $approveData['confidence'] ?? '?';
                $thresh = $approveData['threshold'] ?? '?';
                echo "Fix confidence too low to auto-approve ({$conf}% < {$thresh}%); "
                    . "stopping auto-pipeline — review and approve from the dashboard.\n";
                return;
            }
            if ($code === 'auto_apply_not_enabled') {
                echo "Auto-apply not enabled for this target (server-side gate); stopping "
                    . "auto-pipeline — review and approve from the dashboard.\n";
                return;
            }
            throw new \Exception("approve failed: {$approveCode}");
        }
        if ($approveCode < 200 || $approveCode >= 300) {
            throw new \Exception("approve failed: {$approveCode}");
        }
        echo "Fix approved; fetching fix payload...\n";

        // Get fix with response headers for HMAC verification
        $path3 = PatcherlyApiPaths::appPath('errors', (string) $id, 'fix');
        $url = $this->buildApiEndpoint($path3);
        $reqHeaders = $this->buildAuthHeaders('GET', $path3, '');
        $responseHeaders = [];
        $fixHttpCode = 0;
        $r3 = $this->sendGet($url, $reqHeaders, $responseHeaders, $fixHttpCode);
        if ($this->handleProtectionModeHttp((int) $fixHttpCode, is_string($r3) ? $r3 : '')) {
            return;
        }
        if ($fixHttpCode < 200 || $fixHttpCode >= 300) {
            throw new \Exception("get fix failed: {$fixHttpCode}");
        }
        
        // Verify HMAC signature (MANDATORY - always required)
        $responseSignature = $responseHeaders['X-Patcherly-Signature'] ?? null;
        $responseTimestamp = $responseHeaders['X-Patcherly-Timestamp'] ?? null;
        if (!$this->verifyResponseHmac('GET', $path3, $r3, $responseSignature, $responseTimestamp)) {
            throw new Exception("HMAC signature verification failed for fix response - patch rejected for security");
        }
        
        $data = $r3 ? json_decode($r3, true) : null;
        if (is_array($data) && !empty($data['suspicious'])) {
            error_log(self::SUSPICIOUS_REFUSAL_MSG);
            $this->postRefusedApplyResult((string) $id, self::SUSPICIOUS_REFUSAL_MSG, 'suspicious patch');
            return;
        }
        if (isset($data['fix'])) {
            echo "Received fix: " . substr($data['fix'], 0, 100) . "...\n";
            // v1.43 launch-readiness: target-level dry_run mirrored on the fix payload.
            // When true, preview only -- do not write or restart. Defaults to false (legacy
            // behaviour) for older API builds that don't surface the flag yet.
            $targetDryRun = isset($data['dry_run']) ? (bool) $data['dry_run'] : false;
            $applyResult = $this->applyFix($data['fix'], $id, $targetDryRun);
            $success = $applyResult['success'] ?? false;

            // v1.47 C1: Post-apply manifest. Only run when apply succeeded AND
            // this is not a dry-run preview — mirrors python/node, which skip
            // the restart in dry-run mode so a preview never bounces the app.
            $postApplyResult = null;
            if ($success && !$targetDryRun) {
                try {
                    $postApplyResult = $this->maybeRunPostApply((string)$id, is_array($data) ? $data : []);
                } catch (\Throwable $e) {
                    error_log('[patcherly] maybeRunPostApply raised: ' . $e->getMessage());
                    $postApplyResult = null;  // fail-open — apply-result must still report
                }
            }

            // Report result back
            $applyPayload = [
                'success' => $success,
                'fix_path' => $this->logFile,
                'test_result' => $applyResult['message'] ?? ($success ? 'Fix passed local tests.' : 'Fix failed or rolled back.')
            ];
            if ($targetDryRun) {
                $applyPayload['dry_run'] = true;
            }

            // FixApplyResult expects a flat `backup_path` string. Sending the
            // whole `backup_metadata` array is silently dropped server-side
            // (Pydantic ignores extras), which would leave `backup_path` null
            // in Mongo and break dashboard-initiated rollback.
            if (!empty($applyResult['backup_metadata']['backup_dir'])) {
                $applyPayload['backup_path'] = $applyResult['backup_metadata']['backup_dir'];
            }

            if ($postApplyResult !== null) {
                $applyPayload['post_apply'] = $postApplyResult;
            }

            // Capture HTTP status so we can detect 409 — server-side CAS already
            // advanced this error (race with another connector callback). Treat
            // 409 as terminal: log, do not retry, continue with the next pending
            // error. The server is canonical.
            [$applyRespBody, $applyStatus] = $this->sendSignedWithStatus('POST', PatcherlyApiPaths::appPath('errors', (string) $id, 'fix', 'apply-result'), $applyPayload);
            if ($applyStatus === 409) {
                $detail = '';
                $decoded = is_string($applyRespBody) ? json_decode($applyRespBody, true) : null;
                if (is_array($decoded) && isset($decoded['detail'])) {
                    $detail = (string)$decoded['detail'];
                }
                error_log("apply-result returned 409 for {$id}; server is canonical, not retrying. detail={$detail}");
            }

            // Optional warm-up before tests when post-apply restart steps actually
            // ran (e.g. systemctl reload php-fpm needs a moment before PHPUnit can
            // reconnect to a pooled DB). Mirrors PATCHERLY_POST_APPLY_TEST_DELAY_SEC
            // in connectors/python/python_agent.py and connectors/nodejs/node_agent.js.
            // Skipped on dry-run (no real restart happened) and when post-apply did
            // not run at all. Note: PHP CLI processes errors sequentially in
            // monitorLogs(), so the per-process apply→post-apply→tests workflow lock
            // used by Python/Node would be uncontended here and is intentionally
            // omitted; the per-error_id dedup in postApplySuccessErrorIds is enough
            // to avoid duplicate restarts within a single agent run.
            $delayRaw = (string)getenv('PATCHERLY_POST_APPLY_TEST_DELAY_SEC');
            $delaySec = is_numeric($delayRaw) ? (float)$delayRaw : 0.0;
            if (
                $delaySec > 0
                && $postApplyResult !== null
                && !empty($postApplyResult['ran'])
                && empty($postApplyResult['dry_run'])
            ) {
                usleep((int)round($delaySec * 1_000_000));
            }

            $this->runTestsAndReport($id, $success);
        } else {
            echo "No fix received from server.\n";
        }
    }

    private function extractFilesFromFix($fix) {
        /**
         * Extract file paths from fix content.
         * Handles unified diff format, JSON with patch field, etc.
         */
        $files = [];
        
        // Try to parse as JSON
        $fixJson = json_decode($fix, true);
        if (is_array($fixJson)) {
            $patchContent = $fixJson['patch'] ?? $fixJson['fix'] ?? null;
            if ($patchContent) $fix = $patchContent;
            $filesAffected = $fixJson['files_affected'] ?? [];
            if (!empty($filesAffected)) $files = array_merge($files, $filesAffected);
        }
        
        // Parse unified diff format
        $lines = explode("\n", $fix);
        foreach ($lines as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $filePath = trim(substr($line, 4));
                if (strpos($filePath, 'a/') === 0 || strpos($filePath, 'b/') === 0) {
                    $filePath = substr($filePath, 2);
                }
                if ($filePath && !in_array($filePath, $files)) {
                    $files[] = $filePath;
                }
            }
        }
        
        return !empty($files) ? $files : [$this->logFile];
    }

    public function applyFix($fix, $errorId = null, $dryRun = false) {
        echo "Applying fix (dry_run=" . ($dryRun ? 'true' : 'false') . "): " . substr($fix, 0, 100) . "...\n";
        
        // Extract file paths from fix
        $filesToBackup = $this->extractFilesFromFix($fix);
        
        // Create backup before applying fix
        $backupMetadata = null;
        try {
            if (!$dryRun) {
                $backupErrorId = $errorId ?: 'manual_' . bin2hex(random_bytes(4));
                $backupMetadata = $this->backupManager->createBackup(
                    $backupErrorId,
                    $filesToBackup,
                    true, // compress
                    true  // verify
                );
                echo "Created backup: {$backupMetadata['backup_dir']}\n";
            }
            
            // Parse and apply patch
            try {
                // Try to parse as unified diff patch
                $filePatches = $this->patchApplicator->parsePatch($fix);
                echo "Parsed patch: " . count($filePatches) . " file(s) to modify\n";
                
                $appliedFiles = [];
                $syntaxErrorsAll = [];
                
                // Apply patches to each file
                foreach ($filePatches as $filePatch) {
                    $filePath = $filePatch->filePath;
                    
                    // Resolve absolute path if relative
                    if (!pathinfo($filePath, PATHINFO_DIRNAME) || !realpath($filePath)) {
                        // Try to find file in current directory or common locations
                        $candidates = [
                            $filePath,
                            __DIR__ . '/' . $filePath,
                            __DIR__ . '/src/' . $filePath,
                            __DIR__ . '/app/' . $filePath,
                        ];
                        $found = false;
                        foreach ($candidates as $candidate) {
                            if (file_exists($candidate)) {
                                $filePath = realpath($candidate);
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            // Use relative path as-is (will create if needed)
                            $filePath = realpath(__DIR__) . '/' . $filePatch->filePath;
                        }
                    } else {
                        $filePath = realpath($filePath) ?: $filePath;
                    }

                    if ($this->isPathExcluded((string)$filePath)) {
                        throw new PatchApplyError("Refusing to apply patch to excluded path: {$filePath}");
                    }
                    
                    // Apply patch
                    $result = $this->patchApplicator->applyPatch(
                        $filePatch,
                        $filePath,
                        $dryRun,
                        true // verify syntax
                    );
                    
                    if (!$result['success']) {
                        throw new PatchApplyError("Failed to apply patch to {$filePatch->filePath}: {$result['message']}");
                    }
                    
                    if (!empty($result['syntaxErrors'])) {
                        foreach ($result['syntaxErrors'] as $err) {
                            $syntaxErrorsAll[] = "{$filePatch->filePath}: {$err}";
                        }
                    }
                    
                    $appliedFiles[] = $filePath;
                    echo "Applied patch to {$filePath}: {$result['message']}\n";
                }
                
                if ($dryRun) {
                    return [
                        'success' => true,
                        'message' => "Dry-run: Patch would be applied to " . count($appliedFiles) . " file(s).",
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                if (!empty($syntaxErrorsAll)) {
                    echo "Syntax errors after patch application: " . implode('; ', $syntaxErrorsAll) . "\n";
                    if ($backupMetadata) {
                        $this->rollbackFromBackup($backupMetadata);
                    }
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed: ' . implode('; ', $syntaxErrorsAll),
                        'backup_metadata' => $backupMetadata
                    ];
                }
                
                return [
                    'success' => true,
                    'message' => "Patch applied successfully to " . count($appliedFiles) . " file(s).",
                    'backup_metadata' => $backupMetadata
                ];
                
            } catch (PatchParseError $e) {
                echo "Failed to parse patch, falling back to simple fix: {$e->getMessage()}\n";
                // Fallback: treat fix as simple text replacement
                return $this->applySimpleFix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata);
            } catch (PatchApplyError $e) {
                echo "Failed to apply patch: {$e->getMessage()}\n";
                if ($backupMetadata) {
                    $this->rollbackFromBackup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => $e->getMessage(),
                    'backup_metadata' => $backupMetadata
                ];
            }
        } catch (Exception $e) {
            echo "Exception during fix application: " . $e->getMessage() . "\n";
            if ($backupMetadata) {
                $this->rollbackFromBackup($backupMetadata);
            }
            return ['success' => false, 'message' => 'Exception during fix application: ' . $e->getMessage(), 'backup_metadata' => $backupMetadata];
        }
    }
    
    private function applySimpleFix($fix, $filesToBackup, $errorId, $dryRun, $backupMetadata) {
        /**
         * Apply a simple fix when patch parsing fails.
         * Fallback for non-patch format fixes.
         */
        if ($dryRun) {
            return [
                'success' => true,
                'message' => 'Dry-run: Simple fix would be applied.',
                'backup_metadata' => $backupMetadata
            ];
        }
        
        echo "Applying simple fix (non-patch format)\n";
        
        // If log_file is in backup list, we can write fix there as a test
        if (in_array($this->logFile, $filesToBackup)) {
            try {
                file_put_contents($this->logFile, $fix);
                return [
                    'success' => true,
                    'message' => 'Simple fix applied (written to log file).',
                    'backup_metadata' => $backupMetadata
                ];
            } catch (Exception $e) {
                if ($backupMetadata) {
                    $this->rollbackFromBackup($backupMetadata);
                }
                return [
                    'success' => false,
                    'message' => "Failed to apply simple fix: {$e->getMessage()}",
                    'backup_metadata' => $backupMetadata
                ];
            }
        }
        
        return [
            'success' => true,
            'message' => 'Simple fix processed (no files modified).',
            'backup_metadata' => $backupMetadata
        ];
    }
    
    private function rollbackFromBackup($backupMetadata) {
        if (!$backupMetadata) {
            echo "No backup metadata provided for rollback\n";
            return false;
        }
        
        try {
            $success = $this->backupManager->restoreBackup($backupMetadata['backup_dir']);
            if ($success) {
                echo "Rollback from backup successful: {$backupMetadata['backup_dir']}\n";
            } else {
                echo "Rollback from backup failed: {$backupMetadata['backup_dir']}\n";
            }
            return $success;
        } catch (Exception $e) {
            echo "Exception during rollback from backup: " . $e->getMessage() . "\n";
            return false;
        }
    }

    private function sendPostJson($url, $data, $headers = []) {
        $ch = curl_init($url);
        $h = ['Content-Type: application/json'];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADER, true);
        $response = curl_exec($ch);
        if(curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch) . "\n";
            $response = false;
        }
        $status = 0;
        $body = '';
        if ($response !== false) {
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = substr($response, $header_size);
        }
        curl_close($ch);
        if ($response === false) return false;
        if ($status === 409) return 409;
        return $body;
    }
    /**
     * Phase-4 (v1.46) — Resolve OAuth credentials once, cache for the process.
     * Returns the credential bundle on success, ``null`` if no credentials are
     * available (the caller must short-circuit with a "run patcherly login" hint).
     */
    private function resolveOAuthCreds(): ?array {
        if ($this->oauthResolved) return $this->oauthCreds;
        $this->oauthResolved = true;
        if (!$this->oauthCredFile || !is_file($this->oauthCredFile)) return null;
        $raw = @file_get_contents($this->oauthCredFile);
        if ($raw === false) {
            error_log("[patcherly] credential file unreadable: {$this->oauthCredFile}");
            return null;
        }
        $bundle = json_decode($raw, true);
        if (!is_array($bundle) || empty($bundle['access_token']) || empty($bundle['hmac_secret'])) {
            return null;
        }
        $this->oauthCreds = $bundle;
        return $bundle;
    }

    /**
     * Refresh the OAuth bundle when within 30s of expiry, persisting the new
     * tokens back to ``credentials.json``. Returns the (possibly refreshed)
     * bundle, or ``null`` if refresh fails (operator must run ``patcherly login``).
     */
    private function ensureFreshOAuth(): ?array {
        $creds = $this->resolveOAuthCreds();
        if (!$creds) return null;
        $expiresAt = $creds['expires_at'] ?? null;
        $needsRefresh = false;
        if ($expiresAt) {
            $ts = strtotime((string)$expiresAt);
            if ($ts === false || $ts - 30 <= time()) $needsRefresh = true;
        }
        if (!$needsRefresh) return $creds;
        $refresh = $creds['refresh_token'] ?? '';
        if (!$refresh) {
            error_log('[patcherly] OAuth access expired and no refresh_token. Run `patcherly login`.');
            return null;
        }
        require_once __DIR__ . '/oauth_client.php';
        try {
            $fresh = patcherly_oauth_refresh_token($this->serverUrl, $this->oauthClientId, $refresh);
        } catch (\Throwable $e) {
            patcherly_oauth_signal_disconnect_best_effort(
                $this->serverUrl,
                $this->oauthClientId,
                $refresh,
                is_string($creds['access_token'] ?? null) ? $creds['access_token'] : null
            );
            error_log("[patcherly] OAuth refresh failed: {$e->getMessage()}. Run `patcherly login`.");
            return null;
        }
        if (!is_array($fresh) || empty($fresh['access_token'])) return null;
        $this->oauthCreds = $fresh;
        @file_put_contents($this->oauthCredFile, json_encode($fresh, JSON_PRETTY_PRINT));
        @chmod($this->oauthCredFile, 0600);
        return $fresh;
    }

    /**
     * Build the auth-and-signing headers for an outbound request.
     *
     * OAuth mode: ``Authorization: Bearer …`` + ``X-Patcherly-Timestamp``
     *             + ``X-Patcherly-Signature`` (HMAC-SHA256 over
     *             ``METHOD\npath\nts\nbody``, hex).
     *
     * If no valid OAuth credentials are available the request is sent without
     * auth headers — the API will return 401, which is the correct signal for
     * the operator to run ``patcherly login``.
     *
     * Caller-supplied headers take precedence (e.g. ``Content-Type``).
     */
    private function buildAuthHeaders(string $method, string $path, string $body, array $headers = []): array {
        $creds = $this->ensureFreshOAuth();
        if ($creds) {
            $ts = (string) time();
            $sig = hash_hmac('sha256', strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $body, $creds['hmac_secret']);
            $headers['Authorization'] = 'Bearer ' . $creds['access_token'];
            $headers['X-Patcherly-Timestamp'] = $ts;
            $headers['X-Patcherly-Signature'] = $sig;
            if (!empty($creds['hmac_secret_id'])) {
                $headers['X-Patcherly-Hmac-Kid'] = $creds['hmac_secret_id'];
            }
        }
        return $headers;
    }

    private function sendSigned($method, $path, $data = null, $headers = []) {
        // Use buildApiEndpoint to construct URLs correctly for proxy deployments
        $url = (strpos($path, 'http') === 0) ? $path : $this->buildApiEndpoint($path);
        $body = ($method === 'GET') ? '' : json_encode($data ?: []);
        $headers = $this->buildAuthHeaders($method, $path, $body, $headers);
        if ($method === 'GET') return $this->sendGet($url, $headers);
        return $this->sendPostJson($url, $data ?: [], $headers);
    }

    /**
     * Like sendSigned but returns [$responseBody, $httpStatusCode] so callers can
     * inspect specific status codes (e.g. 409 low_confidence_confirmation_required).
     *
     * @return array{string|false, int}  [$body, $statusCode]
     */
    private function sendSignedWithStatus(string $method, string $path, $data = null, array $headers = []): array {
        $url = (strpos($path, 'http') === 0) ? $path : $this->buildApiEndpoint($path);
        $bodyStr = ($method === 'GET') ? '' : json_encode($data ?: []);
        $headers = $this->buildAuthHeaders($method, $path, $bodyStr, $headers);
        $ch = curl_init($url);
        $h = ['Content-Type: application/json'];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADER, true);
        if ($method !== 'GET') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data ?: []));
        }
        $raw = curl_exec($ch);
        $statusCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body = ($raw !== false) ? substr($raw, $headerSize) : false;
        curl_close($ch);
        return [$body, $statusCode];
    }

    private function loadOrDiscoverIds() : void {
        // Load cached ids if present
        try {
            if (is_string($this->idsPath) && file_exists($this->idsPath)) {
                $json = json_decode(@file_get_contents($this->idsPath), true);
                if (is_array($json)) {
                    $this->tenantId = isset($json['tenant_id']) ? (string)$json['tenant_id'] : null;
                    $this->targetId = isset($json['target_id']) ? (string)$json['target_id'] : null;
                    $this->excludePaths = isset($json['exclude_paths']) && is_array($json['exclude_paths']) ? $json['exclude_paths'] : [];
                    $this->excludePathsCacheTime = isset($json['exclude_paths_cache_time']) ? (int)$json['exclude_paths_cache_time'] : 0;
                }
                if ($this->tenantId && $this->targetId) return;
            }
        } catch (\Throwable $e) {
            // ignore read errors
        }
        // Discover via connector-status using OAuth bearer token
        $creds = $this->ensureFreshOAuth();
        if (!$creds) {
            echo "OAuth credentials not found. Run `patcherly login` to authenticate.\n";
            return;
        }
        [$resp, $httpCode] = $this->sendSignedWithStatus('GET', PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_STATUS);
        if ($resp === false || $httpCode !== 200) {
            if ($httpCode === 401) {
                echo "OAuth authentication failed. Run `patcherly login` to re-authenticate.\n";
            } elseif ($httpCode >= 500) {
                echo "API server error (status $httpCode): API may be down or experiencing issues.\n";
                echo "Will retry on next discovery attempt. Agent will continue monitoring logs.\n";
            } else {
                echo "API request failed (HTTP $httpCode). API may be down or unreachable.\n";
                echo "Will retry on next discovery attempt. Agent will continue monitoring logs.\n";
            }
            return;
        }
        $j = json_decode($resp, true);
        if (is_array($j)) {
            if (isset($j['tenant_id'])) $this->tenantId = (string)$j['tenant_id'];
            if (isset($j['target_id'])) $this->targetId = (string)$j['target_id'];
            if (isset($j['exclude_paths']) && is_array($j['exclude_paths'])) {
                $this->excludePaths = $j['exclude_paths'];
                $this->excludePathsCacheTime = time();
            }
        }
        // Persist if both are known
        if ($this->tenantId && $this->targetId) {
            try { 
                @file_put_contents($this->idsPath, json_encode([
                    'tenant_id' => $this->tenantId, 
                    'target_id' => $this->targetId,
                    'exclude_paths' => $this->excludePaths,
                    'exclude_paths_cache_time' => $this->excludePathsCacheTime
                ], JSON_PRETTY_PRINT)); 
            } catch (\Throwable $e) {}
        }
    }
    
    private function updateExcludePaths() : void {
        // Update exclude_paths from connector-status endpoint if cache is stale
        $currentTime = time();
        if ($currentTime - $this->excludePathsCacheTime < $this->excludePathsCacheTtl) {
            return; // Cache still valid
        }
        
        if (!$this->ensureFreshOAuth()) return;
        
        try {
            [$response, $httpCode] = $this->sendSignedWithStatus('GET', PatcherlyApiPaths::NAMED_TARGETS_CONNECTOR_STATUS);
            
            if ($response !== false && $httpCode === 200) {
                $j = json_decode($response, true);
                if (is_array($j) && isset($j['exclude_paths']) && is_array($j['exclude_paths'])) {
                    $this->excludePaths = $j['exclude_paths'];
                    $this->excludePathsCacheTime = $currentTime;
                    // Update cache file
                    try {
                        if (file_exists($this->idsPath)) {
                            $json = json_decode(@file_get_contents($this->idsPath), true);
                            if (is_array($json)) {
                                $json['exclude_paths'] = $this->excludePaths;
                                $json['exclude_paths_cache_time'] = $this->excludePathsCacheTime;
                                file_put_contents($this->idsPath, json_encode($json, JSON_PRETTY_PRINT));
                            }
                        }
                    } catch (\Throwable $e) {
                        // Non-critical
                    }
                }
            }
        } catch (\Throwable $e) {
            // Non-critical
        }
    }
    
    private function isPathExcluded($filePath) : bool {
        // Check if a file path matches any exclusion pattern (PRIMARY filtering)
        if (empty($this->excludePaths)) {
            return false;
        }
        
        $normalizedPath = str_replace('\\', '/', $filePath);
        
        foreach ($this->excludePaths as $pattern) {
            if (empty($pattern)) continue;
            
            $normalizedPattern = str_replace('\\', '/', $pattern);
            
            // Check exact match
            if ($normalizedPath === $normalizedPattern || $filePath === $pattern) {
                return true;
            }
            
            // Simple glob matching
            $regexPattern = str_replace(['**', '*', '?'], ['.*', '[^/]*', '.'], preg_quote($normalizedPattern, '/'));
            if (preg_match('/^' . $regexPattern . '$/', $normalizedPath) || preg_match('/^' . $regexPattern . '$/', $filePath)) {
                return true;
            }
            
            // Check if pattern appears in path
            $patternClean = rtrim($normalizedPattern, '/');
            if (!empty($patternClean) && (strpos($normalizedPath, $patternClean) !== false || strpos($filePath, $patternClean) !== false)) {
                // For directory patterns ending with /, check directory match
                if (substr($pattern, -1) === '/' || substr($normalizedPattern, -1) === '/') {
                    $pathParts = explode('/', $normalizedPath);
                    $patternParts = explode('/', $patternClean);
                    for ($i = 0; $i <= count($pathParts) - count($patternParts); $i++) {
                        if (array_slice($pathParts, $i, count($patternParts)) === $patternParts) {
                            return true;
                        }
                    }
                } else {
                    // For file patterns
                    if (strpos($normalizedPath, $patternClean) !== false || strpos($filePath, $patternClean) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    private function extractFilePath($errorContext) : ?string {
        // Extract file path from error context/traceback
        if (empty($errorContext)) return null;
        
        // Try to extract from traceback (common format: "File \"/path/to/file.php\", line 123")
        if (preg_match('/File\s+["\']([^"\']+)["\']/', $errorContext, $matches)) {
            return $matches[1];
        }
        
        return null;
    }

    private function sendGet($url, $headers = [], &$responseHeaders = null, &$statusCode = null) {
        $ch = curl_init($url);
        $h = [];
        foreach ($headers as $k => $v) { $h[] = $k . ': ' . $v; }
        if ($h) { curl_setopt($ch, CURLOPT_HTTPHEADER, $h); }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$responseHeaders) {
            $len = strlen($header);
            $header = explode(':', $header, 2);
            if (count($header) < 2) return $len;
            $responseHeaders[trim($header[0])] = trim($header[1]);
            return $len;
        });
        $response = curl_exec($ch);
        if(curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch) . "\n";
            $response = false;
        }
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $response;
    }
    
    private function verifyResponseHmac($method, $path, $body, $signature, $timestamp) {
        // HMAC verification is MANDATORY - always required, cannot be disabled
        // Reject if signature or timestamp headers are missing
        if (empty($signature) || empty($timestamp)) {
            echo "HMAC verification MANDATORY: Missing signature or timestamp headers - patch rejected\n";
            return false;
        }
        
        // Get HMAC secret from OAuth credentials
        $creds = $this->ensureFreshOAuth();
        $secret = $creds['hmac_secret'] ?? '';

        if (empty($secret)) {
            echo "HMAC verification MANDATORY: Secret not configured - patch rejected\n";
            return false;
        }
        
        // Verify timestamp (5 minute window)
        try {
            $ts = (int)$timestamp;
            $now = time();
            if (abs($now - $ts) > 300) {
                echo "Stale timestamp: " . abs($now - $ts) . " seconds old\n";
                return false;
            }
        } catch (Exception $e) {
            echo "Invalid timestamp format\n";
            return false;
        }
        
        // Compute expected signature
        $bodyStr = is_string($body) ? $body : '';
        $canonical = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $bodyStr;
        $expected = hash_hmac('sha256', $canonical, $secret);
        
        // Compare signatures (timing-safe)
        if (!hash_equals($expected, $signature)) {
            echo "HMAC signature verification failed\n";
            return false;
        }
        
        return true;
    }

    private function enqueue(array $payload) : void {
        $this->queueManager->enqueue($payload);
    }

    /** @var array<string,bool> in-memory de-dupe of error_ids handled this run */
    private $rolledBackSeen = [];

    /**
     * Pick up errors that the API has transitioned to ``rolling_back`` because
     * an operator clicked **Rollback** in the dashboard, restore the affected
     * files from the local pre-apply backup, and report the outcome to
     * ``POST /api/errors/{id}/fix/rollback``. Without this poll, dashboard-
     * initiated rollback would stall server-side.
     */
    public function processRollingBackErrors() : void {
        if (!$this->targetId) {
            return; // nothing to scope by yet
        }

        $listPath = PatcherlyApiPaths::NAMED_ERRORS_LIST;
        $listQuery = '?status=rolling_back&target_id=' . rawurlencode((string)$this->targetId) . '&limit=50';
        $url = $this->buildApiEndpoint($listPath . $listQuery);
        $reqHeaders = $this->buildAuthHeaders('GET', $listPath . $listQuery, '');
        $respHeaders = [];
        $httpCode = 0;
        $body = $this->sendGet($url, $reqHeaders, $respHeaders, $httpCode);
        if ($body === false) {
            return;
        }
        if ($httpCode !== 200) {
            return;
        }
        $items = json_decode($body, true);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $errorId = isset($item['id']) ? (string)$item['id'] : '';
            if ($errorId === '' || isset($this->rolledBackSeen[$errorId])) continue;
            $this->rolledBackSeen[$errorId] = true;

            $backupPath = isset($item['backup_path']) ? (string)$item['backup_path'] : '';
            $success = false;
            $message = '';
            try {
                if ($backupPath === '') {
                    $message = 'No backup_path on error; cannot restore.';
                } else {
                    $success = (bool)$this->backupManager->restoreBackup($backupPath);
                    $message = $success
                        ? 'Rollback restored files from backup.'
                        : 'Rollback restore failed; backup directory may be missing or tampered with.';
                }
            } catch (\Throwable $e) {
                error_log('Patcherly: restoreBackup raised for ' . $errorId . ': ' . $e->getMessage());
                $message = 'Restore raised: ' . $e->getMessage();
            }

            $payload = [
                'success' => (bool)$success,
                'backup_path' => $backupPath !== '' ? $backupPath : null,
                'message' => $message,
            ];
            $apiPath = PatcherlyApiPaths::appPath('errors', rawurlencode($errorId), 'fix', 'rollback');
            $resp = $this->sendSigned('POST', $apiPath, $payload);
            if ($resp === false || (is_int($resp) && ($resp < 200 || $resp >= 300))) {
                error_log('Patcherly: rollback report for ' . $errorId . ' returned ' . var_export($resp, true));
                unset($this->rolledBackSeen[$errorId]); // allow retry on next tick
            }
        }
    }

    public function drainQueue() : void {
        if ($this->isProtectionModeStandby()) {
            return;
        }
        $this->queueManager->drainQueue(function($payload) {
            [$body, $code] = $this->sendSignedWithStatus('POST', PatcherlyApiPaths::NAMED_ERRORS_INGEST, $payload);

            if ($body === false && $code === 0) {
                return 'server_error';
            }
            if ($this->handleProtectionModeHttp((int) $code, is_string($body) ? $body : '')) {
                return 'server_error';
            }
            if ($code === 409) {
                return 'duplicate';
            } elseif ($code >= 200 && $code < 300) {
                return 'success';
            } elseif ($code >= 500 || $code === 429) {
                return 'server_error';
            } else {
                return 'client_error';
            }
        });
    }

    /**
     * Detect framework for ingest payload (code_framework). Used for AI template selection.
     * Mirrors context_collector logic; no dependency on context collector.
     */
    private function detectFrameworkForIngest() : ?string {
        if (class_exists('Illuminate\Foundation\Application')) {
            return 'laravel';
        }
        if (class_exists('Symfony\Component\HttpKernel\Kernel')) {
            return 'symfony';
        }
        if (defined('CI_VERSION')) {
            return 'codeigniter';
        }
        if (class_exists('yii\base\Application')) {
            return 'yii';
        }
        if (class_exists('Zend\Version\Version')) {
            return 'zend';
        }
        return null;
    }

    private function uuidv4() : string {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

/**
 * Local HTTP request handler for the optional file-content + local-approvals
 * server. Designed to be the entry point of PHP's built-in web server (SAPI
 * `cli-server`):
 *
 *   php -S 127.0.0.1:8083 connectors/php/php_agent.php
 *
 * Under `cli-server` PHP dispatches every incoming request through this
 * script, populates `$_SERVER['REQUEST_URI']` / `$_SERVER['REQUEST_METHOD']`,
 * and handles socket accept / lifecycle. We deliberately do NOT use
 * `pcntl_fork()` / a hand-rolled socket server here -- that was the shape of
 * an older entry block that never opened a listener and left the
 * `/api/file-content` + `/local-approvals` routes unreachable in 1.45.x and
 * earlier (tracked in `_dev/security/semgrep/follow-ups.md`).
 *
 * The function does NOT enter under the plain `cli` SAPI (used for
 * simulate+drain runs of the agent) -- the gate at the bottom of this file
 * routes only `cli-server` requests through here.
 */
function patcherly_php_local_router() {
    $agent = new PHPAgent();
    $router = function() use ($agent) {
                $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
                header('Content-Type: application/json');
                // Get server URL safely using reflection or method access
                $reflection = new ReflectionClass($agent);
                $serverUrlProp = $reflection->getProperty('serverUrl');
                $serverUrlProp->setAccessible(true);
                $serverUrl = $serverUrlProp->getValue($agent) ?: 'http://localhost:8000';
                
                /**
                 * Error IDs are short opaque tokens (uuid / hex / safe slugs).
                 * Reject anything that could affect URL structure or smuggle
                 * path segments before substituting into the upstream
                 * /api/errors/{id}/(approve|dismiss) URL.
                 */
                $approvalIdRe = '/^[A-Za-z0-9_-]{1,128}$/';

                /**
                 * Defence-in-depth file-read scope. Honours the same env var
                 * the Node connector uses (PATCHERLY_TARGET_ROOTS, path-separator
                 * delimited list). Falls back to cwd at startup so the connector
                 * cannot accidentally serve files outside the directory it was
                 * launched from even if the token is later compromised.
                 */
                $allowedRoots = array_values(array_filter(array_map(
                    function ($p) { $r = $p !== '' ? @realpath($p) : false; return $r === false ? null : $r; },
                    array_merge(
                        explode(PATH_SEPARATOR, getenv('PATCHERLY_TARGET_ROOTS') ?: ''),
                        [getcwd() ?: '.']
                    )
                )));
                $allowedRoots = array_values(array_unique($allowedRoots));

                $isPathWithinAllowedRoots = function (string $candidate) use ($allowedRoots) : bool {
                    if ($candidate === '') { return false; }
                    foreach ($allowedRoots as $root) {
                        if ($root === '' || $root === false) { continue; }
                        $rootWithSep = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                        if ($candidate === $root || strpos($candidate, $rootWithSep) === 0) {
                            return true;
                        }
                    }
                    return false;
                };

                /**
                 * Verify the inbound request carries a valid OAuth Bearer token
                 * matching the access_token in the local credential store.
                 * Returns true on success; sends 401/503 and returns false on failure.
                 */
                $requireBearerToken = function () : bool {
                    require_once __DIR__ . '/credential_store.php';
                    $store = new PatcherlyCredentialStore();
                    $creds = $store->load();
                    if ($creds === null || empty($creds['access_token'])) {
                        http_response_code(503);
                        echo json_encode(['success' => false, 'error' => 'Service unavailable: connector not authenticated. Run `patcherly login`.']);
                        return false;
                    }
                    $expected = (string) $creds['access_token'];
                    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
                    if (strncasecmp($authHeader, 'Bearer ', 7) !== 0) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: missing Bearer token']);
                        return false;
                    }
                    $provided = substr($authHeader, 7);
                    if (!hash_equals($expected, (string)$provided)) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized: invalid Bearer token']);
                        return false;
                    }
                    return true;
                };

                // File content endpoint for AI analysis
                if ($path === PatcherlyApiPaths::CONNECTOR_CONTRACT_FILE_CONTENT && $_SERVER['REQUEST_METHOD']==='POST'){
                    if (!$requireBearerToken()) { return; }
                    
                    $input = file_get_contents('php://input');
                    
                    // Process request
                    $payload = json_decode($input, true);
                    
                    if (!$payload || !isset($payload['file_path'])) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'error' => 'Missing file_path']);
                        return;
                    }
                    
                    $filePath = $payload['file_path'];
                    $lineNumber = $payload['line_number'] ?? null;
                    $contextLines = $payload['context_lines'] ?? 50;
                    
                    // Validate file path (prevent directory traversal)
                    $realPath = realpath($filePath);
                    if (!$realPath || !file_exists($realPath)) {
                        http_response_code(404);
                        echo json_encode(['success' => false, 'error' => 'File not found']);
                        return;
                    }

                    // Defence-in-depth: the Bearer token gate above stops external callers,
                    // but we still must not serve files outside the directory the operator
                    // launched the connector from (or PATCHERLY_TARGET_ROOTS).
                    if (!$isPathWithinAllowedRoots($realPath)) {
                        http_response_code(403);
                        echo json_encode(['success' => false, 'error' => 'File path is outside the connector project root']);
                        return;
                    }
                    
                    // Read file
                    $lines = file($realPath);
                    if ($lines === false) {
                        http_response_code(500);
                        echo json_encode(['success' => false, 'error' => 'Failed to read file']);
                        return;
                    }
                    
                    // Extract relevant lines
                    $totalLines = count($lines);
                    $startLine = 1;
                    $endLine = $totalLines;
                    
                    if ($lineNumber !== null) {
                        $startLine = max(1, $lineNumber - $contextLines);
                        $endLine = min($totalLines, $lineNumber + $contextLines);
                    }
                    
                    $content = implode('', array_slice($lines, $startLine - 1, $endLine - $startLine + 1));
                    
                    // Sanitize content
                    require_once __DIR__ . '/sanitizer.php';
                    $result = \Patcherly\Connector\Sanitizer::sanitizeSensitiveData($content);
                    
                    echo json_encode([
                        'success' => true,
                        'content' => $result['sanitized_content'],
                        'redacted_ranges' => $result['redacted_lines'],
                        'start_line' => $startLine,
                        'end_line' => $endLine,
                        'total_lines' => $totalLines,
                        'file_path' => $filePath
                    ]);
                    return;
                }
                
                if ($path === '/local-approvals' && $_SERVER['REQUEST_METHOD']==='GET'){
                    if (!$requireBearerToken()) { return; }
                    $resp = file_get_contents($serverUrl . PatcherlyApiPaths::NAMED_ERRORS_LIST . '?status=awaiting_approval');
                    echo $resp ?: '[]'; return;
                }
                if (preg_match('#^/local-approvals/([^/]+)/(approve|dismiss)$#', $path, $m)){
                    if (!$requireBearerToken()) { return; }
                    $id = $m[1]; $act = $m[2];
                    if (!preg_match($approvalIdRe, $id)) {
                        http_response_code(400);
                        echo json_encode(['error' => 'error_id must match ^[A-Za-z0-9_-]{1,128}$']);
                        return;
                    }
                    $url = $serverUrl . PatcherlyApiPaths::appPath('errors', rawurlencode($id), $act);
                    $ch = curl_init($url); curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST'); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $resp = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
                    http_response_code($code ?: 200); echo $resp ?: '{}'; return;
                }
                echo '[]';
    };
    $router();
}

/**
 * Entry-point dispatch.
 *
 *   - `cli-server` SAPI (i.e. invoked as `php -S 127.0.0.1:8083 php_agent.php`)
 *     -> serve one HTTP request via patcherly_php_local_router(), then return
 *     so `php -S` can move on to the next connection. The router covers
 *     /api/file-content (Bearer token + project-root scope) and
 *     /local-approvals/{id}/(approve|dismiss) (Bearer token + id regex).
 *
 *   - `cli` SAPI (i.e. plain `php php_agent.php`) -> run the long-lived
 *     poll loop: discover API URL, tail the application log file, send
 *     detected errors to Patcherly, and pick up dashboard-initiated rollbacks.
 *     The loop polls every 5s (`monitorLogs()` internal `sleep(5)`); see
 *     Option B in help/connectors/php.md for the embedded-in-app variant.
 *     Requires prior `patcherly login` (OAuth Device Authorization Grant).
 */
if (php_sapi_name() === 'cli-server') {
    patcherly_php_local_router();
    return;
}

// `PATCHERLY_AGENT_NOAUTORUN=1` suppresses the auto-bootstrap when this file
// is `require_once`-ed from a test harness — mirrors Python's `__main__`
// idiom so connectors/php/tests/*.php can load the agent class without also
// kicking off `monitorLogs()` / discovery side-effects.
if (php_sapi_name() === 'cli' && !getenv('PATCHERLY_AGENT_NOAUTORUN')) {
    $agent = new PHPAgent();
    $agent->monitorLogs();
}

?>
