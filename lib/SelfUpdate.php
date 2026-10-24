<?php
/**
 * Archive-layout remote self-update for the PHP connector.
 *
 * Triggered only when connector-status returns connector_update with
 * desired_version / sha256 / artifact. Preserves .env and local state dirs.
 * Uses ZipArchive for php-connector.zip artifacts.
 */

declare(strict_types=1);

final class PatcherlySelfUpdate
{
    private const DEFAULT_ARTIFACT_BASE = 'https://download.patcherly.com/connectors';
    private const LAYOUT_MARKER = '.patcherly_install_layout';
    private const RATE_PATH = '.patcherly_update_last_attempt';

    /** @var list<string> */
    private const PRESERVE_NAMES = [
        '.env',
        'venv',
        'node_modules',
        'vendor',
        '.patcherly_backups',
        'patcherly_ids.json',
        'patcherly_queue.jsonl',
        '.protection_mode_until',
        self::RATE_PATH,
        self::LAYOUT_MARKER,
    ];

    /** @var bool Process-local swap lock */
    private static $swapBusy = false;

    private static function defaultInstallRoot(): string
    {
        return dirname(__DIR__);
    }

    /**
     * Return archive | registry | unknown for status heal.
     */
    public static function detectInstallLayout(?string $installRoot = null): string
    {
        $env = strtolower(trim(
            (string) (getenv('PATCHERLY_INSTALL_LAYOUT') ?: getenv('INSTALL_LAYOUT') ?: '')
        ));
        if (in_array($env, ['archive', 'registry', 'unknown'], true)) {
            return $env;
        }
        $root = $installRoot !== null ? $installRoot : self::defaultInstallRoot();
        $root = realpath($root) ?: $root;
        $marker = $root . DIRECTORY_SEPARATOR . self::LAYOUT_MARKER;
        if (is_file($marker)) {
            try {
                $val = strtolower(trim((string) @file_get_contents($marker)));
                if (in_array($val, ['archive', 'registry', 'unknown'], true)) {
                    return $val;
                }
            } catch (\Throwable $e) {
                // ignore
            }
        }
        $parts = array_map('strtolower', explode(DIRECTORY_SEPARATOR, $root));
        // Composer package under vendor → registry (not CDN self-update).
        if (in_array('vendor', $parts, true)) {
            return 'registry';
        }
        if (is_file($root . DIRECTORY_SEPARATOR . 'composer.json')
            && is_dir($root . DIRECTORY_SEPARATOR . 'vendor')) {
            return 'registry';
        }
        // Universal installer, CDN extract, monorepo, or Docker bind-mount.
        if (is_file($root . DIRECTORY_SEPARATOR . 'start.sh')
            || is_file($root . DIRECTORY_SEPARATOR . 'start.ps1')
            || is_file($root . DIRECTORY_SEPARATOR . 'patcherly_agent.php')) {
            return 'archive';
        }
        return 'unknown';
    }

    /**
     * Fragile host OR for dashboard auto (wiped when installer rewrites .env).
     */
    public static function preferAutoUpdateEnv(): bool
    {
        $raw = strtolower(trim(
            (string) (getenv('PATCHERLY_CONNECTOR_AUTO_UPDATE') ?: getenv('CONNECTOR_AUTO_UPDATE') ?: '')
        ));
        return in_array($raw, ['1', 'true', 'yes', 'on'], true);
    }

    public static function artifactBase(): string
    {
        $base = trim(
            (string) (
                getenv('PATCHERLY_ARTIFACT_BASE')
                ?: getenv('ARTIFACT_BASE')
                ?: getenv('CONNECTOR_ARTIFACT_BASE_URL')
                ?: self::DEFAULT_ARTIFACT_BASE
            )
        );
        $base = rtrim($base, '/');
        return $base !== '' ? $base : self::DEFAULT_ARTIFACT_BASE;
    }

    private static function rateOk(string $root, float $minIntervalSec = 3600.0): bool
    {
        $path = $root . DIRECTORY_SEPARATOR . self::RATE_PATH;
        try {
            if (!is_file($path)) {
                return true;
            }
            $last = (float) trim((string) @file_get_contents($path));
            return (microtime(true) - $last) >= $minIntervalSec;
        } catch (\Throwable $e) {
            return true;
        }
    }

    private static function stampRate(string $root): void
    {
        try {
            @file_put_contents(
                $root . DIRECTORY_SEPARATOR . self::RATE_PATH,
                (string) microtime(true)
            );
        } catch (\Throwable $e) {
            // ignore
        }
    }

    private static function sha256File(string $path): string
    {
        return hash_file('sha256', $path) ?: '';
    }

    private static function download(string $url, string $dest, int $timeoutSec = 120): void
    {
        $ctx = stream_context_create([
            'http' => [
                'timeout' => $timeoutSec,
                'header' => "User-Agent: Patcherly-Connector-PHP\r\n",
                'follow_location' => 1,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $data = @file_get_contents($url, false, $ctx);
        if ($data === false) {
            throw new \RuntimeException('download_failed');
        }
        if (@file_put_contents($dest, $data) === false) {
            throw new \RuntimeException('write_failed');
        }
    }

    /**
     * Extract zip and return the content root (handles single top-level folder).
     */
    private static function extractZip(string $archive, string $destDir): string
    {
        if (!class_exists('ZipArchive')) {
            throw new \RuntimeException('ZipArchive_unavailable');
        }
        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true)) {
            throw new \RuntimeException('mkdir_failed');
        }
        $zip = new \ZipArchive();
        $open = $zip->open($archive);
        if ($open !== true) {
            throw new \RuntimeException('zip_open_failed');
        }
        try {
            if (!$zip->extractTo($destDir)) {
                throw new \RuntimeException('zip_extract_failed');
            }
        } finally {
            $zip->close();
        }
        $children = array_values(array_filter(
            scandir($destDir) ?: [],
            static fn ($n) => $n !== '.' && $n !== '..'
        ));
        if (count($children) === 1) {
            $only = $destDir . DIRECTORY_SEPARATOR . $children[0];
            if (is_dir($only)) {
                return $only;
            }
        }
        return $destDir;
    }

    private static function copyTreePreserving(string $src, string $dest): void
    {
        $preserve = array_fill_keys(self::PRESERVE_NAMES, true);
        $entries = scandir($src) ?: [];
        foreach ($entries as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            if (isset($preserve[$name])) {
                continue;
            }
            $from = $src . DIRECTORY_SEPARATOR . $name;
            $to = $dest . DIRECTORY_SEPARATOR . $name;
            if (is_dir($from)) {
                if (is_dir($to)) {
                    self::rmTree($to);
                }
                self::copyTreeRecursive($from, $to);
            } else {
                if (!@copy($from, $to)) {
                    throw new \RuntimeException('copy_failed');
                }
            }
        }
    }

    private static function copyTreeRecursive(string $src, string $dest): void
    {
        if (!is_dir($dest) && !@mkdir($dest, 0755, true)) {
            throw new \RuntimeException('mkdir_failed');
        }
        foreach (scandir($src) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $from = $src . DIRECTORY_SEPARATOR . $name;
            $to = $dest . DIRECTORY_SEPARATOR . $name;
            if (is_dir($from)) {
                self::copyTreeRecursive($from, $to);
            } else {
                if (!@copy($from, $to)) {
                    throw new \RuntimeException('copy_failed');
                }
            }
        }
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_dir($path)) {
                self::rmTree($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * Download, verify, and swap.
     *
     * @param array<string, mixed> $intent
     * @return array{0: bool, 1: string, 2: ?string} [ok, reason_or_error, new_version]
     */
    public static function applyArchiveUpdate(array $intent, ?string $installRoot = null): array
    {
        $root = $installRoot !== null ? $installRoot : self::defaultInstallRoot();
        $resolved = realpath($root);
        $root = $resolved !== false ? $resolved : $root;

        $layout = self::detectInstallLayout($root);
        if ($layout === 'registry') {
            return [false, 'skipped_registry', null];
        }
        if ($layout !== 'archive') {
            return [false, 'skipped_unknown', null];
        }

        $desired = trim((string) ($intent['desired_version'] ?? ''));
        $sha = strtolower(trim((string) ($intent['sha256'] ?? '')));
        $artifact = trim((string) ($intent['artifact'] ?? ''));
        if ($desired === '' || $sha === '' || $artifact === '') {
            return [false, 'invalid_intent', null];
        }
        if (strpos($artifact, '..') !== false
            || (isset($artifact[0]) && $artifact[0] === '/')
            || strpos($artifact, '\\') !== false) {
            return [false, 'invalid_artifact', null];
        }

        if (self::$swapBusy) {
            return [false, 'swap_busy', null];
        }
        self::$swapBusy = true;
        $tmpRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-upd-' . bin2hex(random_bytes(8));
        try {
            if (!@mkdir($tmpRoot, 0700, true)) {
                return [false, 'tmpdir_failed', null];
            }
            if (!self::rateOk($root)) {
                return [false, 'rate_limited', null];
            }
            self::stampRate($root);

            $url = self::artifactBase() . '/' . $artifact;
            $archive = $tmpRoot . DIRECTORY_SEPARATOR . str_replace('/', '_', $artifact);
            try {
                self::download($url, $archive);
            } catch (\Throwable $exc) {
                return [false, 'download_failed:' . get_class($exc), null];
            }
            $digest = self::sha256File($archive);
            if ($digest !== $sha) {
                return [false, 'sha256_mismatch', null];
            }
            $extractRoot = $tmpRoot . DIRECTORY_SEPARATOR . 'extract';
            try {
                $content = self::extractZip($archive, $extractRoot);
            } catch (\Throwable $exc) {
                return [false, 'extract_failed:' . (method_exists($exc, 'getMessage') ? $exc->getMessage() : get_class($exc)), null];
            }
            try {
                self::copyTreePreserving($content, $root);
            } catch (\Throwable $exc) {
                return [false, 'swap_failed:' . get_class($exc), null];
            }
            try {
                @file_put_contents(
                    $root . DIRECTORY_SEPARATOR . self::LAYOUT_MARKER,
                    "archive\n"
                );
            } catch (\Throwable $e) {
                // ignore
            }
            error_log('[patcherly] Connector self-update swapped to ' . $desired);
            return [true, 'ok', $desired];
        } finally {
            self::$swapBusy = false;
            self::rmTree($tmpRoot);
        }
    }

    /**
     * Restart via systemd when available; otherwise exit so a supervisor can relaunch.
     */
    public static function scheduleRestartBestEffort(): void
    {
        try {
            $out = [];
            $code = 1;
            @exec('systemctl restart patcherly-connector 2>/dev/null', $out, $code);
            if ($code === 0) {
                error_log('[patcherly] Requested systemctl restart patcherly-connector');
                return;
            }
        } catch (\Throwable $e) {
            // fall through
        }
        try {
            if (function_exists('pcntl_exec')) {
                $php = PHP_BINARY;
                $script = $_SERVER['argv'][0] ?? null;
                if (is_string($script) && $script !== '' && is_file($script)) {
                    error_log('[patcherly] Re-executing connector process after self-update');
                    pcntl_exec($php, array_slice($_SERVER['argv'] ?? [$script], 0));
                }
            }
        } catch (\Throwable $e) {
            // fall through
        }
        error_log('[patcherly] Exiting after self-update so supervisor can relaunch');
        exit(0);
    }
}
