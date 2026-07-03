<?php
/**
 * Local OAuth credential store for the Patcherly PHP connector.
 *
 * Phase-4 (RFC 8628) onboarding stores its access/refresh/HMAC bundle here
 * instead of the legacy ``api_key`` env entry. File is created with 0o600
 * perms so a shared-host neighbor cannot read it.
 *
 * Default path:
 *   $HOME/.patcherly/credentials.json
 * Override via:
 *   PATCHERLY_CREDENTIAL_FILE=/some/path/credentials.json (env var)
 */

declare(strict_types=1);

class PatcherlyCredentialStore
{
    private string $filePath;

    public function __construct(?string $filePath = null)
    {
        if ($filePath !== null) {
            $this->filePath = $filePath;
            return;
        }
        $env = getenv('PATCHERLY_CREDENTIAL_FILE');
        if (is_string($env) && $env !== '') {
            $this->filePath = $env;
            return;
        }
        $home = getenv('HOME') ?: (getenv('USERPROFILE') ?: sys_get_temp_dir());
        $this->filePath = rtrim($home, '/\\') . DIRECTORY_SEPARATOR . '.patcherly' . DIRECTORY_SEPARATOR . 'credentials.json';
    }

    public function getFilePath(): string
    {
        return $this->filePath;
    }

    /** @return array<string,mixed>|null */
    public function load(): ?array
    {
        if (!is_file($this->filePath)) {
            return null;
        }
        $raw = @file_get_contents($this->filePath);
        if ($raw === false) {
            return null;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new RuntimeException(
                'Failed to parse credential file at ' . $this->filePath
            );
        }
        return $decoded;
    }

    /** @param array<string,mixed> $creds */
    public function save(array $creds): void
    {
        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $tmp = $this->filePath . '.tmp.' . getmypid();
        $payload = json_encode($creds, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            throw new RuntimeException('Failed to JSON-encode credentials');
        }
        if (file_put_contents($tmp, $payload) === false) {
            throw new RuntimeException('Failed to write credential temp file');
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $this->filePath)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to move credential temp file into place');
        }
        @chmod($this->filePath, 0600);
    }

    public function clear(): void
    {
        if (is_file($this->filePath)) {
            @unlink($this->filePath);
        }
    }

    /** @param array<string,mixed> $creds */
    public function isExpired(array $creds, int $skewSeconds = 30): bool
    {
        $ea = $creds['expires_at'] ?? null;
        if (!is_string($ea) || $ea === '') {
            return true;
        }
        $ts = strtotime($ea);
        if ($ts === false) {
            return true;
        }
        return (time() + $skewSeconds) >= $ts;
    }
}
