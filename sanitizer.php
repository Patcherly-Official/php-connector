<?php
/**
 * Sanitizer module for PHP code.
 *
 * This module provides functions to:
 * 1. Sanitize sensitive data (API keys, passwords, tokens) from PHP source code
 * 2. Check if patches are safe to apply (don't overwrite redacted sensitive data)
 *
 * Used by the file content endpoint and AI service to protect sensitive information.
 */

namespace Patcherly\Connector;

class Sanitizer
{
    /**
     * Patterns that span multiple lines and must run on the whole content BEFORE
     * the per-line loop. Same fix as connectors/python/sanitizer.py (1.46.0):
     * pasted PEM blocks were never redacted before because the loop only saw one
     * line at a time. Line count is preserved by padding the replacement with
     * the same number of newlines as the original match.
     *
     * 1.47.0 (V3): added the canonical OpenSSH "ssh-rsa AAAA…" blob shape so
     * that `~/.ssh/id_rsa.pub` dumps printed into a log/error trace get
     * redacted in one whole-content sweep.
     */
    private const MULTILINE_SENSITIVE_PATTERNS = [
        // `[A-Z ]*` (not `+`) so PKCS#8 unencrypted keys
        // (`-----BEGIN PRIVATE KEY-----` with no algorithm prefix — the
        // format `openssl pkcs8` exports for modern Ed25519/RSA/EC keys)
        // get redacted alongside OPENSSH / RSA / DSA / EC / ENCRYPTED
        // PRIVATE KEY blocks.
        '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/' => 'PRIVATE_KEY_REDACTED',
        '/(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\s+AAAA[A-Za-z0-9+\/=\s]{40,}(?:\s+[^\s\n]+)?/' => 'SSH_PUBLIC_KEY_REDACTED',
    ];

    /**
     * Common patterns for sensitive data in PHP.
     *
     * Notes for 1.47.0 (V3, "high-signal vendor tokens"):
     *   - The vendor-token regexes below are anchored on the canonical vendor
     *     PREFIX (AKIA / ASIA / ghp_ / ghs_ / xoxb- / sk_live_ / whsec_ / …)
     *     so they fire on log/trace text, not just on `$name = "value"` source.
     *   - Each replacement is a fixed placeholder, NEVER a back-reference
     *     into the matched value, so the secret cannot leak through the
     *     placeholder.
     */
    private const SENSITIVE_PATTERNS = [
        // API keys and tokens
        '/["\']([A-Za-z0-9_-]{32,})["\']/' => 'API_KEY_REDACTED',
        '/\$api[_-]?key\s*=\s*["\']([^"\']+)["\']/' => 'API_KEY_REDACTED',
        '/\$secret[_-]?key\s*=\s*["\']([^"\']+)["\']/' => 'SECRET_KEY_REDACTED',
        '/\$access[_-]?token\s*=\s*["\']([^"\']+)["\']/' => 'ACCESS_TOKEN_REDACTED',
        '/\$auth[_-]?token\s*=\s*["\']([^"\']+)["\']/' => 'AUTH_TOKEN_REDACTED',
        '/bearer\s+([A-Za-z0-9._-]{20,})/i' => 'BEARER_TOKEN_REDACTED',

        // HMAC / JWT / signing secrets (parity with the WordPress + Python + Node connectors)
        '/(hmac[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*=\s*["\']([^"\']{8,})["\']/i' => 'HMAC_SECRET_REDACTED',
        '/(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*=\s*["\']([^"\']{8,})["\']/i' => 'JWT_SECRET_REDACTED',

        // AWS credentials (parity with Python + Node)
        '/aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([^"\']+)["\']/i' => 'AWS_ACCESS_KEY_REDACTED',
        '/aws[_-]?secret[_-]?access[_-]?key\s*=\s*["\']([^"\']+)["\']/i' => 'AWS_SECRET_KEY_REDACTED',
        // 1.47.0 (V3): canonical AKIA*/ASIA* bare-value match so bare AWS access
        // keys in stack traces / shell history dumps get redacted even when they
        // are not wrapped in an aws_access_key_id="..." assignment.
        '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/' => 'AWS_ACCESS_KEY_ID_REDACTED',

        // 1.47.0 (V3): GitHub tokens (PAT / OAuth / user-to-server /
        // server-to-server / refresh). Spec: 36-255 base62 chars after prefix.
        '/\bgh[pousr]_[A-Za-z0-9]{36,255}\b/' => 'GITHUB_TOKEN_REDACTED',

        // 1.47.0 (V3): Slack legacy and rotated tokens (bot / user / app / signing).
        '/\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b/' => 'SLACK_TOKEN_REDACTED',
        '/\bxapp-[0-9]+-[A-Z0-9]+-[A-Za-z0-9]+\b/' => 'SLACK_APP_TOKEN_REDACTED',

        // 1.47.0 (V3): Stripe API keys (secret / restricted / publishable / webhook).
        '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_SECRET_KEY_REDACTED',
        '/\bpk_(?:live|test)_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_PUBLISHABLE_KEY_REDACTED',
        '/\bwhsec_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_WEBHOOK_SECRET_REDACTED',

        // Database credentials
        '/\$password\s*=\s*["\']([^"\']+)["\']/' => 'PASSWORD_REDACTED',
        '/\$db[_-]?password\s*=\s*["\']([^"\']+)["\']/' => 'DB_PASSWORD_REDACTED',
        '/\$mysql[_-]?password\s*=\s*["\']([^"\']+)["\']/' => 'MYSQL_PASSWORD_REDACTED',

        // SMTP / mail credentials (parity with the WordPress + Python + Node connectors)
        '/(smtp[_-]?password|mail[_-]?password|email[_-]?password)\s*=\s*["\']([^"\']+)["\']/i' => 'SMTP_PASSWORD_REDACTED',

        // define() constants with sensitive names
        '/define\s*\(\s*["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\s*,\s*["\']([^"\']+)["\']\s*\)/' => 'SENSITIVE_DEFINE_REDACTED',

        // Connection strings with credentials. 1.47.0 (V3): added `amqp(s)`,
        // `clickhouse(s)`, `mssql`, `oracle`, `jdbc:*://` shapes so RabbitMQ /
        // ClickHouse / SQL Server / Oracle URIs in error traces get redacted.
        '/(postgres|postgresql|mysql|pgsql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|clickhouse|clickhouses|mssql|oracle):\/\/([^:\s]+):([^@\s]+)@/' => '\1://USERNAME_REDACTED:PASSWORD_REDACTED@',
        '/jdbc:([a-z0-9]+):\/\/([^:\s]+):([^@\s]+)@/' => 'jdbc:\1://USERNAME_REDACTED:PASSWORD_REDACTED@',

        // $_ENV and getenv() with sensitive names
        '/\$_ENV\[["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\]/' => 'SENSITIVE_ENV_REDACTED',
        '/getenv\(["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\)/' => 'SENSITIVE_ENV_REDACTED',
    ];

    /**
     * Sanitize sensitive data from PHP source code.
     *
     * @param string $fileContent The raw file content
     * @return array Associative array with:
     *   - sanitized_content: The content with sensitive data replaced
     *   - redacted_lines: Array of line numbers that were redacted
     *   - metadata: Array with redaction statistics and warnings
     */
    public static function sanitizeSensitiveData(string $fileContent): array
    {
        // Pre-pass: redact multi-line PEM blocks at the whole-content level so the
        // per-line loop below can keep operating one line at a time without missing
        // cross-line secrets.
        foreach (self::MULTILINE_SENSITIVE_PATTERNS as $pattern => $replacement) {
            $fileContent = preg_replace_callback(
                $pattern,
                function ($match) use ($replacement) {
                    return $replacement . str_repeat("\n", substr_count($match[0], "\n"));
                },
                $fileContent
            );
        }

        $lines = explode("\n", $fileContent);
        $redactedLines = [];
        $redactionCount = 0;
        $redactionTypes = [];

        // Lines that the multi-line pre-pass just touched (look for the literal
        // replacement markers — extended in 1.47.0 V3 to also cover SSH
        // public-key blobs).
        $multilineMarkers = ['PRIVATE_KEY_REDACTED', 'SSH_PUBLIC_KEY_REDACTED'];
        foreach ($lines as $i => $line) {
            foreach ($multilineMarkers as $marker) {
                if (strpos($line, $marker) !== false) {
                    $redactedLines[] = $i + 1;
                    $redactionCount++;
                    if (!isset($redactionTypes[$marker])) {
                        $redactionTypes[$marker] = 0;
                    }
                    $redactionTypes[$marker]++;
                    break;
                }
            }
        }

        foreach (self::SENSITIVE_PATTERNS as $pattern => $replacement) {
            foreach ($lines as $i => $line) {
                // Skip comments (basic check)
                if (preg_match('/^\s*\/\//', $line) || preg_match('/^\s*#/', $line) || preg_match('/^\s*\/\*/', $line)) {
                    continue;
                }
                
                // Check if line matches pattern
                if (preg_match($pattern, $line)) {
                    // Apply redaction
                    $originalLine = $line;
                    $line = preg_replace($pattern, $replacement, $line);
                    
                    if ($originalLine !== $line) {
                        $lines[$i] = $line;
                        $redactedLines[] = $i + 1; // 1-indexed
                        $redactionCount++;
                        
                        // Track redaction type
                        $redactionType = is_string($replacement) ? $replacement : 'PATTERN_REDACTED';
                        if (!isset($redactionTypes[$redactionType])) {
                            $redactionTypes[$redactionType] = 0;
                        }
                        $redactionTypes[$redactionType]++;
                    }
                }
            }
        }
        
        $sanitizedContent = implode("\n", $lines);
        $redactedLines = array_unique($redactedLines);
        sort($redactedLines);
        
        $metadata = [
            'redaction_count' => $redactionCount,
            'redaction_types' => $redactionTypes,
            'has_redactions' => $redactionCount > 0,
            'redacted_lines_count' => count($redactedLines),
            'warning' => $redactionCount > 0 ? 'This file contains sensitive data that has been redacted' : null
        ];
        
        return [
            'sanitized_content' => $sanitizedContent,
            'redacted_lines' => $redactedLines,
            'metadata' => $metadata
        ];
    }

    /**
     * Check if a patch is safe to apply (doesn't modify redacted lines).
     *
     * @param string $patchContent The unified diff patch content
     * @param array $redactedLines Array of line numbers that were redacted
     * @param string $filePath Path to the file being patched
     * @return array Associative array with:
     *   - is_safe: Boolean indicating if patch is safe
     *   - reason: If not safe, explanation of why (null if safe)
     */
    public static function isPatchSafeToApply(string $patchContent, array $redactedLines, string $filePath): array
    {
        if (empty($redactedLines)) {
            return ['is_safe' => true, 'reason' => null];
        }
        
        // Parse unified diff format to extract modified lines
        $modifiedLines = [];
        $currentLine = null;
        
        foreach (explode("\n", $patchContent) as $line) {
            // Parse hunk header
            if (preg_match('/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/', $line, $matches)) {
                $currentLine = (int)$matches[3]; // Starting line in new file
            } elseif ($currentLine !== null) {
                if (strpos($line, '+') === 0) {
                    $modifiedLines[] = $currentLine;
                    $currentLine++;
                } elseif (strpos($line, '-') === 0) {
                    // Deleted line doesn't increment current_line
                } elseif (strpos($line, ' ') === 0) {
                    // Context line
                    $currentLine++;
                }
            }
        }
        
        // Check if any modified lines overlap with redacted lines
        $overlappingLines = array_intersect($modifiedLines, $redactedLines);
        
        if (!empty($overlappingLines)) {
            sort($overlappingLines);
            return [
                'is_safe' => false,
                'reason' => 'Patch attempts to modify redacted sensitive data on lines: ' . implode(', ', $overlappingLines)
            ];
        }
        
        return ['is_safe' => true, 'reason' => null];
    }

    /**
     * Generate a human-readable summary of redactions.
     *
     * @param array $metadata Metadata from sanitizeSensitiveData()
     * @return string Human-readable summary string
     */
    public static function getRedactionSummary(array $metadata): string
    {
        if (!$metadata['has_redactions']) {
            return "No sensitive data detected in this file.";
        }
        
        $count = $metadata['redaction_count'];
        $linesCount = $metadata['redacted_lines_count'];
        $types = $metadata['redaction_types'];
        
        $summaryParts = [
            "Redacted {$count} sensitive value(s) across {$linesCount} line(s):"
        ];
        
        foreach ($types as $redactionType => $typeCount) {
            $summaryParts[] = "  - {$redactionType}: {$typeCount} occurrence(s)";
        }
        
        return implode("\n", $summaryParts);
    }

    /**
     * Mask a sensitive value, revealing only the last N characters.
     *
     * @param string $value The sensitive value to mask
     * @param int $revealChars Number of characters to reveal at the end
     * @return string Masked value (e.g., "****abcd")
     */
    public static function maskSensitiveValue(string $value, int $revealChars = 4): string
    {
        $length = strlen($value);
        
        if ($length <= $revealChars) {
            return str_repeat('*', $length);
        }
        
        return str_repeat('*', $length - $revealChars) . substr($value, -$revealChars);
    }

    /**
     * Best-effort redaction of common secret patterns in error/log text before ingest.
     * Uses the same pattern set as file-content sanitisation; heuristic only (not exhaustive).
     */
    public static function sanitizeLogLineForIngest(string $logLine): string
    {
        $result = self::sanitizeSensitiveData($logLine);

        return $result['sanitized_content'];
    }
}

