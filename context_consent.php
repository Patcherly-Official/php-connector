<?php
/**
 * Context collection consent (Full / Minimal / Off) for PHP connectors.
 *
 * Resolution order:
 *   1. env  PATCHERLY_CONTEXT_CONSENT
 *   2. file {PATCHERLY_CACHE_DIR}/context_consent  (default cache .patcherly_cache)
 *   3. default: full
 *
 * Mirrors connectors/python/context_consent.py exactly.
 */

if (!defined('PATCHERLY_VALID_CONSENT_TIERS')) {
    define('PATCHERLY_VALID_CONSENT_TIERS', ['full', 'minimal', 'off']);
}
if (!defined('PATCHERLY_DEFAULT_CONSENT_TIER')) {
    define('PATCHERLY_DEFAULT_CONSENT_TIER', 'full');
}

/**
 * Resolve the cache directory (create if missing) and return its path.
 */
function patcherly_consent_cache_dir(): string
{
    $raw = trim((string)(getenv('PATCHERLY_CACHE_DIR') ?: ''));
    $dir = $raw !== '' ? $raw : '.patcherly_cache';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    return $dir;
}

/**
 * Path to the consent tier file.
 */
function patcherly_consent_file_path(): string
{
    return patcherly_consent_cache_dir() . '/context_consent';
}

/**
 * Normalize a raw string to a valid tier or return null for invalid values.
 */
function patcherly_normalize_consent_tier(?string $raw): ?string
{
    if ($raw === null) {
        return null;
    }
    $v = strtolower(trim($raw));
    return in_array($v, PATCHERLY_VALID_CONSENT_TIERS, true) ? $v : null;
}

/**
 * Return [tier, source] where source is 'env'|'file'|'default'.
 *
 * Invalid values in env or file are treated as absent (fall through to next).
 *
 * @return array{string, string}
 */
function patcherly_get_context_consent(): array
{
    $envRaw = getenv('PATCHERLY_CONTEXT_CONSENT');
    if ($envRaw !== false) {
        $tier = patcherly_normalize_consent_tier((string) $envRaw);
        if ($tier !== null) {
            return [$tier, 'env'];
        }
        // Invalid env value — fall through to file / default (matches Python behavior).
    }
    try {
        $path = patcherly_consent_file_path();
        if (is_file($path)) {
            $tier = patcherly_normalize_consent_tier(
                file_get_contents($path) !== false ? (string) file_get_contents($path) : null
            );
            if ($tier !== null) {
                return [$tier, 'file'];
            }
        }
    } catch (\Throwable $e) {
        // IO error — fall through to default.
    }
    return [PATCHERLY_DEFAULT_CONSENT_TIER, 'default'];
}

/**
 * Write the normalized tier to the consent file and return it.
 *
 * @throws \InvalidArgumentException for unrecognized tier values.
 */
function patcherly_set_context_consent(string $tier): string
{
    $normalized = patcherly_normalize_consent_tier($tier);
    if ($normalized === null) {
        throw new \InvalidArgumentException(
            'Invalid consent tier ' . json_encode($tier) . '; expected full|minimal|off'
        );
    }
    $path = patcherly_consent_file_path();
    file_put_contents($path, $normalized . "\n");
    return $normalized;
}
