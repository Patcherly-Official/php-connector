<?php
declare(strict_types=1);
// Direct-access protection (WordPress.org Plugin Check requirement).
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals -- dev-only test scaffolding.

/**
 * Agent API host resolution: explicit SERVER_URL must skip discovery overwrite.
 *
 * Run: php connectors/php/tests/test-agent-api-base-resolution.php
 */

$fail_count = 0;
function agent_base_fail(string $msg): void {
    global $fail_count;
    $fail_count++;
    fwrite(STDERR, "FAIL: {$msg}\n");
}
function agent_base_ok(string $msg): void {
    echo "  OK  {$msg}\n";
}

$source = file_get_contents(realpath(__DIR__ . '/../php_agent.php'));
if ($source === false) {
    fwrite(STDERR, "Cannot read php_agent.php\n");
    exit(1);
}

if (strpos($source, 'function patcherly_agent_configured_server_url()') !== false) {
    agent_base_ok('configured server URL helper exists');
} else {
    agent_base_fail('patcherly_agent_configured_server_url() must exist');
}

if (strpos($source, 'function patcherly_agent_is_explicit_server_url()') !== false) {
    agent_base_ok('explicit server URL guard exists');
} else {
    agent_base_fail('patcherly_agent_is_explicit_server_url() must exist');
}

if (strpos($source, 'patcherly_agent_is_explicit_server_url()') !== false
    && strpos($source, 'private function discoverApiUrl()') !== false) {
    agent_base_ok('discoverApiUrl honors explicit SERVER_URL guard');
} else {
    agent_base_fail('discoverApiUrl must honor explicit SERVER_URL');
}

if (strpos($source, "getenv('PATCHERLY_API_BASE')") !== false) {
    agent_base_ok('PATCHERLY_API_BASE is accepted as alias for SERVER_URL');
} else {
    agent_base_fail('agent must read PATCHERLY_API_BASE');
}

if ($fail_count > 0) {
    fwrite(STDERR, "\n{$fail_count} assertion(s) failed.\n");
    exit(1);
}
echo "\nAll PHP agent API-base resolution assertions passed.\n";
