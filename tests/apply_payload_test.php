<?php
/**
 * apply_payload_test.php
 *
 * Regression test for the PHP connector apply-result wire format.
 *
 * Background: prior to v1.44 the PHP connector posted the entire
 * `backup_metadata` array under the key `backup_metadata` to
 * /api/errors/{id}/fix/apply-result. The API model `FixApplyResult`
 * only knows about a flat `backup_path` string and silently drops
 * `backup_metadata` (Pydantic `extra='ignore'`), so `backup_path` was
 * never persisted on the error doc and dashboard-initiated rollback
 * stalled for PHP installs.
 *
 * The fix in php_agent.php (around line 642) is:
 *
 *     if (!empty($applyResult['backup_metadata']['backup_dir'])) {
 *         $applyPayload['backup_path'] = $applyResult['backup_metadata']['backup_dir'];
 *     }
 *
 * This test mirrors that exact transform and asserts the contract:
 *   - Output payload contains a top-level `backup_path` string
 *   - Output payload does NOT contain a `backup_metadata` key
 *   - Empty / malformed legacy metadata yields no backup_path key
 *
 * If this test starts failing, the production transform in php_agent.php
 * has drifted from the API contract; re-align both before merging.
 *
 * Usage:
 *   php connectors/php/tests/apply_payload_test.php
 */

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Mirror of the production transform in connectors/php/php_agent.php
 * (search for "FixApplyResult expects a flat backup_path"). Kept in
 * sync by hand; both must move together.
 */
function buildApplyPayload(array $applyResult, string $logFile, bool $targetDryRun): array {
    $success = $applyResult['success'] ?? false;
    $applyPayload = [
        'success' => $success,
        'fix_path' => $logFile,
        'test_result' => $applyResult['message'] ?? ($success ? 'Fix passed local tests.' : 'Fix failed or rolled back.'),
    ];
    if ($targetDryRun) {
        $applyPayload['dry_run'] = true;
    }
    if (!empty($applyResult['backup_metadata']['backup_dir'])) {
        $applyPayload['backup_path'] = $applyResult['backup_metadata']['backup_dir'];
    }
    return $applyPayload;
}

// -------------------------------------------------------------------------
// Test 1: success + legacy backup_metadata yields canonical backup_path.
// -------------------------------------------------------------------------
$payload = buildApplyPayload([
    'success' => true,
    'message' => 'Fix applied to 2 file(s).',
    'backup_metadata' => [
        'error_id' => 'err_a',
        'backup_dir' => '/var/www/.patcherly_backups/err_a/20260505_030200',
        'files' => ['app/foo.php'],
    ],
], '/var/log/patcherly/agent.log', false);

if (!isset($payload['backup_path'])) {
    fail('Expected `backup_path` in the apply payload after a successful apply.');
}
if ($payload['backup_path'] !== '/var/www/.patcherly_backups/err_a/20260505_030200') {
    fail('Apply payload backup_path does not match backup_metadata.backup_dir; got: ' . $payload['backup_path']);
}
if (array_key_exists('backup_metadata', $payload)) {
    fail('Apply payload must NOT carry the legacy `backup_metadata` key on the wire.');
}
if (($payload['success'] ?? null) !== true) {
    fail('Apply payload success flag is wrong.');
}

// -------------------------------------------------------------------------
// Test 2: dry-run still flagged on the wire.
// -------------------------------------------------------------------------
$dry = buildApplyPayload([
    'success' => true,
    'message' => 'Dry run.',
    'backup_metadata' => null,
], '/var/log/patcherly/agent.log', true);

if (($dry['dry_run'] ?? null) !== true) {
    fail('Dry-run flag missing on apply payload.');
}
if (array_key_exists('backup_path', $dry)) {
    fail('Dry-run with no backup must not set backup_path.');
}

// -------------------------------------------------------------------------
// Test 3: missing backup_metadata.backup_dir does not produce a bogus key.
// -------------------------------------------------------------------------
$noDir = buildApplyPayload([
    'success' => true,
    'message' => 'ok',
    'backup_metadata' => ['files' => ['a.php']],
], '/var/log/patcherly/agent.log', false);

if (array_key_exists('backup_path', $noDir)) {
    fail('Apply payload must omit backup_path when backup_metadata.backup_dir is missing.');
}

// -------------------------------------------------------------------------
// Test 4: failed apply with no backup still produces a valid payload.
// -------------------------------------------------------------------------
$failed = buildApplyPayload([
    'success' => false,
    'message' => 'Patch parse error',
], '/var/log/patcherly/agent.log', false);

if (($failed['success'] ?? null) !== false) {
    fail('Failed apply payload success flag wrong.');
}
if (array_key_exists('backup_path', $failed)) {
    fail('Failed apply with no backup must omit backup_path.');
}
if (($failed['test_result'] ?? '') !== 'Patch parse error') {
    fail('Failed apply payload should surface the message in test_result.');
}

echo "apply_payload_test.php: OK\n";
