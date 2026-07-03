<?php
/**
 * rolling_back_flow_test.php
 *
 * Contract regression for the manual-rollback report payload built inside
 * connectors/php/php_agent.php::processRollingBackErrors() (~1220–1241).
 *
 * Mirrors the decision tree (backup_path empty vs restore outcome) so PHP
 * stays aligned with the API's POST /api/errors/{id}/fix/rollback body
 * (`success`, `backup_path`, `message`).
 *
 * Usage:
 *   php connectors/php/tests/rolling_back_flow_test.php
 */

function fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Mirror of processRollingBackErrors inner payload construction after
 * restore attempt (see php_agent.php).
 *
 * @param string $backupPath  Raw backup_path from GET /api/errors list item
 * @param bool   $restoreOk   Outcome of backupManager->restoreBackup()
 */
function buildRollbackReportPayload(string $backupPath, bool $restoreOk): array
{
    $success = false;
    $message = '';
    try {
        if ($backupPath === '') {
            $message = 'No backup_path on error; cannot restore.';
        } else {
            $success = $restoreOk;
            $message = $success
                ? 'Rollback restored files from backup.'
                : 'Rollback restore failed; backup directory may be missing or tampered with.';
        }
    } catch (Throwable $e) {
        $message = 'Restore raised: ' . $e->getMessage();
    }

    return [
        'success' => (bool) $success,
        'backup_path' => $backupPath !== '' ? $backupPath : null,
        'message' => $message,
    ];
}

// -------------------------------------------------------------------------
// Missing backup_path
// -------------------------------------------------------------------------
$p0 = buildRollbackReportPayload('', false);
if ($p0['success'] !== false) {
    fail('expected success=false when backup_path empty');
}
if ($p0['backup_path'] !== null) {
    fail('expected null backup_path when empty string');
}
if (strpos($p0['message'], 'No backup_path') === false) {
    fail('expected No backup_path message');
}

// -------------------------------------------------------------------------
// Restore success
// -------------------------------------------------------------------------
$p1 = buildRollbackReportPayload('/var/backups/err/2026', true);
if ($p1['success'] !== true || $p1['backup_path'] !== '/var/backups/err/2026') {
    fail('success path mismatch');
}
if (strpos($p1['message'], 'Rollback restored') === false) {
    fail('expected restore success message');
}

// -------------------------------------------------------------------------
// Restore failure (directory missing)
// -------------------------------------------------------------------------
$p2 = buildRollbackReportPayload('/var/backups/missing', false);
if ($p2['success'] !== false) {
    fail('expected success=false when restore returns false');
}
if ($p2['backup_path'] !== '/var/backups/missing') {
    fail('backup_path should echo API value even on failure');
}
if (strpos($p2['message'], 'Rollback restore failed') === false) {
    fail('expected restore failure message');
}

echo "rolling_back_flow_test.php: OK\n";
