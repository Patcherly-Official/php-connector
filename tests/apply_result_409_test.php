<?php
/**
 * apply_result_409_test.php
 *
 * Connector-side 409 contract for POST /api/errors/{id}/fix/apply-result.
 *
 * When the server's CAS already advanced this error (race with another
 * connector callback, or a dashboard action), the API returns 409. The
 * connector MUST:
 *   (a) NOT retry — the server is canonical;
 *   (b) emit an error_log line including the error_id and the server-returned
 *       `detail`;
 *   (c) continue with the next pending error.
 *
 * This test mirrors the production decision tree in
 * `connectors/php/php_agent.php` (search for "apply-result returned 409").
 * Kept in sync by hand; both must move together.
 *
 * Usage:
 *   php connectors/php/tests/apply_result_409_test.php
 */

function fail409($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Mirror of the production decision tree. Returns a structured action
 * (string action + optional detail) so the test can assert without
 * depending on PHP's `error_log` sink.
 */
function decide_apply_result_action(int $status, string $body): array {
    if ($status >= 200 && $status < 300) {
        return ['action' => 'ok'];
    }
    if ($status === 409) {
        $detail = '';
        $decoded = json_decode($body, true);
        if (is_array($decoded) && isset($decoded['detail'])) {
            $detail = (string) $decoded['detail'];
        }
        return ['action' => 'log_409_terminal', 'detail' => $detail];
    }
    return ['action' => 'log_failure', 'status' => $status];
}

// -------------------------------------------------------------------------
// Test 1: 409 with detail — log + terminal (no retry).
// -------------------------------------------------------------------------
$r1 = decide_apply_result_action(
    409,
    json_encode([
        'detail' => 'Concurrent apply-result detected; another caller already advanced this error. Current status: fixed',
    ])
);
if ($r1['action'] !== 'log_409_terminal') {
    fail409('Expected log_409_terminal on 409, got ' . $r1['action']);
}
if (strpos($r1['detail'], 'Current status: fixed') === false) {
    fail409('Expected detail to include "Current status: fixed", got: ' . $r1['detail']);
}

// -------------------------------------------------------------------------
// Test 2: 409 with empty body — still terminal, empty detail.
// -------------------------------------------------------------------------
$r2 = decide_apply_result_action(409, '');
if ($r2['action'] !== 'log_409_terminal') {
    fail409('Expected log_409_terminal on 409 with empty body, got ' . $r2['action']);
}
if ($r2['detail'] !== '') {
    fail409('Expected empty detail on empty body, got: ' . $r2['detail']);
}

// -------------------------------------------------------------------------
// Test 3: 200 — silent (no log action).
// -------------------------------------------------------------------------
$r3 = decide_apply_result_action(200, '{"id":"err_x","status":"fixed"}');
if ($r3['action'] !== 'ok') {
    fail409('Expected ok on 200, got ' . $r3['action']);
}

// -------------------------------------------------------------------------
// Test 4: 503 — generic failure log, NOT terminal-409 log.
// -------------------------------------------------------------------------
$r4 = decide_apply_result_action(503, '');
if ($r4['action'] !== 'log_failure') {
    fail409('Expected log_failure on 503, got ' . $r4['action']);
}
if (($r4['status'] ?? 0) !== 503) {
    fail409('Expected status=503 to surface in failure log, got ' . ($r4['status'] ?? 'null'));
}

// -------------------------------------------------------------------------
// Test 5: 401 — also a generic failure (not 409 terminal).
// -------------------------------------------------------------------------
$r5 = decide_apply_result_action(401, '');
if ($r5['action'] !== 'log_failure') {
    fail409('Expected log_failure on 401, got ' . $r5['action']);
}

echo "apply_result_409_test.php: OK\n";
