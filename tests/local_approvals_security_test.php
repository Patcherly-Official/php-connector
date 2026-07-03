<?php
/**
 * local_approvals_security_test.php
 *
 * Regression: defence-in-depth hardening of the PHP connector's optional
 * local-approvals + /api/file-content endpoints (parity with the Python
 * connector hardening).
 *
 * Why a structural test rather than a live HTTP test:
 *  - The PHP HTTP server in php_agent.php is served by PHP's built-in web
 *    server (SAPI `cli-server`), entered as
 *    `php -S 127.0.0.1:8083 connectors/php/php_agent.php`. A companion
 *    smoke test (`server_smoke_test.php`) actually spawns `php -S`, hits an
 *    endpoint, and asserts the routing closure runs. This file stays at the
 *    source level on purpose so the fast in-CI test does not depend on the
 *    operator's PHP build being able to fork / open a listener.
 *  - The semantic risk we are guarding against here is "someone refactors and
 *    silently drops the Bearer-token check / id regex / project-root scope /
 *    SAPI gate". A source-level structural assertion catches that class of
 *    regression at zero infra cost.
 *
 * The test also exercises the approval-id regex contract semantically against
 * the SAME pattern that lives in php_agent.php, with a DRY guard that fails if
 * the pattern in the agent ever diverges from the one in this test.
 *
 * Usage:
 *   php connectors/php/tests/local_approvals_security_test.php
 */

function fail($msg) {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function assert_eq($expected, $actual, $msg) {
    if ($expected !== $actual) {
        fail("{$msg} -- expected " . var_export($expected, true) . " got " . var_export($actual, true));
    }
}

function assert_contains($haystack, $needle, $msg) {
    if (strpos($haystack, $needle) === false) {
        fail("{$msg} -- expected substring " . var_export($needle, true) . " to be present");
    }
}

function assert_regex_count($source, $pattern, $expected, $msg) {
    $n = preg_match_all($pattern, $source);
    if ($n !== $expected) {
        fail("{$msg} -- expected {$expected} matches of {$pattern}, got {$n}");
    }
}

$agentPath = realpath(__DIR__ . '/../php_agent.php');
if (!$agentPath || !file_exists($agentPath)) {
    fail("php_agent.php not found at expected path");
}
$source = file_get_contents($agentPath);
if ($source === false) { fail("could not read php_agent.php"); }

// ---- 1. Approval-id regex contract -------------------------------------------------

/** Mirror of the regex used in php_agent.php /local-approvals/{id}/(approve|dismiss). */
$APPROVAL_ID_RE = '/^[A-Za-z0-9_-]{1,128}$/';

// DRY guard: the same pattern must appear verbatim in the agent source.
assert_contains(
    $source,
    "'/^[A-Za-z0-9_-]{1,128}\$/'",
    "approval-id regex in php_agent.php has drifted from the one tested here"
);

$validIds = ['abc-123', 'A', '0123456789', 'mixed_Case-001', str_repeat('x', 128)];
foreach ($validIds as $ok) {
    assert_eq(1, preg_match($APPROVAL_ID_RE, $ok), "regex should accept {$ok}");
}

$invalidIds = [
    '',
    '../evil',
    'abc/extra',
    '/abs/path',
    'abc?query=1',
    'abc#frag',
    'abc def',
    'abc&dismiss',
    'abc..',
    str_repeat('x', 129),
    '127.0.0.1',  // dots are not allowed
    'http://x',   // colons + slashes are not allowed
];
foreach ($invalidIds as $bad) {
    assert_eq(0, preg_match($APPROVAL_ID_RE, $bad), "regex should reject " . var_export($bad, true));
}

// ---- 2. Structural assertions on php_agent.php -------------------------------------

// /local-approvals (GET) must call $requireBearerToken() before forwarding.
assert_regex_count(
    $source,
    "#'/local-approvals' && \\\$_SERVER\\['REQUEST_METHOD'\\]==='GET'\\)\\{\\s*if \\(!\\\$requireBearerToken\\(\\)\\)#",
    1,
    "/local-approvals GET handler is missing the \$requireBearerToken() gate"
);

// /local-approvals/{id}/(approve|dismiss) (POST) must call $requireBearerToken() and validate id.
assert_regex_count(
    $source,
    '#local-approvals/\(\[\^/\]\+\)/\(approve\|dismiss\)#',
    1,
    "POST /local-approvals/{id}/(approve|dismiss) route regex changed unexpectedly"
);
assert_contains(
    $source,
    "if (!preg_match(\$approvalIdRe, \$id))",
    "POST /local-approvals/{id}/(approve|dismiss) handler is missing the id regex validation"
);

// /api/file-content must enforce the project-root allowlist after realpath().
assert_contains(
    $source,
    '$isPathWithinAllowedRoots($realPath)',
    "/api/file-content is missing the \$isPathWithinAllowedRoots(\$realPath) scope check"
);
assert_contains(
    $source,
    "'PATCHERLY_TARGET_ROOTS'",
    "/api/file-content is no longer reading PATCHERLY_TARGET_ROOTS for the allowlist"
);

// Bearer token check must use hash_equals (constant-time) to prevent timing attacks.
assert_contains(
    $source,
    'hash_equals($expected, (string)$provided)',
    "\$requireBearerToken() is no longer using hash_equals() for constant-time compare"
);

// The router must use $requireBearerToken (OAuth) — NOT the old $requireApiKey.
if (strpos($source, '$requireApiKey') !== false) {
    fail("php_agent.php still references \$requireApiKey — must be replaced with \$requireBearerToken");
}

// Entry-point SAPI dispatch must route the HTTP server through `cli-server`
// (php -S), not the `cli` SAPI -- the latter is reserved for the long-lived
// log-monitoring loop that doesn't open a listener.
assert_contains(
    $source,
    "if (php_sapi_name() === 'cli-server')",
    "php_agent.php is no longer dispatching the HTTP server under the `cli-server` SAPI gate"
);
assert_contains(
    $source,
    "function patcherly_php_local_router()",
    "patcherly_php_local_router() entry function is missing from php_agent.php"
);
// `pcntl_fork()` must not appear in the routing path -- a forked listener
// inside the cli-server router would never accept connections (cli-server
// already owns the socket). We scan only non-comment lines so an unrelated
// docblock that mentions pcntl_fork doesn't trip the guard.
foreach (explode("\n", $source) as $lineNo => $line) {
    $stripped = ltrim($line);
    if ($stripped === '' || $stripped[0] === '*'
        || strpos($stripped, '//') === 0
        || strpos($stripped, '#') === 0) {
        continue;
    }
    if (preg_match('/pcntl_fork\s*\(/', $line)) {
        fail("php_agent.php now calls pcntl_fork() in the routing path -- this would never accept connections under the cli-server SAPI (line " . ($lineNo + 1) . ")");
    }
}

echo "OK: connectors/php/tests/local_approvals_security_test.php (" . (count($validIds) + count($invalidIds)) . " regex cases + 9 structural assertions)\n";
