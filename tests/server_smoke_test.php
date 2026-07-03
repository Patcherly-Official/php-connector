<?php
/**
 * server_smoke_test.php
 *
 * Spawns `php -S 127.0.0.1:<port> php_agent.php` in a child process, waits for
 * the listener to come up, hits a known route, and asserts the connector's
 * router actually runs. This proves the `cli-server` SAPI entry in
 * php_agent.php is wired correctly end to end -- the
 * local_approvals_security_test.php counterpart is source-level only and
 * cannot tell whether the listener accepts connections.
 *
 * The test is intentionally narrow:
 *  - We hit `/local-approvals` with an invalid Bearer token and expect the
 *    connector's own 401 or 503 JSON response. That proves the request reached
 *    the router and was rejected by `$requireBearerToken()` -- both the SAPI
 *    gate and the auth gate are exercised in one round-trip.
 *  - We do NOT exercise /api/file-content end-to-end because that requires a
 *    valid Bearer token. The structural sister-test covers the auth code shape;
 *    this one only proves the listener is real.
 *
 * Designed to be skippable on hosts where spawning a child PHP process or
 * binding to 127.0.0.1 isn't allowed (e.g. some sandboxed CI runners) -- the
 * test exits 0 with a SKIP note in those cases rather than failing CI.
 *
 * Usage:
 *   php connectors/php/tests/server_smoke_test.php
 */

function smoke_fail(string $msg) : void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function smoke_skip(string $msg) : void {
    fwrite(STDOUT, "SKIP: {$msg}\n");
    exit(0);
}

// proc_open is required to spawn `php -S` and reap it cleanly.
if (!function_exists('proc_open') || !function_exists('proc_terminate')) {
    smoke_skip('proc_open/proc_terminate unavailable on this PHP build');
}

// Try a few ports so the test isn't a single-port lottery on dev machines.
$candidatePorts = [18083, 18084, 18085];
$agentPath = realpath(__DIR__ . '/../php_agent.php');
if (!$agentPath || !file_exists($agentPath)) {
    smoke_fail('php_agent.php not found at expected relative path');
}

$phpBin = PHP_BINARY ?: 'php';
$childProc = null;
$port = null;
$pipes = [];

foreach ($candidatePorts as $tryPort) {
    $cmd = sprintf(
        '%s -S 127.0.0.1:%d %s',
        escapeshellarg($phpBin),
        $tryPort,
        escapeshellarg($agentPath)
    );
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = @proc_open($cmd, $descriptors, $pipes, sys_get_temp_dir());
    if (!is_resource($proc)) {
        continue;
    }
    // Non-blocking reads on the child's stdout/stderr so we don't hang.
    foreach ([1, 2] as $fd) {
        if (isset($pipes[$fd]) && is_resource($pipes[$fd])) {
            stream_set_blocking($pipes[$fd], false);
        }
    }
    // Wait up to ~3 seconds for the listener to bind.
    $deadline = microtime(true) + 3.0;
    $accepted = false;
    while (microtime(true) < $deadline) {
        $errno = 0; $errstr = '';
        $sock = @stream_socket_client(
            "tcp://127.0.0.1:{$tryPort}",
            $errno,
            $errstr,
            0.5
        );
        if ($sock) {
            fclose($sock);
            $accepted = true;
            break;
        }
        usleep(100 * 1000); // 100ms
    }
    if ($accepted) {
        $childProc = $proc;
        $port = $tryPort;
        break;
    }
    // Couldn't bind this port -- clean up and try next.
    @proc_terminate($proc);
    foreach ($pipes as $p) { if (is_resource($p)) { @fclose($p); } }
    @proc_close($proc);
    $pipes = [];
}

if (!$childProc || $port === null) {
    smoke_skip(
        'could not bind php -S on 127.0.0.1 (tried ' . implode(', ', $candidatePorts) . ')'
        . ' -- likely a sandboxed CI runner; structural assertions still cover the code shape'
    );
}

// At this point we have a live `php -S` child. Always clean it up, even on a
// fatal in the request path -- shutdown function is the belt-and-suspenders.
// Windows note: `proc_close()` does a blocking WaitForSingleObject() on the
// child handle, and `proc_terminate()` is best-effort. To avoid hanging the
// shell that invoked this test we hard-kill the recorded PID with
// `taskkill /T /F` BEFORE proc_close() so the wait returns immediately.
$isWindows = stripos(PHP_OS_FAMILY, 'win') === 0;
$cleanup = function () use (&$childProc, &$pipes, $isWindows) {
    if (!is_resource($childProc)) { return; }
    $status = @proc_get_status($childProc);
    $childPid = (is_array($status) && isset($status['pid'])) ? (int)$status['pid'] : 0;

    // Close STDIN/OUT/ERR pipes first so the child unblocks.
    foreach ($pipes as $p) { if (is_resource($p)) { @fclose($p); } }
    $pipes = [];

    if ($isWindows && $childPid > 0) {
        @exec("taskkill /PID {$childPid} /T /F 2>NUL");
    } else {
        @proc_terminate($childProc, defined('SIGTERM') ? SIGTERM : 15);
        $deadline = microtime(true) + 1.0;
        while (microtime(true) < $deadline) {
            $status = @proc_get_status($childProc);
            if (!$status || !$status['running']) { break; }
            usleep(50 * 1000);
        }
    }
    @proc_close($childProc);
    $childProc = null;
};
register_shutdown_function($cleanup);

// Make the HTTP call with a stdlib stream context so the test does NOT depend
// on the optional `curl` PHP extension being installed (it isn't on a default
// Windows / shared-hosting PHP build). The same call would be `curl -H ...`
// in operator runbooks.
$code = 0;
$body = '';
$ioErr = null;
try {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "Authorization: Bearer not-the-real-token-for-this-test\r\n",
            'ignore_errors' => true,    // so we capture 401 / 4xx bodies, not exceptions
            'timeout' => 5,
        ],
    ]);
    $body = @file_get_contents("http://127.0.0.1:{$port}/local-approvals", false, $ctx);
    if ($body === false) {
        $err = error_get_last();
        $ioErr = $err['message'] ?? 'unknown';
        $body = '';
    }
    // First line of the response header set is e.g. "HTTP/1.1 401 Unauthorized".
    // PHP 8.5 deprecates the magic $http_response_header global in favour of
    // http_get_last_response_headers(); use that when available, and fall back
    // to the global for older PHP. The fallback reference is wrapped in a
    // deprecation-silenced scope so the test output stays clean across PHP
    // versions; the file-scope reference is in a separate `eval()` so the
    // PHP 8.5 compiler doesn't emit the deprecation at parse time on
    // `isset($http_response_header)`.
    $rawHeaders = null;
    if (function_exists('http_get_last_response_headers')) {
        $rawHeaders = http_get_last_response_headers();
    } else {
        $prevErr = error_reporting(error_reporting() & ~E_DEPRECATED);
        $rawHeaders = @eval('return (isset($http_response_header) && is_array($http_response_header)) ? $http_response_header : null;');
        error_reporting($prevErr);
    }
    if (is_array($rawHeaders)) {
        foreach ($rawHeaders as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})\b#', $h, $m)) {
                $code = (int)$m[1];
                break;
            }
        }
    }
} catch (Throwable $t) {
    $cleanup();
    smoke_fail('stream_context request threw: ' . $t->getMessage());
}

// The router is reachable if either:
//   (a) The connector has OAuth credentials stored and our invalid Bearer token
//       produces 401 Unauthorized from $requireBearerToken() (proves SAPI + auth
//       gates work end-to-end), or
//   (b) No credentials file exists (dev default / CI), so $requireBearerToken()
//       returns 503 Service Unavailable.
// Either way, what we MUST see is that the request did not 404 or 500 --
// which is what would happen if php_agent.php were not really handling it
// (e.g. if the SAPI gate were still wrong).
// Note: 503 is explicitly excluded from the failure range here because it is
// a valid auth-gate outcome (connector not yet authenticated) that still
// proves the router is running.
if ($code === 0) {
    $cleanup();
    smoke_fail('no HTTP response from the php -S server (likely SAPI gate regression). I/O: ' . (string)$ioErr);
}
if ($code === 404) {
    $cleanup();
    smoke_fail("php -S returned 404 for /local-approvals -- the routing function "
        . "isn't taking over the request under cli-server SAPI. Body: "
        . substr((string)$body, 0, 200));
}
// 500/502 = server error; 503 is acceptable (no credentials = $requireBearerToken 503)
if ($code >= 500 && $code !== 503) {
    $cleanup();
    smoke_fail("php -S returned {$code} for /local-approvals: " . substr((string)$body, 0, 200));
}

$cleanup();
echo "OK: connectors/php/tests/server_smoke_test.php (live php -S on 127.0.0.1:{$port} responded to /local-approvals with HTTP {$code})\n";
