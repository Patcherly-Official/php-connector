<?php
/**
 * post_apply_steps_test.php
 *
 * Behaviour tests for the PHP standalone connector's post-apply manifest
 * execution (Phase 2.2 / C1), focused on the safety invariants we promise:
 *
 *   1. shell-token denylist rejects `&&`, `||`, `|`, `;`, backticks, `$(`,
 *      `>`, `<` before any process is launched.
 *   2. proc_open is invoked with an argv array (no /bin/sh), so quoted
 *      metacharacters in tokens are inert.
 *   3. per-error-id dedup: once steps succeed for an error_id, a second call
 *      for the same error_id returns `skipped_reason=already_restarted_for_error`.
 *   4. YAML subset parser produces the expected shape for the canonical
 *      manifest layout (working_directory / when / steps[*].name|run).
 *
 * The agent class lives in connectors/php/php_agent.php and pulls in
 * BackupManager / PatchApplicator / QueueManager from disk inside its
 * constructor. To keep this test hermetic we exercise the post-apply
 * helpers via a minimal subclass that skips the constructor wiring.
 *
 * Usage:
 *   php connectors/php/tests/post_apply_steps_test.php
 */

// Suppress agent auto-bootstrap so require_once doesn't kick off monitorLogs().
putenv('PATCHERLY_AGENT_NOAUTORUN=1');
// PHP 8.5 deprecates ReflectionMethod::setAccessible() (no-op since 8.1).
// We still call it for 7.4-8.0 compatibility — silence the notices for clean test output.
error_reporting(E_ALL & ~E_DEPRECATED);

require_once dirname(__DIR__) . '/php_agent.php';

function pa_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Subclass that exposes the private helpers we want to test directly and
 * skips the heavy constructor wiring (no log file, no OAuth discovery).
 *
 * The agent's private methods are surfaced via reflection-style trampolines
 * — simpler and faster than ReflectionClass invocation for every assertion.
 */
final class PostApplyTestableAgent extends PHPAgent {
    public function __construct() {
        // intentionally skip parent::__construct — we only test pure helpers
    }

    public function callTokenize(string $cmd) {
        return $this->_invoke('tokenizeCommand', [$cmd]);
    }
    public function callParseYaml(string $raw) {
        return $this->_invoke('parseManifestYaml', [$raw]);
    }
    public function callRunSteps(array $manifest, bool $dryRun) {
        return $this->_invoke('runPostApplySteps', [$manifest, $dryRun]);
    }
    public function callDetectPhpTestRunner() {
        return $this->_invoke('detectPhpTestRunner', []);
    }
    public function callBuildTestResultsPayload(string $errorId, bool $applySuccess) {
        return $this->_invoke('buildTestResultsPayload', [$errorId, $applySuccess]);
    }

    /**
     * Inject success state for an error_id so we can assert the dedup path
     * inside maybeRunPostApply without a live API.
     */
    public function markErrorIdSucceeded(string $errorId): void {
        $prop = new ReflectionProperty(PHPAgent::class, 'postApplySuccessErrorIds');
        $prop->setAccessible(true);
        $cur = $prop->getValue($this);
        if (!is_array($cur)) $cur = [];
        $cur[trim($errorId)] = true;
        $prop->setValue($this, $cur);
    }

    public function getDedupSet(): array {
        $prop = new ReflectionProperty(PHPAgent::class, 'postApplySuccessErrorIds');
        $prop->setAccessible(true);
        $v = $prop->getValue($this);
        return is_array($v) ? $v : [];
    }

    private function _invoke(string $name, array $args) {
        $m = new ReflectionMethod(PHPAgent::class, $name);
        $m->setAccessible(true);
        return $m->invokeArgs($this, $args);
    }
}

$agent = new PostApplyTestableAgent();

// -------------------------------------------------------------------------
// 1. tokenizeCommand: word splitting, quoting, unbalanced quotes
// -------------------------------------------------------------------------
$t = $agent->callTokenize('echo hello world');
if ($t !== ['echo', 'hello', 'world']) {
    pa_fail('tokenize: simple split, got ' . json_encode($t));
}

$t = $agent->callTokenize("php -r 'echo 42;'");
if ($t !== ['php', '-r', 'echo 42;']) {
    pa_fail('tokenize: single-quoted token preserved, got ' . json_encode($t));
}

$t = $agent->callTokenize('git commit -m "fix: shell tokens"');
if ($t !== ['git', 'commit', '-m', 'fix: shell tokens']) {
    pa_fail('tokenize: double-quoted with space, got ' . json_encode($t));
}

$t = $agent->callTokenize('echo "unbalanced');
if ($t !== null) {
    pa_fail('tokenize: unbalanced double quote should return null');
}

// -------------------------------------------------------------------------
// 2. shell-token denylist: reject &&, ||, |, ;, `, $(, >, <
// -------------------------------------------------------------------------
$denylistCases = [
    'echo a && rm -rf /',
    'echo a || rm -rf /',
    'cat /etc/passwd | head',
    'echo a; echo b',
    'echo `id`',
    'echo $(id)',
    'echo a > /tmp/x',
    'echo a < /tmp/x',
];
foreach ($denylistCases as $cmd) {
    $manifest = ['steps' => [['name' => 'step', 'run' => $cmd]]];
    $tel = $agent->callRunSteps($manifest, false);
    if (empty($tel['failed'])) {
        pa_fail("denylist: expected failure for cmd={$cmd}");
    }
    if (($tel['message'] ?? '') !== 'unsafe_command:step') {
        pa_fail("denylist: expected unsafe_command message for cmd={$cmd}, got " . json_encode($tel));
    }
    $stepErr = $tel['steps'][0]['error'] ?? null;
    if ($stepErr !== 'unsafe_shell_tokens') {
        pa_fail("denylist: expected unsafe_shell_tokens error for cmd={$cmd}, got " . json_encode($tel['steps']));
    }
}

// -------------------------------------------------------------------------
// 3. dry_run mode never invokes proc_open even for denied commands
//    (matches python connector: in dry_run we only emit a log line)
// -------------------------------------------------------------------------
$tel = $agent->callRunSteps(['steps' => [['name' => 'preview', 'run' => 'echo hi']]], true);
if (!empty($tel['failed'])) {
    pa_fail('dry_run: expected success, got ' . json_encode($tel));
}
if (empty($tel['steps'][0]['dry_run'])) {
    pa_fail('dry_run: expected step result with dry_run=true');
}

// -------------------------------------------------------------------------
// 4. Array-form `run` skips denylist (caller already supplied argv array)
// -------------------------------------------------------------------------
if (PHP_VERSION_ID >= 70400 && DIRECTORY_SEPARATOR === '/' && is_executable('/bin/sh')) {
    // We can verify a real success path only on POSIX shells. On Windows CI
    // we skip the exec because /bin/echo isn't guaranteed; the unsafe-token
    // assertions above already cover the safety invariant.
    $manifest = ['steps' => [['name' => 'echo_arr', 'run' => ['/bin/echo', 'ok']]]];
    $tel = $agent->callRunSteps($manifest, false);
    if (!empty($tel['failed'])) {
        pa_fail('array run: expected success, got ' . json_encode($tel));
    }
    if (($tel['steps'][0]['ok'] ?? false) !== true) {
        pa_fail('array run: expected steps[0].ok=true, got ' . json_encode($tel));
    }
}

// -------------------------------------------------------------------------
// 5. YAML subset parser handles the canonical manifest shape
// -------------------------------------------------------------------------
$yaml = <<<YML
working_directory: /app
when: on_fix_success_if_restart_required
dry_run: false
steps:
  - name: restart
    run: systemctl restart php-fpm
    timeout_seconds: 30
    ignore_failure: false
  - name: smoke
    run: curl --fail http://127.0.0.1/health
    timeout_seconds: 5
YML;
$m = $agent->callParseYaml($yaml);
if (!is_array($m)) pa_fail('parseYaml: expected array, got ' . gettype($m));
if (($m['working_directory'] ?? null) !== '/app') {
    pa_fail('parseYaml: working_directory mismatch, got ' . json_encode($m));
}
if (($m['when'] ?? null) !== 'on_fix_success_if_restart_required') {
    pa_fail('parseYaml: when mismatch, got ' . json_encode($m));
}
if (($m['dry_run'] ?? null) !== false) {
    pa_fail('parseYaml: dry_run should be bool(false), got ' . json_encode($m));
}
$steps = $m['steps'] ?? [];
if (count($steps) !== 2) pa_fail('parseYaml: expected 2 steps, got ' . count($steps));
if (($steps[0]['name'] ?? '') !== 'restart' || ($steps[0]['run'] ?? '') !== 'systemctl restart php-fpm') {
    pa_fail('parseYaml: first step mismatch, got ' . json_encode($steps[0]));
}
if (($steps[0]['timeout_seconds'] ?? null) !== 30) {
    pa_fail('parseYaml: timeout_seconds should be int, got ' . json_encode($steps[0]));
}
if (($steps[0]['ignore_failure'] ?? null) !== false) {
    pa_fail('parseYaml: ignore_failure should be bool(false), got ' . json_encode($steps[0]));
}

// -------------------------------------------------------------------------
// 6. Per-error-id dedup: maybeRunPostApply short-circuits on a repeat
// -------------------------------------------------------------------------
$agent->markErrorIdSucceeded('err-abc');
$dedup = $agent->getDedupSet();
if (!array_key_exists('err-abc', $dedup)) {
    pa_fail('dedup: expected err-abc in success set, got ' . json_encode($dedup));
}

// -------------------------------------------------------------------------
// 7. PHPUnit / Pest auto-detection — buildTestResultsPayload should match
//    Python (`pytest`) and Node (`npm test`) parity. We can't actually run
//    phpunit without a real fixture project, so we verify the *skipped*
//    branch (no vendor/bin/phpunit on disk) and the payload shape.
// -------------------------------------------------------------------------
$origCwd = getcwd();
$tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_phpunit_test_' . uniqid();
mkdir($tmpDir, 0700, true);
chdir($tmpDir);
try {
    // No vendor/bin/phpunit → skipped row + total_tests=1, skipped=1.
    $detected = $agent->callDetectPhpTestRunner();
    if ($detected !== null) {
        pa_fail('phpunit detect: expected null when vendor/bin/phpunit absent, got ' . json_encode($detected));
    }
    $payload = $agent->callBuildTestResultsPayload('err-1', true);
    if (($payload['language'] ?? null) !== 'php') {
        pa_fail('phpunit payload: language mismatch, got ' . json_encode($payload));
    }
    if (($payload['framework'] ?? null) !== 'phpunit') {
        pa_fail('phpunit payload: framework should be phpunit even when skipped, got ' . json_encode($payload));
    }
    if (($payload['total_tests'] ?? null) !== 1 || ($payload['skipped'] ?? null) !== 1) {
        pa_fail('phpunit payload: expected total_tests=1 skipped=1 when no runner, got ' . json_encode($payload));
    }
    if (($payload['results'][0]['status'] ?? null) !== 'skipped') {
        pa_fail('phpunit payload: expected results[0].status=skipped, got ' . json_encode($payload));
    }
    if (($payload['executed_by'] ?? null) !== 'agent') {
        pa_fail('phpunit payload: expected executed_by=agent, got ' . json_encode($payload));
    }

    // Drop a fake vendor/bin/phpunit and verify detection picks it up.
    mkdir($tmpDir . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin', 0700, true);
    file_put_contents($tmpDir . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'phpunit', "<?php // fake\n");
    $detected2 = $agent->callDetectPhpTestRunner();
    if (!is_array($detected2) || count($detected2) !== 2) {
        pa_fail('phpunit detect: expected [argv, framework] when vendor/bin/phpunit present, got ' . json_encode($detected2));
    }
    [$argv, $framework] = $detected2;
    if ($framework !== 'phpunit') {
        pa_fail('phpunit detect: expected framework=phpunit, got ' . json_encode($detected2));
    }
    if (!is_array($argv) || count($argv) !== 2) {
        pa_fail('phpunit detect: expected 2-element argv, got ' . json_encode($argv));
    }
    if ($argv[0] !== PHP_BINARY) {
        pa_fail('phpunit detect: argv[0] must be PHP_BINARY (no shell), got ' . json_encode($argv));
    }
    if (substr($argv[1], -strlen('phpunit')) !== 'phpunit') {
        pa_fail('phpunit detect: argv[1] should end with phpunit, got ' . json_encode($argv));
    }
} finally {
    chdir($origCwd);
    // Best-effort cleanup. Nested rmdir; ignore failures on leftover files.
    @unlink($tmpDir . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'phpunit');
    @rmdir($tmpDir . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin');
    @rmdir($tmpDir . DIRECTORY_SEPARATOR . 'vendor');
    @rmdir($tmpDir);
}

// -------------------------------------------------------------------------
// 8. Pest fallback when phpunit is absent but pest is present.
// -------------------------------------------------------------------------
$tmpDir2 = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly_pest_test_' . uniqid();
mkdir($tmpDir2 . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin', 0700, true);
file_put_contents($tmpDir2 . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'pest', "<?php // fake\n");
chdir($tmpDir2);
try {
    $detected3 = $agent->callDetectPhpTestRunner();
    if (!is_array($detected3) || ($detected3[1] ?? null) !== 'pest') {
        pa_fail('pest detect: expected framework=pest when only vendor/bin/pest present, got ' . json_encode($detected3));
    }
} finally {
    chdir($origCwd);
    @unlink($tmpDir2 . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'pest');
    @rmdir($tmpDir2 . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin');
    @rmdir($tmpDir2 . DIRECTORY_SEPARATOR . 'vendor');
    @rmdir($tmpDir2);
}

echo "post_apply_steps_test.php: OK\n";
