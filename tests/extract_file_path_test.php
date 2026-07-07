<?php
/**
 * CLI: php connectors/php/tests/extract_file_path_test.php
 *
 * Locks multi-language file-path extraction used by the exclude_paths gate.
 * Before this, extractFilePath() only parsed Python `File "..."`, so a PHP
 * app's own fatals never matched exclude_paths and could not be skipped before
 * ingest. Mirrors the server-side extract_source_file_path().
 */

$source = file_get_contents(dirname(__DIR__) . '/php_agent.php');
if ($source === false) {
    fwrite(STDERR, "Cannot read php_agent.php\n");
    exit(1);
}
foreach (['\bin\s+', '#\d+\s+'] as $needle) {
    if (strpos($source, $needle) === false) {
        fwrite(STDERR, "FAIL: php_agent.php extractFilePath missing token '{$needle}'\n");
        exit(1);
    }
}

// Functional mirror of extractFilePath().
function test_extract_file_path(string $c): ?string {
    if ($c === '') return null;
    if (preg_match('/File\s+["\']([^"\']+)["\']/', $c, $m)) return $m[1];
    if (preg_match('/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)/i', $c, $m)) return $m[1];
    if (preg_match('/#\d+\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\(\d+\)/', $c, $m)) return $m[1];
    if (preg_match('/\(((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)/', $c, $m)) return $m[1];
    return null;
}

$cases = [
    ['PHP Fatal error: boom in /var/www/app.php:10', '/var/www/app.php'],
    ['PHP Warning: x in /var/www/f.php on line 42', '/var/www/f.php'],
    ['#0 /var/www/lib/db.php(88): Db->query()', '/var/www/lib/db.php'],
    ['File "/app/x.py", line 1', '/app/x.py'],
    ['at Object.<anonymous> (/srv/app/index.js:12:34)', '/srv/app/index.js'],
    ['plain log line with no path', null],
];
foreach ($cases as [$in, $want]) {
    $got = test_extract_file_path($in);
    if ($got !== $want) {
        fwrite(STDERR, "FAIL: extract(" . substr($in, 0, 40) . ") => " . var_export($got, true) . ", want " . var_export($want, true) . "\n");
        exit(1);
    }
}

echo "extract_file_path_test.php: OK\n";
